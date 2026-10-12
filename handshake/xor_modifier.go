package handshake

import (
	"io"
	"sync"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// randReader is the random source used by NewXORModifier. It is a package-level
// variable to allow tests to inject a failing reader for the entropy-failure
// fallback path without relying on OS-level entropy failures.
var randReader io.Reader = rand.Reader

// XORModifier is a simple obfuscation modifier. It scrambles handshake data
// by XORing it with a repeating key pattern, and unscrambles it the same way
// on the way in. This adds a layer of obfuscation without affecting the
// security of the underlying Noise protocol.
//
// After Close() is called, ModifyOutbound and ModifyInbound return an error.
// This prevents a silent security problem: with a zeroed key, XOR would do
// nothing, and data would pass through with no obfuscation at all.
type XORModifier struct {
	mu      sync.Mutex
	name    string
	xorKey  []byte
	keySize int
	closed  bool
}

// NewXORModifier creates a new XOR modifier that uses the given key. The key
// is repeated as needed to match the length of the data being transformed.
//
// If key is nil or empty, a 32-byte cryptographically random key is generated
// automatically. Do not rely on any particular default value — the old
// well-known default (0xAA) provided no meaningful obfuscation and has been
// replaced by this random fallback.
//
// If the OS entropy source is unavailable (crypto/rand fails), this function
// returns an error. Callers MUST NOT proceed with a connection that cannot be
// obfuscated, because silently degrading to a weak key breaks anonymity
// guarantees.
func NewXORModifier(name string, xorKey []byte) (*XORModifier, error) {
	if len(xorKey) == 0 {
		// Generate a cryptographically random 32-byte key so that each modifier
		// instance with no explicit key still produces distinct output.
		randomKey := make([]byte, 32)
		if _, err := io.ReadFull(randReader, randomKey); err != nil {
			// Return an error instead of silently degrading to a 1-byte key.
			// This forces callers to handle the entropy failure explicitly
			// rather than proceeding with broken obfuscation.
			flog("NewXORModifier", logger.Fields{"name": name}).WithError(err).Error("crypto/rand failed; cannot create XOR modifier without degradation")
			return nil, oops.
				Code("RNG_FAILED").
				Wrapf(err, "failed to generate random XOR key")
		}
		xorKey = randomKey
	}

	// Make a copy to prevent external modification
	key := make([]byte, len(xorKey))
	copy(key, xorKey)

	return &XORModifier{
		name:    name,
		xorKey:  key,
		keySize: len(key),
	}, nil
}

// ModifyOutbound applies XOR obfuscation to outbound handshake data. It
// returns an error if Close() has been called.
//
// For [PhaseData] (and any future phase beyond [PhaseFinal]), data is
// returned unmodified. The XOR key is a single static, non-advancing
// keystream: applying it at the same byte offsets to every post-handshake
// message would reuse the same keystream bytes across the connection's
// entire data phase. An adversary who learns or guesses plaintext at any
// offset in one message would then recover the keystream bytes needed to
// de-obfuscate that same offset in every other message. Confining XOR to the
// one-shot handshake phases avoids this repeated-keystream break.
func (xm *XORModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	if xm.closed {
		return nil, oops.
			Code("MODIFIER_CLOSED").
			In("handshake").
			With("modifier_name", xm.name).
			Errorf("XORModifier has been closed")
	}

	if phase > PhaseFinal {
		return data, nil // Post-handshake: pass through unmodified
	}

	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xm.xorKey[i%xm.keySize]
	}

	return result, nil
}

// ModifyInbound removes XOR obfuscation from inbound handshake data. Because
// XOR is symmetric, this performs the same operation as ModifyOutbound.
func (xm *XORModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	return xm.ModifyOutbound(phase, data)
}

// Name returns the name of the XOR modifier for logging and debugging.
func (xm *XORModifier) Name() string {
	return xm.name
}

// Close zeroes the XOR key to prevent session-derived key material from
// lingering in memory after the connection is torn down. After Close(),
// ModifyOutbound and ModifyInbound will return an error to prevent silent
// security degradation from XOR with an all-zero key.
func (xm *XORModifier) Close() error {
	xm.mu.Lock()
	defer xm.mu.Unlock()

	securemem.SecureZero(xm.xorKey)
	xm.closed = true
	return nil
}
