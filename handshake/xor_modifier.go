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

// XORModifier implements a simple XOR-based obfuscation modifier.
// It XORs handshake data with a configurable key pattern to provide
// basic obfuscation without compromising Noise protocol security.
// Moved from: handshake/modifiers.go
//
// After Close() is called, ModifyOutbound and ModifyInbound return an error.
// This prevents silent security degradation where zeroed key material would
// cause XOR to become a no-op (identity function), passing data through
// without any obfuscation.
type XORModifier struct {
	mu      sync.Mutex
	name    string
	xorKey  []byte
	keySize int
	closed  bool
}

// NewXORModifier creates a new XOR modifier with the specified key.
// The key is repeated as needed to match the data length.
//
// Security note: if key is nil or empty, a 32-byte cryptographically random
// key is generated automatically. Callers must NOT rely on any particular
// default value — the old well-known default (0xAA) provided no meaningful
// obfuscation and has been replaced by this random fallback.
func NewXORModifier(name string, xorKey []byte) *XORModifier {
	if len(xorKey) == 0 {
		// Generate a cryptographically random 32-byte key so that each modifier
		// instance with no explicit key still produces distinct output.
		randomKey := make([]byte, 32)
		if _, err := io.ReadFull(randReader, randomKey); err != nil {
			// Fall back to a single non-zero byte only if the OS rand source is
			// completely broken.  This is a security degradation: the resulting
			// key provides near-zero obfuscation (1 byte, well-known constant).
			log.WithFields(logger.Fields{"pkg": "handshake", "func": "NewXORModifier", "name": name}).WithError(err).Error("crypto/rand failed, falling back to degraded 1-byte key")
			randomKey = []byte{0x01}
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
	}
}

// ModifyOutbound applies XOR obfuscation to outbound handshake data.
// Returns an error if Close() has been called.
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

	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xm.xorKey[i%xm.keySize]
	}

	return result, nil
}

// ModifyInbound removes XOR obfuscation from inbound handshake data.
// Since XOR is symmetric, this performs the same operation as ModifyOutbound.
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
