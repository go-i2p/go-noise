package wire

import (
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// ChaChaObfuscationModifier implements SSU2's ChaCha20-based obfuscation.
// Per the SSU2 specification, SessionRequest and SessionCreated obfuscate
// 48 bytes (header[16:32] || ephemeral_key) with a single ChaCha20 stream
// at counter position n=1 ("key: Bob's intro key, n: 1, data: 48 bytes").
// This modifier supports both the 48-byte spec-compliant mode
// and 32-byte ephemeral-key-only mode for backward compatibility.
//
// Note: The primary obfuscation path in SSU2 is handled by
// HeaderProtector.encryptLongHeaderExtension, which processes the assembled
// packet. This modifier is available for use in modifier chains where the
// data is processed separately.
type ChaChaObfuscationModifier struct {
	mu       sync.RWMutex
	closed   bool
	name     string
	introKey []byte // 32-byte intro key (Bob's intro key per SSU2 spec)
}

// chachaNonce is the 12-byte all-zero nonce used with ChaCha20 for SSU2
// header obfuscation. The spec requires counter position n=1, which is
// set via SetCounter(1) after cipher creation.
var chachaNonce = make([]byte, 12)

// NewChaChaObfuscationModifier creates a new ChaCha20 obfuscation modifier for SSU2.
// introKey must be 32 bytes (Bob's intro key per the SSU2 spec).
// Returns error if parameters are invalid.
func NewChaChaObfuscationModifier(name string, introKey []byte) (*ChaChaObfuscationModifier, error) {
	flog("NewChaChaObfuscationModifier", logger.Fields{"name": name}).Debug("Creating new ChaChaObfuscationModifier")
	if len(introKey) != 32 {
		return nil, oops.
			Code("INVALID_INTRO_KEY").
			In("wire").
			With("key_length", len(introKey)).
			Errorf("intro key must be exactly 32 bytes")
	}

	// Make defensive copy to prevent external modification
	key := make([]byte, 32)
	copy(key, introKey)

	return &ChaChaObfuscationModifier{
		name:     name,
		introKey: key,
	}, nil
}

// ModifyOutbound applies ChaCha20 obfuscation to handshake messages.
// Accepts 48 bytes (header[16:32] || ephemeral key) per SSU2 spec, or
// 32 bytes (ephemeral key only) for backward compatibility.
// Message 3+: No obfuscation
func (com *ChaChaObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifyOutbound", logger.Fields{"phase": phase, "dataLen": len(data)}).Debug("ChaCha obfuscation ModifyOutbound")
	if err := validateChaChaInputLength(len(data)); err != nil {
		return nil, err
	}

	switch phase {
	case handshake.PhaseInitial, handshake.PhaseExchange:
		return com.applyChacha(data)
	default:
		return data, nil
	}
}

// ModifyInbound removes ChaCha20 obfuscation from handshake messages.
// ChaCha20 is symmetric (XOR-based), so encryption and decryption are identical.
// Accepts 48 bytes (spec-compliant) or 32 bytes (backward compatibility).
func (com *ChaChaObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifyInbound", logger.Fields{"phase": phase, "dataLen": len(data)}).Debug("ChaCha obfuscation ModifyInbound")
	if err := validateChaChaInputLength(len(data)); err != nil {
		return nil, err
	}

	switch phase {
	case handshake.PhaseInitial, handshake.PhaseExchange:
		return com.applyChacha(data)
	default:
		return data, nil
	}
}

// Name returns the modifier name for logging and debugging.
func (com *ChaChaObfuscationModifier) Name() string {
	return com.name
}

func validateChaChaInputLength(length int) error {
	if length == 32 || length == 48 {
		return nil
	}

	return oops.
		Code("INVALID_CHACHA_INPUT_LENGTH").
		In("wire").
		With("length", length).
		Errorf("unexpected data length %d for chacha obfuscation: expected 32 or 48", length)
}

// applyChacha creates a ChaCha20 cipher at counter position n=1 per the SSU2
// spec and XORs the data. Supports 48-byte (spec-compliant) and 32-byte
// (ephemeral-only) inputs. Returns an error if the modifier has been closed.
func (com *ChaChaObfuscationModifier) applyChacha(data []byte) ([]byte, error) {
	flog("applyChacha", logger.Fields{"dataLen": len(data)}).Debug("applyChacha: applying ChaCha20 XOR")
	com.mu.RLock()
	defer com.mu.RUnlock()

	if com.closed {
		return nil, oops.
			Code("MODIFIER_CLOSED").
			In("wire").
			With("modifier_name", com.name).
			Errorf("ChaChaObfuscationModifier has been closed")
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(com.introKey, chachaNonce)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("wire").
			With("modifier_name", com.name).
			Wrap(err)
	}
	// SSU2 spec requires n=1 (counter position 1, skipping the first 64 bytes)
	cipher.SetCounter(1)

	result := make([]byte, len(data))
	copy(result, data)
	cipher.XORKeyStream(result, result)
	return result, nil
}

// Close releases resources and zeroes sensitive key material.
// After Close returns, ModifyOutbound and ModifyInbound will return an error.
// Close is safe to call concurrently with ModifyOutbound/ModifyInbound.
func (com *ChaChaObfuscationModifier) Close() error {
	flog("Close", logger.Fields{"name": com.name}).Debug("Close: releasing ChaChaObfuscationModifier resources")
	com.mu.Lock()
	defer com.mu.Unlock()
	if !com.closed {
		com.closed = true
		securemem.SecureZero(com.introKey)
	}
	return nil
}
