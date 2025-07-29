package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// AESObfuscationModifier implements NTCP2's AES-based ephemeral key obfuscation.
// This modifier encrypts/decrypts the X and Y ephemeral keys in messages 1 and 2
// using AES-256-CBC with the router hash as key and published IV.
// Moved from: ntcp2/modifier.go
type AESObfuscationModifier struct {
	name       string
	routerHash []byte // 32-byte router hash (RH_B)
	iv         []byte // 16-byte IV from network database
	aesState   []byte // AES state for message 2 (reused from message 1)
}

// NewAESObfuscationModifier creates a new AES obfuscation modifier for NTCP2.
// routerHash must be 32 bytes (RH_B), iv must be 16 bytes from network database.
func NewAESObfuscationModifier(name string, routerHash, iv []byte) (*AESObfuscationModifier, error) {
	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	if len(iv) != 16 {
		return nil, oops.
			Code("INVALID_IV").
			In("ntcp2").
			With("iv_length", len(iv)).
			Errorf("IV must be exactly 16 bytes")
	}

	// Make defensive copies
	hash := make([]byte, 32)
	copy(hash, routerHash)

	initIV := make([]byte, 16)
	copy(initIV, iv)

	return &AESObfuscationModifier{
		name:       name,
		routerHash: hash,
		iv:         initIV,
	}, nil
}

// ModifyOutbound applies AES obfuscation to ephemeral keys in handshake messages.
// For message 1: encrypts X key with RH_B and published IV
// For message 2: encrypts Y key with RH_B and AES state from message 1
func (aom *AESObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != 32 {
		return data, nil
	}

	block, err := aes.NewCipher(aom.routerHash)
	if err != nil {
		return nil, oops.
			Code("AES_CIPHER_CREATION_FAILED").
			In("ntcp2").
			With("modifier_name", aom.name).
			Wrap(err)
	}

	var mode cipher.BlockMode
	switch phase {
	case handshake.PhaseInitial:
		// Message 1: use published IV
		mode = cipher.NewCBCEncrypter(block, aom.iv)
		// Save AES state for message 2
		aom.aesState = make([]byte, 16)
		copy(aom.aesState, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCEncrypter(block, aom.aesState)
	default:
		// Message 3 and beyond: no AES obfuscation
		return data, nil
	}

	result := make([]byte, 32)
	copy(result, data)
	mode.CryptBlocks(result, result)

	return result, nil
}

// ModifyInbound removes AES obfuscation from ephemeral keys in handshake messages.
func (aom *AESObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != 32 {
		return data, nil
	}

	block, err := aes.NewCipher(aom.routerHash)
	if err != nil {
		return nil, oops.
			Code("AES_CIPHER_CREATION_FAILED").
			In("ntcp2").
			With("modifier_name", aom.name).
			Wrap(err)
	}

	var mode cipher.BlockMode
	switch phase {
	case handshake.PhaseInitial:
		// Message 1: use published IV
		mode = cipher.NewCBCDecrypter(block, aom.iv)
		// Save AES state for message 2
		aom.aesState = make([]byte, 16)
		copy(aom.aesState, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCDecrypter(block, aom.aesState)
	default:
		// Message 3 and beyond: no AES obfuscation
		return data, nil
	}

	result := make([]byte, 32)
	copy(result, data)
	mode.CryptBlocks(result, result)

	return result, nil
}

// Name returns the modifier name for logging and debugging.
func (aom *AESObfuscationModifier) Name() string {
	return aom.name
}
