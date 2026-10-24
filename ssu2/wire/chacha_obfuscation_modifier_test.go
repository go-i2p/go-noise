package wire

import (
	"bytes"
	"github.com/go-i2p/crypto/rand"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewChaChaObfuscationModifier tests the constructor validation
func TestNewChaChaObfuscationModifier(t *testing.T) {
	tests := []struct {
		name        string
		modName     string
		introKey    []byte
		expectError bool
		errorCode   string
	}{
		{
			name:        "valid parameters",
			modName:     "test-chacha",
			introKey:    make([]byte, 32),
			expectError: false,
		},
		{
			name:        "invalid intro key - too short",
			modName:     "test-chacha",
			introKey:    make([]byte, 31),
			expectError: true,
			errorCode:   "INVALID_INTRO_KEY",
		},
		{
			name:        "invalid intro key - too long",
			modName:     "test-chacha",
			introKey:    make([]byte, 33),
			expectError: true,
			errorCode:   "INVALID_INTRO_KEY",
		},
		{
			name:        "empty intro key",
			modName:     "test-chacha",
			introKey:    []byte{},
			expectError: true,
			errorCode:   "INVALID_INTRO_KEY",
		},
		{
			name:        "nil intro key",
			modName:     "test-chacha",
			introKey:    nil,
			expectError: true,
			errorCode:   "INVALID_INTRO_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod, err := NewChaChaObfuscationModifier(tt.modName, tt.introKey)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mod)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mod)
				assert.Equal(t, tt.modName, mod.Name())
			}
		})
	}
}

// TestChaChaObfuscationModifier_DefensiveCopy verifies defensive copying
func TestChaChaObfuscationModifier_DefensiveCopy(t *testing.T) {
	introKey := make([]byte, 32)
	for i := range introKey {
		introKey[i] = byte(i)
	}

	mod, err := NewChaChaObfuscationModifier("test", introKey)
	require.NoError(t, err)

	// Modify original slice
	introKey[0] = 0xFF

	// Verify modifier's internal copy is unchanged
	assert.NotEqual(t, byte(0xFF), mod.introKey[0])
	assert.Equal(t, byte(0), mod.introKey[0])
}

// TestChaChaObfuscationModifier_Roundtrip tests encryption/decryption roundtrip
func TestChaChaObfuscationModifier_Roundtrip(t *testing.T) {
	introKey := make([]byte, 32)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-roundtrip", introKey)
	require.NoError(t, err)

	// Test message 1 (PhaseInitial)
	original1 := make([]byte, 32)
	_, err = rand.Read(original1)
	require.NoError(t, err)

	encrypted1, err := mod.ModifyOutbound(handshake.PhaseInitial, original1)
	require.NoError(t, err)
	assert.NotNil(t, encrypted1)
	assert.Len(t, encrypted1, 32)
	assert.False(t, bytes.Equal(original1, encrypted1), "encrypted data should differ from original")

	// Create new modifier for decryption (simulates receiver)
	modDecrypt, err := NewChaChaObfuscationModifier("test-decrypt", introKey)
	require.NoError(t, err)

	decrypted1, err := modDecrypt.ModifyInbound(handshake.PhaseInitial, encrypted1)
	require.NoError(t, err)
	assert.Equal(t, original1, decrypted1, "decrypted should match original")

	// Test message 2 (PhaseExchange) - uses same key and nonce per spec
	original2 := make([]byte, 32)
	_, err = rand.Read(original2)
	require.NoError(t, err)

	encrypted2, err := mod.ModifyOutbound(handshake.PhaseExchange, original2)
	require.NoError(t, err)
	assert.NotNil(t, encrypted2)
	assert.Len(t, encrypted2, 32)
	assert.False(t, bytes.Equal(original2, encrypted2), "encrypted data should differ from original")

	decrypted2, err := modDecrypt.ModifyInbound(handshake.PhaseExchange, encrypted2)
	require.NoError(t, err)
	assert.Equal(t, original2, decrypted2, "decrypted should match original")
}

// TestChaChaObfuscationModifier_PhaseSpecific tests phase-specific behavior
func TestChaChaObfuscationModifier_PhaseSpecific(t *testing.T) {
	introKey := make([]byte, 32)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-phase", introKey)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// Test PhaseInitial - should encrypt
	result, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(data, result))

	// Test PhaseExchange - should encrypt
	result2, err := mod.ModifyOutbound(handshake.PhaseExchange, data)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(data, result2))

	// Test PhaseFinal - should NOT encrypt (pass through)
	result3, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, result3), "PhaseFinal should pass data through unchanged")
}

// TestChaChaObfuscationModifier_NonEphemeralKey tests handling of non-32-byte data
func TestChaChaObfuscationModifier_NonEphemeralKey(t *testing.T) {
	introKey := make([]byte, 32)

	mod, err := NewChaChaObfuscationModifier("test-size", introKey)
	require.NoError(t, err)

	// Lengths that are neither 32 nor 48 should now return an error.
	unexpectedSizes := []int{0, 1, 16, 31, 33, 64, 128}

	for _, size := range unexpectedSizes {
		t.Run(string(rune(size))+"_bytes", func(t *testing.T) {
			data := make([]byte, size)
			_, _ = rand.Read(data)

			_, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
			require.Error(t, err, "unexpected data length should return error")
		})
	}
}

// TestChaChaObfuscationModifier_FixedNonce tests that the modifier uses n=1 counter per SSU2 spec
func TestChaChaObfuscationModifier_FixedNonce(t *testing.T) {
	introKey := make([]byte, 32)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-nonce", introKey)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// Message 1 and message 2 with same data should produce same output
	// because both use the same key and all-zero nonce
	enc1, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	enc2, err := mod.ModifyOutbound(handshake.PhaseExchange, data)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2, "same key+nonce should produce same output for same input")
}

// TestChaChaObfuscationModifier_DifferentKeys tests that different keys produce different output
func TestChaChaObfuscationModifier_DifferentKeys(t *testing.T) {
	introKey1 := make([]byte, 32)
	introKey2 := make([]byte, 32)
	_, err := rand.Read(introKey1)
	require.NoError(t, err)
	_, err = rand.Read(introKey2)
	require.NoError(t, err)

	mod1, err := NewChaChaObfuscationModifier("mod1", introKey1)
	require.NoError(t, err)

	mod2, err := NewChaChaObfuscationModifier("mod2", introKey2)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	encrypted1, err := mod1.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	encrypted2, err := mod2.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(encrypted1, encrypted2), "different keys should produce different output")
}

// TestChaChaObfuscationModifier_SymmetricOperation tests that ChaCha20 encryption and decryption are identical
func TestChaChaObfuscationModifier_SymmetricOperation(t *testing.T) {
	introKey := make([]byte, 32)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-symmetric", introKey)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	encrypted, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	mod2, err := NewChaChaObfuscationModifier("test-symmetric2", introKey)
	require.NoError(t, err)

	decrypted, err := mod2.ModifyInbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	assert.Equal(t, encrypted, decrypted, "ChaCha20 is symmetric - encrypt and decrypt should be identical")
}

// BenchmarkChaChaObfuscation benchmarks the ChaCha20 obfuscation performance
func BenchmarkChaChaObfuscation(b *testing.B) {
	introKey := make([]byte, 32)
	_, _ = rand.Read(introKey)

	mod, _ := NewChaChaObfuscationModifier("bench", introKey)
	data := make([]byte, 32)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ModifyOutbound(handshake.PhaseInitial, data)
	}
}
