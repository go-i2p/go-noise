package ntcp2

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/crypto/aes"

	"github.com/go-i2p/crypto/siphash"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertSipHashRoundTrip verifies that sender.ModifyOutbound → receiver.ModifyInbound
// produces the original length for `count` iterations starting at `baseLen` with
// the given step. msgFmt is a format string receiving (index, original, got).
func assertSipHashRoundTrip(
	t testing.TB,
	sender, receiver handshake.HandshakeModifier,
	count, baseLen, step int,
	msgFmt string,
) {
	t.Helper()
	for i := 0; i < count; i++ {
		original := uint16(baseLen + i*step)
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, original)

		obfuscated, err := sender.ModifyOutbound(handshake.PhaseData, data)
		require.NoError(t, err)

		recovered, err := receiver.ModifyInbound(handshake.PhaseData, obfuscated)
		require.NoError(t, err)

		got := binary.BigEndian.Uint16(recovered)
		assert.Equal(t, original, got, msgFmt, i, original, got)
	}
}

// assertAESRoundTrip verifies that sender.ModifyOutbound → receiver.ModifyInbound
// recovers the original plaintext for a given handshake phase. The label is used
// in assertion messages to identify which key/phase is being tested.
func assertAESRoundTrip(
	t *testing.T,
	sender, receiver *AESObfuscationModifier,
	phase handshake.HandshakePhase,
	plaintext []byte,
	label string,
) {
	t.Helper()
	ciphertext, err := sender.ModifyOutbound(phase, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext, "%s must be encrypted", label)

	recovered, err := receiver.ModifyInbound(phase, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered, "Receiver must recover original %s", label)
}

// assertSipHashMaskRoundTrip verifies a single frame's SipHash length obfuscation
// round trip: sender masks the length, receiver unmasks it, and the result matches.
func assertSipHashMaskRoundTrip(
	t *testing.T,
	sender, receiver *SipHashLengthModifier,
	originalLen uint16,
	msgFmtArgs ...interface{},
) {
	t.Helper()
	outMask := sender.NextOutboundMask()
	obfuscated := originalLen ^ outMask

	wire := make([]byte, 2)
	binary.BigEndian.PutUint16(wire, obfuscated)

	inMask := receiver.NextInboundMask()
	recovered := binary.BigEndian.Uint16(wire) ^ inMask

	assert.Equal(t, originalLen, recovered, msgFmtArgs...)
}

func TestAESObfuscationModifier_Creation(t *testing.T) {
	tests := []struct {
		name           string
		routerHash     []byte
		iv             []byte
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:        "Valid parameters",
			routerHash:  make([]byte, 32),
			iv:          make([]byte, 16),
			expectError: false,
		},
		{
			name:           "Invalid router hash length",
			routerHash:     make([]byte, 31),
			iv:             make([]byte, 16),
			expectError:    true,
			expectedErrMsg: "router hash must be exactly 32 bytes",
		},
		{
			name:           "Invalid IV length",
			routerHash:     make([]byte, 32),
			iv:             make([]byte, 15),
			expectError:    true,
			expectedErrMsg: "IV must be exactly 16 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewAESObfuscationModifier("test", tt.routerHash, tt.iv)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
				assert.Nil(t, modifier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, modifier)
				assert.Equal(t, "test", modifier.Name())
			}
		})
	}
}

func TestAESObfuscationModifier_Roundtrip(t *testing.T) {
	// Create test data
	routerHash := deterministicBytes(32, 0)
	iv := deterministicBytes(16, 32)
	ephemeralKey := deterministicBytes(32, 64)

	modifier, err := NewAESObfuscationModifier("aes_test", routerHash, iv)
	require.NoError(t, err)

	tests := []struct {
		name  string
		phase handshake.HandshakePhase
		data  []byte
	}{
		{
			name:  "Message 1 (PhaseInitial)",
			phase: handshake.PhaseInitial,
			data:  ephemeralKey,
		},
		{
			name:  "Message 2 (PhaseExchange)",
			phase: handshake.PhaseExchange,
			data:  ephemeralKey,
		},
		{
			name:  "Message 3 (PhaseFinal) - no obfuscation",
			phase: handshake.PhaseFinal,
			data:  ephemeralKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply outbound transformation
			obfuscated, err := modifier.ModifyOutbound(tt.phase, tt.data)
			require.NoError(t, err)

			if tt.phase == handshake.PhaseFinal {
				// No obfuscation for message 3 and beyond
				assert.Equal(t, tt.data, obfuscated)
			} else {
				// Should be different for messages 1 and 2
				assert.NotEqual(t, tt.data, obfuscated)
				assert.Len(t, obfuscated, 32)
			}

			// Apply inbound transformation to recover original
			recovered, err := modifier.ModifyInbound(tt.phase, obfuscated)
			require.NoError(t, err)
			assert.Equal(t, tt.data, recovered)
		})
	}
}

func TestAESObfuscationModifier_NonKeyData(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)

	modifier, err := NewAESObfuscationModifier("test", routerHash, iv)
	require.NoError(t, err)

	// Test with non-32-byte data (should pass through unchanged)
	testData := []byte("not a 32-byte key")

	result, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)
}

func TestSipHashLengthModifier_Creation(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	initialIV := uint64(0x1122334455667788)

	modifier := NewSipHashLengthModifier("siphash_test", sipKeys, initialIV)
	assert.NotNil(t, modifier)
	assert.Equal(t, "siphash_test", modifier.Name())
}

func TestSipHashLengthModifier_Roundtrip(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	initialIV := uint64(0x1122334455667788)

	modifier := NewSipHashLengthModifier("test", sipKeys, initialIV)

	tests := []struct {
		name   string
		phase  handshake.HandshakePhase
		length uint16
	}{
		{
			name:   "Data phase length",
			phase:  handshake.PhaseFinal,
			length: 1024,
		},
		{
			name:   "Minimum length",
			phase:  handshake.PhaseFinal,
			length: 16,
		},
		{
			name:   "Maximum length",
			phase:  handshake.PhaseFinal,
			length: 65535,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare 2-byte length data
			lengthData := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthData, tt.length)

			// Apply obfuscation
			obfuscated, err := modifier.ModifyOutbound(tt.phase, lengthData)
			require.NoError(t, err)
			assert.Len(t, obfuscated, 2)

			// Should be different (unless mask is zero, which is unlikely)
			obfuscatedLength := binary.BigEndian.Uint16(obfuscated)
			if obfuscatedLength == tt.length {
				t.Logf("Warning: mask was zero, obfuscated length equals original")
			}

			// Apply deobfuscation to recover original
			recovered, err := modifier.ModifyInbound(tt.phase, obfuscated)
			require.NoError(t, err)
			recoveredLength := binary.BigEndian.Uint16(recovered)
			assert.Equal(t, tt.length, recoveredLength)
		})
	}
}

func TestSipHashLengthModifier_NonDataPhase(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSipHashLengthModifier("test", sipKeys, 0)

	testData := []byte{0x04, 0x00} // 1024 in big endian

	// Should not modify handshake phase data
	for _, phase := range []handshake.HandshakePhase{handshake.PhaseInitial, handshake.PhaseExchange} {
		result, err := modifier.ModifyOutbound(phase, testData)
		require.NoError(t, err)
		assert.Equal(t, testData, result)
	}
}

func TestNTCP2PaddingModifier_Creation(t *testing.T) {
	tests := []struct {
		name           string
		minPadding     int
		maxPadding     int
		useAEADPadding bool
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:           "Valid cleartext padding",
			minPadding:     0,
			maxPadding:     31,
			useAEADPadding: false,
			expectError:    false,
		},
		{
			name:           "Valid AEAD padding",
			minPadding:     4,
			maxPadding:     16,
			useAEADPadding: true,
			expectError:    false,
		},
		{
			name:           "Negative minimum padding",
			minPadding:     -1,
			maxPadding:     10,
			useAEADPadding: false,
			expectError:    true,
			expectedErrMsg: "minimum padding cannot be negative",
		},
		{
			name:           "Maximum less than minimum",
			minPadding:     10,
			maxPadding:     5,
			useAEADPadding: false,
			expectError:    true,
			expectedErrMsg: "maximum padding cannot be less than minimum padding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewNTCP2PaddingModifier("test", tt.minPadding, tt.maxPadding, tt.useAEADPadding)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
				assert.Nil(t, modifier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, modifier)
				assert.Equal(t, "test", modifier.Name())
			}
		})
	}
}

func TestNTCP2PaddingModifier_CleartextPadding(t *testing.T) {
	// Test cleartext padding for messages 1 and 2 with production-grade implementation
	modifier, err := newNTCP2TestModifier(t, "cleartext_test", 4, 16, false)
	require.NoError(t, err)

	originalData := []byte("test handshake data")

	tests := []struct {
		name  string
		phase handshake.HandshakePhase
	}{
		{
			name:  "Message 1 (PhaseInitial)",
			phase: handshake.PhaseInitial,
		},
		{
			name:  "Message 2 (PhaseExchange)",
			phase: handshake.PhaseExchange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply padding
			padded, err := modifier.ModifyOutbound(tt.phase, originalData)
			require.NoError(t, err)

			// Should be longer than original
			assert.Greater(t, len(padded), len(originalData))

			// Original data should be at the beginning
			assert.Equal(t, originalData, padded[:len(originalData)])

			// Padding amount should be within range
			paddingSize := len(padded) - len(originalData)
			assert.GreaterOrEqual(t, paddingSize, 4)
			assert.LessOrEqual(t, paddingSize, 16)

			// For cleartext padding, ModifyInbound should return data unchanged
			// (padding removal is handled by the protocol)
			result, err := modifier.ModifyInbound(tt.phase, padded)
			require.NoError(t, err)
			assert.Equal(t, padded, result)
		})
	}
}

func TestNTCP2PaddingModifier_AEADPadding(t *testing.T) {
	// Test AEAD padding for data phase with production-grade implementation.
	// AEAD padding is only applied during PhaseData (post-handshake), not
	// PhaseFinal (message 3), because message 3 padding must be included
	// in m3p2Len which is committed in message 1.
	modifier, err := newNTCP2TestModifier(t, "aead_test", 4, 16, true)
	require.NoError(t, err)

	originalData := []byte("test data phase message")

	// PhaseFinal must NOT add AEAD padding (would corrupt handshake framing)
	notPadded, err := modifier.ModifyOutbound(handshake.PhaseFinal, originalData)
	require.NoError(t, err)
	assert.Equal(t, originalData, notPadded, "PhaseFinal must not add AEAD padding")

	// Apply AEAD padding (PhaseData)
	padded, err := modifier.ModifyOutbound(handshake.PhaseData, originalData)
	require.NoError(t, err)

	// Debug output
	t.Logf("Original data length: %d", len(originalData))
	t.Logf("Padded data length: %d", len(padded))
	t.Logf("Padded data: %x", padded)

	// Should be longer than original
	assert.Greater(t, len(padded), len(originalData))

	// Original data should be at the beginning
	assert.Equal(t, originalData, padded[:len(originalData)])

	// Should have padding block at the end (type 254)
	paddingBlockStart := len(originalData)
	assert.Equal(t, byte(254), padded[paddingBlockStart]) // Padding block type

	// Get padding size from block header
	paddingSize := binary.BigEndian.Uint16(padded[paddingBlockStart+1 : paddingBlockStart+3])
	assert.GreaterOrEqual(t, int(paddingSize), 4)
	assert.LessOrEqual(t, int(paddingSize), 16)

	// Total length should match
	expectedLength := len(originalData) + 3 + int(paddingSize) // data + block_header + padding
	assert.Equal(t, expectedLength, len(padded))

	// Remove padding
	recovered, err := modifier.ModifyInbound(handshake.PhaseData, padded)
	require.NoError(t, err)
	t.Logf("Recovered data length: %d", len(recovered))
	t.Logf("Recovered data: %x", recovered)
	assert.Equal(t, originalData, recovered)
}

func TestNTCP2PaddingModifier_NoPadding(t *testing.T) {
	// Test with no padding configured
	modifier, err := newNTCP2TestModifier(t, "no_padding", 0, 0, false)
	require.NoError(t, err)

	testData := []byte("test data")

	result, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)
}

func TestNTCP2PaddingModifier_PhaseMatching(t *testing.T) {
	cleartextModifier, err := newNTCP2TestModifier(t, "cleartext", 4, 8, false)
	require.NoError(t, err)
	aeadModifier, err := newNTCP2TestModifier(t, "aead", 4, 8, true)
	require.NoError(t, err)

	testData := []byte("test data")

	// Verify modifiers do not affect phases they don't target.
	tests := []struct {
		name     string
		modifier handshake.HandshakeModifier
		phase    handshake.HandshakePhase
	}{
		{"cleartext ignores final", cleartextModifier, handshake.PhaseFinal},
		{"AEAD ignores initial", aeadModifier, handshake.PhaseInitial},
		{"AEAD ignores exchange", aeadModifier, handshake.PhaseExchange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.modifier.ModifyOutbound(tt.phase, testData)
			require.NoError(t, err)
			assert.Equal(t, testData, result)
		})
	}
}

func TestNTCP2Modifiers_Integration(t *testing.T) {
	// Test using multiple NTCP2 modifiers together
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 32)
	}

	// Create modifiers
	aesModifier, err := NewAESObfuscationModifier("aes", routerHash, iv)
	require.NoError(t, err)

	cleartextPadding, err := newNTCP2TestModifier(t, "cleartext_pad", 4, 8, false)
	require.NoError(t, err)

	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	sipModifier := NewSipHashLengthModifier("siphash", sipKeys, 0x1122334455667788)

	// Test message 1: AES + cleartext padding
	ephemeralKey := make([]byte, 32)
	for i := range ephemeralKey {
		ephemeralKey[i] = byte(i + 64)
	}

	// Apply AES obfuscation first
	obfuscated, err := aesModifier.ModifyOutbound(handshake.PhaseInitial, ephemeralKey)
	require.NoError(t, err)

	// Apply cleartext padding
	padded, err := cleartextPadding.ModifyOutbound(handshake.PhaseInitial, obfuscated)
	require.NoError(t, err)

	// Should be longer due to padding
	assert.Greater(t, len(padded), len(obfuscated))

	// Test data phase: SipHash length obfuscation
	lengthData := []byte{0x04, 0x00} // 1024 bytes
	obfuscatedLength, err := sipModifier.ModifyOutbound(handshake.PhaseData, lengthData)
	require.NoError(t, err)

	// Should be different (unless mask is zero)
	if bytes.Equal(lengthData, obfuscatedLength) {
		t.Logf("Warning: SipHash mask was zero")
	}

	// Recovery should work
	recoveredLength, err := sipModifier.ModifyInbound(handshake.PhaseData, obfuscatedLength)
	require.NoError(t, err)
	assert.Equal(t, lengthData, recoveredLength)
}

func TestNTCP2PaddingModifier_ProductionFeatures(t *testing.T) {
	t.Run("Padding Ratio Configuration", func(t *testing.T) {
		// Test padding ratio functionality
		modifier, err := NewNTCP2PaddingModifierWithRatio("ratio_test", 4, 32, true, 1.0)
		require.NoError(t, err)

		// 1.0 ratio means 100% padding (double the size)
		testData := []byte("hello world") // 11 bytes
		result, err := modifier.ModifyOutbound(handshake.PhaseData, testData)
		require.NoError(t, err)

		// Should have padding block (type 254) with approximately 11 bytes of padding
		assert.Greater(t, len(result), len(testData)+3)   // data + block header + some padding
		assert.Equal(t, byte(254), result[len(testData)]) // Padding block type

		// Verify ratio can be updated
		err = modifier.SetPaddingRatio(0.5) // 50% padding
		require.NoError(t, err)
		assert.Equal(t, 0.5, modifier.GetPaddingRatio())
	})

	t.Run("Padding Limits Validation", func(t *testing.T) {
		// Test I2P NTCP2 spec limits
		_, err := NewNTCP2PaddingModifier("test", 0, 65517, false)
		assert.Error(t, err, "Should reject padding > 65516 bytes")

		_, err = NewNTCP2PaddingModifier("test", -1, 10, false)
		assert.Error(t, err, "Should reject negative min padding")

		_, err = NewNTCP2PaddingModifier("test", 10, 5, false)
		assert.Error(t, err, "Should reject max < min")

		// Test ratio limits
		_, err = NewNTCP2PaddingModifierWithRatio("test", 0, 10, false, -0.1)
		assert.Error(t, err, "Should reject negative ratio")

		_, err = NewNTCP2PaddingModifierWithRatio("test", 0, 10, false, 16.0)
		assert.Error(t, err, "Should reject ratio > 15.9375")
	})

	t.Run("Dynamic Parameter Updates", func(t *testing.T) {
		modifier, err := NewNTCP2PaddingModifier("dynamic_test", 0, 10, true)
		require.NoError(t, err)

		// Update padding limits
		err = modifier.SetPaddingLimits(5, 20)
		require.NoError(t, err)

		min, max := modifier.GetPaddingLimits()
		assert.Equal(t, 5, min)
		assert.Equal(t, 20, max)

		// Test with invalid updates
		err = modifier.SetPaddingLimits(-1, 20)
		assert.Error(t, err)

		err = modifier.SetPaddingLimits(25, 20)
		assert.Error(t, err)
	})

	t.Run("AEAD Frame Validation", func(t *testing.T) {
		modifier, err := newNTCP2TestModifier(t, "validation_test", 4, 8, true)
		require.NoError(t, err)

		// Create proper I2P block format data
		i2npBlock := []byte{3, 0, 5, 1, 2, 3, 4, 5} // I2NP block type 3, size 5, data
		padded, err := modifier.ModifyOutbound(handshake.PhaseData, i2npBlock)
		require.NoError(t, err)

		// Valid frame should pass validation
		assert.True(t, modifier.ValidateAEADFrame(padded))

		// Test invalid frames
		assert.False(t, modifier.ValidateAEADFrame([]byte{254, 0}))           // Incomplete header
		assert.False(t, modifier.ValidateAEADFrame([]byte{254, 0, 10, 1, 2})) // Size mismatch
	})

	t.Run("Padding Size Estimation", func(t *testing.T) {
		// Test with ratio-based padding
		modifier, err := NewNTCP2PaddingModifierWithRatio("estimate_test", 4, 32, true, 0.5)
		require.NoError(t, err)

		estimate := modifier.EstimatePaddingSize(20) // 20 bytes data
		assert.GreaterOrEqual(t, estimate, 4)        // At least min padding
		assert.LessOrEqual(t, estimate, 32)          // At most max padding

		// For 50% ratio, expect around 10 bytes padding for 20 bytes data
		assert.GreaterOrEqual(t, estimate, 10)

		// Test without ratio
		modifier2, err := NewNTCP2PaddingModifier("estimate_test2", 8, 16, true)
		require.NoError(t, err)

		estimate2 := modifier2.EstimatePaddingSize(100)
		assert.Equal(t, 12, estimate2) // Average of 8 and 16
	})

	t.Run("Mode Detection", func(t *testing.T) {
		cleartextMod, err := NewNTCP2PaddingModifier("cleartext", 0, 10, false)
		require.NoError(t, err)
		assert.False(t, cleartextMod.IsAEADMode())

		aeadMod, err := NewNTCP2PaddingModifier("aead", 0, 10, true)
		require.NoError(t, err)
		assert.True(t, aeadMod.IsAEADMode())
	})
}

func TestNTCP2PaddingModifier_SecurityProperties(t *testing.T) {
	t.Run("Secure Random vs Deterministic", func(t *testing.T) {
		// Production modifier should produce different padding each time
		prodMod, err := NewNTCP2PaddingModifier("prod", 4, 16, false)
		require.NoError(t, err)

		testData := []byte("consistent test data")

		// Generate multiple padded versions
		results := make([][]byte, 5)
		for i := range results {
			result, err := prodMod.ModifyOutbound(handshake.PhaseInitial, testData)
			require.NoError(t, err)
			results[i] = result
		}

		// Results should have different padding (very high probability)
		allSame := true
		for i := 1; i < len(results); i++ {
			if !bytes.Equal(results[0], results[i]) {
				allSame = false
				break
			}
		}
		assert.False(t, allSame, "Production padding should be non-deterministic")

		// Test deterministic mode produces same results
		testMod, err := newNTCP2TestModifier(t, "test", 4, 16, false)
		require.NoError(t, err)

		result1, err := testMod.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)
		result2, err := testMod.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)

		assert.Equal(t, result1, result2, "Test mode should be deterministic")
	})

	t.Run("AEAD Block Parsing Security", func(t *testing.T) {
		modifier, err := newNTCP2TestModifier(t, "security_test", 4, 8, true)
		require.NoError(t, err)

		// Test malformed block handling - should handle gracefully without error
		malformedData := []byte{254, 0, 100, 1, 2, 3} // Claims 100 bytes but only has 3
		result, err := modifier.ModifyInbound(handshake.PhaseData, malformedData)
		require.NoError(t, err, "Should handle malformed blocks gracefully")
		// Should return original data since no valid padding found
		assert.Equal(t, malformedData, result)

		// Test oversized block
		oversized := make([]byte, 3+65520) // Larger than spec limit
		oversized[0] = 254
		binary.BigEndian.PutUint16(oversized[1:3], 65520)
		result, err = modifier.ModifyInbound(handshake.PhaseData, oversized)
		require.NoError(t, err)
		// Should handle gracefully
		assert.NotNil(t, result)

		// Validation should catch multiple padding blocks
		multiPadding := []byte{254, 0, 2, 1, 2, 254, 0, 2, 3, 4}
		assert.False(t, modifier.ValidateAEADFrame(multiPadding))
	})
}

func TestNTCP2PaddingModifier_I2PCompliance(t *testing.T) {
	t.Run("Handshake Phase Compliance", func(t *testing.T) {
		// Messages 1-2: cleartext padding (outside AEAD)
		cleartextMod, err := newNTCP2TestModifier(t, "msg12", 0, 31, false)
		require.NoError(t, err)

		msg1Data := []byte("SessionRequest ephemeral key and options")
		padded1, err := cleartextMod.ModifyOutbound(handshake.PhaseInitial, msg1Data)
		require.NoError(t, err)

		// Should add padding but not AEAD block format
		assert.NotEqual(t, byte(254), padded1[len(msg1Data)]) // No AEAD padding block

		// Message 3+: AEAD padding (inside AEAD frames)
		aeadMod, err := newNTCP2TestModifier(t, "msg3", 0, 32, true)
		require.NoError(t, err)

		msg3Data := []byte("SessionConfirmed RouterInfo and options")
		padded3, err := aeadMod.ModifyOutbound(handshake.PhaseFinal, msg3Data)
		require.NoError(t, err)

		// PhaseFinal should NOT add AEAD padding (handled by handshake code)
		assert.Equal(t, msg3Data, padded3, "PhaseFinal must not add AEAD padding")
	})

	t.Run("Data Phase Block Format", func(t *testing.T) {
		modifier, err := newNTCP2TestModifier(t, "data_phase", 8, 16, true)
		require.NoError(t, err)

		// Simulate data phase message with I2NP message block
		i2npBlock := []byte{3, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

		padded, err := modifier.ModifyOutbound(handshake.PhaseData, i2npBlock)
		require.NoError(t, err)

		// Should append padding block after I2NP block
		assert.True(t, modifier.ValidateAEADFrame(padded))

		// Padding block should be last
		lastBlockPos := len(i2npBlock)
		if len(padded) > len(i2npBlock) {
			assert.Equal(t, byte(254), padded[lastBlockPos])
		}

		// Should be able to remove padding cleanly
		recovered, err := modifier.ModifyInbound(handshake.PhaseData, padded)
		require.NoError(t, err)
		assert.Equal(t, i2npBlock, recovered)
	})

	t.Run("Padding Ratio I2P Format", func(t *testing.T) {
		// Test I2P 4.4 fixed-point format (0 to 15.9375)
		ratios := []float64{0.0, 0.0625, 1.0, 8.0, 15.9375}

		for _, ratio := range ratios {
			modifier, err := NewNTCP2PaddingModifierWithRatio("ratio_test", 0, 100, true, ratio)
			require.NoError(t, err, "Ratio %f should be valid", ratio)

			assert.Equal(t, ratio, modifier.GetPaddingRatio())
		}

		// Test invalid ratios
		invalidRatios := []float64{-0.1, 16.0, 20.0}
		for _, ratio := range invalidRatios {
			_, err := NewNTCP2PaddingModifierWithRatio("invalid", 0, 100, true, ratio)
			assert.Error(t, err, "Ratio %f should be invalid", ratio)
		}
	})
}

// ============================================================================
// Tests from audit_fixes_test.go — modifier-related
// ============================================================================

func TestAudit_AESStatePropagation_CrossMessage(t *testing.T) {
	routerHash := deterministicBytes(32, 1)
	iv := deterministicBytes(16, 0x80)

	sender, err := NewAESObfuscationModifier("sender", routerHash, iv)
	require.NoError(t, err)
	receiver, err := NewAESObfuscationModifier("receiver", routerHash, iv)
	require.NoError(t, err)

	keyX := deterministicBytes(32, 0x40)
	keyY := deterministicBytes(32, 0xC0)
	keyY[31] &= 0x7F

	assertAESRoundTrip(t, sender, receiver, handshake.PhaseInitial, keyX, "X")
	assertAESRoundTrip(t, sender, receiver, handshake.PhaseExchange, keyY, "Y (using state from msg1)")
}

func TestAudit_AESState_IsLastCiphertextBlock(t *testing.T) {
	routerHash := deterministicBytes(32, 10)
	iv := deterministicBytes(16, 50)
	keyX := deterministicBytes(32, 100)

	block, err := aes.NewCipher(routerHash)
	require.NoError(t, err)

	manualCipher := make([]byte, 32)
	copy(manualCipher, keyX)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(manualCipher, manualCipher)

	expectedState := manualCipher[16:32]

	keyY := deterministicBytes(32, 200)
	manualCipherY := make([]byte, 32)
	copy(manualCipherY, keyY)
	mode2 := cipher.NewCBCEncrypter(block, expectedState)
	mode2.CryptBlocks(manualCipherY, manualCipherY)

	modifier, err := NewAESObfuscationModifier("verify", routerHash, iv)
	require.NoError(t, err)

	cipherX, err := modifier.ModifyOutbound(handshake.PhaseInitial, keyX)
	require.NoError(t, err)
	assert.Equal(t, manualCipher, cipherX, "msg1 encryption must match manual AES-CBC")

	cipherY, err := modifier.ModifyOutbound(handshake.PhaseExchange, keyY)
	require.NoError(t, err)
	assert.Equal(t, manualCipherY, cipherY,
		"msg2 encryption must use last ciphertext block from msg1 as IV")
}

func TestAudit_AESMissingState_Error(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)

	modifier, err := NewAESObfuscationModifier("test", routerHash, iv)
	require.NoError(t, err)

	keyY := make([]byte, 32)
	_, err = modifier.ModifyOutbound(handshake.PhaseExchange, keyY)
	assert.Error(t, err, "PhaseExchange without prior PhaseInitial must fail")
	assert.Contains(t, err.Error(), "AES state not available")

	_, err = modifier.ModifyInbound(handshake.PhaseExchange, keyY)
	assert.Error(t, err, "PhaseExchange inbound without prior PhaseInitial must fail")
	assert.Contains(t, err.Error(), "AES state not available")
}

func TestAudit_SipHashIVChaining(t *testing.T) {
	sipKeys := [2]uint64{0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF}
	initialIV := uint64(0xAAAABBBBCCCCDDDD)

	mod1 := NewSipHashLengthModifier("mod1", sipKeys, initialIV)
	mod2 := NewSipHashLengthModifier("mod2", sipKeys, initialIV)

	lengthData := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthData, 1000)

	for i := 0; i < 20; i++ {
		result1, err := mod1.ModifyOutbound(handshake.PhaseData, lengthData)
		require.NoError(t, err)
		result2, err := mod2.ModifyOutbound(handshake.PhaseData, lengthData)
		require.NoError(t, err)
		assert.Equal(t, result1, result2,
			"Identically-configured modifiers must produce same mask at step %d", i)
	}
}

func TestAudit_SipHashIVChaining_MatchesSpec(t *testing.T) {
	k1 := uint64(0x1111111122222222)
	k2 := uint64(0x3333333344444444)
	iv0 := uint64(0x5555555566666666)

	var expectedMasks [5]uint16
	currentIV := iv0
	for i := 0; i < 5; i++ {
		input := make([]byte, 8)
		binary.LittleEndian.PutUint64(input, currentIV)
		hash := siphash.Hash(k1, k2, input)
		expectedMasks[i] = uint16(hash & 0xFFFF)
		currentIV = hash
	}

	mod := NewSipHashLengthModifier("spec_test", [2]uint64{k1, k2}, iv0)
	for i := 0; i < 5; i++ {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, 0)
		result, err := mod.ModifyOutbound(handshake.PhaseData, data)
		require.NoError(t, err)
		mask := binary.BigEndian.Uint16(result)
		assert.Equal(t, expectedMasks[i], mask,
			"Mask at step %d must match spec-computed value", i)
	}
}

func TestAudit_SipHashIVChaining_NotCounterBased(t *testing.T) {
	sipKeys := [2]uint64{0xABCDEF0123456789, 0x9876543210FEDCBA}
	initialIV := uint64(0x1234567890ABCDEF)

	mod := NewSipHashLengthModifier("chain_test", sipKeys, initialIV)

	chainedMasks := make([]uint16, 10)
	for i := 0; i < 10; i++ {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, 0)
		result, err := mod.ModifyOutbound(handshake.PhaseData, data)
		require.NoError(t, err)
		chainedMasks[i] = binary.BigEndian.Uint16(result)
	}

	counterMasks := make([]uint16, 10)
	for i := 0; i < 10; i++ {
		input := make([]byte, 8)
		binary.LittleEndian.PutUint64(input, uint64(i))
		hash := siphash.Hash(sipKeys[0], sipKeys[1], input)
		counterMasks[i] = uint16(hash & 0xFFFF)
	}

	assert.False(t, masksEqual(chainedMasks, counterMasks),
		"IV-chained masks must differ from counter-based masks")
}

func TestAudit_SipHashOutboundInbound_Symmetric(t *testing.T) {
	sipKeys := [2]uint64{0x0102030405060708, 0x090A0B0C0D0E0F10}
	initialIV := uint64(0xFEDCBA9876543210)

	mod := NewSipHashLengthModifier("sym_test", sipKeys, initialIV)

	assertSipHashRoundTrip(t, mod, mod, 10, 100, 50,
		"Round-trip at step %d failed: original=%d, got=%d")
}

func TestAudit_Quality_32BitModulus(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("modulus_test", 0, 100, false)
	require.NoError(t, err)

	testData := make([]byte, 50)
	for i := 0; i < 200; i++ {
		padded, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)
		paddingLen := len(padded) - len(testData)
		assert.GreaterOrEqual(t, paddingLen, 0,
			"Padding must never be negative (iteration %d)", i)
		assert.LessOrEqual(t, paddingLen, 100,
			"Padding must not exceed maxPadding (iteration %d)", i)
	}
}

func TestAudit_Quality_ThreadSafety(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)

	t.Run("AES concurrent access", func(t *testing.T) {
		modifier, err := NewAESObfuscationModifier("thread_test", routerHash, iv)
		require.NoError(t, err)

		key := make([]byte, 32)
		_, err = modifier.ModifyOutbound(handshake.PhaseInitial, key)
		require.NoError(t, err)

		done := make(chan struct{})
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				k := make([]byte, 32)
				// These mutation calls are probed for race-safety; the test only
				// cares that they do not panic or race, not about returned errors.
				modifier.ModifyOutbound(handshake.PhaseExchange, k) //nolint:errcheck
				modifier.ModifyInbound(handshake.PhaseExchange, k)  //nolint:errcheck
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("SipHash concurrent access", func(t *testing.T) {
		sipKeys := [2]uint64{0x1234, 0x5678}
		modifier := NewSipHashLengthModifier("thread_test", sipKeys, 42)

		done := make(chan struct{})
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				data := make([]byte, 2)
				binary.BigEndian.PutUint16(data, 1000)
				// Same race-safety rationale as above: errors are not expected in
				// this concurrency probe and would only add noise to the test.
				modifier.ModifyOutbound(handshake.PhaseData, data) //nolint:errcheck
				modifier.ModifyInbound(handshake.PhaseData, data)  //nolint:errcheck
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestAudit_PhaseFinal_NoAESObfuscation(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)
	modifier, err := NewAESObfuscationModifier("noop", routerHash, iv)
	require.NoError(t, err)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	result, err := modifier.ModifyOutbound(handshake.PhaseFinal, key)
	require.NoError(t, err)
	assert.Equal(t, key, result, "PhaseFinal must not apply AES obfuscation")

	result, err = modifier.ModifyInbound(handshake.PhaseFinal, key)
	require.NoError(t, err)
	assert.Equal(t, key, result, "PhaseFinal must not apply AES obfuscation")
}

func TestAudit_SipHash_NonDataPhasePassthrough(t *testing.T) {
	sipKeys := [2]uint64{0xAAAA, 0xBBBB}
	mod := NewSipHashLengthModifier("passthrough", sipKeys, 0xCCCC)

	data := []byte{0x04, 0x00}
	phases := []handshake.HandshakePhase{
		handshake.PhaseInitial,
		handshake.PhaseExchange,
	}
	for _, phase := range phases {
		result, err := mod.ModifyOutbound(phase, data)
		require.NoError(t, err)
		assert.Equal(t, data, result, "Non-data phase must pass through")

		result, err = mod.ModifyInbound(phase, data)
		require.NoError(t, err)
		assert.Equal(t, data, result, "Non-data phase must pass through")
	}
}

func TestAudit_SipHashDirectional_RoundTrip(t *testing.T) {
	keysAB := [2]uint64{0xAAAABBBBCCCCDDDD, 0x1111222233334444}
	keysBA := [2]uint64{0x5555666677778888, 0x9999AAAABBBBCCCC}
	ivAB := uint64(0x1234567890ABCDEF)
	ivBA := uint64(0xFEDCBA0987654321)

	initiator := NewSipHashLengthModifierDirectional("alice", keysAB, keysBA, ivAB, ivBA)
	responder := NewSipHashLengthModifierDirectional("bob", keysBA, keysAB, ivBA, ivAB)

	assertSipHashRoundTrip(t, initiator, responder, 50, 100, 7,
		"Directional round-trip failed at frame %d: original=%d, got=%d")

	responder2 := NewSipHashLengthModifierDirectional("bob2", keysBA, keysAB, ivBA, ivAB)
	initiator2 := NewSipHashLengthModifierDirectional("alice2", keysAB, keysBA, ivAB, ivBA)

	assertSipHashRoundTrip(t, responder2, initiator2, 50, 200, 3,
		"Reverse round-trip failed at frame %d: original=%d, got=%d")
}

func TestAudit_SipHashDirectional_KeysMatter(t *testing.T) {
	keysAB := [2]uint64{0x1111, 0x2222}
	keysBA := [2]uint64{0x3333, 0x4444}
	iv := uint64(0)

	directional := NewSipHashLengthModifierDirectional("dir", keysAB, keysBA, iv, iv)
	shared := NewSipHashLengthModifier("shared", keysAB, iv)

	data := make([]byte, 2)
	out1, _ := directional.ModifyOutbound(handshake.PhaseData, data)
	out2, _ := shared.ModifyOutbound(handshake.PhaseData, data)
	assert.Equal(t, out1, out2, "Outbound with same keys should match")

	directional2 := NewSipHashLengthModifierDirectional("dir2", keysAB, keysBA, iv, iv)
	shared2 := NewSipHashLengthModifier("shared2", keysAB, iv)

	in1, _ := directional2.ModifyInbound(handshake.PhaseData, data)
	in2, _ := shared2.ModifyInbound(handshake.PhaseData, data)
	assert.NotEqual(t, in1, in2, "Inbound with different keys must differ")
}

// ============================================================================
// Tests from audit_fixes_3_test.go — modifier-related
// ============================================================================

func TestFrameLengthObfuscation_DirectionalRoundTrip(t *testing.T) {
	askMaster := deterministicBytes(32, 0)
	handshakeHash := deterministicBytes(32, 128)

	keysAB, ivAB, keysBA, ivBA, err := DeriveSipHashKeys(askMaster, handshakeHash)
	require.NoError(t, err)

	initiator := NewSipHashLengthModifierDirectional("alice", keysAB, keysBA, ivAB, ivBA)
	responder := NewSipHashLengthModifierDirectional("bob", keysBA, keysAB, ivBA, ivAB)

	for i := 0; i < 20; i++ {
		originalLen := uint16(16 + i*100)
		assertSipHashMaskRoundTrip(t, initiator, responder,
			originalLen, "Directional round-trip failed at frame %d", i)
	}
}

// ============================================================================
// Tests from audit_fixes_4_test.go — padding modifier-related
// ============================================================================

func TestAuditFix_RemoveTrailingPaddingBlock_BoundedByMaxPadding(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 16, false)
	require.NoError(t, err)

	paddingSize := 100
	payload := []byte("real data here and some more data to fill it up!!")
	data := make([]byte, len(payload)+3+paddingSize)
	copy(data[:len(payload)], payload)
	data[len(payload)] = PaddingBlockType
	data[len(payload)+1] = byte(paddingSize >> 8)
	data[len(payload)+2] = byte(paddingSize)

	result, err := modifier.removeAEADPadding(data)
	require.NoError(t, err)

	assert.Equal(t, len(data), len(result),
		"padding block exceeding maxPadding should not be removed")
}

func TestAuditFix_RemoveTrailingPaddingBlock_WithinMaxPadding(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 64, false)
	require.NoError(t, err)

	payloadStr := "real data"
	payload := []byte(payloadStr)
	paddingSize := 10
	data := make([]byte, len(payload)+3+paddingSize)
	copy(data, payload)
	data[len(payload)] = PaddingBlockType
	data[len(payload)+1] = 0
	data[len(payload)+2] = byte(paddingSize)

	result, err := modifier.removeAEADPadding(data)
	require.NoError(t, err)

	assert.Equal(t, len(payload), len(result),
		"padding block within maxPadding should be removed")
	assert.Equal(t, payloadStr, string(result))
}

// ============================================================================
// Helpers
// ============================================================================

func masksEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildI2PBlock constructs a single I2P block in [type:1][size:2 big-endian][data...] format.
func buildI2PBlock(blockType byte, data []byte) []byte {
	header := []byte{blockType, byte(len(data) >> 8), byte(len(data))}
	return append(header, data...)
}

// TestAuditFix_RemoveAEADPadding_BlocksAfterPaddingReturnsData verifies that
// a payload where a data block follows a padding block is returned unchanged.
// Forward block parsing is no longer used (it misparses raw data), so block
// order violations are not detected at this layer — the trailing padding scan
// simply finds no valid trailing padding block and returns the original data.
func TestAuditFix_RemoveAEADPadding_BlocksAfterPaddingReturnsData(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 64, false)
	require.NoError(t, err)

	// Build: [data_block][padding_block][data_block2] — padding is NOT last.
	var buf []byte
	buf = append(buf, buildI2PBlock(0x00, []byte("hello"))...)
	buf = append(buf, buildI2PBlock(PaddingBlockType, []byte{0x00, 0x00})...)
	buf = append(buf, buildI2PBlock(0x00, []byte("world"))...) // spec violation

	result, err := modifier.removeAEADPadding(buf)
	require.NoError(t, err, "trailing scan returns data unchanged when no trailing padding found")
	assert.Equal(t, buf, result, "data should be returned unchanged")
}

// TestAuditFix_ParseBlockStructure_BlocksAfterPaddingDetected verifies that
// parseBlockStructure sets blocksAfterPadding=true when any non-padding block
// follows the first padding block.
func TestAuditFix_ParseBlockStructure_BlocksAfterPaddingDetected(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 64, false)
	require.NoError(t, err)

	// [data_block][padding_block][extra_data_block]
	var buf []byte
	buf = append(buf, buildI2PBlock(0x00, []byte("data"))...)
	buf = append(buf, buildI2PBlock(PaddingBlockType, []byte{0x00})...)
	buf = append(buf, buildI2PBlock(0x01, []byte{})...) // trailing non-padding block

	result := modifier.parseBlockStructure(buf)
	assert.True(t, result.foundValidBlocks, "blocks were parsed")
	assert.True(t, result.blocksAfterPadding, "must detect data block following padding block")
}

// TestAuditFix_RemoveAEADPadding_CompliantOrderSucceeds verifies that a
// spec-compliant payload ([data_block][padding_block]) is still processed
// correctly after the block-ordering validation is added.
func TestAuditFix_RemoveAEADPadding_CompliantOrderSucceeds(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 64, false)
	require.NoError(t, err)

	dataContent := []byte("real data")
	var buf []byte
	buf = append(buf, buildI2PBlock(0x00, dataContent)...)
	buf = append(buf, buildI2PBlock(PaddingBlockType, []byte{0x00, 0x00, 0x00})...)

	result, err := modifier.removeAEADPadding(buf)
	require.NoError(t, err)
	expected := buildI2PBlock(0x00, dataContent)
	assert.Equal(t, expected, result, "data block must be preserved; padding block must be stripped")
}

// TestAuditFix_SipHashMask_StackAllocZero verifies that NextOutboundMask and
// NextInboundMask produce zero heap allocations. The underlying implementation
// uses a stack-allocated [8]byte instead of make([]byte, 8).
func TestAuditFix_SipHashMask_StackAllocZero(t *testing.T) {
	sipKeys := [2]uint64{0xDEADBEEFCAFE0001, 0xC0FFEE0102030405}
	mod := NewSipHashLengthModifier("alloc_test", sipKeys, 0xA1B2C3D4E5F60708)

	// Warm up: flush any one-time initialisation allocations.
	mod.NextOutboundMask()
	mod.NextInboundMask()

	outboundAllocs := testing.AllocsPerRun(200, func() {
		mod.NextOutboundMask()
	})
	inboundAllocs := testing.AllocsPerRun(200, func() {
		mod.NextInboundMask()
	})

	assert.Zero(t, outboundAllocs, "NextOutboundMask must not heap-allocate (uses stack [8]byte)")
	assert.Zero(t, inboundAllocs, "NextInboundMask must not heap-allocate (uses stack [8]byte)")
}
