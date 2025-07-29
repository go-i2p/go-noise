package ntcp2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 32)
	}

	ephemeralKey := make([]byte, 32)
	for i := range ephemeralKey {
		ephemeralKey[i] = byte(i + 64)
	}

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

	// Should not modify handshake phase data
	testData := []byte{0x04, 0x00} // 1024 in big endian

	result, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)

	result, err = modifier.ModifyOutbound(handshake.PhaseExchange, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)
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
	modifier, err := NewNTCP2PaddingModifierForTesting("cleartext_test", 4, 16, false)
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
	// Test AEAD padding for message 3 and data phase with production-grade implementation
	modifier, err := NewNTCP2PaddingModifierForTesting("aead_test", 4, 16, true)
	require.NoError(t, err)

	originalData := []byte("test data phase message")

	// Apply AEAD padding (PhaseFinal)
	padded, err := modifier.ModifyOutbound(handshake.PhaseFinal, originalData)
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

	// Validate AEAD frame structure - skip this for simple data+padding case
	// In the simple test case, we have raw data + padding block, not full I2P block format
	// So let's just validate that padding removal works correctly
	// isValid := modifier.ValidateAEADFrame(padded)
	// t.Logf("Frame validation result: %v", isValid)
	// assert.True(t, isValid)

	// Remove padding
	recovered, err := modifier.ModifyInbound(handshake.PhaseFinal, padded)
	require.NoError(t, err)
	t.Logf("Recovered data length: %d", len(recovered))
	t.Logf("Recovered data: %x", recovered)
	assert.Equal(t, originalData, recovered)
}

func TestNTCP2PaddingModifier_NoPadding(t *testing.T) {
	// Test with no padding configured
	modifier, err := NewNTCP2PaddingModifierForTesting("no_padding", 0, 0, false)
	require.NoError(t, err)

	testData := []byte("test data")

	result, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)
}

func TestNTCP2PaddingModifier_PhaseMatching(t *testing.T) {
	// Test that cleartext modifier doesn't affect final phase
	cleartextModifier, err := NewNTCP2PaddingModifierForTesting("cleartext", 4, 8, false)
	require.NoError(t, err)

	// Test that AEAD modifier doesn't affect initial phases
	aeadModifier, err := NewNTCP2PaddingModifierForTesting("aead", 4, 8, true)
	require.NoError(t, err)

	testData := []byte("test data")

	// Cleartext modifier should not affect final phase
	result, err := cleartextModifier.ModifyOutbound(handshake.PhaseFinal, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)

	// AEAD modifier should not affect initial phases
	result, err = aeadModifier.ModifyOutbound(handshake.PhaseInitial, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)

	result, err = aeadModifier.ModifyOutbound(handshake.PhaseExchange, testData)
	require.NoError(t, err)
	assert.Equal(t, testData, result)
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

	cleartextPadding, err := NewNTCP2PaddingModifierForTesting("cleartext_pad", 4, 8, false)
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
	obfuscatedLength, err := sipModifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	// Should be different (unless mask is zero)
	if bytes.Equal(lengthData, obfuscatedLength) {
		t.Logf("Warning: SipHash mask was zero")
	}

	// Recovery should work
	recoveredLength, err := sipModifier.ModifyInbound(handshake.PhaseFinal, obfuscatedLength)
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
		result, err := modifier.ModifyOutbound(handshake.PhaseFinal, testData)
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
		modifier, err := NewNTCP2PaddingModifierForTesting("validation_test", 4, 8, true)
		require.NoError(t, err)

		// Create proper I2P block format data
		i2npBlock := []byte{3, 0, 5, 1, 2, 3, 4, 5} // I2NP block type 3, size 5, data
		padded, err := modifier.ModifyOutbound(handshake.PhaseFinal, i2npBlock)
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
		testMod, err := NewNTCP2PaddingModifierForTesting("test", 4, 16, false)
		require.NoError(t, err)

		result1, err := testMod.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)
		result2, err := testMod.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)

		assert.Equal(t, result1, result2, "Test mode should be deterministic")
	})

	t.Run("AEAD Block Parsing Security", func(t *testing.T) {
		modifier, err := NewNTCP2PaddingModifierForTesting("security_test", 4, 8, true)
		require.NoError(t, err)

		// Test malformed block handling - should handle gracefully without error
		malformedData := []byte{254, 0, 100, 1, 2, 3} // Claims 100 bytes but only has 3
		result, err := modifier.ModifyInbound(handshake.PhaseFinal, malformedData)
		require.NoError(t, err, "Should handle malformed blocks gracefully")
		// Should return original data since no valid padding found
		assert.Equal(t, malformedData, result)

		// Test oversized block
		oversized := make([]byte, 3+65520) // Larger than spec limit
		oversized[0] = 254
		binary.BigEndian.PutUint16(oversized[1:3], 65520)
		result, err = modifier.ModifyInbound(handshake.PhaseFinal, oversized)
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
		cleartextMod, err := NewNTCP2PaddingModifierForTesting("msg12", 0, 31, false)
		require.NoError(t, err)

		msg1Data := []byte("SessionRequest ephemeral key and options")
		padded1, err := cleartextMod.ModifyOutbound(handshake.PhaseInitial, msg1Data)
		require.NoError(t, err)

		// Should add padding but not AEAD block format
		assert.NotEqual(t, byte(254), padded1[len(msg1Data)]) // No AEAD padding block

		// Message 3+: AEAD padding (inside AEAD frames)
		aeadMod, err := NewNTCP2PaddingModifierForTesting("msg3", 0, 32, true)
		require.NoError(t, err)

		msg3Data := []byte("SessionConfirmed RouterInfo and options")
		padded3, err := aeadMod.ModifyOutbound(handshake.PhaseFinal, msg3Data)
		require.NoError(t, err)

		// Should use AEAD block format if padding is added
		if len(padded3) > len(msg3Data) {
			assert.Equal(t, byte(254), padded3[len(msg3Data)]) // AEAD padding block
		}
	})

	t.Run("Data Phase Block Format", func(t *testing.T) {
		modifier, err := NewNTCP2PaddingModifierForTesting("data_phase", 8, 16, true)
		require.NoError(t, err)

		// Simulate data phase message with I2NP message block
		i2npBlock := []byte{3, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

		padded, err := modifier.ModifyOutbound(handshake.PhaseFinal, i2npBlock)
		require.NoError(t, err)

		// Should append padding block after I2NP block
		assert.True(t, modifier.ValidateAEADFrame(padded))

		// Padding block should be last
		lastBlockPos := len(i2npBlock)
		if len(padded) > len(i2npBlock) {
			assert.Equal(t, byte(254), padded[lastBlockPos])
		}

		// Should be able to remove padding cleanly
		recovered, err := modifier.ModifyInbound(handshake.PhaseFinal, padded)
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
