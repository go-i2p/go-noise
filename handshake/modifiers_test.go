package handshake

import (
	"testing"
)

func TestXORModifier(t *testing.T) {
	t.Run("NewXORModifier with key", func(t *testing.T) {
		key := []byte{0xAA, 0xBB, 0xCC}
		modifier := NewXORModifier("test-xor", key)

		if modifier.Name() != "test-xor" {
			t.Errorf("Name() = %v, want %v", modifier.Name(), "test-xor")
		}

		if len(modifier.xorKey) != 3 {
			t.Errorf("Key length = %v, want %v", len(modifier.xorKey), 3)
		}

		// Verify key independence
		key[0] = 0xFF
		if modifier.xorKey[0] != 0xAA {
			t.Error("XOR key was affected by external modification")
		}
	})

	t.Run("NewXORModifier with empty key", func(t *testing.T) {
		modifier := NewXORModifier("empty-key", []byte{})

		if len(modifier.xorKey) != 1 || modifier.xorKey[0] != 0xAA {
			t.Error("Empty key should default to [0xAA]")
		}
	})

	t.Run("XOR round-trip", func(t *testing.T) {
		key := []byte{0xAA, 0xBB}
		modifier := NewXORModifier("roundtrip", key)
		originalData := []byte("Hello, Noise Protocol!")

		// Apply XOR transformation
		outbound, err := modifier.ModifyOutbound(PhaseInitial, originalData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Data should be different
		if string(outbound) == string(originalData) {
			t.Error("XOR should transform data, but it's unchanged")
		}

		// Apply XOR again to reverse
		recovered, err := modifier.ModifyInbound(PhaseInitial, outbound)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		// Should get back original data
		if string(recovered) != string(originalData) {
			t.Errorf("XOR round-trip failed: got %v, want %v", string(recovered), string(originalData))
		}
	})

	t.Run("XOR with different phases", func(t *testing.T) {
		modifier := NewXORModifier("phase-test", []byte{0x42})
		testData := []byte("test")

		// XOR should work the same regardless of phase
		phases := []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal}
		for _, phase := range phases {
			result, err := modifier.ModifyOutbound(phase, testData)
			if err != nil {
				t.Errorf("ModifyOutbound() phase %v error = %v", phase, err)
			}

			// Verify consistent transformation
			expected := make([]byte, len(testData))
			for i, b := range testData {
				expected[i] = b ^ 0x42
			}

			if string(result) != string(expected) {
				t.Errorf("Phase %v: got %v, want %v", phase, result, expected)
			}
		}
	})

	t.Run("XOR with empty data", func(t *testing.T) {
		modifier := NewXORModifier("empty-data", []byte{0xFF})

		result, err := modifier.ModifyOutbound(PhaseInitial, []byte{})
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		if len(result) != 0 {
			t.Errorf("Empty data should remain empty, got %v", result)
		}
	})

	t.Run("XOR key cycling", func(t *testing.T) {
		key := []byte{0x01, 0x02}
		modifier := NewXORModifier("cycling", key)
		data := []byte{0x10, 0x20, 0x30, 0x40, 0x50}

		result, err := modifier.ModifyOutbound(PhaseExchange, data)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		expected := []byte{
			0x10 ^ 0x01, // data[0] ^ key[0]
			0x20 ^ 0x02, // data[1] ^ key[1]
			0x30 ^ 0x01, // data[2] ^ key[0] (cycle)
			0x40 ^ 0x02, // data[3] ^ key[1] (cycle)
			0x50 ^ 0x01, // data[4] ^ key[0] (cycle)
		}

		for i, b := range result {
			if b != expected[i] {
				t.Errorf("Byte %d: got %v, want %v", i, b, expected[i])
			}
		}
	})
}

func TestPaddingModifier(t *testing.T) {
	t.Run("NewPaddingModifier valid parameters", func(t *testing.T) {
		modifier, err := NewPaddingModifier("test-padding", 5, 10)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		if modifier.Name() != "test-padding" {
			t.Errorf("Name() = %v, want %v", modifier.Name(), "test-padding")
		}

		if modifier.minPadding != 5 {
			t.Errorf("minPadding = %v, want %v", modifier.minPadding, 5)
		}

		if modifier.maxPadding != 10 {
			t.Errorf("maxPadding = %v, want %v", modifier.maxPadding, 10)
		}
	})

	t.Run("NewPaddingModifier negative minimum", func(t *testing.T) {
		_, err := NewPaddingModifier("negative", -1, 5)
		if err == nil {
			t.Error("NewPaddingModifier() expected error for negative minimum")
		}

		if !contains(err.Error(), "minimum padding cannot be negative") {
			t.Errorf("Error message = %v, want minimum padding error", err.Error())
		}
	})

	t.Run("NewPaddingModifier max less than min", func(t *testing.T) {
		_, err := NewPaddingModifier("invalid", 10, 5)
		if err == nil {
			t.Error("NewPaddingModifier() expected error for max < min")
		}

		if !contains(err.Error(), "maximum padding cannot be less than minimum padding") {
			t.Errorf("Error message = %v, want max < min error", err.Error())
		}
	})

	t.Run("Padding round-trip", func(t *testing.T) {
		modifier, err := NewPaddingModifier("roundtrip", 4, 4)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		originalData := []byte("Hello, World!")

		// Apply padding
		padded, err := modifier.ModifyOutbound(PhaseInitial, originalData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Padded data should be longer
		expectedLen := 4 + len(originalData) + 4 // length prefix + data + padding
		if len(padded) != expectedLen {
			t.Errorf("Padded length = %v, want %v", len(padded), expectedLen)
		}

		// Remove padding
		recovered, err := modifier.ModifyInbound(PhaseInitial, padded)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		// Should get back original data
		if string(recovered) != string(originalData) {
			t.Errorf("Padding round-trip failed: got %v, want %v", string(recovered), string(originalData))
		}
	})

	t.Run("No padding configuration", func(t *testing.T) {
		modifier, err := NewPaddingModifier("no-padding", 0, 0)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		testData := []byte("test data")

		result, err := modifier.ModifyOutbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Should be unchanged when no padding
		if string(result) != string(testData) {
			t.Errorf("No padding should leave data unchanged")
		}
	})

	t.Run("Invalid padded data - too short", func(t *testing.T) {
		modifier, err := NewPaddingModifier("short-data", 1, 1)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		// Data too short for length prefix
		shortData := []byte{0x01, 0x02}

		_, err = modifier.ModifyInbound(PhaseFinal, shortData)
		if err == nil {
			t.Error("ModifyInbound() expected error for short data")
		}

		if !contains(err.Error(), "padded data too short") {
			t.Errorf("Error message = %v, want short data error", err.Error())
		}
	})

	t.Run("Invalid padded data - bad length", func(t *testing.T) {
		modifier, err := NewPaddingModifier("bad-length", 1, 1)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		// Create data with invalid length prefix
		badData := []byte{0x00, 0x00, 0x00, 0xFF, 0x01, 0x02} // length = 255, but only 2 data bytes

		_, err = modifier.ModifyInbound(PhaseFinal, badData)
		if err == nil {
			t.Error("ModifyInbound() expected error for invalid length")
		}

		if !contains(err.Error(), "invalid original length") {
			t.Errorf("Error message = %v, want invalid length error", err.Error())
		}
	})

	t.Run("Empty data padding", func(t *testing.T) {
		modifier, err := NewPaddingModifier("empty", 2, 2)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		emptyData := []byte{}

		// Pad empty data
		padded, err := modifier.ModifyOutbound(PhaseInitial, emptyData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Should have length prefix and padding
		expectedLen := 4 + 0 + 2 // prefix + empty data + padding
		if len(padded) != expectedLen {
			t.Errorf("Padded empty data length = %v, want %v", len(padded), expectedLen)
		}

		// Recover empty data
		recovered, err := modifier.ModifyInbound(PhaseInitial, padded)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		if len(recovered) != 0 {
			t.Errorf("Recovered data should be empty, got %v", recovered)
		}
	})
}

func TestModifierInterface(t *testing.T) {
	// Test that our implementations satisfy the HandshakeModifier interface
	var _ HandshakeModifier = NewXORModifier("test", []byte{0xFF})

	padding, _ := NewPaddingModifier("test", 1, 1)
	var _ HandshakeModifier = padding
}

func TestModifierChaining(t *testing.T) {
	// Test real modifiers in a chain
	xorMod := NewXORModifier("xor", []byte{0xAA})
	paddingMod, err := NewPaddingModifier("padding", 3, 3)
	if err != nil {
		t.Fatalf("NewPaddingModifier() error = %v", err)
	}

	chain := NewModifierChain("test-chain", xorMod, paddingMod)
	originalData := []byte("Test message for chaining")

	// Apply chain outbound (XOR then padding)
	outbound, err := chain.ModifyOutbound(PhaseExchange, originalData)
	if err != nil {
		t.Errorf("Chain ModifyOutbound() error = %v", err)
	}

	// Data should be transformed
	if string(outbound) == string(originalData) {
		t.Error("Chain should transform data")
	}

	// Apply chain inbound (padding removal then XOR)
	recovered, err := chain.ModifyInbound(PhaseExchange, outbound)
	if err != nil {
		t.Errorf("Chain ModifyInbound() error = %v", err)
	}

	// Should get back original data
	if string(recovered) != string(originalData) {
		t.Errorf("Chain round-trip failed: got %v, want %v", string(recovered), string(originalData))
	}
}
