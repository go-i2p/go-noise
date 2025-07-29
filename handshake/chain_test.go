package handshake

import (
	"errors"
	"testing"
)

func TestNewModifierChain(t *testing.T) {
	t.Run("Empty chain", func(t *testing.T) {
		chain := NewModifierChain("empty")

		if chain.Name() != "empty" {
			t.Errorf("Name() = %v, want %v", chain.Name(), "empty")
		}

		if !chain.IsEmpty() {
			t.Error("IsEmpty() = false, want true")
		}

		if chain.Count() != 0 {
			t.Errorf("Count() = %v, want %v", chain.Count(), 0)
		}

		names := chain.ModifierNames()
		if len(names) != 0 {
			t.Errorf("ModifierNames() length = %v, want %v", len(names), 0)
		}
	})

	t.Run("Chain with modifiers", func(t *testing.T) {
		mod1 := &testModifier{name: "modifier1"}
		mod2 := &testModifier{name: "modifier2"}
		mod3 := &testModifier{name: "modifier3"}

		chain := NewModifierChain("test-chain", mod1, mod2, mod3)

		if chain.Name() != "test-chain" {
			t.Errorf("Name() = %v, want %v", chain.Name(), "test-chain")
		}

		if chain.IsEmpty() {
			t.Error("IsEmpty() = true, want false")
		}

		if chain.Count() != 3 {
			t.Errorf("Count() = %v, want %v", chain.Count(), 3)
		}

		names := chain.ModifierNames()
		expected := []string{"modifier1", "modifier2", "modifier3"}
		if len(names) != len(expected) {
			t.Errorf("ModifierNames() length = %v, want %v", len(names), len(expected))
		}

		for i, name := range names {
			if name != expected[i] {
				t.Errorf("ModifierNames()[%d] = %v, want %v", i, name, expected[i])
			}
		}
	})

	t.Run("Modifiers array independence", func(t *testing.T) {
		modifiers := []HandshakeModifier{
			&testModifier{name: "original"},
		}

		chain := NewModifierChain("independence-test", modifiers...)

		// Modify original slice
		modifiers[0] = &testModifier{name: "modified"}

		// Chain should still have original modifier
		names := chain.ModifierNames()
		if len(names) != 1 || names[0] != "original" {
			t.Error("Chain was affected by external modification of modifiers slice")
		}
	})
}

func TestModifierChain_Interface(t *testing.T) {
	// Test that ModifierChain satisfies HandshakeModifier interface
	var _ HandshakeModifier = &ModifierChain{}
}

func TestModifierChain_ModifyOutbound(t *testing.T) {
	t.Run("Empty chain passthrough", func(t *testing.T) {
		chain := NewModifierChain("empty")
		testData := []byte("test data")

		result, err := chain.ModifyOutbound(PhaseInitial, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		if string(result) != string(testData) {
			t.Errorf("ModifyOutbound() = %v, want %v", string(result), string(testData))
		}
	})

	t.Run("Single modifier", func(t *testing.T) {
		modifier := &testModifier{
			name: "single",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-modified")...), nil
			},
		}

		chain := NewModifierChain("single-chain", modifier)
		testData := []byte("test")

		result, err := chain.ModifyOutbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		expected := "test-modified"
		if string(result) != expected {
			t.Errorf("ModifyOutbound() = %v, want %v", string(result), expected)
		}
	})

	t.Run("Multiple modifiers in order", func(t *testing.T) {
		mod1 := &testModifier{
			name: "first",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-first")...), nil
			},
		}

		mod2 := &testModifier{
			name: "second",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-second")...), nil
			},
		}

		mod3 := &testModifier{
			name: "third",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-third")...), nil
			},
		}

		chain := NewModifierChain("multi-chain", mod1, mod2, mod3)
		testData := []byte("test")

		result, err := chain.ModifyOutbound(PhaseFinal, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		expected := "test-first-second-third"
		if string(result) != expected {
			t.Errorf("ModifyOutbound() = %v, want %v", string(result), expected)
		}
	})

	t.Run("Error in first modifier", func(t *testing.T) {
		mod1 := &testModifier{
			name: "error-mod",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return nil, errors.New("first modifier error")
			},
		}

		mod2 := &testModifier{
			name: "never-called",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				t.Error("Second modifier should not be called after first fails")
				return data, nil
			},
		}

		chain := NewModifierChain("error-chain", mod1, mod2)
		testData := []byte("test")

		result, err := chain.ModifyOutbound(PhaseInitial, testData)
		if err == nil {
			t.Error("ModifyOutbound() expected error, got nil")
		}

		if result != nil {
			t.Errorf("ModifyOutbound() result = %v, want nil", result)
		} // Check error message contains basic context
		errStr := err.Error()
		if !contains(errStr, "modifier chain outbound processing failed") {
			t.Errorf("Error missing expected message: %v", errStr)
		}
	})

	t.Run("Error in middle modifier", func(t *testing.T) {
		mod1 := &testModifier{
			name: "success-mod",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-success")...), nil
			},
		}

		mod2 := &testModifier{
			name: "error-mod",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return nil, errors.New("middle modifier error")
			},
		}

		mod3 := &testModifier{
			name: "never-called",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				t.Error("Third modifier should not be called after second fails")
				return data, nil
			},
		}

		chain := NewModifierChain("error-middle-chain", mod1, mod2, mod3)
		testData := []byte("test")

		result, err := chain.ModifyOutbound(PhaseExchange, testData)
		if err == nil {
			t.Error("ModifyOutbound() expected error, got nil")
		}

		if result != nil {
			t.Errorf("ModifyOutbound() result = %v, want nil", result)
		}

		// Check error message contains basic context
		errStr := err.Error()
		if !contains(errStr, "modifier chain outbound processing failed") {
			t.Errorf("Error missing expected message: %v", errStr)
		}
	})
}

func TestModifierChain_ModifyInbound(t *testing.T) {
	t.Run("Empty chain passthrough", func(t *testing.T) {
		chain := NewModifierChain("empty")
		testData := []byte("test data")

		result, err := chain.ModifyInbound(PhaseInitial, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		if string(result) != string(testData) {
			t.Errorf("ModifyInbound() = %v, want %v", string(result), string(testData))
		}
	})

	t.Run("Single modifier", func(t *testing.T) {
		modifier := &testModifier{
			name: "single",
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-inbound")...), nil
			},
		}

		chain := NewModifierChain("single-chain", modifier)
		testData := []byte("test")

		result, err := chain.ModifyInbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		expected := "test-inbound"
		if string(result) != expected {
			t.Errorf("ModifyInbound() = %v, want %v", string(result), expected)
		}
	})

	t.Run("Multiple modifiers in reverse order", func(t *testing.T) {
		mod1 := &testModifier{
			name: "first",
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-first")...), nil
			},
		}

		mod2 := &testModifier{
			name: "second",
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-second")...), nil
			},
		}

		mod3 := &testModifier{
			name: "third",
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return append(data, []byte("-third")...), nil
			},
		}

		chain := NewModifierChain("reverse-chain", mod1, mod2, mod3)
		testData := []byte("test")

		result, err := chain.ModifyInbound(PhaseFinal, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		// Should apply in reverse order: third, second, first
		expected := "test-third-second-first"
		if string(result) != expected {
			t.Errorf("ModifyInbound() = %v, want %v", string(result), expected)
		}
	})

	t.Run("Error handling", func(t *testing.T) {
		mod1 := &testModifier{name: "first"}
		mod2 := &testModifier{
			name: "error-mod",
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return nil, errors.New("inbound error")
			},
		}
		mod3 := &testModifier{name: "third"}

		chain := NewModifierChain("inbound-error-chain", mod1, mod2, mod3)
		testData := []byte("test")

		// Inbound processes in reverse order, so mod2 (error-mod) will be hit first
		result, err := chain.ModifyInbound(PhaseInitial, testData)
		if err == nil {
			t.Error("ModifyInbound() expected error, got nil")
		}

		if result != nil {
			t.Errorf("ModifyInbound() result = %v, want nil", result)
		}

		// Check error message contains basic context
		errStr := err.Error()
		if !contains(errStr, "modifier chain inbound processing failed") {
			t.Errorf("Error missing expected message: %v", errStr)
		}
	})
}

func TestModifierChain_RoundTrip(t *testing.T) {
	// Test that a round-trip (outbound then inbound) works correctly
	// with modifiers that can undo each other's transformations

	// XOR modifier for testing - XORing twice gives original data
	xorModifier := &testModifier{
		name: "xor",
		modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			result := make([]byte, len(data))
			for i, b := range data {
				result[i] = b ^ 0xAA // XOR with pattern
			}
			return result, nil
		},
		modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			result := make([]byte, len(data))
			for i, b := range data {
				result[i] = b ^ 0xAA // XOR with same pattern undoes transformation
			}
			return result, nil
		},
	}

	// Reverse modifier for testing
	reverseModifier := &testModifier{
		name: "reverse",
		modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			result := make([]byte, len(data))
			for i, b := range data {
				result[len(data)-1-i] = b
			}
			return result, nil
		},
		modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			result := make([]byte, len(data))
			for i, b := range data {
				result[len(data)-1-i] = b // Reverse again to undo
			}
			return result, nil
		},
	}

	chain := NewModifierChain("roundtrip", xorModifier, reverseModifier)
	originalData := []byte("Hello, Noise Protocol!")

	// Apply outbound transformations
	outbound, err := chain.ModifyOutbound(PhaseInitial, originalData)
	if err != nil {
		t.Errorf("ModifyOutbound() error = %v", err)
	}

	// Data should be transformed
	if string(outbound) == string(originalData) {
		t.Error("Outbound data should be transformed, but it's unchanged")
	}

	// Apply inbound transformations to reverse the process
	recovered, err := chain.ModifyInbound(PhaseInitial, outbound)
	if err != nil {
		t.Errorf("ModifyInbound() error = %v", err)
	}

	// Should get back original data
	if string(recovered) != string(originalData) {
		t.Errorf("Round-trip failed: got %v, want %v", string(recovered), string(originalData))
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
