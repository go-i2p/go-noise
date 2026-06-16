package handshake

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// assertModifierRoundTrip verifies that outbound+inbound modification
// through a chain recovers the original data.
func assertModifierRoundTrip(t *testing.T, chain *ModifierChain, phase HandshakePhase, originalData []byte) {
	t.Helper()
	outbound, err := chain.ModifyOutbound(phase, originalData)
	if err != nil {
		t.Errorf("ModifyOutbound() error = %v", err)
	}
	if string(outbound) == string(originalData) {
		t.Error("Outbound data should be transformed, but it's unchanged")
	}
	recovered, err := chain.ModifyInbound(phase, outbound)
	if err != nil {
		t.Errorf("ModifyInbound() error = %v", err)
	}
	if string(recovered) != string(originalData) {
		t.Errorf("Round-trip failed: got %v, want %v", string(recovered), string(originalData))
	}
}

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
		if !strings.Contains(errStr, "modifier chain outbound processing failed") {
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
		if !strings.Contains(errStr, "modifier chain outbound processing failed") {
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
		if !strings.Contains(errStr, "modifier chain inbound processing failed") {
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

	assertModifierRoundTrip(t, chain, PhaseInitial, originalData)
}

func TestModifierChaining(t *testing.T) {
	// Test real modifiers in a chain
	xorMod, err := NewXORModifier("xor", []byte{0xAA})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	paddingMod, err := NewPaddingModifier("padding", 3, 3)
	if err != nil {
		t.Fatalf("NewPaddingModifier() error = %v", err)
	}

	chain := NewModifierChain("test-chain", xorMod, paddingMod)
	originalData := []byte("Test message for chaining")

	assertModifierRoundTrip(t, chain, PhaseExchange, originalData)
}

func TestNewModifierChain_NilFiltering(t *testing.T) {
	t.Run("All nil modifiers produces empty chain", func(t *testing.T) {
		chain := NewModifierChain("all-nil", nil, nil, nil)

		if chain.Count() != 0 {
			t.Errorf("Count() = %v, want 0 after nil filtering", chain.Count())
		}

		if !chain.IsEmpty() {
			t.Error("IsEmpty() should be true when all modifiers are nil")
		}
	})

	t.Run("Mixed nil and valid modifiers", func(t *testing.T) {
		mod1 := &testModifier{name: "valid-1"}
		mod2 := &testModifier{name: "valid-2"}

		chain := NewModifierChain("mixed", nil, mod1, nil, mod2, nil)

		if chain.Count() != 2 {
			t.Errorf("Count() = %v, want 2 after nil filtering", chain.Count())
		}

		names := chain.ModifierNames()
		if names[0] != "valid-1" || names[1] != "valid-2" {
			t.Errorf("ModifierNames() = %v, want [valid-1, valid-2]", names)
		}
	})

	t.Run("Nil-filtered chain still processes data correctly", func(t *testing.T) {
		xorMod, err := NewXORModifier("xor", []byte{0x42})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
		chain := NewModifierChain("nil-mixed", nil, xorMod, nil)

		testData := []byte("test data")

		outbound, err := chain.ModifyOutbound(PhaseInitial, testData)
		if err != nil {
			t.Fatalf("ModifyOutbound() error = %v", err)
		}

		recovered, err := chain.ModifyInbound(PhaseInitial, outbound)
		if err != nil {
			t.Fatalf("ModifyInbound() error = %v", err)
		}

		if string(recovered) != string(testData) {
			t.Errorf("Round-trip failed: got %q, want %q", string(recovered), string(testData))
		}
	})
}

// TestModifierChain_PhaseData verifies that all modifiers in a chain handle
// PhaseData correctly — no modifier should block or corrupt data for this phase.
func TestModifierChain_PhaseData(t *testing.T) {
	xorMod, err := NewXORModifier("xor", []byte{0x7E})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	chain := NewModifierChain("phase-data-chain", xorMod)
	testData := []byte("phase data round-trip content")

	for _, phase := range []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal, PhaseData} {
		out, err := chain.ModifyOutbound(phase, testData)
		if err != nil {
			t.Errorf("ModifyOutbound(phase=%v) error = %v", phase, err)
			continue
		}
		recovered, err := chain.ModifyInbound(phase, out)
		if err != nil {
			t.Errorf("ModifyInbound(phase=%v) error = %v", phase, err)
			continue
		}
		if string(recovered) != string(testData) {
			t.Errorf("Phase %v round-trip failed: got %q, want %q", phase, recovered, testData)
		}
	}
}

// TestModifierChain_Concurrent verifies that concurrent ModifyOutbound and
// ModifyInbound calls from multiple goroutines are race-free.
func TestModifierChain_Concurrent(t *testing.T) {
	xorMod, err := NewXORModifier("concurrent-xor", []byte{0x3C})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	chain := NewModifierChain("concurrent-chain", xorMod)
	testData := []byte("concurrent chain test payload")
	const goroutines = 32

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := chain.ModifyOutbound(PhaseData, testData)
			if err != nil {
				errs <- err
				return
			}
			recovered, err := chain.ModifyInbound(PhaseData, out)
			if err != nil {
				errs <- err
				return
			}
			if string(recovered) != string(testData) {
				errs <- fmt.Errorf("concurrent round-trip mismatch")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestModifierChain_Close verifies that Close() propagates to all members.
func TestModifierChain_Close(t *testing.T) {
	mod1 := &testModifier{name: "m1"}
	mod2 := &testModifier{name: "m2"}
	chain := NewModifierChain("close-chain", mod1, mod2)

	if err := chain.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !mod1.closeCalled {
		t.Error("Close() not propagated to first modifier")
	}
	if !mod2.closeCalled {
		t.Error("Close() not propagated to second modifier")
	}
}

// TestModifierChain_Close_Error verifies that Close() returns all errors
// aggregated via errors.Join while still calling Close() on all members.
func TestModifierChain_Close_Error(t *testing.T) {
	closingOrder := []string{}

	errMod := &closeTestModifier{
		name:     "err-mod",
		closeErr: errors.New("close failed"),
		onClose:  func() { closingOrder = append(closingOrder, "err-mod") },
	}
	goodMod := &closeTestModifier{
		name:    "good-mod",
		onClose: func() { closingOrder = append(closingOrder, "good-mod") },
	}
	chain := NewModifierChain("error-close-chain", errMod, goodMod)

	err := chain.Close()
	if err == nil {
		t.Error("Close() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "close failed") {
		t.Errorf("Close() error = %v, want 'close failed'", err)
	}
	// Both members must be closed regardless of the first error
	if len(closingOrder) != 2 {
		t.Errorf("Close() called on %d members, want 2 (all members closed despite error)", len(closingOrder))
	}
}

// TestModifierChain_Close_AllErrorsAggregated verifies that Close() aggregates
// all errors from failing modifiers via errors.Join, not just the first.
func TestModifierChain_Close_AllErrorsAggregated(t *testing.T) {
	err1 := errors.New("first close error")
	err2 := errors.New("second close error")
	err3 := errors.New("third close error")

	mod1 := &closeTestModifier{name: "fail-1", closeErr: err1}
	mod2 := &closeTestModifier{name: "fail-2", closeErr: err2}
	mod3 := &closeTestModifier{name: "fail-3", closeErr: err3}

	chain := NewModifierChain("all-errors-chain", mod1, mod2, mod3)

	err := chain.Close()
	if err == nil {
		t.Fatal("Close() expected aggregated error, got nil")
	}

	// errors.Join produces an error that unwraps to each component via errors.Is
	if !errors.Is(err, err1) {
		t.Errorf("Close() error does not wrap first error: %v", err)
	}
	if !errors.Is(err, err2) {
		t.Errorf("Close() error does not wrap second error: %v", err)
	}
	if !errors.Is(err, err3) {
		t.Errorf("Close() error does not wrap third error: %v", err)
	}

	// The string representation should contain all three messages
	errStr := err.Error()
	if !strings.Contains(errStr, "first close error") {
		t.Errorf("Close() error string missing 'first close error': %v", errStr)
	}
	if !strings.Contains(errStr, "second close error") {
		t.Errorf("Close() error string missing 'second close error': %v", errStr)
	}
	if !strings.Contains(errStr, "third close error") {
		t.Errorf("Close() error string missing 'third close error': %v", errStr)
	}
}

// closeTestModifier is a test helper that records Close() calls and optionally returns an error.
type closeTestModifier struct {
	name     string
	closeErr error
	onClose  func()
}

func (c *closeTestModifier) ModifyOutbound(_ HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (c *closeTestModifier) ModifyInbound(_ HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}
func (c *closeTestModifier) Name() string { return c.name }
func (c *closeTestModifier) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.closeErr
}

// TestModifierChain_Nesting verifies that a ModifierChain containing another
// ModifierChain as a member correctly applies transformations in both directions.
// Since ModifierChain implements HandshakeModifier, nesting is supported by the
// type system but needs validation for correct round-trip behavior.
func TestModifierChain_Nesting(t *testing.T) {
	// Create an inner chain with two XOR modifiers
	xor1, err := NewXORModifier("inner-xor-1", []byte{0xAA})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	xor2, err := NewXORModifier("inner-xor-2", []byte{0x55})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	innerChain := NewModifierChain("inner-chain", xor1, xor2)

	// Create an outer chain that includes the inner chain plus another modifier
	xor3, err := NewXORModifier("outer-xor", []byte{0x0F})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	outerChain := NewModifierChain("outer-chain", innerChain, xor3)

	originalData := []byte("nested chain test data for round-trip")

	// Outbound: inner-xor-1 -> inner-xor-2 -> outer-xor
	outbound, err := outerChain.ModifyOutbound(PhaseExchange, originalData)
	if err != nil {
		t.Fatalf("Nested ModifyOutbound() error = %v", err)
	}

	// Data should be transformed
	if string(outbound) == string(originalData) {
		t.Error("Nested chain should transform data")
	}

	// Inbound (reverse): outer-xor -> inner-xor-2 -> inner-xor-1
	recovered, err := outerChain.ModifyInbound(PhaseExchange, outbound)
	if err != nil {
		t.Fatalf("Nested ModifyInbound() error = %v", err)
	}

	if string(recovered) != string(originalData) {
		t.Errorf("Nested chain round-trip failed: got %q, want %q", recovered, originalData)
	}

	// Verify Close propagates through nested chains
	if err := outerChain.Close(); err != nil {
		t.Errorf("Nested Close() error = %v", err)
	}

	// After Close, inner modifiers should be closed (use-after-close returns error)
	_, err = xor1.ModifyOutbound(PhaseInitial, originalData)
	if err == nil {
		t.Error("Inner modifier should return error after nested Close()")
	}
	_, err = xor3.ModifyOutbound(PhaseInitial, originalData)
	if err == nil {
		t.Error("Outer modifier should return error after nested Close()")
	}
}
