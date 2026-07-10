package handshake

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestXORModifier(t *testing.T) {
	t.Run("NewXORModifier with key", func(t *testing.T) {
		key := []byte{0xAA, 0xBB, 0xCC}
		modifier, err := NewXORModifier("test-xor", key)
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}

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

	t.Run("NewXORModifier with empty key generates random key", func(t *testing.T) {
		mod1, err := NewXORModifier("empty-key-1", []byte{})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
		mod2, err := NewXORModifier("empty-key-2", []byte{})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}

		// The random default should be 32 bytes long
		if len(mod1.xorKey) != 32 {
			t.Errorf("Empty-key default key length = %v, want 32", len(mod1.xorKey))
		}
		if len(mod2.xorKey) != 32 {
			t.Errorf("Empty-key default key length = %v, want 32", len(mod2.xorKey))
		}

		// Two separate calls should produce different keys (probabilistic: P(collision) ≈ 2^-256)
		sameKey := true
		for i := range mod1.xorKey {
			if mod1.xorKey[i] != mod2.xorKey[i] {
				sameKey = false
				break
			}
		}
		if sameKey {
			t.Error("Two NewXORModifier(empty) calls produced the same key (astronomically unlikely unless broken)")
		}
	})

	t.Run("XOR round-trip", func(t *testing.T) {
		key := []byte{0xAA, 0xBB}
		modifier, err := NewXORModifier("roundtrip", key)
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
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

	t.Run("XOR applies to handshake phases but passes PhaseData through unmodified", func(t *testing.T) {
		modifier, err := NewXORModifier("phase-test", []byte{0x42})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
		testData := []byte("test")

		handshakePhases := []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal}
		for _, phase := range handshakePhases {
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

			// Verify round-trip
			recovered, err := modifier.ModifyInbound(phase, result)
			if err != nil {
				t.Errorf("ModifyInbound() phase %v error = %v", phase, err)
			}
			if string(recovered) != string(testData) {
				t.Errorf("Round-trip failed for phase %v", phase)
			}
		}

		// PhaseData must pass through unmodified (no XOR applied), to avoid
		// reusing the same static keystream across every post-handshake
		// message.
		result, err := modifier.ModifyOutbound(PhaseData, testData)
		if err != nil {
			t.Errorf("ModifyOutbound(PhaseData) error = %v", err)
		}
		if string(result) != string(testData) {
			t.Errorf("PhaseData: got %v, want data unchanged (%v)", result, testData)
		}
		recovered, err := modifier.ModifyInbound(PhaseData, result)
		if err != nil {
			t.Errorf("ModifyInbound(PhaseData) error = %v", err)
		}
		if string(recovered) != string(testData) {
			t.Errorf("PhaseData round-trip failed: got %v, want %v", recovered, testData)
		}
	})

	t.Run("XOR with empty data", func(t *testing.T) {
		modifier, err := NewXORModifier("empty-data", []byte{0xFF})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}

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
		modifier, err := NewXORModifier("cycling", key)
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
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

	t.Run("Close zeroes key material", func(t *testing.T) {
		key := []byte{0x11, 0x22, 0x33}
		modifier, err := NewXORModifier("close-test", key)
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}

		if err := modifier.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}

		for i, b := range modifier.xorKey {
			if b != 0 {
				t.Errorf("xorKey[%d] = %02x after Close(), want 0x00", i, b)
			}
		}
	})

	t.Run("Concurrent ModifyOutbound and ModifyInbound", func(t *testing.T) {
		modifier, err := NewXORModifier("concurrent-xor", []byte{0x5A, 0xA5})
		if err != nil {
			t.Fatalf("NewXORModifier() error = %v", err)
		}
		testData := []byte("concurrent test data for XOR modifier")

		const goroutines = 16
		var wg sync.WaitGroup
		errs := make(chan error, goroutines*2)

		for i := 0; i < goroutines; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				out, err := modifier.ModifyOutbound(PhaseData, testData)
				if err != nil {
					errs <- err
					return
				}
				recovered, err := modifier.ModifyInbound(PhaseData, out)
				if err != nil {
					errs <- err
					return
				}
				if string(recovered) != string(testData) {
					errs <- fmt.Errorf("concurrent round-trip mismatch")
				}
			}()
			go func() {
				defer wg.Done()
				out, err := modifier.ModifyOutbound(PhaseFinal, testData)
				if err != nil {
					errs <- err
					return
				}
				recovered, err := modifier.ModifyInbound(PhaseFinal, out)
				if err != nil {
					errs <- err
					return
				}
				if string(recovered) != string(testData) {
					errs <- fmt.Errorf("concurrent round-trip mismatch (PhaseFinal)")
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// failingReader is an io.Reader that always returns an error, used to test
// the NewXORModifier entropy-failure fallback path.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated entropy failure")
}

// TestNewXORModifier_EntropyFailureFallback verifies that when the random
// source fails, NewXORModifier returns an error instead of silently
// degrading to a weak fallback key. This ensures fail-fast behavior when
// entropy is unavailable (which is an extremely rare condition).
func TestNewXORModifier_EntropyFailureFallback(t *testing.T) {
	// Save and restore the package-level randReader
	originalReader := randReader
	t.Cleanup(func() { randReader = originalReader })

	// Inject a failing reader
	randReader = io.Reader(failingReader{})

	mod, err := NewXORModifier("entropy-fail", nil)

	// Should return an error, not a degraded modifier
	if err == nil {
		t.Fatal("NewXORModifier with failed entropy should return error")
	}
	if mod != nil {
		t.Error("NewXORModifier with failed entropy should return nil modifier")
	}
	// Verify the error contains appropriate context
	if !strings.Contains(err.Error(), "RNG") && !strings.Contains(err.Error(), "random") {
		t.Logf("Warning: error message may not clearly indicate RNG failure: %v", err)
	}
}

// TestNewXORModifier_NormalRandReaderRestored verifies that the injected
// reader does not leak across tests (basic sanity check).
func TestNewXORModifier_NormalRandReaderRestored(t *testing.T) {
	mod, err := NewXORModifier("after-restore", nil)
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	if len(mod.xorKey) != 32 {
		t.Errorf("Expected 32-byte random key after reader restore, got %d bytes", len(mod.xorKey))
	}
}

// TestXORModifier_ConcurrentClose exercises Close() concurrently with
// ModifyOutbound and ModifyInbound to verify that the sync.Mutex prevents
// data races on `closed` and `xorKey`. Run with: go test -race ./handshake/...
func TestXORModifier_ConcurrentClose(t *testing.T) {
	modifier, err := NewXORModifier("race-close", []byte{0x5A, 0xA5})
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	testData := []byte("concurrent close test data")

	const goroutines = 16
	var wg sync.WaitGroup

	// Launch goroutines that call ModifyOutbound/ModifyInbound continuously
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = modifier.ModifyOutbound(PhaseData, testData)
				_, _ = modifier.ModifyInbound(PhaseData, testData)
			}
		}()
	}

	// Concurrently close the modifier
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = modifier.Close()
	}()

	wg.Wait()

	// After Close, further calls must return an error
	_, err = modifier.ModifyOutbound(PhaseData, testData)
	if err == nil {
		t.Error("ModifyOutbound after Close should return error")
	}
}

// TestXORModifier_UseAfterClose verifies that ModifyOutbound and ModifyInbound
// return errors after Close() has been called, preventing silent security
// degradation where zeroed key material would cause XOR to become a no-op.
func TestXORModifier_UseAfterClose(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC}
	modifier, err := NewXORModifier("use-after-close", key)
	if err != nil {
		t.Fatalf("NewXORModifier() error = %v", err)
	}
	testData := []byte("hello noise")

	// Verify it works before Close
	out, err := modifier.ModifyOutbound(PhaseInitial, testData)
	if err != nil {
		t.Fatalf("ModifyOutbound() before Close error = %v", err)
	}
	if string(out) == string(testData) {
		t.Fatal("ModifyOutbound() should transform data before Close")
	}

	// Close the modifier
	if err := modifier.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ModifyOutbound after Close should return error
	_, err = modifier.ModifyOutbound(PhaseInitial, testData)
	if err == nil {
		t.Error("ModifyOutbound() after Close() should return error")
	}

	// ModifyInbound after Close should return error
	_, err = modifier.ModifyInbound(PhaseInitial, testData)
	if err == nil {
		t.Error("ModifyInbound() after Close() should return error")
	}

	// Empty data after Close should also return error
	_, err = modifier.ModifyOutbound(PhaseInitial, []byte{})
	if err == nil {
		t.Error("ModifyOutbound() with empty data after Close() should return error")
	}

	// All phases should return error after Close
	for _, phase := range []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal, PhaseData} {
		_, err = modifier.ModifyOutbound(phase, testData)
		if err == nil {
			t.Errorf("ModifyOutbound(phase=%v) after Close() should return error", phase)
		}
		_, err = modifier.ModifyInbound(phase, testData)
		if err == nil {
			t.Errorf("ModifyInbound(phase=%v) after Close() should return error", phase)
		}
	}
}
