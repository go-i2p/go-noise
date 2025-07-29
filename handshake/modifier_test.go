package handshake

import (
	"errors"
	"testing"
)

// testModifier is a simple test implementation of HandshakeModifier
type testModifier struct {
	name           string
	modifyOutbound func(phase HandshakePhase, data []byte) ([]byte, error)
	modifyInbound  func(phase HandshakePhase, data []byte) ([]byte, error)
}

func (tm *testModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if tm.modifyOutbound != nil {
		return tm.modifyOutbound(phase, data)
	}
	return data, nil
}

func (tm *testModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if tm.modifyInbound != nil {
		return tm.modifyInbound(phase, data)
	}
	return data, nil
}

func (tm *testModifier) Name() string {
	return tm.name
}

func TestHandshakePhase_String(t *testing.T) {
	tests := []struct {
		name  string
		phase HandshakePhase
		want  string
	}{
		{
			name:  "PhaseInitial",
			phase: PhaseInitial,
			want:  "initial",
		},
		{
			name:  "PhaseExchange",
			phase: PhaseExchange,
			want:  "exchange",
		},
		{
			name:  "PhaseFinal",
			phase: PhaseFinal,
			want:  "final",
		},
		{
			name:  "Unknown phase",
			phase: HandshakePhase(99),
			want:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.phase.String(); got != tt.want {
				t.Errorf("HandshakePhase.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandshakeModifier_Interface(t *testing.T) {
	// Test that our test implementation satisfies the interface
	var _ HandshakeModifier = &testModifier{}

	testData := []byte("test data")

	t.Run("Basic modifier functionality", func(t *testing.T) {
		modifier := &testModifier{
			name: "test-modifier",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				// Simple append operation for testing
				return append(data, []byte("-outbound")...), nil
			},
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				// Simple append operation for testing
				return append(data, []byte("-inbound")...), nil
			},
		}

		// Test Name method
		if modifier.Name() != "test-modifier" {
			t.Errorf("Name() = %v, want %v", modifier.Name(), "test-modifier")
		}

		// Test ModifyOutbound
		outbound, err := modifier.ModifyOutbound(PhaseInitial, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}
		expected := "test data-outbound"
		if string(outbound) != expected {
			t.Errorf("ModifyOutbound() = %v, want %v", string(outbound), expected)
		}

		// Test ModifyInbound
		inbound, err := modifier.ModifyInbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}
		expected = "test data-inbound"
		if string(inbound) != expected {
			t.Errorf("ModifyInbound() = %v, want %v", string(inbound), expected)
		}
	})

	t.Run("Modifier with errors", func(t *testing.T) {
		modifier := &testModifier{
			name: "error-modifier",
			modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return nil, errors.New("outbound error")
			},
			modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
				return nil, errors.New("inbound error")
			},
		}

		// Test error handling in ModifyOutbound
		_, err := modifier.ModifyOutbound(PhaseInitial, testData)
		if err == nil {
			t.Error("ModifyOutbound() expected error, got nil")
		}
		if err.Error() != "outbound error" {
			t.Errorf("ModifyOutbound() error = %v, want %v", err, "outbound error")
		}

		// Test error handling in ModifyInbound
		_, err = modifier.ModifyInbound(PhaseExchange, testData)
		if err == nil {
			t.Error("ModifyInbound() expected error, got nil")
		}
		if err.Error() != "inbound error" {
			t.Errorf("ModifyInbound() error = %v, want %v", err, "inbound error")
		}
	})

	t.Run("Passthrough modifier", func(t *testing.T) {
		// Test default behavior (passthrough)
		modifier := &testModifier{name: "passthrough"}

		outbound, err := modifier.ModifyOutbound(PhaseFinal, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}
		if string(outbound) != string(testData) {
			t.Errorf("ModifyOutbound() = %v, want %v", string(outbound), string(testData))
		}

		inbound, err := modifier.ModifyInbound(PhaseFinal, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}
		if string(inbound) != string(testData) {
			t.Errorf("ModifyInbound() = %v, want %v", string(inbound), string(testData))
		}
	})
}

func TestHandshakeModifier_PhaseHandling(t *testing.T) {
	// Test that modifiers can handle different phases correctly
	phaseTracker := make([]HandshakePhase, 0)

	modifier := &testModifier{
		name: "phase-tracker",
		modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			phaseTracker = append(phaseTracker, phase)
			return data, nil
		},
	}

	// Test different phases
	phases := []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal}
	for _, phase := range phases {
		_, err := modifier.ModifyOutbound(phase, []byte("test"))
		if err != nil {
			t.Errorf("ModifyOutbound() for phase %v error = %v", phase, err)
		}
	}

	// Verify all phases were tracked
	if len(phaseTracker) != len(phases) {
		t.Errorf("Expected %d phases tracked, got %d", len(phases), len(phaseTracker))
	}

	for i, expectedPhase := range phases {
		if phaseTracker[i] != expectedPhase {
			t.Errorf("Phase %d: expected %v, got %v", i, expectedPhase, phaseTracker[i])
		}
	}
}

func TestHandshakeModifier_DataIntegrity(t *testing.T) {
	// Test that modifiers handle data correctly without corruption
	originalData := []byte("sensitive handshake data")

	modifier := &testModifier{
		name: "data-modifier",
		modifyOutbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			// Make a copy to avoid modifying original
			result := make([]byte, len(data))
			copy(result, data)
			return result, nil
		},
		modifyInbound: func(phase HandshakePhase, data []byte) ([]byte, error) {
			// Make a copy and reverse for testing
			result := make([]byte, len(data))
			for i, b := range data {
				result[len(data)-1-i] = b
			}
			return result, nil
		},
	}

	// Test outbound preserves data
	outbound, err := modifier.ModifyOutbound(PhaseInitial, originalData)
	if err != nil {
		t.Errorf("ModifyOutbound() error = %v", err)
	}
	if string(outbound) != string(originalData) {
		t.Errorf("ModifyOutbound() = %v, want %v", string(outbound), string(originalData))
	}

	// Test inbound transformation
	inbound, err := modifier.ModifyInbound(PhaseInitial, originalData)
	if err != nil {
		t.Errorf("ModifyInbound() error = %v", err)
	}

	// Verify the data was reversed
	expected := "atad ekahsdnah evitisnes"
	if string(inbound) != expected {
		t.Errorf("ModifyInbound() = %v, want %v", string(inbound), expected)
	}

	// Verify original data unchanged
	if string(originalData) != "sensitive handshake data" {
		t.Error("Original data was modified, should be immutable")
	}
}
