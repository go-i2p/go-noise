package noise

import (
	"testing"
	"time"

	"github.com/flynn/noise"
)

func TestParseHandshakePattern(t *testing.T) {
	tests := []struct {
		name        string
		patternName string
		expected    noise.HandshakePattern
		shouldError bool
	}{
		{
			name:        "XX pattern with full name",
			patternName: "Noise_XX_25519_AESGCM_SHA256",
			expected:    noise.HandshakeXX,
			shouldError: false,
		},
		{
			name:        "XX pattern with short name",
			patternName: "XX",
			expected:    noise.HandshakeXX,
			shouldError: false,
		},
		{
			name:        "NN pattern",
			patternName: "NN",
			expected:    noise.HandshakeNN,
			shouldError: false,
		},
		{
			name:        "NK pattern",
			patternName: "NK",
			expected:    noise.HandshakeNK,
			shouldError: false,
		},
		{
			name:        "IK pattern",
			patternName: "IK",
			expected:    noise.HandshakeIK,
			shouldError: false,
		},
		{
			name:        "Invalid pattern",
			patternName: "INVALID",
			expected:    noise.HandshakePattern{},
			shouldError: true,
		},
		{
			name:        "Empty pattern",
			patternName: "",
			expected:    noise.HandshakePattern{},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHandshakePattern(tt.patternName)

			if tt.shouldError && err == nil {
				t.Errorf("Expected error for pattern %s, but got none", tt.patternName)
				return
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error for pattern %s: %v", tt.patternName, err)
				return
			}

			if !tt.shouldError {
				if result.Name != tt.expected.Name {
					t.Errorf("Expected pattern name %s, got %s", tt.expected.Name, result.Name)
				}
			}
		})
	}
}

func TestConnConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnConfig
		shouldError bool
		errorCode   string
	}{
		{
			name: "Valid config",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 30,
			},
			shouldError: false,
		},
		{
			name: "Empty pattern",
			config: &ConnConfig{
				Pattern:          "",
				Initiator:        true,
				HandshakeTimeout: 30,
			},
			shouldError: true,
		},
		{
			name: "Invalid timeout",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 0,
			},
			shouldError: true,
		},
		{
			name: "Invalid static key length",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 30,
				StaticKey:        []byte("short"),
			},
			shouldError: true,
		},
		{
			name: "Valid static key length",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 30,
				StaticKey:        make([]byte, 32),
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.shouldError && err == nil {
				t.Errorf("Expected validation error, but got none")
				return
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
				return
			}
		})
	}
}

func TestNoiseAddrImplementation(t *testing.T) {
	// Test that NoiseAddr implements net.Addr interface
	var _ interface{} = (*NoiseAddr)(nil)

	// Create a mock address for testing
	mockAddr := &mockNetAddr{network: "tcp", address: "192.168.1.1:8080"}

	addr := NewNoiseAddr(mockAddr, "XX", "initiator")

	// Test Network() method
	expectedNetwork := "noise+tcp"
	if addr.Network() != expectedNetwork {
		t.Errorf("Expected network %s, got %s", expectedNetwork, addr.Network())
	}

	// Test String() method
	expectedString := "noise://XX/initiator/192.168.1.1:8080"
	if addr.String() != expectedString {
		t.Errorf("Expected string %s, got %s", expectedString, addr.String())
	}

	// Test accessor methods
	if addr.Pattern() != "XX" {
		t.Errorf("Expected pattern XX, got %s", addr.Pattern())
	}

	if addr.Role() != "initiator" {
		t.Errorf("Expected role initiator, got %s", addr.Role())
	}

	if addr.Underlying() != mockAddr {
		t.Errorf("Expected underlying address to match")
	}
}

// mockNetAddr is a simple implementation of net.Addr for testing
type mockNetAddr struct {
	network string
	address string
}

func (m *mockNetAddr) Network() string { return m.network }
func (m *mockNetAddr) String() string  { return m.address }

// Additional comprehensive tests for pattern parsing and edge cases

func TestParseHandshakePatternFullCoverage(t *testing.T) {
	tests := []struct {
		name        string
		patternName string
		expected    string // Expected pattern name
		shouldError bool
	}{
		// Test all standard patterns
		{
			name:        "NN pattern full name",
			patternName: "Noise_NN_25519_AESGCM_SHA256",
			expected:    "NN",
			shouldError: false,
		},
		{
			name:        "NK pattern full name",
			patternName: "Noise_NK_25519_AESGCM_SHA256",
			expected:    "NK",
			shouldError: false,
		},
		{
			name:        "NX pattern",
			patternName: "NX",
			expected:    "NX",
			shouldError: false,
		},
		{
			name:        "KN pattern",
			patternName: "KN",
			expected:    "KN",
			shouldError: false,
		},
		{
			name:        "KK pattern",
			patternName: "KK",
			expected:    "KK",
			shouldError: false,
		},
		{
			name:        "KX pattern",
			patternName: "KX",
			expected:    "KX",
			shouldError: false,
		},
		{
			name:        "IN pattern",
			patternName: "IN",
			expected:    "IN",
			shouldError: false,
		},
		{
			name:        "IK pattern full name",
			patternName: "Noise_IK_25519_AESGCM_SHA256",
			expected:    "IK",
			shouldError: false,
		},
		{
			name:        "IX pattern",
			patternName: "IX",
			expected:    "IX",
			shouldError: false,
		},
		// Test invalid patterns
		{
			name:        "Invalid pattern ZZ",
			patternName: "ZZ",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "Mixed case pattern",
			patternName: "xx",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "Pattern with spaces",
			patternName: "X X",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "Malformed full pattern",
			patternName: "Noise_XX_INVALID_AESGCM_SHA256",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "Numeric pattern",
			patternName: "123",
			expected:    "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHandshakePattern(tt.patternName)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for pattern %s, but got none", tt.patternName)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for pattern %s: %v", tt.patternName, err)
				return
			}

			if result.Name != tt.expected {
				t.Errorf("Expected pattern name %s, got %s", tt.expected, result.Name)
			}
		})
	}
}

func TestConnConfigValidationComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnConfig
		shouldError bool
		errorField  string // Which field should cause the error
	}{
		{
			name: "Valid minimal config",
			config: &ConnConfig{
				Pattern:          "NN",
				Initiator:        true,
				HandshakeTimeout: 1 * time.Second,
			},
			shouldError: false,
		},
		{
			name: "Valid config with all fields",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        false,
				StaticKey:        make([]byte, 32),
				RemoteKey:        make([]byte, 32),
				HandshakeTimeout: 30 * time.Second,
				ReadTimeout:      60 * time.Second,
				WriteTimeout:     60 * time.Second,
			},
			shouldError: false,
		},
		{
			name: "Empty pattern",
			config: &ConnConfig{
				Pattern:          "",
				Initiator:        true,
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			errorField:  "pattern",
		},
		{
			name: "Invalid handshake timeout - zero",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 0,
			},
			shouldError: true,
			errorField:  "handshake_timeout",
		},
		{
			name: "Invalid handshake timeout - negative",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: -1 * time.Second,
			},
			shouldError: true,
			errorField:  "handshake_timeout",
		},
		{
			name: "Invalid static key - too short",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				StaticKey:        make([]byte, 16), // Should be 32 bytes
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			errorField:  "static_key",
		},
		{
			name: "Invalid static key - too long",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				StaticKey:        make([]byte, 64), // Should be 32 bytes
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			errorField:  "static_key",
		},
		{
			name: "Invalid remote key - too short",
			config: &ConnConfig{
				Pattern:          "NK",
				Initiator:        true,
				RemoteKey:        make([]byte, 16), // Should be 32 bytes
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			errorField:  "remote_key",
		},
		{
			name: "Invalid pattern for validation",
			config: &ConnConfig{
				Pattern:          "INVALID_PATTERN",
				Initiator:        true,
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: false, // Config validation only checks for empty pattern, not validity
			errorField:  "pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.shouldError && err == nil {
				t.Errorf("Expected validation error for %s field, but got none", tt.errorField)
				return
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
				return
			}

			// In a real implementation, you might check for specific error codes or messages
			// related to the expected error field
		})
	}
}

// Test edge cases and boundary conditions
func TestNoiseAddrEdgeCases(t *testing.T) {
	// Test with very long addresses
	longAddress := string(make([]byte, 1000))
	longAddr := &mockNetAddr{network: "tcp", address: longAddress}
	addr := NewNoiseAddr(longAddr, "XX", "initiator")

	// Should handle long addresses gracefully
	result := addr.String()
	if len(result) == 0 {
		t.Errorf("String() should handle long addresses")
	}

	// Test with special characters in address
	specialAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080?param=value&other=123"}
	addr2 := NewNoiseAddr(specialAddr, "XX", "initiator")
	result2 := addr2.String()

	if !contains(result2, "127.0.0.1:8080?param=value&other=123") {
		t.Errorf("Should preserve special characters in address")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Test concurrent access to pattern parsing
func TestParseHandshakePatternConcurrency(t *testing.T) {
	patterns := []string{"XX", "NN", "NK", "IK", "KK"}
	results := make(chan error, len(patterns)*10)

	// Run concurrent pattern parsing
	for _, pattern := range patterns {
		for i := 0; i < 10; i++ {
			go func(p string) {
				_, err := parseHandshakePattern(p)
				results <- err
			}(pattern)
		}
	}

	// Collect results
	for i := 0; i < len(patterns)*10; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Concurrent pattern parsing failed: %v", err)
		}
	}
}
