package noise

import (
	"testing"
	"time"
)

// Tests to reach the remaining coverage gaps

// Test all WithMethods return chain properly
func TestConnConfigMethodChaining(t *testing.T) {
	config := NewConnConfig("XX", true)
	originalConfig := config

	// Test that all methods return the same instance
	result1 := config.WithStaticKey(make([]byte, 32))
	if result1 != originalConfig {
		t.Errorf("WithStaticKey should return same instance")
	}

	result2 := config.WithRemoteKey(make([]byte, 32))
	if result2 != originalConfig {
		t.Errorf("WithRemoteKey should return same instance")
	}

	result3 := config.WithHandshakeTimeout(time.Minute)
	if result3 != originalConfig {
		t.Errorf("WithHandshakeTimeout should return same instance")
	}

	result4 := config.WithReadTimeout(time.Minute)
	if result4 != originalConfig {
		t.Errorf("WithReadTimeout should return same instance")
	}

	result5 := config.WithWriteTimeout(time.Minute)
	if result5 != originalConfig {
		t.Errorf("WithWriteTimeout should return same instance")
	}
}

// Test key copying behavior more thoroughly
func TestConnConfigKeyCopying(t *testing.T) {
	config := NewConnConfig("XX", true)

	// Test static key copying
	originalKey := []byte{1, 2, 3, 4, 5}
	config.WithStaticKey(originalKey)

	// Modify original key
	originalKey[0] = 99

	// Config should have original value
	if len(config.StaticKey) != 5 {
		t.Errorf("Static key should be copied, not referenced")
	}
	if config.StaticKey[0] != 1 {
		t.Errorf("Static key should maintain original value after source modification")
	}

	// Test remote key copying
	originalRemoteKey := []byte{10, 20, 30, 40, 50}
	config.WithRemoteKey(originalRemoteKey)

	// Modify original key
	originalRemoteKey[0] = 99

	// Config should have original value
	if len(config.RemoteKey) != 5 {
		t.Errorf("Remote key should be copied, not referenced")
	}
	if config.RemoteKey[0] != 10 {
		t.Errorf("Remote key should maintain original value after source modification")
	}
}

// Test validation with various key combinations
func TestConnConfigValidationKeyScenarios(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		staticKey   []byte
		remoteKey   []byte
		shouldError bool
		description string
	}{
		{
			name:        "No keys required for NN",
			pattern:     "NN",
			staticKey:   nil,
			remoteKey:   nil,
			shouldError: false,
			description: "NN pattern doesn't require any keys",
		},
		{
			name:        "Static key but no remote key",
			pattern:     "XX",
			staticKey:   make([]byte, 32),
			remoteKey:   nil,
			shouldError: false,
			description: "XX pattern with just static key should be valid",
		},
		{
			name:        "Both keys provided",
			pattern:     "IK",
			staticKey:   make([]byte, 32),
			remoteKey:   make([]byte, 32),
			shouldError: false,
			description: "IK pattern with both keys should be valid",
		},
		{
			name:        "Empty static key slice",
			pattern:     "XX",
			staticKey:   []byte{},
			remoteKey:   nil,
			shouldError: false,
			description: "Empty key slice should be treated as no key",
		},
		{
			name:        "Empty remote key slice",
			pattern:     "NK",
			staticKey:   nil,
			remoteKey:   []byte{},
			shouldError: false,
			description: "Empty remote key slice should be treated as no key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ConnConfig{
				Pattern:          tt.pattern,
				Initiator:        true,
				StaticKey:        tt.staticKey,
				RemoteKey:        tt.remoteKey,
				HandshakeTimeout: 30 * time.Second,
			}

			err := config.Validate()

			if tt.shouldError && err == nil {
				t.Errorf("Expected validation error for %s, but got none", tt.description)
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected validation error for %s: %v", tt.description, err)
			}
		})
	}
}

// Test address methods with extreme values
func TestNoiseAddrExtremeValues(t *testing.T) {
	tests := []struct {
		name       string
		underlying *mockNetAddr
		pattern    string
		role       string
	}{
		{
			name:       "Empty everything",
			underlying: &mockNetAddr{network: "", address: ""},
			pattern:    "",
			role:       "",
		},
		{
			name:       "Very long pattern name",
			underlying: &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"},
			pattern:    "Noise_XX_25519_AESGCM_SHA256_with_very_long_additional_suffix_that_is_not_standard",
			role:       "initiator",
		},
		{
			name:       "Very long role name",
			underlying: &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"},
			pattern:    "XX",
			role:       "super_long_role_name_that_exceeds_normal_expectations_for_role_naming",
		},
		{
			name:       "Unicode in pattern",
			underlying: &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"},
			pattern:    "XX_🔒_secure",
			role:       "initiator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := NewNoiseAddr(tt.underlying, tt.pattern, tt.role)

			// These operations should not panic
			_ = addr.Network()
			_ = addr.String()
			_ = addr.Pattern()
			_ = addr.Role()
			_ = addr.Underlying()

			// Verify the values are preserved
			if addr.Pattern() != tt.pattern {
				t.Errorf("Pattern not preserved correctly")
			}
			if addr.Role() != tt.role {
				t.Errorf("Role not preserved correctly")
			}
			if addr.Underlying() != tt.underlying {
				t.Errorf("Underlying address not preserved correctly")
			}
		})
	}
}

// Test configuration defaults more thoroughly
func TestConnConfigDefaults(t *testing.T) {
	config := NewConnConfig("XX", true)

	// Test all default values
	expectedTimeout := 30 * time.Second
	if config.HandshakeTimeout != expectedTimeout {
		t.Errorf("Expected handshake timeout %v, got %v", expectedTimeout, config.HandshakeTimeout)
	}

	if config.ReadTimeout != 0 {
		t.Errorf("Expected read timeout 0, got %v", config.ReadTimeout)
	}

	if config.WriteTimeout != 0 {
		t.Errorf("Expected write timeout 0, got %v", config.WriteTimeout)
	}

	if config.Pattern != "XX" {
		t.Errorf("Expected pattern XX, got %s", config.Pattern)
	}

	if !config.Initiator {
		t.Errorf("Expected initiator true")
	}

	if config.StaticKey != nil {
		t.Errorf("Expected static key nil by default")
	}

	if config.RemoteKey != nil {
		t.Errorf("Expected remote key nil by default")
	}
}

// Test error message content and structure
func TestErrorMessages(t *testing.T) {
	// Test config validation error messages
	config := &ConnConfig{
		Pattern:          "",
		Initiator:        true,
		HandshakeTimeout: 0,
	}

	err := config.Validate()
	if err == nil {
		t.Fatalf("Expected validation error")
	}

	errStr := err.Error()
	if errStr == "" {
		t.Errorf("Error message should not be empty")
	}

	// Test invalid key length error
	config2 := &ConnConfig{
		Pattern:          "XX",
		Initiator:        true,
		StaticKey:        make([]byte, 16), // Wrong length
		HandshakeTimeout: 30 * time.Second,
	}

	err2 := config2.Validate()
	if err2 == nil {
		t.Fatalf("Expected validation error for wrong key length")
	}

	errStr2 := err2.Error()
	if errStr2 == "" {
		t.Errorf("Error message should not be empty")
	}
}

// Test pattern name extraction from full pattern names
func TestPatternNameExtraction(t *testing.T) {
	tests := []struct {
		fullPattern string
		expected    string
		shouldError bool
	}{
		{
			fullPattern: "Noise_XX_25519_AESGCM_SHA256",
			expected:    "XX",
			shouldError: false,
		},
		{
			fullPattern: "Noise_NN_25519_AESGCM_SHA256",
			expected:    "NN",
			shouldError: false,
		},
		{
			fullPattern: "Noise_NK_25519_AESGCM_SHA256",
			expected:    "NK",
			shouldError: false,
		},
		{
			fullPattern: "XX", // Short pattern
			expected:    "XX",
			shouldError: false,
		},
		{
			fullPattern: "Noise_ZZ_25519_AESGCM_SHA256", // Invalid pattern
			expected:    "",
			shouldError: true,
		},
		{
			fullPattern: "Malformed_Pattern_Name",
			expected:    "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.fullPattern, func(t *testing.T) {
			result, err := parseHandshakePattern(tt.fullPattern)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for pattern %s", tt.fullPattern)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for pattern %s: %v", tt.fullPattern, err)
				return
			}

			if result.Name != tt.expected {
				t.Errorf("Expected pattern name %s, got %s", tt.expected, result.Name)
			}
		})
	}
}
