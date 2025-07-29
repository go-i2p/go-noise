package noise

import (
	"testing"
	"time"

	"github.com/go-i2p/go-noise/handshake"
)

func TestNewConnConfig(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		initiator bool
	}{
		{
			name:      "XX pattern initiator",
			pattern:   "XX",
			initiator: true,
		},
		{
			name:      "NN pattern responder",
			pattern:   "NN",
			initiator: false,
		},
		{
			name:      "Empty pattern",
			pattern:   "",
			initiator: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConnConfig(tt.pattern, tt.initiator)

			if config.Pattern != tt.pattern {
				t.Errorf("Expected pattern %s, got %s", tt.pattern, config.Pattern)
			}

			if config.Initiator != tt.initiator {
				t.Errorf("Expected initiator %v, got %v", tt.initiator, config.Initiator)
			}

			// Check defaults
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
		})
	}
}

func TestConnConfigWithStaticKey(t *testing.T) {
	config := NewConnConfig("XX", true)

	tests := []struct {
		name        string
		key         []byte
		shouldError bool
	}{
		{
			name:        "Valid 32-byte key",
			key:         make([]byte, 32),
			shouldError: false,
		},
		{
			name:        "Nil key",
			key:         nil,
			shouldError: false, // Should be allowed for patterns that don't require static keys
		},
		{
			name:        "Empty key",
			key:         []byte{},
			shouldError: false, // Should be allowed
		},
		{
			name:        "Short key",
			key:         make([]byte, 16),
			shouldError: false, // Validation happens in Validate(), not in WithStaticKey
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.WithStaticKey(tt.key)

			// WithStaticKey should return the same config for chaining
			if result != config {
				t.Errorf("WithStaticKey should return the same config instance")
			}

			// Check that the key was set
			if len(tt.key) > 0 {
				if len(config.StaticKey) != len(tt.key) {
					t.Errorf("Static key not set correctly")
				}
				for i, b := range tt.key {
					if config.StaticKey[i] != b {
						t.Errorf("Static key byte %d doesn't match", i)
						break
					}
				}
			} else if tt.key == nil {
				// For nil key, WithStaticKey creates empty slice
				if config.StaticKey == nil {
					t.Errorf("Static key should be empty slice, not nil")
				}
			}
		})
	}
}

func TestConnConfigWithRemoteKey(t *testing.T) {
	config := NewConnConfig("NK", true) // NK pattern requires remote key

	tests := []struct {
		name string
		key  []byte
	}{
		{
			name: "Valid 32-byte remote key",
			key:  make([]byte, 32),
		},
		{
			name: "Nil remote key",
			key:  nil,
		},
		{
			name: "Empty remote key",
			key:  []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.WithRemoteKey(tt.key)

			// WithRemoteKey should return the same config for chaining
			if result != config {
				t.Errorf("WithRemoteKey should return the same config instance")
			}

			// Check that the key was set
			if len(tt.key) > 0 {
				if len(config.RemoteKey) != len(tt.key) {
					t.Errorf("Remote key not set correctly")
				}
			} else if tt.key == nil {
				// For nil key, WithRemoteKey creates empty slice
				if config.RemoteKey == nil {
					t.Errorf("Remote key should be empty slice, not nil")
				}
			}
		})
	}
}

func TestConnConfigWithHandshakeTimeout(t *testing.T) {
	config := NewConnConfig("XX", true)

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "30 second timeout",
			timeout: 30 * time.Second,
		},
		{
			name:    "1 minute timeout",
			timeout: time.Minute,
		},
		{
			name:    "Zero timeout",
			timeout: 0,
		},
		{
			name:    "Negative timeout",
			timeout: -time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.WithHandshakeTimeout(tt.timeout)

			// WithHandshakeTimeout should return the same config for chaining
			if result != config {
				t.Errorf("WithHandshakeTimeout should return the same config instance")
			}

			if config.HandshakeTimeout != tt.timeout {
				t.Errorf("Expected handshake timeout %v, got %v", tt.timeout, config.HandshakeTimeout)
			}
		})
	}
}

func TestConnConfigWithReadTimeout(t *testing.T) {
	config := NewConnConfig("XX", true)

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "30 second read timeout",
			timeout: 30 * time.Second,
		},
		{
			name:    "No timeout",
			timeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.WithReadTimeout(tt.timeout)

			if result != config {
				t.Errorf("WithReadTimeout should return the same config instance")
			}

			if config.ReadTimeout != tt.timeout {
				t.Errorf("Expected read timeout %v, got %v", tt.timeout, config.ReadTimeout)
			}
		})
	}
}

func TestConnConfigWithWriteTimeout(t *testing.T) {
	config := NewConnConfig("XX", true)

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "30 second write timeout",
			timeout: 30 * time.Second,
		},
		{
			name:    "No timeout",
			timeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.WithWriteTimeout(tt.timeout)

			if result != config {
				t.Errorf("WithWriteTimeout should return the same config instance")
			}

			if config.WriteTimeout != tt.timeout {
				t.Errorf("Expected write timeout %v, got %v", tt.timeout, config.WriteTimeout)
			}
		})
	}
}

func TestConnConfigBuilderPattern(t *testing.T) {
	// Test method chaining
	staticKey := make([]byte, 32)
	remoteKey := make([]byte, 32)

	config := NewConnConfig("XX", true).
		WithStaticKey(staticKey).
		WithRemoteKey(remoteKey).
		WithHandshakeTimeout(time.Minute).
		WithReadTimeout(30 * time.Second).
		WithWriteTimeout(30 * time.Second)

	// Verify all values were set correctly
	if config.Pattern != "XX" {
		t.Errorf("Expected pattern XX, got %s", config.Pattern)
	}

	if !config.Initiator {
		t.Errorf("Expected initiator true")
	}

	if len(config.StaticKey) != 32 {
		t.Errorf("Expected static key length 32, got %d", len(config.StaticKey))
	}

	if len(config.RemoteKey) != 32 {
		t.Errorf("Expected remote key length 32, got %d", len(config.RemoteKey))
	}

	if config.HandshakeTimeout != time.Minute {
		t.Errorf("Expected handshake timeout 1m, got %v", config.HandshakeTimeout)
	}

	if config.ReadTimeout != 30*time.Second {
		t.Errorf("Expected read timeout 30s, got %v", config.ReadTimeout)
	}

	if config.WriteTimeout != 30*time.Second {
		t.Errorf("Expected write timeout 30s, got %v", config.WriteTimeout)
	}
}

func TestConnConfigValidationExtended(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnConfig
		shouldError bool
		description string
	}{
		{
			name: "Valid XX pattern with static key",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				StaticKey:        make([]byte, 32),
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: false,
			description: "Standard valid configuration",
		},
		{
			name: "Valid NN pattern without static key",
			config: &ConnConfig{
				Pattern:          "NN",
				Initiator:        true,
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: false,
			description: "NN pattern doesn't require static key",
		},
		{
			name: "Invalid pattern name",
			config: &ConnConfig{
				Pattern:          "INVALID",
				Initiator:        true,
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: false, // Current validation only checks if pattern is empty, not if it's valid
			description: "Pattern validation happens during handshake, not in config validation",
		},
		{
			name: "Zero handshake timeout",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: 0,
			},
			shouldError: true,
			description: "Should reject zero timeout",
		},
		{
			name: "Negative handshake timeout",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				HandshakeTimeout: -time.Second,
			},
			shouldError: true,
			description: "Should reject negative timeout",
		},
		{
			name: "Valid IK pattern",
			config: &ConnConfig{
				Pattern:          "IK",
				Initiator:        true,
				StaticKey:        make([]byte, 32),
				RemoteKey:        make([]byte, 32),
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: false,
			description: "IK pattern with both keys",
		},
		{
			name: "Short static key",
			config: &ConnConfig{
				Pattern:          "XX",
				Initiator:        true,
				StaticKey:        make([]byte, 16), // Too short
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			description: "Should reject short static key",
		},
		{
			name: "Short remote key",
			config: &ConnConfig{
				Pattern:          "NK",
				Initiator:        true,
				RemoteKey:        make([]byte, 16), // Too short
				HandshakeTimeout: 30 * time.Second,
			},
			shouldError: true,
			description: "Should reject short remote key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.shouldError && err == nil {
				t.Errorf("Expected validation error for %s, but got none", tt.description)
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected validation error for %s: %v", tt.description, err)
			}
		})
	}
}

func TestConnConfig_ModifierMethods(t *testing.T) {
	// Create test modifiers
	mod1 := &testHandshakeModifier{name: "modifier1"}
	mod2 := &testHandshakeModifier{name: "modifier2"}
	mod3 := &testHandshakeModifier{name: "modifier3"}

	t.Run("WithModifiers", func(t *testing.T) {
		config := NewConnConfig("XX", true).WithModifiers(mod1, mod2)

		if len(config.Modifiers) != 2 {
			t.Errorf("WithModifiers() count = %v, want %v", len(config.Modifiers), 2)
		}

		if config.Modifiers[0].Name() != "modifier1" {
			t.Errorf("WithModifiers()[0] = %v, want %v", config.Modifiers[0].Name(), "modifier1")
		}

		if config.Modifiers[1].Name() != "modifier2" {
			t.Errorf("WithModifiers()[1] = %v, want %v", config.Modifiers[1].Name(), "modifier2")
		}
	})

	t.Run("WithModifiers independence", func(t *testing.T) {
		modifiers := []handshake.HandshakeModifier{mod1, mod2}
		config := NewConnConfig("XX", true).WithModifiers(modifiers...)

		// Modify original slice
		modifiers[0] = mod3

		// Config should be unaffected
		if config.Modifiers[0].Name() != "modifier1" {
			t.Error("Config was affected by external modification of modifiers slice")
		}
	})

	t.Run("AddModifier", func(t *testing.T) {
		config := NewConnConfig("XX", true).
			WithModifiers(mod1).
			AddModifier(mod2).
			AddModifier(mod3)

		if len(config.Modifiers) != 3 {
			t.Errorf("AddModifier() count = %v, want %v", len(config.Modifiers), 3)
		}

		expected := []string{"modifier1", "modifier2", "modifier3"}
		for i, modifier := range config.Modifiers {
			if modifier.Name() != expected[i] {
				t.Errorf("AddModifier()[%d] = %v, want %v", i, modifier.Name(), expected[i])
			}
		}
	})

	t.Run("ClearModifiers", func(t *testing.T) {
		config := NewConnConfig("XX", true).
			WithModifiers(mod1, mod2, mod3).
			ClearModifiers()

		if len(config.Modifiers) != 0 {
			t.Errorf("ClearModifiers() count = %v, want %v", len(config.Modifiers), 0)
		}

		if config.Modifiers != nil {
			t.Error("ClearModifiers() should set Modifiers to nil")
		}
	})

	t.Run("GetModifierChain with modifiers", func(t *testing.T) {
		config := NewConnConfig("XX", true).WithModifiers(mod1, mod2)
		chain := config.GetModifierChain()

		if chain == nil {
			t.Error("GetModifierChain() returned nil, expected chain")
		}

		if chain.Count() != 2 {
			t.Errorf("GetModifierChain().Count() = %v, want %v", chain.Count(), 2)
		}

		if chain.Name() != "config-chain" {
			t.Errorf("GetModifierChain().Name() = %v, want %v", chain.Name(), "config-chain")
		}
	})

	t.Run("GetModifierChain without modifiers", func(t *testing.T) {
		config := NewConnConfig("XX", true)
		chain := config.GetModifierChain()

		if chain != nil {
			t.Error("GetModifierChain() returned non-nil, expected nil")
		}
	})

	t.Run("Builder pattern chaining", func(t *testing.T) {
		config := NewConnConfig("XX", true).
			WithHandshakeTimeout(10*time.Second).
			WithModifiers(mod1, mod2).
			AddModifier(mod3).
			WithReadTimeout(5 * time.Second)

		if config.HandshakeTimeout != 10*time.Second {
			t.Errorf("Builder chaining broke HandshakeTimeout")
		}

		if len(config.Modifiers) != 3 {
			t.Errorf("Builder chaining broke modifiers count")
		}

		if config.ReadTimeout != 5*time.Second {
			t.Errorf("Builder chaining broke ReadTimeout")
		}
	})
}

// testHandshakeModifier is a simple test implementation for ConnConfig tests
type testHandshakeModifier struct {
	name string
}

func (thm *testHandshakeModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (thm *testHandshakeModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (thm *testHandshakeModifier) Name() string {
	return thm.name
}
