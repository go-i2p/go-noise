package noise

import (
	"context"
	"testing"
	"time"
)

func TestDialNoiseWithHandshake(t *testing.T) {
	// This is an integration test that would require a real server
	// For now, we'll test that the function exists and handles validation correctly

	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ConnConfig
		expectError bool
	}{
		{
			name:        "invalid network",
			network:     "",
			addr:        "localhost:8080",
			config:      NewConnConfig("XX", true),
			expectError: true,
		},
		{
			name:        "invalid address",
			network:     "tcp",
			addr:        "",
			config:      NewConnConfig("XX", true),
			expectError: true,
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "localhost:8080",
			config:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialNoiseWithHandshake(tt.network, tt.addr, tt.config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err == nil {
				t.Errorf("Expected connection establishment to fail due to no server, but validation passed")
			}
		})
	}
}

func TestDialNoiseWithHandshakeContext(t *testing.T) {
	config := NewConnConfig("XX", true)

	// Test context cancellation during dial
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Use a non-existent address to ensure dial will fail
	_, err := DialNoiseWithHandshakeContext(ctx, "tcp", "127.0.0.1:65535", config)
	if err == nil {
		t.Errorf("Expected dial error for non-existent address")
	}
}

func TestDialNoiseWithPoolAndHandshake(t *testing.T) {
	// Test parameter validation for pool-enabled dial
	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ConnConfig
		expectError bool
	}{
		{
			name:        "dial fails to non-existent address",
			network:     "tcp",
			addr:        "127.0.0.1:65535", // Non-existent port
			config:      NewConnConfig("XX", true),
			expectError: true, // Will fail on dial
		},
		{
			name:        "invalid config",
			network:     "tcp",
			addr:        "localhost:8080",
			config:      NewConnConfig("", true), // Invalid pattern
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialNoiseWithPoolAndHandshake(tt.network, tt.addr, tt.config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
		})
	}
}

func TestCreatePoolAddr(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		addr     string
		pattern  string
		expected string
	}{
		{
			name:     "tcp connection",
			network:  "tcp",
			addr:     "localhost:8080",
			pattern:  "XX",
			expected: "tcp://localhost:8080/XX",
		},
		{
			name:     "udp connection",
			network:  "udp",
			addr:     "127.0.0.1:9090",
			pattern:  "NN",
			expected: "udp://127.0.0.1:9090/NN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createPoolAddr(tt.network, tt.addr, tt.pattern)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
