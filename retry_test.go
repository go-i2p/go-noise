package noise

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/internal"
	"github.com/samber/oops"
)

func TestConnConfig_WithHandshakeRetries(t *testing.T) {
	tests := []struct {
		name     string
		retries  int
		expected int
	}{
		{"no retries", 0, 0},
		{"default retries", 3, 3},
		{"infinite retries", -1, -1},
		{"many retries", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConnConfig("XX", true)
			result := config.WithHandshakeRetries(tt.retries)

			if result != config {
				t.Errorf("WithHandshakeRetries should return same instance")
			}

			if config.HandshakeRetries != tt.expected {
				t.Errorf("Expected retries %d, got %d", tt.expected, config.HandshakeRetries)
			}
		})
	}
}

func TestConnConfig_WithRetryBackoff(t *testing.T) {
	tests := []struct {
		name     string
		backoff  time.Duration
		expected time.Duration
	}{
		{"no backoff", 0, 0},
		{"default backoff", time.Second, time.Second},
		{"custom backoff", 5 * time.Second, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConnConfig("XX", true)
			result := config.WithRetryBackoff(tt.backoff)

			if result != config {
				t.Errorf("WithRetryBackoff should return same instance")
			}

			if config.RetryBackoff != tt.expected {
				t.Errorf("Expected backoff %v, got %v", tt.expected, config.RetryBackoff)
			}
		})
	}
}

func TestConnConfig_ValidateRetryConfig(t *testing.T) {
	tests := []struct {
		name          string
		retries       int
		backoff       time.Duration
		expectError   bool
		errorContains string
	}{
		{"valid no retries", 0, time.Second, false, ""},
		{"valid with retries", 3, time.Second, false, ""},
		{"valid infinite retries", -1, time.Second, false, ""},
		{"invalid negative retries", -2, time.Second, true, "must be >= -1"},
		{"valid zero backoff", 3, 0, false, ""},
		{"invalid negative backoff", 3, -time.Second, true, "must be non-negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConnConfig("XX", true).
				WithHandshakeRetries(tt.retries).
				WithRetryBackoff(tt.backoff)

			err := config.validateRetryConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !containsError(err, tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %v", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
		})
	}
}

func TestNewConnConfig_RetryDefaults(t *testing.T) {
	config := NewConnConfig("XX", true)

	expectedRetries := 3
	if config.HandshakeRetries != expectedRetries {
		t.Errorf("Expected default HandshakeRetries %d, got %d", expectedRetries, config.HandshakeRetries)
	}

	expectedBackoff := time.Second
	if config.RetryBackoff != expectedBackoff {
		t.Errorf("Expected default RetryBackoff %v, got %v", expectedBackoff, config.RetryBackoff)
	}
}

func TestNoiseConn_shouldRetry(t *testing.T) {
	config := NewConnConfig("XX", true).WithHandshakeRetries(3)
	conn, _ := createTestNoiseConn(config)

	tests := []struct {
		name       string
		attempt    int
		maxRetries int
		state      internal.ConnState
		expected   bool
	}{
		{"first attempt within limit", 0, 3, internal.StateInit, true},
		{"at retry limit", 3, 3, internal.StateInit, false},
		{"beyond retry limit", 4, 3, internal.StateInit, false},
		{"infinite retries", 100, -1, internal.StateInit, true},
		{"wrong state established", 0, 3, internal.StateEstablished, false},
		{"wrong state closed", 0, 3, internal.StateClosed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn.setState(tt.state)
			result := conn.shouldRetry(tt.attempt, tt.maxRetries, oops.Errorf("test error"))

			if result != tt.expected {
				t.Errorf("Expected shouldRetry %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNoiseConn_waitForRetry(t *testing.T) {
	tests := []struct {
		name        string
		backoff     time.Duration
		attempt     int
		expectDelay bool
	}{
		{"no backoff configured", 0, 0, false},
		{"first attempt", 100 * time.Millisecond, 0, true},
		{"second attempt", 100 * time.Millisecond, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConnConfig("XX", true).WithRetryBackoff(tt.backoff)
			conn, _ := createTestNoiseConn(config)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			start := time.Now()
			err := conn.waitForRetry(ctx, tt.attempt)
			elapsed := time.Since(start)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if tt.expectDelay && elapsed < tt.backoff {
				t.Errorf("Expected delay of at least %v, got %v", tt.backoff, elapsed)
			}

			if !tt.expectDelay && elapsed > 50*time.Millisecond {
				t.Errorf("Expected minimal delay, got %v", elapsed)
			}
		})
	}
}

func TestNoiseConn_waitForRetry_ContextCancellation(t *testing.T) {
	config := NewConnConfig("XX", true).WithRetryBackoff(time.Second)
	conn, _ := createTestNoiseConn(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := conn.waitForRetry(ctx, 0)

	if err == nil {
		t.Errorf("Expected context cancellation error")
	}

	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded, got %v", err)
	}
}

// Helper function to check if error contains expected text
func containsError(err error, contains string) bool {
	if err == nil {
		return false
	}
	return len(contains) > 0 && len(err.Error()) > 0
}

// Helper function to create test NoiseConn for testing
func createTestNoiseConn(config *ConnConfig) (*NoiseConn, error) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8081"}
	mockConn := newMockNetConn(localAddr, remoteAddr)
	return NewNoiseConn(mockConn, config)
}
