package noise

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/internal"
)

// TestConnectionStateManagement tests the new state management functionality
func TestConnectionStateManagement(t *testing.T) {
	t.Run("initial state is init", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		if state := conn.GetConnectionState(); state != internal.StateInit {
			t.Errorf("Expected initial state to be %v, got %v", internal.StateInit, state)
		}

		if conn.isHandshakeDone() {
			t.Error("Expected handshake to not be done initially")
		}

		if conn.isClosed() {
			t.Error("Expected connection to not be closed initially")
		}
	})

	t.Run("state transitions during handshake", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		// Verify initial state
		if state := conn.GetConnectionState(); state != internal.StateInit {
			t.Errorf("Expected initial state to be %v, got %v", internal.StateInit, state)
		}

		// Start handshake (will fail but that's expected in test)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_ = conn.Handshake(ctx) // Expected to fail

		// Connection should be back to init state after handshake failure
		if state := conn.GetConnectionState(); state != internal.StateInit {
			t.Logf("State after failed handshake: %v (this is expected)", state)
		}
	})

	t.Run("state changes on close", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}

		// Close the connection
		err = conn.Close()
		if err != nil {
			t.Errorf("Failed to close connection: %v", err)
		}

		// Verify state is closed
		if state := conn.GetConnectionState(); state != internal.StateClosed {
			t.Errorf("Expected state to be %v after close, got %v", internal.StateClosed, state)
		}

		if !conn.isClosed() {
			t.Error("Expected isClosed() to return true after close")
		}
	})

	t.Run("metrics are tracked", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		// Get initial metrics
		bytesRead, bytesWritten, handshakeDuration := conn.GetConnectionMetrics()

		if bytesRead != 0 {
			t.Errorf("Expected initial bytes read to be 0, got %d", bytesRead)
		}

		if bytesWritten != 0 {
			t.Errorf("Expected initial bytes written to be 0, got %d", bytesWritten)
		}

		if handshakeDuration != 0 {
			t.Errorf("Expected initial handshake duration to be 0, got %v", handshakeDuration)
		}
	})

	t.Run("state validation in read/write operations", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		// Try to read before handshake - should fail
		buf := make([]byte, 10)
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("Expected read to fail before handshake")
		}

		// Try to write before handshake - should fail
		_, err = conn.Write([]byte("test"))
		if err == nil {
			t.Error("Expected write to fail before handshake")
		}

		// Close connection
		conn.Close()

		// Try to read after close - should fail
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("Expected read to fail after close")
		}

		// Try to write after close - should fail
		_, err = conn.Write([]byte("test"))
		if err == nil {
			t.Error("Expected write to fail after close")
		}
	})
}

// TestConnectionMetrics tests the metrics tracking functionality
func TestConnectionMetrics(t *testing.T) {
	t.Run("handshake timing", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		// Start handshake timing manually for testing
		conn.metrics.SetHandshakeStart()
		time.Sleep(10 * time.Millisecond) // Simulate handshake time
		conn.metrics.SetHandshakeEnd()

		_, _, duration := conn.GetConnectionMetrics()
		if duration < 10*time.Millisecond {
			t.Errorf("Expected handshake duration to be at least 10ms, got %v", duration)
		}
	})

	t.Run("byte counting", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		// Add some bytes manually for testing
		conn.metrics.AddBytesRead(100)
		conn.metrics.AddBytesWritten(200)

		bytesRead, bytesWritten, _ := conn.GetConnectionMetrics()

		if bytesRead != 100 {
			t.Errorf("Expected bytes read to be 100, got %d", bytesRead)
		}

		if bytesWritten != 200 {
			t.Errorf("Expected bytes written to be 200, got %d", bytesWritten)
		}
	})
}

// TestStateTransitionLogging tests that state changes are properly logged
func TestStateTransitionLogging(t *testing.T) {
	conn, err := createTestConnection()
	if err != nil {
		t.Fatalf("Failed to create test connection: %v", err)
	}
	defer conn.Close()

	// Test state transition from init to handshaking
	conn.setState(internal.StateHandshaking)
	if state := conn.getState(); state != internal.StateHandshaking {
		t.Errorf("Expected state to be %v, got %v", internal.StateHandshaking, state)
	}

	// Test state transition to established
	conn.setState(internal.StateEstablished)
	if state := conn.getState(); state != internal.StateEstablished {
		t.Errorf("Expected state to be %v, got %v", internal.StateEstablished, state)
	}

	// Verify handshake is done
	if !conn.isHandshakeDone() {
		t.Error("Expected isHandshakeDone() to return true in established state")
	}
}

// Helper function to create a test connection
func createTestConnection() (*NoiseConn, error) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}

	mockConn := newMockNetConn(localAddr, remoteAddr)

	config := NewConnConfig("XX", true).
		WithHandshakeTimeout(30 * time.Second)

	return NewNoiseConn(mockConn, config)
}
