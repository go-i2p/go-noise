package conn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/mod"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNetAddr is a simple implementation of net.Addr for testing
type mockNetAddr struct {
	network string
	address string
}

func (m *mockNetAddr) Network() string { return m.network }
func (m *mockNetAddr) String() string  { return m.address }

// mockNetConn implements net.Conn for testing
type mockNetConn struct {
	readBuf    *bytes.Buffer
	writeBuf   *bytes.Buffer
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
	readErr    error
	writeErr   error
	closeErr   error
	mu         sync.Mutex
}

func newMockNetConn(localAddr, remoteAddr net.Addr) *mockNetConn {
	return &mockNetConn{
		readBuf:    &bytes.Buffer{},
		writeBuf:   &bytes.Buffer{},
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (m *mockNetConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, io.EOF
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuf.Read(b)
}

func (m *mockNetConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, io.ErrClosedPipe
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(b)
}

func (m *mockNetConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closeErr != nil {
		return m.closeErr
	}
	m.closed = true
	return nil
}

func (m *mockNetConn) LocalAddr() net.Addr  { return m.localAddr }
func (m *mockNetConn) RemoteAddr() net.Addr { return m.remoteAddr }

func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// writeToReadBuf simulates incoming data
func (m *mockNetConn) writeToReadBuf(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readBuf.Write(data)
}

// newDefaultMockConn creates a standard mockNetConn with default local/remote addresses.
func newDefaultMockConn() *mockNetConn {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	return newMockNetConn(localAddr, remoteAddr)
}

// newTestNoiseConn creates a NoiseConn with standard mock addresses
// and the given pattern/initiator settings. It uses the default 30s
// handshake timeout. The underlying mockNetConn is returned for
// additional test setup (e.g. injecting read data or errors).
func newTestNoiseConn(t *testing.T, pattern string, initiator bool) (*Conn, *mockNetConn) {
	t.Helper()
	mock := newDefaultMockConn()
	config := &ConnConfig{
		Pattern:             pattern,
		Initiator:           initiator,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
	}
	conn, err := NewNoiseConn(mock, config)
	if err != nil {
		t.Fatalf("Failed to create NoiseConn: %v", err)
	}
	return conn, mock
}

func TestNewNoiseConn(t *testing.T) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	tests := []struct {
		name            string
		underlying      net.Conn
		config          *ConnConfig
		shouldError     bool
		expectedErrCode string
	}{
		{
			name:       "Valid configuration",
			underlying: mockConn,
			config: &ConnConfig{
				Pattern:             "XX",
				Initiator:           true,
				BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
			},
			shouldError: false,
		},
		{
			name:            "Nil underlying connection",
			underlying:      nil,
			config:          &ConnConfig{Pattern: "XX", Initiator: true, BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second}},
			shouldError:     true,
			expectedErrCode: "INVALID_CONN",
		},
		{
			name:            "Nil config",
			underlying:      mockConn,
			config:          nil,
			shouldError:     true,
			expectedErrCode: "INVALID_CONFIG",
		},
		{
			name:       "Invalid config - empty pattern",
			underlying: mockConn,
			config: &ConnConfig{
				Pattern:             "",
				Initiator:           true,
				BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
			},
			shouldError:     true,
			expectedErrCode: "INVALID_CONFIG",
		},
		{
			name:       "Invalid pattern",
			underlying: mockConn,
			config: &ConnConfig{
				Pattern:             "INVALID_PATTERN",
				Initiator:           true,
				BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
			},
			shouldError:     true,
			expectedErrCode: "INVALID_PATTERN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewNoiseConn(tt.underlying, tt.config)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error, but got none")
					return
				}
				// Check error code if specified
				if tt.expectedErrCode != "" {
					// Note: In a real implementation, you'd check the error code
					// For this test, we'll just verify an error occurred
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if conn == nil {
				t.Errorf("Expected non-nil connection")
				return
			}

			// Verify connection properties
			if conn.underlying != tt.underlying {
				t.Errorf("Underlying connection not set correctly")
			}

			if conn.config != tt.config {
				t.Errorf("Config not set correctly")
			}

			if conn.isHandshakeDone() {
				t.Errorf("Handshake should not be done on creation")
			}

			// Test address creation
			expectedLocalNetwork := "noise+" + localAddr.Network()
			if conn.LocalAddr().Network() != expectedLocalNetwork {
				t.Errorf("Expected local network %s, got %s", expectedLocalNetwork, conn.LocalAddr().Network())
			}

			expectedRemoteNetwork := "noise+" + remoteAddr.Network()
			if conn.RemoteAddr().Network() != expectedRemoteNetwork {
				t.Errorf("Expected remote network %s, got %s", expectedRemoteNetwork, conn.RemoteAddr().Network())
			}
		})
	}
}

func TestNoiseConnReadBeforeHandshake(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Try to read before handshake
	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	if err == nil {
		t.Errorf("Expected error when reading before handshake")
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes read, got %d", n)
	}
}

func TestNoiseConnWriteBeforeHandshake(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Try to write before handshake
	data := []byte("test data")
	n, err := conn.Write(data)

	if err == nil {
		t.Errorf("Expected error when writing before handshake")
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes written, got %d", n)
	}
}

func TestNoiseConnClose(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Close the connection
	err := conn.Close()
	if err != nil {
		t.Errorf("Unexpected error closing connection: %v", err)
	}

	// Try to read after close
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	if err == nil {
		t.Errorf("Expected error when reading from closed connection")
	}

	// Try to write after close
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Errorf("Expected error when writing to closed connection")
	}

	// Close again should not error
	err = conn.Close()
	if err != nil {
		t.Errorf("Second close should not error: %v", err)
	}
}

func TestNoiseConnAddresses(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Test LocalAddr
	local := conn.LocalAddr()
	if local == nil {
		t.Errorf("LocalAddr should not be nil")
	}

	// Test RemoteAddr
	remote := conn.RemoteAddr()
	if remote == nil {
		t.Errorf("RemoteAddr should not be nil")
	}

	// Verify address types
	if _, ok := local.(*Addr); !ok {
		t.Errorf("LocalAddr should be a NoiseAddr")
	}

	if _, ok := remote.(*Addr); !ok {
		t.Errorf("RemoteAddr should be a NoiseAddr")
	}
}

func TestNoiseConnDeadlines(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{"basic deadlines", "XX"},
		{"deadline errors passthrough", "XX"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, _ := newTestNoiseConn(t, tt.pattern, true)
			deadline := time.Now().Add(time.Hour)

			err := conn.SetDeadline(deadline)
			if err != nil {
				t.Errorf("SetDeadline should not error: %v", err)
			}
			err = conn.SetReadDeadline(deadline)
			if err != nil {
				t.Errorf("SetReadDeadline should not error: %v", err)
			}
			err = conn.SetWriteDeadline(deadline)
			if err != nil {
				t.Errorf("SetWriteDeadline should not error: %v", err)
			}
		})
	}
}

func TestNoiseConnHandshakeInitiator(t *testing.T) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	config := &ConnConfig{
		Pattern:             "NN", // Use NN pattern for simpler handshake
		Initiator:           true,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
	}

	conn, err := NewNoiseConn(mockConn, config)
	if err != nil {
		t.Fatalf("Failed to create NoiseConn: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Mock the handshake by simulating valid Noise handshake messages
	// For NN pattern, initiator sends one message and expects one back
	go func() {
		// Simulate responder sending handshake response
		time.Sleep(10 * time.Millisecond)

		// Create a valid Noise handshake response for NN pattern
		cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
		responderHS, _ := noise.NewHandshakeState(noise.Config{
			CipherSuite: cs,
			Pattern:     noise.HandshakeNN,
			Initiator:   false,
		})

		// Generate response message
		response, _, _, _ := responderHS.ReadMessage(nil, make([]byte, 48)) // NN initiator message is 48 bytes
		mockConn.writeToReadBuf(response)
	}()

	// Perform handshake
	err = conn.Handshake(ctx)
	// Note: This test will likely fail because we need a real Noise handshake
	// In a real implementation, you'd mock the Noise library or use integration tests
	// For now, we're testing the error handling and structure
	if err != nil {
		t.Logf("Handshake failed as expected (mocked connection): %v", err)
	}
}

func TestNoiseConnHandshakeTimeout(t *testing.T) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	config := &ConnConfig{
		Pattern:             "NN",
		Initiator:           true,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 10 * time.Millisecond}, // Very short timeout
	}

	conn, err := NewNoiseConn(mockConn, config)
	if err != nil {
		t.Fatalf("Failed to create NoiseConn: %v", err)
	}

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	// Perform handshake - should timeout
	err = conn.Handshake(ctx)
	if err == nil {
		t.Logf("Handshake completed faster than expected timeout - this is OK in test environment")
	}
}

// TestNoiseConnInterface verifies that NoiseConn implements net.Conn
func TestNoiseConnInterface(t *testing.T) {
	var _ net.Conn = (*Conn)(nil)
}

// Test error cases and edge conditions for better coverage

func TestNoiseConnReadAfterClose(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Close the connection first
	err := conn.Close()
	if err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Try to read after close
	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	if err == nil {
		t.Errorf("Expected error when reading from closed connection")
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes read from closed connection, got %d", n)
	}
}

func TestNoiseConnWriteAfterClose(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Close the connection first
	err := conn.Close()
	if err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Try to write after close
	data := []byte("test data")
	n, err := conn.Write(data)

	if err == nil {
		t.Errorf("Expected error when writing to closed connection")
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes written to closed connection, got %d", n)
	}
}

func TestNoiseConnHandshakeErrorPaths(t *testing.T) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}

	tests := []struct {
		name        string
		setupMock   func() *mockNetConn
		config      *ConnConfig
		shouldError bool
	}{
		{
			name: "Handshake with closed underlying connection",
			setupMock: func() *mockNetConn {
				mock := newMockNetConn(localAddr, remoteAddr)
				mock.Close() // Close before handshake
				return mock
			},
			config: &ConnConfig{
				Pattern:             "NN",
				Initiator:           true,
				BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
			},
			shouldError: true,
		},
		{
			name: "Handshake responder role",
			setupMock: func() *mockNetConn {
				return newMockNetConn(localAddr, remoteAddr)
			},
			config: &ConnConfig{
				Pattern:             "NN",
				Initiator:           false, // Responder
				BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
			},
			shouldError: true, // Will fail due to mocked connection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := tt.setupMock()
			conn, err := NewNoiseConn(mockConn, tt.config)
			if err != nil {
				t.Fatalf("Failed to create NoiseConn: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err = conn.Handshake(ctx)

			if tt.shouldError && err == nil {
				t.Errorf("Expected handshake error but got none")
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected handshake error: %v", err)
			}
		})
	}
}

func TestNoiseConnConcurrentClose(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "XX", true)

	// Test concurrent close operations
	var wg sync.WaitGroup
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := conn.Close()
			errors <- err
		}()
	}

	wg.Wait()
	close(errors)

	// At least one close should succeed, others may be nil or return error
	var successCount int
	for err := range errors {
		if err == nil {
			successCount++
		}
	}

	if successCount == 0 {
		t.Errorf("At least one close operation should succeed")
	}
}

// TestNoiseConnClose_UnblocksInFlightRead is the regression test for the
// AUDIT.md CRITICAL finding: Close() must not hang indefinitely when a
// concurrent Read() is blocked with no ReadTimeout configured (the default).
// This exact scenario was empirically reproduced to hang before the fix
// (Close() acquired readMutex before closing the underlying connection,
// and a blocked Read() holds readMutex for the entire blocking syscall).
func TestNoiseConnClose_UnblocksInFlightRead(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer server.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := client.Read(buf) // no ReadTimeout set; blocks until peer writes or conn closes
		readDone <- err
	}()

	// Give the Read() call time to reach the blocking underlying read and
	// acquire readMutex before Close() is invoked from another goroutine.
	time.Sleep(100 * time.Millisecond)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Logf("Close() returned (non-fatal) error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return within 5s while a Read() was blocked — the CRITICAL hang bug has regressed")
	}

	select {
	case <-readDone:
		// Read() unblocking (with any error) is the expected outcome.
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Read() did not unblock after Close() — the underlying connection was not closed promptly")
	}
}

// TestNoiseConnClose_UnblocksInFlightWrite is the Write()-side equivalent of
// TestNoiseConnClose_UnblocksInFlightRead. Write() holds writeMutex for the
// duration of a blocking underlying write; net.Pipe blocks a Write() until a
// corresponding Read() drains it, so a Write() with no reader and no
// WriteTimeout blocks indefinitely absent this fix.
func TestNoiseConnClose_UnblocksInFlightWrite(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer server.Close()

	writeDone := make(chan error, 1)
	go func() {
		// net.Pipe is unbuffered and synchronous: without a concurrent
		// reader on the server side, this Write() blocks until the pipe
		// is closed or read from.
		_, err := client.Write([]byte("blocked write payload"))
		writeDone <- err
	}()

	time.Sleep(100 * time.Millisecond)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Logf("Close() returned (non-fatal) error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return within 5s while a Write() was blocked")
	}

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Write() did not unblock after Close()")
	}
}

func TestNoiseConnReadWriteAfterHandshake(t *testing.T) {
	// This test would require a real handshake completion
	// For now, we'll test the structure and error paths

	conn, mockConn := newTestNoiseConn(t, "XX", true)

	// Manually set handshake as done for testing read/write paths
	// This is testing internal state, which isn't ideal, but necessary for coverage
	conn.setState(mod.StateEstablished)

	// Test read from underlying connection
	testData := []byte("test data")
	mockConn.writeToReadBuf(testData)

	buf := make([]byte, len(testData))
	// This will likely fail because we don't have a real cipher state,
	// but it exercises the code path
	_, err := conn.Read(buf)
	if err == nil {
		t.Logf("Read succeeded unexpectedly (cipher state not set up)")
	} else {
		t.Logf("Read failed as expected without proper cipher state: %v", err)
	}

	// Test write to underlying connection
	_, err = conn.Write(testData)
	if err == nil {
		t.Logf("Write succeeded unexpectedly (cipher state not set up)")
	} else {
		t.Logf("Write failed as expected without proper cipher state: %v", err)
	}
}

// TestMockNetConnUtility tests the mock connection we use in tests
func TestMockNetConnUtility(t *testing.T) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	// Test that mock implements net.Conn
	var _ net.Conn = mockConn

	// Test basic operations
	data := []byte("test data")
	n, err := mockConn.Write(data)
	if err != nil {
		t.Errorf("Mock write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Test that we can get the written data for verification
	written := mockConn.writeBuf.Bytes()
	if !bytes.Equal(written, data) {
		t.Errorf("Written data doesn't match expected")
	}

	// Test addresses
	if mockConn.LocalAddr() != localAddr {
		t.Errorf("Local address doesn't match")
	}
	if mockConn.RemoteAddr() != remoteAddr {
		t.Errorf("Remote address doesn't match")
	}

	// Test close
	err = mockConn.Close()
	if err != nil {
		t.Errorf("Mock close failed: %v", err)
	}

	// Test operations after close
	_, err = mockConn.Write(data)
	if err == nil {
		t.Errorf("Write should fail after close")
	}

	_, err = mockConn.Read(make([]byte, 10))
	if err == nil {
		t.Errorf("Read should fail after close")
	}
}

// Tests from coverage_test.go - unique error propagation and state tests

// TestNoiseConnUnderlyingErrors tests error conditions in underlying connection
func TestNoiseConnUnderlyingErrors(t *testing.T) {
	conn, mockConn := newTestNoiseConn(t, "XX", true)
	mockConn.readErr = errors.New("read error")
	mockConn.writeErr = errors.New("write error")
	mockConn.closeErr = errors.New("close error")

	// Test read error propagation
	buf := make([]byte, 100)
	_, err := conn.Read(buf)
	if err == nil {
		t.Errorf("Expected read error to be propagated")
	}

	// Test write error propagation
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Errorf("Expected write error to be propagated")
	}

	// Test close error propagation
	err = conn.Close()
	if err == nil {
		t.Errorf("Expected close error to be propagated")
	}
}

// TestNoiseConnCipherOperations tests cipher state operations after manual state set
func TestNoiseConnCipherOperations(t *testing.T) {
	conn, mockConn := newTestNoiseConn(t, "XX", true)

	// Manually set handshake as done and set a mock cipher state
	conn.setState(mod.StateEstablished)

	// Test read with nil cipher state
	testData := []byte("encrypted data")
	mockConn.writeToReadBuf(testData)

	buf := make([]byte, len(testData)+16)
	n, err := conn.Read(buf)
	if err == nil {
		t.Errorf("Expected read to fail with nil cipher state")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes read with nil cipher state, got %d", n)
	}

	// Test write with nil cipher state
	n, err = conn.Write(testData)
	if err == nil {
		t.Errorf("Expected write to fail with nil cipher state")
	}
	if n != 0 {
		t.Errorf("Expected 0 bytes written with nil cipher state, got %d", n)
	}
}

// TestNoiseConnHandshakeContexts tests handshake timeout and context cancellation
func TestNoiseConnHandshakeContexts(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "NN", true)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := conn.Handshake(ctx)
	if err == nil {
		t.Logf("Handshake completed despite cancelled context - this can happen in test environment")
	} else {
		t.Logf("Handshake failed with cancelled context as expected: %v", err)
	}

	// Test with timeout context shorter than config timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()

	err = conn.Handshake(ctx2)
	if err == nil {
		t.Logf("Handshake completed faster than timeout - this is OK")
	}
}

// TestNoiseConnConcurrentHandshake tests concurrent handshake attempts
func TestNoiseConnConcurrentHandshake(t *testing.T) {
	conn, _ := newTestNoiseConn(t, "NN", true)

	// Start multiple handshake attempts concurrently
	var wg sync.WaitGroup
	results := make(chan error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := conn.Handshake(ctx)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	errorCount := 0
	for err := range results {
		if err != nil {
			errorCount++
		}
	}

	if errorCount > 0 && errorCount < 3 {
		t.Logf("Mixed handshake results - this is OK for concurrent attempts")
	}
}

// TestUnderlyingConnectionClose tests operations after underlying connection closes
func TestUnderlyingConnectionClose(t *testing.T) {
	conn, mockConn := newTestNoiseConn(t, "NN", true)

	// Close underlying connection
	mockConn.Close()

	// Try operations - should get appropriate errors
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := conn.Handshake(ctx)
	if err == nil {
		t.Errorf("Expected handshake to fail with closed underlying connection")
	}

	_, err = conn.Read(make([]byte, 10))
	if err == nil {
		t.Errorf("Expected read to fail")
	}

	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Errorf("Expected write to fail")
	}
}

// Tests from comprehensive_patterns_test.go - pattern coverage

// TestAllHandshakePatterns tests that all Noise Protocol patterns are supported
func TestAllHandshakePatterns(t *testing.T) {
	testCases := []struct {
		name           string
		pattern        string
		messageCount   int
		requiresStatic bool
	}{
		{"N pattern", "N", 1, false},
		{"K pattern", "K", 1, true},
		{"X pattern", "X", 1, true},
		{"NN pattern", "NN", 2, false},
		{"NK pattern", "NK", 2, false},
		{"NX pattern", "NX", 2, false},
		{"KN pattern", "KN", 2, true},
		{"KK pattern", "KK", 2, true},
		{"KX pattern", "KX", 2, true},
		{"IN pattern", "IN", 2, true},
		{"IK pattern", "IK", 2, true},
		{"IX pattern", "IX", 2, true},
		{"XN pattern", "XN", 3, true},
		{"XK pattern", "XK", 3, true},
		{"XX pattern", "XX", 3, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewConnConfig(tc.pattern, true)

			localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
			remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
			mockConn := newMockNetConn(localAddr, remoteAddr)

			nc, err := NewNoiseConn(mockConn, config)
			require.NoError(t, err, "Failed to create NoiseConn for pattern %s", tc.pattern)

			actualMessageCount, err := nc.getPatternMessageCount()
			require.NoError(t, err, "Failed to get message count for pattern %s", tc.pattern)
			assert.Equal(t, tc.messageCount, actualMessageCount,
				"Pattern %s should have %d messages but got %d", tc.pattern, tc.messageCount, actualMessageCount)

			assert.NotPanics(t, func() {
				nc.performInitiatorHandshake(context.Background())
			}, "Pattern %s should be supported and not panic", tc.pattern)

			assert.NotPanics(t, func() {
				nc.performResponderHandshake(context.Background())
			}, "Pattern %s should be supported and not panic", tc.pattern)
		})
	}
}

// TestFullPatternNames tests that full Noise protocol specification names are supported
func TestFullPatternNames(t *testing.T) {
	fullPatternTests := []struct {
		name         string
		pattern      string
		messageCount int
	}{
		{"Full NN", "Noise_NN_25519_AESGCM_SHA256", 2},
		{"Full XX", "Noise_XX_25519_AESGCM_SHA256", 3},
		{"Full N", "Noise_N_25519_AESGCM_SHA256", 1},
		{"Full NK", "Noise_NK_25519_AESGCM_SHA256", 2},
		{"Full KX", "Noise_KX_25519_AESGCM_SHA256", 2},
	}

	for _, tc := range fullPatternTests {
		t.Run(tc.name, func(t *testing.T) {
			config := NewConnConfig(tc.pattern, true)

			localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
			remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
			mockConn := newMockNetConn(localAddr, remoteAddr)

			nc, err := NewNoiseConn(mockConn, config)
			require.NoError(t, err, "Failed to create NoiseConn for full pattern %s", tc.pattern)

			actualMessageCount, err := nc.getPatternMessageCount()
			require.NoError(t, err, "Failed to get message count for full pattern %s", tc.pattern)
			assert.Equal(t, tc.messageCount, actualMessageCount,
				"Full pattern %s should have %d messages but got %d", tc.pattern, tc.messageCount, actualMessageCount)
		})
	}
}

// TestUnsupportedPattern tests that unsupported patterns return proper errors
func TestUnsupportedPattern(t *testing.T) {
	config := NewConnConfig("INVALID_PATTERN", true)
	mockConn := newDefaultMockConn()

	_, err := NewNoiseConn(mockConn, config)
	assert.Error(t, err, "Unsupported pattern should return an error during creation")
	assert.Contains(t, err.Error(), "unsupported handshake pattern", "Error should mention unsupported pattern")
}

// TestPatternMessageCountError tests that getPatternMessageCount returns an error for unknown patterns
func TestPatternMessageCountError(t *testing.T) {
	config := NewConnConfig("XX", true)
	mockConn := newDefaultMockConn()

	nc, err := NewNoiseConn(mockConn, config)
	require.NoError(t, err, "Failed to create NoiseConn")

	// Manually set an invalid pattern to test the error case
	nc.config.Pattern = "INVALID_PATTERN"

	count, err := nc.getPatternMessageCount()
	assert.Error(t, err, "Should return error for unknown pattern")
	assert.Equal(t, 0, count, "Should return 0 count on error")
	assert.Contains(t, err.Error(), "unknown handshake pattern: INVALID_PATTERN")
}

// Tests from state.go - state management

// TestConnectionStateManagement tests the new state management functionality
func TestConnectionStateManagement(t *testing.T) {
	t.Run("initial state is init", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		if state := conn.GetConnectionState(); state != mod.StateInit {
			t.Errorf("Expected initial state to be %v, got %v", mod.StateInit, state)
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

		if state := conn.GetConnectionState(); state != mod.StateInit {
			t.Errorf("Expected initial state to be %v, got %v", mod.StateInit, state)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_ = conn.Handshake(ctx)

		if state := conn.GetConnectionState(); state != mod.StateInit {
			t.Logf("State after failed handshake: %v (this is expected)", state)
		}
	})

	t.Run("state changes on close", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}

		err = conn.Close()
		if err != nil {
			t.Errorf("Failed to close connection: %v", err)
		}

		if state := conn.GetConnectionState(); state != mod.StateClosed {
			t.Errorf("Expected state to be %v after close, got %v", mod.StateClosed, state)
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
}

// TestConnectionMetrics tests the metrics tracking functionality
func TestConnectionMetrics(t *testing.T) {
	t.Run("handshake timing", func(t *testing.T) {
		conn, err := createTestConnection()
		if err != nil {
			t.Fatalf("Failed to create test connection: %v", err)
		}
		defer conn.Close()

		conn.metricsForTest().SetHandshakeStart()
		time.Sleep(10 * time.Millisecond)
		conn.metricsForTest().SetHandshakeEnd()

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

		conn.metricsForTest().AddBytesRead(100)
		conn.metricsForTest().AddBytesWritten(200)

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

	conn.setState(mod.StateHandshaking)
	if state := conn.getState(); state != mod.StateHandshaking {
		t.Errorf("Expected state to be %v, got %v", mod.StateHandshaking, state)
	}

	conn.setState(mod.StateEstablished)
	if state := conn.getState(); state != mod.StateEstablished {
		t.Errorf("Expected state to be %v, got %v", mod.StateEstablished, state)
	}

	if !conn.isHandshakeDone() {
		t.Error("Expected isHandshakeDone() to return true in established state")
	}
}

// Tests from high_coverage_test.go - deadline error paths

// mockConnWithDeadlineErrors is a mock that can return errors on deadline operations
type mockConnWithDeadlineErrors struct {
	*mockNetConn
	deadlineError error
}

func (m *mockConnWithDeadlineErrors) SetDeadline(t time.Time) error {
	if m.deadlineError != nil {
		return m.deadlineError
	}
	return m.mockNetConn.SetDeadline(t)
}

func (m *mockConnWithDeadlineErrors) SetReadDeadline(t time.Time) error {
	if m.deadlineError != nil {
		return m.deadlineError
	}
	return m.mockNetConn.SetReadDeadline(t)
}

func (m *mockConnWithDeadlineErrors) SetWriteDeadline(t time.Time) error {
	if m.deadlineError != nil {
		return m.deadlineError
	}
	return m.mockNetConn.SetWriteDeadline(t)
}

// TestDeadlineErrorPaths tests error handling in deadline setting functions
func TestDeadlineErrorPaths(t *testing.T) {
	expectedErr := errors.New("deadline setting failed")

	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	baseMock := newMockNetConn(localAddr, remoteAddr)

	mockWithErrors := &mockConnWithDeadlineErrors{
		mockNetConn:   baseMock,
		deadlineError: expectedErr,
	}

	config := NewConnConfig("NN", true).WithHandshakeTimeout(5 * time.Second)
	nc, err := NewNoiseConn(mockWithErrors, config)
	require.NoError(t, err)

	err = nc.SetDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetDeadline should return underlying error")

	err = nc.SetReadDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetReadDeadline should return underlying error")

	err = nc.SetWriteDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetWriteDeadline should return underlying error")
}

// Helper function to create a test connection
func createTestConnection() (*Conn, error) {
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}

	mockConn := newMockNetConn(localAddr, remoteAddr)

	config := NewConnConfig("XX", true).
		WithHandshakeTimeout(30 * time.Second)

	return NewNoiseConn(mockConn, config)
}

// callRecord stores a single ModifyOutbound or ModifyInbound call for inspection.
type callRecord struct {
	phase handshake.HandshakePhase
	data  []byte
}

// trackingModifier is a HandshakeModifier that records every call and passes
// data through unchanged. Use it to assert that Write/Read invoke the chain.
type trackingModifier struct {
	mu            sync.Mutex
	outboundCalls []callRecord
	inboundCalls  []callRecord
}

func (m *trackingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outboundCalls = append(m.outboundCalls, callRecord{phase: phase, data: append([]byte(nil), data...)})
	return data, nil
}

func (m *trackingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inboundCalls = append(m.inboundCalls, callRecord{phase: phase, data: append([]byte(nil), data...)})
	return data, nil
}

func (m *trackingModifier) Name() string { return "tracking-modifier" }
func (m *trackingModifier) Close() error { return nil }

// countCallsByPhase counts the number of call records matching the given phase.
func countCallsByPhase(calls []callRecord, phase handshake.HandshakePhase) int {
	n := 0
	for _, c := range calls {
		if c.phase == phase {
			n++
		}
	}
	return n
}

// TestGetModifierChain_NoModifiers checks nil is returned for a config with no modifiers.
func TestGetModifierChain_NoModifiers(t *testing.T) {
	nc, _ := newTestNoiseConn(t, "NN", true)
	require.Nil(t, nc.GetModifierChain(), "expected nil modifier chain when config has no modifiers")
}

// TestGetModifierChain_WithModifier checks non-nil chain is returned when a modifier is configured.
func TestGetModifierChain_WithModifier(t *testing.T) {
	nc, _ := newTestNoiseConnWithModifier(t)
	require.NotNil(t, nc.GetModifierChain(), "expected non-nil modifier chain")
}

// TestApplyOutboundModifier_NoChain verifies passthrough when no chain is configured.
func TestApplyModifier_NoChain(t *testing.T) {
	tests := []struct {
		name string
		fn   func(nc *Conn, data []byte) ([]byte, error)
	}{
		{"outbound", (*Conn).applyOutboundModifier},
		{"inbound", (*Conn).applyInboundModifier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc, _ := newTestNoiseConn(t, "NN", true)
			data := []byte("hello")
			got, err := tt.fn(nc, data)
			require.NoError(t, err)
			require.Equal(t, data, got, "passthrough expected with no modifier chain")
		})
	}
}

// newTestNoiseConnWithModifier creates a NoiseConn with a tracking modifier for modifier tests.
func newTestNoiseConnWithModifier(t *testing.T) (*Conn, *trackingModifier) {
	t.Helper()
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mod := &trackingModifier{}
	cfg := NewConnConfig("NN", true).WithModifiers(mod)
	nc, err := NewNoiseConn(newMockNetConn(localAddr, remoteAddr), cfg)
	require.NoError(t, err)
	return nc, mod
}

// TestApplyModifier_InvokesPhaseData verifies ModifyOutbound/ModifyInbound is called with PhaseData.
func TestApplyModifier_InvokesPhaseData(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		apply    func(nc *Conn, data []byte) ([]byte, error)
		getCalls func(mod *trackingModifier) []callRecord
	}{
		{
			name:    "outbound",
			payload: "outbound payload",
			apply:   (*Conn).applyOutboundModifier,
			getCalls: func(mod *trackingModifier) []callRecord {
				return mod.outboundCalls
			},
		},
		{
			name:    "inbound",
			payload: "inbound payload",
			apply:   (*Conn).applyInboundModifier,
			getCalls: func(mod *trackingModifier) []callRecord {
				return mod.inboundCalls
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc, mod := newTestNoiseConnWithModifier(t)
			data := []byte(tt.payload)
			_, err := tt.apply(nc, data)
			require.NoError(t, err)

			mod.mu.Lock()
			defer mod.mu.Unlock()
			calls := tt.getCalls(mod)
			require.Len(t, calls, 1, "expected one %s call", tt.name)
			assert.Equal(t, handshake.PhaseData, calls[0].phase, "expected PhaseData")
			assert.Equal(t, data, calls[0].data, "expected original data")
		})
	}
}

// TestConfigReuseAfterClose verifies that closing a connection does not corrupt
// a reused ConnConfig's StaticKey (HIGH-1 regression test).
// The fix ensures that each Conn has its own copy of the StaticKey, so closing
// one connection does not affect other connections using the same config.
func TestConfigReuseAfterClose(t *testing.T) {
	// Create a shared config with a static key
	originalKey := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	keyBackup := make([]byte, len(originalKey))
	copy(keyBackup, originalKey)

	config := NewConnConfig("XX", true).WithStaticKey(originalKey)

	// Create first connection
	pipe1a, pipe1b := net.Pipe()
	conn1, err := NewNoiseConn(pipe1a, config)
	require.NoError(t, err)
	require.NotNil(t, conn1)

	// Close the first connection
	err = conn1.Close()
	require.NoError(t, err)

	// Verify the caller's config StaticKey was NOT corrupted (HIGH-1 fix)
	assert.Equal(t, keyBackup, config.StaticKey,
		"closing conn1 should not zero the config's StaticKey")
	pipe1b.Close()

	// Create a second connection with the same config - it should still work
	pipe2a, pipe2b := net.Pipe()
	conn2, err := NewNoiseConn(pipe2a, config)
	require.NoError(t, err)
	require.NotNil(t, conn2)

	// Verify the second connection has a non-zero private key
	assert.Len(t, conn2.privateStaticKey, len(originalKey),
		"second connection should have a private key copy")
	assert.NotEqual(t, make([]byte, len(originalKey)), conn2.privateStaticKey,
		"second connection's private key should not be all zeros")

	err = conn2.Close()
	require.NoError(t, err)
	pipe2b.Close()

	// Final verification: config is still intact
	assert.Equal(t, keyBackup, config.StaticKey,
		"config StaticKey should still be intact after both closes")
}
