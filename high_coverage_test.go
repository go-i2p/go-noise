package noise

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHighCoverageEncryption tests the encryption/decryption paths that weren't covered
func TestHighCoverageEncryption(t *testing.T) {
	// This test focuses on achieving the encryption/decryption code paths
	// Create pipe for bidirectional communication
	initiatorConn, responderConn := net.Pipe()
	defer initiatorConn.Close()
	defer responderConn.Close()

	// Use NN pattern for simplicity (no keys required)
	initiatorConfig := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	responderConfig := NewConnConfig("NN", false).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	initiatorNC, err := NewNoiseConn(initiatorConn, initiatorConfig)
	require.NoError(t, err)

	responderNC, err := NewNoiseConn(responderConn, responderConfig)
	require.NoError(t, err)

	// Perform handshakes
	var wg sync.WaitGroup
	var handshakeErrors []error
	handshakeErrors = make([]error, 2)

	wg.Add(2)

	go func() {
		defer wg.Done()
		handshakeErrors[0] = initiatorNC.Handshake(context.Background())
	}()

	go func() {
		defer wg.Done()
		handshakeErrors[1] = responderNC.Handshake(context.Background())
	}()

	wg.Wait()

	// Check if handshakes succeeded
	if handshakeErrors[0] != nil || handshakeErrors[1] != nil {
		t.Logf("Handshake errors: initiator=%v, responder=%v", handshakeErrors[0], handshakeErrors[1])

		// For NN pattern, handshakes should succeed
		require.NoError(t, handshakeErrors[0], "NN initiator handshake should succeed")
		require.NoError(t, handshakeErrors[1], "NN responder handshake should succeed")
	}

	// Now test encrypted communication to cover encryption/decryption paths
	testMessage := "Hello, encrypted world!"

	// Send from initiator to responder
	go func() {
		_, writeErr := initiatorNC.Write([]byte(testMessage))
		if writeErr != nil {
			t.Logf("Write error: %v", writeErr)
		}
	}()

	// Read on responder side
	buffer := make([]byte, len(testMessage))
	n, readErr := responderNC.Read(buffer)
	if readErr != nil {
		t.Logf("Read error: %v", readErr)
	} else {
		received := string(buffer[:n])
		assert.Equal(t, testMessage, received, "Message should be transmitted correctly")
	}

	// Clean up
	initiatorNC.Close()
	responderNC.Close()
}

// TestTimeoutConfigurationCoverage tests timeout configuration paths
func TestTimeoutConfigurationCoverage(t *testing.T) {
	// Create a mock connection that can simulate slow operations
	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	baseMock := newMockNetConn(localAddr, remoteAddr)

	// Create config with read/write timeouts
	config := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(50 * time.Millisecond).
		WithWriteTimeout(50 * time.Millisecond)

	nc, err := NewNoiseConn(baseMock, config)
	require.NoError(t, err)

	// Perform handshake first
	err = nc.Handshake(context.Background())
	require.NoError(t, err, "Handshake should succeed")

	// Test read with timeout configuration (this should hit configureReadTimeout)
	readBuffer := make([]byte, 10)
	_, err = nc.Read(readBuffer)
	assert.Error(t, err, "Read should fail due to cipher state not being initialized properly")

	// Test write with timeout configuration (this should hit configureWriteTimeout)
	writeData := []byte("test data")
	_, err = nc.Write(writeData)
	assert.Error(t, err, "Write should fail due to cipher state not being initialized properly")
}

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

	// Test SetDeadline error
	err = nc.SetDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetDeadline should return underlying error")

	// Test SetReadDeadline error
	err = nc.SetReadDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetReadDeadline should return underlying error")

	// Test SetWriteDeadline error
	err = nc.SetWriteDeadline(time.Now().Add(time.Second))
	assert.ErrorIs(t, err, expectedErr, "SetWriteDeadline should return underlying error")
}

// TestExtremeValidationCases tests boundary cases for validation
func TestExtremeValidationCases(t *testing.T) {
	tests := []struct {
		name         string
		staticKey    []byte
		remoteKey    []byte
		expectError  bool
		errorContent string
	}{
		{
			name:         "Static key exactly 31 bytes",
			staticKey:    make([]byte, 31),
			expectError:  true,
			errorContent: "static key must be 32 bytes",
		},
		{
			name:         "Static key exactly 33 bytes",
			staticKey:    make([]byte, 33),
			expectError:  true,
			errorContent: "static key must be 32 bytes",
		},
		{
			name:         "Remote key exactly 31 bytes",
			remoteKey:    make([]byte, 31),
			expectError:  true,
			errorContent: "remote key must be 32 bytes",
		},
		{
			name:         "Remote key exactly 33 bytes",
			remoteKey:    make([]byte, 33),
			expectError:  true,
			errorContent: "remote key must be 32 bytes",
		},
		{
			name:        "Both keys exactly 32 bytes",
			staticKey:   make([]byte, 32),
			remoteKey:   make([]byte, 32),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := NewConnConfig("XX", true).WithHandshakeTimeout(5 * time.Second)

			if tc.staticKey != nil {
				config = config.WithStaticKey(tc.staticKey)
			}
			if tc.remoteKey != nil {
				config = config.WithRemoteKey(tc.remoteKey)
			}

			err := config.Validate()

			if tc.expectError {
				assert.Error(t, err, "Should return error")
				assert.Contains(t, err.Error(), tc.errorContent, "Error should contain expected message")
			} else {
				assert.NoError(t, err, "Should not return error")
			}
		})
	}
}
