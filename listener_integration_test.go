package noise

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoiseListenerIntegration tests the complete listener workflow
func TestNoiseListenerIntegration(t *testing.T) {
	// Create a TCP listener
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	// Create static key for the listener
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	// Create noise listener configuration
	config := NewListenerConfig("NN").WithStaticKey(staticKey)

	// Create the noise listener
	noiseListener, err := NewNoiseListener(tcpListener, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	// Test that we can get the address
	addr := noiseListener.Addr()
	require.NotNil(t, addr)
	noiseAddr, ok := addr.(*NoiseAddr)
	require.True(t, ok)
	assert.Equal(t, "noise+tcp", noiseAddr.Network())
	assert.Contains(t, noiseAddr.String(), "NN")
	assert.Contains(t, noiseAddr.String(), "responder")

	// Test concurrent close operations are safe
	go func() {
		time.Sleep(10 * time.Millisecond)
		noiseListener.Close()
	}()

	// Accept should fail after the listener is closed
	_, err = noiseListener.Accept()
	assert.Error(t, err)

	// Verify listener is closed
	assert.True(t, noiseListener.isClosed())
}

// TestNoiseListenerWithDifferentPatterns tests that the listener works with different patterns
func TestNoiseListenerWithDifferentPatterns(t *testing.T) {
	patterns := []string{"NN", "XX", "NK", "XK"}

	for _, pattern := range patterns {
		t.Run(fmt.Sprintf("Pattern_%s", pattern), func(t *testing.T) {
			// Create a TCP listener
			tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer tcpListener.Close()

			// Create static key
			staticKey := make([]byte, 32)
			_, err = rand.Read(staticKey)
			require.NoError(t, err)

			// Create noise listener configuration
			config := NewListenerConfig(pattern).WithStaticKey(staticKey)

			// Create the noise listener
			noiseListener, err := NewNoiseListener(tcpListener, config)
			require.NoError(t, err)
			defer noiseListener.Close()

			// Verify the pattern is set correctly
			addr := noiseListener.Addr()
			noiseAddr, ok := addr.(*NoiseAddr)
			require.True(t, ok)
			assert.Contains(t, noiseAddr.String(), pattern)
		})
	}
}

// TestNoiseListenerLifecycle tests the complete lifecycle of a noise listener
func TestNoiseListenerLifecycle(t *testing.T) {
	// Create a TCP listener
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Don't defer close here since we'll close it explicitly

	// Create static key
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	// Create noise listener configuration with timeouts
	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	// Create the noise listener
	noiseListener, err := NewNoiseListener(tcpListener, config)
	require.NoError(t, err)

	// Test that listener is initially not closed
	assert.False(t, noiseListener.isClosed())

	// Test that we can get the address before closing
	addr := noiseListener.Addr()
	require.NotNil(t, addr)

	// Close the noise listener (this should also close the underlying listener)
	err = noiseListener.Close()
	assert.NoError(t, err)

	// Test that listener is now closed
	assert.True(t, noiseListener.isClosed())

	// Test that accept fails after close
	_, err = noiseListener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listener is closed")

	// Test that second close is idempotent
	err = noiseListener.Close()
	assert.NoError(t, err)
}

// TestNoiseListenerErrorHandling tests error handling in various scenarios
func TestNoiseListenerErrorHandling(t *testing.T) {
	// Test with a listener that will fail to accept
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Close the underlying listener before creating the noise listener
	tcpListener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("NN").WithStaticKey(staticKey)

	// This should still succeed because we don't test the underlying listener in NewNoiseListener
	noiseListener, err := NewNoiseListener(tcpListener, config)
	require.NoError(t, err)

	// But Accept should fail because the underlying listener is closed
	_, err = noiseListener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to accept underlying connection")

	// Close should still work
	err = noiseListener.Close()
	// This might error because the underlying listener is already closed, but that's OK
	// The important thing is that our listener state is updated correctly
	assert.True(t, noiseListener.isClosed())
}

// TestNoiseListenerNetListenerInterface verifies that NoiseListener implements net.Listener correctly
func TestNoiseListenerNetListenerInterface(t *testing.T) {
	// Create a TCP listener
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	// Create static key
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	// Create noise listener configuration
	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	// Create the noise listener
	noiseListener, err := NewNoiseListener(tcpListener, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	// Verify it implements net.Listener
	var _ net.Listener = noiseListener

	// Test the interface methods
	addr := noiseListener.Addr()
	assert.NotNil(t, addr)
	assert.Implements(t, (*net.Addr)(nil), addr)

	// Test that Close is idempotent (interface requirement)
	err1 := noiseListener.Close()
	err2 := noiseListener.Close()
	assert.NoError(t, err1)
	assert.NoError(t, err2)
}
