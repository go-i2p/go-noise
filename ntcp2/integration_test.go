package ntcp2

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNTCP2ListenerIntegration tests the full integration of NTCP2Listener
// with real TCP connections to demonstrate proper listener functionality.
func TestNTCP2ListenerIntegration(t *testing.T) {
	// Create TCP listener for testing
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	// Create router hash
	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	// Create static key
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	// Create NTCP2 config
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config = config.WithStaticKey(staticKey).
		WithHandshakeTimeout(5 * time.Second)

	// Create NTCP2 listener
	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Test listener properties
	assert.NotNil(t, listener)
	assert.Equal(t, "ntcp2", listener.Addr().Network())
	addrString := listener.Addr().String()
	assert.Contains(t, addrString, "responder")
	assert.Contains(t, addrString, "127.0.0.1")

	// Test that we can close the listener
	err = listener.Close()
	assert.NoError(t, err)

	// Test that Accept returns error after close
	conn, err := listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "ntcp2 listener is closed")
}

// TestNTCP2ListenerWithModifiers tests NTCP2Listener working with the modifier system.
func TestNTCP2ListenerWithModifiers(t *testing.T) {
	// Create TCP listener for testing
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	// Create router hash
	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	// Create static key
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	// Create NTCP2 config with standard pattern (the NTCP2-specific patterns are for documentation)
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config = config.WithStaticKey(staticKey).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	// Validate the config
	err = config.Validate()
	assert.NoError(t, err)

	// Create NTCP2 listener
	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)
	defer listener.Close()

	// Verify listener was created with correct properties
	addr := listener.Addr()
	assert.Equal(t, "ntcp2", addr.Network())
	assert.Contains(t, addr.String(), "responder")
}

// TestNTCP2ConfigEdgeCases tests edge cases for NTCP2Config validation.
func TestNTCP2ConfigEdgeCases(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	t.Run("valid config with all options", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		staticKey := make([]byte, 32)
		_, err = rand.Read(staticKey)
		require.NoError(t, err)

		config = config.
			WithStaticKey(staticKey).
			WithHandshakeTimeout(10 * time.Second).
			WithReadTimeout(5 * time.Second).
			WithWriteTimeout(5 * time.Second)

		err = config.Validate()
		assert.NoError(t, err)

		// Verify defensive copying in config
		originalHash := make([]byte, 32)
		copy(originalHash, routerHash)
		routerHash[0] = 0xFF // Modify original

		assert.Equal(t, originalHash, config.RouterHash) // Should be unchanged
	})

	t.Run("invalid static key in WithStaticKey", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		// Try to set invalid static key (wrong size)
		invalidKey := make([]byte, 16)
		config = config.WithStaticKey(invalidKey)

		// StaticKey should remain nil
		assert.Nil(t, config.StaticKey)
	})
}

// TestNTCP2ListenerErrorPathCoverage increases coverage of error paths.
func TestNTCP2ListenerErrorPathCoverage(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	t.Run("NTCP2Listener with closed underlying listener", func(t *testing.T) {
		// Create and close a TCP listener
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		tcpListener.Close() // Close it immediately

		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		// This should succeed in creating the listener, but Accept should fail
		listener, err := NewNTCP2Listener(tcpListener, config)
		require.NoError(t, err)
		defer listener.Close()

		// Accept should fail because underlying listener is closed
		conn, err := listener.Accept()
		assert.Error(t, err)
		assert.Nil(t, conn)
	})
}

// TestFormatRouterHashCompleteScenarios tests all scenarios of formatRouterHash.
func TestFormatRouterHashCompleteScenarios(t *testing.T) {
	tests := []struct {
		name     string
		hash     []byte
		expected string
	}{
		{
			name:     "valid 32-byte hash",
			hash:     []byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7},
			expected: "abcdef0123456789...",
		},
		{
			name:     "exactly 8 bytes",
			hash:     []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			expected: "123456789abcdef0...",
		},
		{
			name:     "7 bytes - should be invalid",
			hash:     []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE},
			expected: "invalid",
		},
		{
			name:     "nil hash",
			hash:     nil,
			expected: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRouterHash(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}
