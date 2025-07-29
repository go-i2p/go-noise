package ntcp2

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNTCP2Config(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, false, config.Initiator)
	assert.Equal(t, routerHash, config.RouterHash)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
	assert.Equal(t, 3, config.HandshakeRetries)
	assert.Equal(t, 1*time.Second, config.RetryBackoff)
	assert.Equal(t, true, config.EnableAESObfuscation)
	assert.Equal(t, true, config.EnableSipHashLength)
}

func TestNewNTCP2ConfigInvalidRouterHash(t *testing.T) {
	tests := []struct {
		name           string
		routerHashSize int
	}{
		{"empty hash", 0},
		{"short hash", 16},
		{"long hash", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routerHash := make([]byte, tt.routerHashSize)
			config, err := NewNTCP2Config(routerHash, false)
			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), "router hash must be exactly 32 bytes")
		})
	}
}

func TestNTCP2ConfigBuilder(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config = config.
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, routerHash, config.RouterHash)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.WriteTimeout)
}

func TestNTCP2ConfigBuilderInvalidStaticKey(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Test with invalid key size - should not modify config
	invalidKey := make([]byte, 16)
	config = config.WithStaticKey(invalidKey)
	assert.Nil(t, config.StaticKey) // Should remain nil

	// Test with valid key size
	validKey := make([]byte, 32)
	config = config.WithStaticKey(validKey)
	assert.Equal(t, validKey, config.StaticKey)
}

func TestNTCP2ConfigValidation(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		expectError bool
		description string
	}{
		{
			name: "valid config",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: false,
			description: "Valid config should pass validation",
		},
		{
			name: "invalid router hash",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.RouterHash = make([]byte, 16) // Wrong size
				return config
			},
			expectError: true,
			description: "Should reject invalid router hash size",
		},
		{
			name: "invalid static key length",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.StaticKey = make([]byte, 16) // Wrong size
				return config
			},
			expectError: true,
			description: "Should reject invalid static key size",
		},
		{
			name: "zero handshake timeout",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeTimeout = 0
				return config
			},
			expectError: true,
			description: "Should reject zero handshake timeout",
		},
		{
			name: "negative handshake timeout",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeTimeout = -5 * time.Second
				return config
			},
			expectError: true,
			description: "Should reject negative handshake timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()

			if tt.expectError && err == nil {
				t.Errorf("Expected validation error for %s, but got none", tt.description)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error for %s: %v", tt.description, err)
			}
		})
	}
}

func TestNewNTCP2Listener(t *testing.T) {
	// Create TCP listener for testing
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)
	defer listener.Close()

	assert.NotNil(t, listener)
	assert.NotNil(t, listener.Addr())
	assert.Equal(t, "ntcp2", listener.Addr().Network())
}

func TestNewNTCP2ListenerErrors(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	tests := []struct {
		name          string
		listener      net.Listener
		config        *NTCP2Config
		expectedError string
	}{
		{
			name:          "nil underlying listener",
			listener:      nil,
			config:        config,
			expectedError: "underlying listener cannot be nil",
		},
		{
			name: "nil config",
			listener: func() net.Listener {
				l, _ := net.Listen("tcp", "127.0.0.1:0")
				return l
			}(),
			config:        nil,
			expectedError: "ntcp2 config cannot be nil",
		},
		{
			name: "invalid config",
			listener: func() net.Listener {
				l, _ := net.Listen("tcp", "127.0.0.1:0")
				return l
			}(),
			config: func() *NTCP2Config {
				c, _ := NewNTCP2Config(routerHash, false)
				c.RouterHash = make([]byte, 16) // Invalid router hash size
				return c
			}(),
			expectedError: "invalid ntcp2 listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := NewNTCP2Listener(tt.listener, tt.config)
			assert.Error(t, err)
			assert.Nil(t, listener)
			assert.Contains(t, err.Error(), tt.expectedError)

			// Clean up valid listeners
			if tt.listener != nil {
				tt.listener.Close()
			}
		})
	}
}

func TestNTCP2ListenerAddr(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpListener.Close()

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr()
	assert.NotNil(t, addr)
	assert.Equal(t, "ntcp2", addr.Network())

	// Should be NTCP2Addr
	ntcp2Addr, ok := addr.(*NTCP2Addr)
	assert.True(t, ok)
	assert.Equal(t, routerHash, ntcp2Addr.routerHash)
	assert.Equal(t, "responder", ntcp2Addr.role)
}

func TestNTCP2ListenerClose(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Close should work
	err = listener.Close()
	assert.NoError(t, err)

	// Second close should also work (idempotent)
	err = listener.Close()
	assert.NoError(t, err)
}

func TestNTCP2ListenerAcceptAfterClose(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Close the listener
	err = listener.Close()
	require.NoError(t, err)

	// Accept should return error
	conn, err := listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "ntcp2 listener is closed")
}

func TestNTCP2ListenerConcurrentClose(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Test concurrent close operations
	var wg sync.WaitGroup
	closeCount := 10

	for i := 0; i < closeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			listener.Close()
		}()
	}

	wg.Wait()

	// Listener should be closed
	conn, err := listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestFormatRouterHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     []byte
		expected string
	}{
		{
			name:     "valid hash",
			hash:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			expected: "0102030405060708...",
		},
		{
			name:     "short hash",
			hash:     []byte{0x01, 0x02, 0x03},
			expected: "invalid",
		},
		{
			name:     "empty hash",
			hash:     []byte{},
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
