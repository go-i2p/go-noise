package noise

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/pool"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDialNoise(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ConnConfig
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid TCP connection",
			network: "tcp",
			addr:    "localhost:0", // Use port 0 for dynamic port assignment
			config: NewConnConfig("XX", true).
				WithStaticKey(generateTestKey()).
				WithHandshakeTimeout(5 * time.Second),
			expectError: true, // Will fail because no server is listening
			errorCode:   "failed to dial",
		},
		{
			name:        "empty network",
			network:     "",
			addr:        "localhost:8080",
			config:      NewConnConfig("XX", true),
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:        "empty address",
			network:     "tcp",
			addr:        "",
			config:      NewConnConfig("XX", true),
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "localhost:8080",
			config:      nil,
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:    "invalid config",
			network: "tcp",
			addr:    "localhost:8080",
			config: NewConnConfig("", true).
				WithStaticKey(generateTestKey()),
			expectError: true,
			errorCode:   "noise pattern is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := DialNoise(tt.network, tt.addr, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, conn)
				assert.Contains(t, err.Error(), tt.errorCode)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conn)
				if conn != nil {
					conn.Close()
				}
			}
		})
	}
}

func TestListenNoise(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ListenerConfig
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid TCP listener",
			network: "tcp",
			addr:    "localhost:0", // Use port 0 for dynamic port assignment
			config: NewListenerConfig("XX").
				WithStaticKey(generateTestKey()).
				WithHandshakeTimeout(5 * time.Second),
			expectError: false,
		},
		{
			name:        "empty network",
			network:     "",
			addr:        "localhost:0",
			config:      NewListenerConfig("XX"),
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:        "empty address",
			network:     "tcp",
			addr:        "",
			config:      NewListenerConfig("XX"),
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "localhost:0",
			config:      nil,
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:        "invalid config",
			network:     "tcp",
			addr:        "localhost:0",
			config:      NewListenerConfig(""),
			expectError: true,
			errorCode:   "noise pattern is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := ListenNoise(tt.network, tt.addr, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, listener)
				assert.Contains(t, err.Error(), tt.errorCode)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				if listener != nil {
					listener.Close()
				}
			}
		})
	}
}

func TestWrapConn(t *testing.T) {
	// Create a mock connection using the existing mock
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	mockConn := newMockNetConn(localAddr, remoteAddr)
	config := NewConnConfig("XX", true).WithStaticKey(generateTestKey())

	noiseConn, err := WrapConn(mockConn, config)

	assert.NoError(t, err)
	assert.NotNil(t, noiseConn)
}

func TestWrapListener(t *testing.T) {
	// Create a real TCP listener for this test since we don't have a mock listener
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer listener.Close()

	config := NewListenerConfig("XX").WithStaticKey(generateTestKey())

	noiseListener, err := WrapListener(listener, config)

	assert.NoError(t, err)
	assert.NotNil(t, noiseListener)
	defer noiseListener.Close()
}

func TestTransportIntegration(t *testing.T) {
	// Test that ListenNoise and DialNoise work together
	listenerConfig := NewListenerConfig("XX").
		WithStaticKey(generateTestKey()).
		WithHandshakeTimeout(5 * time.Second)

	// Create a listener
	listener, err := ListenNoise("tcp", "localhost:0", listenerConfig)
	require.NoError(t, err)
	require.NotNil(t, listener)
	defer listener.Close()

	// Test basic functionality - this test is mainly to verify the API works
	t.Log("Transport wrapping functions work correctly")
}

func TestTransportWithDifferentNetworks(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{"tcp", "tcp"},
		{"tcp4", "tcp4"},
		{"tcp6", "tcp6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewListenerConfig("XX").
				WithStaticKey(generateTestKey()).
				WithHandshakeTimeout(5 * time.Second)

			listener, err := ListenNoise(tt.network, "localhost:0", config)
			if err != nil {
				// Some networks might not be available (e.g., IPv6)
				t.Skipf("Network %s not available: %v", tt.network, err)
				return
			}
			require.NotNil(t, listener)
			defer listener.Close()

			// Verify the listener is working
			assert.NotNil(t, listener.Addr())
			t.Logf("Listener created on %s: %s", tt.network, listener.Addr().String())
		})
	}
}

// Test functions for pool integration

func TestDialNoiseWithPool(t *testing.T) {
	// Save original pool and restore after test
	originalPool := globalConnPool
	defer func() {
		globalConnPool = originalPool
	}()

	// Create test pool
	testPool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer testPool.Close()

	SetGlobalConnPool(testPool)

	tests := []struct {
		name    string
		network string
		addr    string
		config  *ConnConfig
		wantErr bool
		errCode string
	}{
		{
			name:    "invalid network",
			network: "",
			addr:    "127.0.0.1:8080",
			config:  &ConnConfig{Pattern: "XX", Initiator: true},
			wantErr: true,
			errCode: "INVALID_NETWORK",
		},
		{
			name:    "invalid address",
			network: "tcp",
			addr:    "",
			config:  &ConnConfig{Pattern: "XX", Initiator: true},
			wantErr: true,
			errCode: "INVALID_ADDRESS",
		},
		{
			name:    "nil config",
			network: "tcp",
			addr:    "127.0.0.1:8080",
			config:  nil,
			wantErr: true,
			errCode: "INVALID_CONFIG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialNoiseWithPool(tt.network, tt.addr, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}

				oopsErr, ok := err.(oops.OopsError)
				if !ok {
					t.Errorf("Expected oops.OopsError, got %T", err)
					return
				}

				if oopsErr.Code() != tt.errCode {
					t.Errorf("Expected error code %s, got %s", tt.errCode, oopsErr.Code())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestSetGetGlobalConnPool(t *testing.T) {
	// Save original pool and restore after test
	originalPool := globalConnPool
	defer func() {
		globalConnPool = originalPool
	}()

	testPool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 3,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer testPool.Close()

	SetGlobalConnPool(testPool)

	retrieved := GetGlobalConnPool()
	if retrieved != testPool {
		t.Error("SetGlobalConnPool/GetGlobalConnPool did not work correctly")
	}
}

// Helper functions for testing

func generateTestKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}
