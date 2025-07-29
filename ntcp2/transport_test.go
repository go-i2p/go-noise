package ntcp2

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateRandomBytes generates random bytes for testing
func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return bytes
}

func TestDialNTCP2(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		network     string
		addr        string
		expectError bool
		errorCode   string
	}{
		{
			name: "successful dial with valid config",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)

				config, err := NewNTCP2Config(routerHash, true)
				require.NoError(t, err)

				return config.
					WithStaticKey(staticKey).
					WithRemoteRouterHash(remoteHash).
					WithHandshakeTimeout(5 * time.Second)
			},
			network:     "tcp",
			addr:        "127.0.0.1:0", // Use available port
			expectError: true,          // Will fail to connect since no server
			errorCode:   "failed to dial tcp://127.0.0.1:0",
		},
		{
			name: "invalid network parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			network:     "",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name: "invalid address parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			network:     "tcp",
			addr:        "",
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			setupConfig: func() *NTCP2Config { return nil },
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name: "responder config for dial operation",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				return config
			},
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "dial operations require initiator=true in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()

			conn, err := DialNTCP2(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, conn)
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

func TestListenNTCP2(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		network     string
		addr        string
		expectError bool
		errorCode   string
	}{
		{
			name: "successful listen with valid config",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)

				config, err := NewNTCP2Config(routerHash, false) // responder
				require.NoError(t, err)

				return config.
					WithStaticKey(staticKey).
					WithHandshakeTimeout(5 * time.Second)
			},
			network:     "tcp",
			addr:        "127.0.0.1:0", // Use available port
			expectError: false,
		},
		{
			name: "invalid network parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			network:     "",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name: "invalid address parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			network:     "tcp",
			addr:        "",
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			setupConfig: func() *NTCP2Config { return nil },
			network:     "tcp",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name: "initiator config for listen operation",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true) // initiator
				return config
			},
			network:     "tcp",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "listen operations require initiator=false in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()

			listener, err := ListenNTCP2(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, listener)
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

func TestWrapNTCP2Conn(t *testing.T) {
	tests := []struct {
		name        string
		setupConn   func() net.Conn
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name: "successful wrap with valid connection and config",
			setupConn: func() net.Conn {
				// Create a pipe connection for testing
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					// Simple echo server
					buf := make([]byte, 1024)
					for {
						n, err := server.Read(buf)
						if err != nil {
							return
						}
						server.Write(buf[:n])
					}
				}()
				return client
			},
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)

				config, err := NewNTCP2Config(routerHash, true)
				require.NoError(t, err)

				return config.
					WithStaticKey(staticKey).
					WithRemoteRouterHash(remoteHash)
			},
			expectError: false,
		},
		{
			name:      "nil connection",
			setupConn: func() net.Conn { return nil },
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "connection cannot be nil",
		},
		{
			name: "nil config",
			setupConn: func() net.Conn {
				client, server := net.Pipe()
				go func() { defer server.Close() }()
				return client
			},
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.setupConn()
			config := tt.setupConfig()

			ntcp2Conn, err := WrapNTCP2Conn(conn, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, ntcp2Conn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ntcp2Conn)
				if ntcp2Conn != nil {
					ntcp2Conn.Close()
				}
			}

			if conn != nil {
				conn.Close()
			}
		})
	}
}

func TestWrapNTCP2Listener(t *testing.T) {
	t.Run("successful wrap", func(t *testing.T) {
		// Create a TCP listener
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer tcpListener.Close()

		// Create NTCP2 config
		routerHash := generateRandomBytes(32)
		staticKey := generateRandomBytes(32)

		config, err := NewNTCP2Config(routerHash, false) // responder
		require.NoError(t, err)

		config = config.WithStaticKey(staticKey)

		// Wrap the listener
		ntcp2Listener, err := WrapNTCP2Listener(tcpListener, config)
		assert.NoError(t, err)
		assert.NotNil(t, ntcp2Listener)

		if ntcp2Listener != nil {
			ntcp2Listener.Close()
		}
	})
}

func TestDialNTCP2WithHandshake(t *testing.T) {
	t.Run("handshake with context timeout", func(t *testing.T) {
		// Create a listener for the test
		routerHash := generateRandomBytes(32)
		staticKey := generateRandomBytes(32)

		listenerConfig, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)
		listenerConfig = listenerConfig.WithStaticKey(staticKey)

		listener, err := ListenNTCP2("tcp", "127.0.0.1:0", listenerConfig)
		require.NoError(t, err)
		defer listener.Close()

		// Create dial config
		clientRouterHash := generateRandomBytes(32)
		clientStaticKey := generateRandomBytes(32)

		dialConfig, err := NewNTCP2Config(clientRouterHash, true)
		require.NoError(t, err)
		dialConfig = dialConfig.
			WithStaticKey(clientStaticKey).
			WithRemoteRouterHash(routerHash).
			WithHandshakeTimeout(1 * time.Second)

		// Try to dial with handshake (will fail due to no handshake responder)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Get the underlying TCP address from the NTCP2 listener
		ntcp2Addr := listener.Addr().(*NTCP2Addr)
		underlyingAddr := ntcp2Addr.UnderlyingAddr().String()

		conn, err := DialNTCP2WithHandshakeContext(ctx, "tcp", underlyingAddr, dialConfig)

		// Expected to fail since there's no actual handshake responder set up
		assert.Error(t, err)
		assert.Nil(t, conn)
		// The handshake will fail with a more specific error about bad point length or similar
		assert.Contains(t, err.Error(), "handshake failed")
	})
}

func TestValidateDialParams(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid parameters",
			network: "tcp",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config.WithStaticKey(staticKey).WithRemoteRouterHash(remoteHash)
			},
			expectError: false,
		},
		{
			name:    "empty network",
			network: "",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:    "empty address",
			network: "tcp",
			addr:    "",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:    "responder config",
			network: "tcp",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				return config
			},
			expectError: true,
			errorCode:   "dial operations require initiator=true in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := validateDialParams(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateListenParams(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid parameters",
			network: "tcp",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				return config.WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name:    "empty network",
			network: "",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:    "empty address",
			network: "tcp",
			addr:    "",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "127.0.0.1:0",
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:    "initiator config",
			network: "tcp",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true) // initiator
				return config
			},
			expectError: true,
			errorCode:   "listen operations require initiator=false in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := validateListenParams(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateDialAddresses(t *testing.T) {
	t.Run("successful address creation", func(t *testing.T) {
		// Create a pipe connection for testing
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		// Create config
		routerHash := generateRandomBytes(32)
		remoteHash := generateRandomBytes(32)

		config, err := NewNTCP2Config(routerHash, true)
		require.NoError(t, err)
		config = config.WithRemoteRouterHash(remoteHash)

		// Create addresses
		localAddr, remoteAddr, err := createDialAddresses(client, config)

		assert.NoError(t, err)
		assert.NotNil(t, localAddr)
		assert.NotNil(t, remoteAddr)

		// Verify addresses
		assert.Equal(t, "initiator", localAddr.Role())
		assert.Equal(t, "responder", remoteAddr.Role())
		assert.Equal(t, routerHash, localAddr.RouterHash())
		assert.Equal(t, remoteHash, remoteAddr.RouterHash())
	})
}
