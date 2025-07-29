package noise

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewListenerConfig(t *testing.T) {
	config := NewListenerConfig("XX")

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
}

func TestListenerConfigBuilder(t *testing.T) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.WriteTimeout)
}

func TestListenerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *ListenerConfig
		expectError bool
		errorCode   string
	}{
		{
			name: "valid config",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "valid config without static key",
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("NN") // No static key - should be valid
			},
			expectError: false,
		},
		{
			name: "empty pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "noise pattern is required",
		},
		{
			name: "invalid pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("INVALID").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "invalid noise pattern",
		},
		{
			name: "invalid key length",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 16) // Wrong length
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "static key must be 32 bytes",
		},
		{
			name: "invalid timeout",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").
					WithStaticKey(staticKey).
					WithHandshakeTimeout(-1 * time.Second)
			},
			expectError: true,
			errorCode:   "handshake timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()

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

func TestNewNoiseListener(t *testing.T) {
	tests := []struct {
		name            string
		setupUnderlying func() net.Listener
		setupConfig     func() *ListenerConfig
		expectError     bool
		errorType       string
	}{
		{
			name: "valid listener creation",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				_, err := rand.Read(staticKey)
				require.NoError(t, err)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "nil underlying listener",
			setupUnderlying: func() net.Listener {
				return nil
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorType:   "underlying listener cannot be nil",
		},
		{
			name: "nil config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return nil
			},
			expectError: true,
			errorType:   "listener config cannot be nil",
		},
		{
			name: "invalid config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("") // Invalid pattern
			},
			expectError: true,
			errorType:   "invalid listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := tt.setupUnderlying()
			if underlying != nil {
				defer underlying.Close()
			}
			config := tt.setupConfig()

			listener, err := NewNoiseListener(underlying, config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, listener)
				if tt.errorType != "" {
					assert.Contains(t, err.Error(), tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				assert.Equal(t, underlying.Addr().Network(), listener.Addr().(*NoiseAddr).underlying.Network())
				listener.Close()
			}
		})
	}
}

func TestNoiseListenerAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	addr := noiseListener.Addr()
	noiseAddr, ok := addr.(*NoiseAddr)
	require.True(t, ok)

	assert.Equal(t, "noise+tcp", noiseAddr.Network())
	assert.Contains(t, noiseAddr.String(), "XX")
	assert.Contains(t, noiseAddr.String(), "responder")
	assert.Contains(t, noiseAddr.String(), listener.Addr().String())
}

func TestNoiseListenerClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)

	// Close should succeed
	err = noiseListener.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = noiseListener.Close()
	assert.NoError(t, err)

	// Accept should fail after close
	_, err = noiseListener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listener is closed")
}

func TestNoiseListenerAcceptAfterClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)

	// Close the listener
	err = noiseListener.Close()
	require.NoError(t, err)

	// Accept should return error
	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "listener is closed")
}

// mockListener implements net.Listener for testing
type mockListener struct {
	addr       net.Addr
	acceptFunc func() (net.Conn, error)
	closeFunc  func() error
	closed     bool
	mu         sync.Mutex
}

func (ml *mockListener) Accept() (net.Conn, error) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	if ml.closed {
		return nil, net.ErrClosed
	}
	if ml.acceptFunc != nil {
		return ml.acceptFunc()
	}
	return nil, assert.AnError
}

func (ml *mockListener) Close() error {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.closed = true
	if ml.closeFunc != nil {
		return ml.closeFunc()
	}
	return nil
}

func (ml *mockListener) Addr() net.Addr {
	return ml.addr
}

func TestNoiseListenerAcceptError(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	mockListener := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return nil, assert.AnError
		},
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(mockListener, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to accept underlying connection")
}

func TestNoiseListenerConcurrentOperations(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)

	// Test concurrent close operations
	var wg sync.WaitGroup
	closeErrors := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			closeErrors[index] = noiseListener.Close()
		}(i)
	}

	wg.Wait()

	// All close operations should succeed (idempotent)
	for i, err := range closeErrors {
		assert.NoError(t, err, "Close operation %d should succeed", i)
	}
}

func TestNoiseListenerNetworkInterface(t *testing.T) {
	// Verify NoiseListener implements net.Listener interface
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	// Verify it implements net.Listener
	var _ net.Listener = noiseListener

	// Test interface methods
	addr := noiseListener.Addr()
	assert.NotNil(t, addr)

	// Accept should work (but we won't wait for connections)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go func() {
		<-ctx.Done()
		noiseListener.Close()
	}()

	_, err = noiseListener.Accept()
	// Should get an error due to timeout/close, but that's expected
	assert.Error(t, err)
}

func TestListenerConfigAllPatterns(t *testing.T) {
	patterns := []string{
		"NN", "NK", "NX", "XN", "XK", "XX",
		"KN", "KK", "KX", "IN", "IK", "IX",
		"N", "K", "X",
		"Noise_NN_25519_AESGCM_SHA256",
		"Noise_XX_25519_AESGCM_SHA256",
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			config := NewListenerConfig(pattern).WithStaticKey(staticKey)
			err := config.Validate()
			assert.NoError(t, err, "Pattern %s should be valid", pattern)
		})
	}
}

// Benchmark the listener creation and basic operations
func BenchmarkNoiseListenerCreation(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)
	defer listener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		noiseListener, err := NewNoiseListener(listener, config)
		if err != nil {
			b.Fatal(err)
		}
		noiseListener.Close()
	}
}

func BenchmarkListenerConfigValidation(b *testing.B) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}
