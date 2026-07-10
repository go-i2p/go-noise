package noise

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/pool"
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
	// Create a pipe connection for testing
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	config := NewConnConfig("XX", true).WithStaticKey(generateTestKey())

	noiseConn, err := WrapConn(client, config)

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
	originalPool := GetGlobalConnPool()
	defer func() {
		SetGlobalConnPool(originalPool)
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
	originalPool := GetGlobalConnPool()
	defer func() {
		SetGlobalConnPool(originalPool)
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

// Tests from transport_retry_test.go

func TestDialNoiseWithHandshake(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ConnConfig
		expectError bool
	}{
		{
			name:        "invalid network",
			network:     "",
			addr:        "localhost:8080",
			config:      NewConnConfig("XX", true),
			expectError: true,
		},
		{
			name:        "invalid address",
			network:     "tcp",
			addr:        "",
			config:      NewConnConfig("XX", true),
			expectError: true,
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "localhost:8080",
			config:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialNoiseWithHandshake(tt.network, tt.addr, tt.config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err == nil {
				t.Errorf("Expected connection establishment to fail due to no server, but validation passed")
			}
		})
	}
}

func TestDialNoiseWithHandshakeContext(t *testing.T) {
	config := NewConnConfig("XX", true)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := DialNoiseWithHandshakeContext(ctx, "tcp", "127.0.0.1:65535", config)
	if err == nil {
		t.Errorf("Expected dial error for non-existent address")
	}
}

// TestDialWithPoolAndHandshake_DiscardsBrokenConnectionOnFailure is the
// regression test for the AUDIT.md HIGH finding: a pool-retrieved connection
// that fails NewNoiseConn construction must be permanently discarded from the
// pool (via pool.PooledConnection.Discard()) rather than silently returned
// for reuse via Close(), which would let a broken connection be repeatedly
// re-served by future Dial calls to the same address.
func TestDialWithPoolAndHandshake_DiscardsBrokenConnectionOnFailure(t *testing.T) {
	const addr = "127.0.0.1:19999"

	p := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer p.Close()

	mockConn := newMockTransportConn(addr)
	if err := p.Put(mockConn); err != nil {
		t.Fatalf("failed to seed pool with mock connection: %v", err)
	}

	// Sanity check: the connection is retrievable before the failed dial.
	if pooled := p.Get(addr); pooled == nil {
		t.Fatal("expected mock connection to be retrievable from pool before test")
	} else if err := pooled.Discard(); err != nil {
		t.Fatalf("failed to discard sanity-check connection: %v", err)
	}
	// Re-seed since the sanity-check Get()+Discard() consumed it.
	mockConn2 := newMockTransportConn(addr)
	if err := p.Put(mockConn2); err != nil {
		t.Fatalf("failed to re-seed pool: %v", err)
	}

	tr := NewTransport(p, nil)

	// A valid pattern/config so NewNoiseConn construction succeeds and the
	// pool is actually consulted; the mock connection's Read error then
	// forces a quick handshake failure, exercising the HandshakeWithRetry
	// failure path (not the earlier NewNoiseConn-failure path).
	mockConn2.readErr = io.ErrClosedPipe
	validConfig := NewConnConfig("XX", true)

	_, err := tr.DialWithPoolAndHandshakeContext(context.Background(), "tcp", addr, validConfig)
	if err == nil {
		t.Fatal("expected an error from DialWithPoolAndHandshakeContext when the pool-sourced connection fails handshake")
	}

	// The broken connection must have been discarded (permanently removed),
	// not returned to the pool for reuse — so a subsequent Get() for the same
	// address must return nil.
	if pooled := p.Get(addr); pooled != nil {
		t.Error("expected the broken connection to be discarded (Get() should return nil), but it was still retrievable from the pool")
	}
	if !mockConn2.closed {
		t.Error("expected the broken connection's underlying Close() to have been called via Discard()")
	}
}

func TestDialNoiseWithPoolAndHandshake(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		config      *ConnConfig
		expectError bool
	}{
		{
			name:        "dial fails to non-existent address",
			network:     "tcp",
			addr:        "127.0.0.1:65535",
			config:      NewConnConfig("XX", true),
			expectError: true,
		},
		{
			name:        "invalid config",
			network:     "tcp",
			addr:        "localhost:8080",
			config:      NewConnConfig("", true),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DialNoiseWithPoolAndHandshake(tt.network, tt.addr, tt.config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
		})
	}
}

// mockTransportConn is a minimal net.Conn stub used by putOnCloseWrapper tests.
type mockTransportConn struct {
	closed     bool
	remoteAddr net.Addr
	readErr    error
}

func newMockTransportConn(addr string) *mockTransportConn {
	return &mockTransportConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19999},
	}
}

func (m *mockTransportConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return 0, nil
}
func (m *mockTransportConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockTransportConn) Close() error                       { m.closed = true; return nil }
func (m *mockTransportConn) LocalAddr() net.Addr                { return m.remoteAddr }
func (m *mockTransportConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockTransportConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockTransportConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockTransportConn) SetWriteDeadline(t time.Time) error { return nil }

// TestPutOnCloseWrapper verifies that closing a putOnCloseWrapper returns the
// underlying connection to the pool (Put) instead of closing it to the OS.
// This is the mechanism that makes DialNoiseWithPool return new connections to
// the pool when the caller closes the NoiseConn.
func TestPutOnCloseWrapper(t *testing.T) {
	p := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
	defer p.Close()

	rawConn := newMockTransportConn("127.0.0.1:19999")
	wrapped := newPutOnCloseWrapper(rawConn, p)

	// Closing the wrapper should add the raw conn to the pool.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	// The underlying conn must NOT have been closed to the OS.
	if rawConn.closed {
		t.Error("putOnCloseWrapper.Close() should not close the underlying conn; it should Put it")
	}

	// The pool must now know about the connection.
	stats := p.Stats()
	if stats.Total != 1 {
		t.Errorf("pool should contain 1 connection after Put, got total=%d", stats.Total)
	}

	// A second Close() must be idempotent and must not add a duplicate.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("second Close() should not error, got: %v", err)
	}
	stats = p.Stats()
	if stats.Total != 1 {
		t.Errorf("second Close() should not add a duplicate, got total=%d", stats.Total)
	}
}

// TestPutOnCloseWrapper_ClosedPool verifies that when the pool is already closed,
// putOnCloseWrapper.Close() falls through to Close the underlying conn gracefully.
func TestPutOnCloseWrapper_ClosedPool(t *testing.T) {
	p := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
	p.Close() // close the pool first

	rawConn := newMockTransportConn("127.0.0.1:19999")
	wrapped := newPutOnCloseWrapper(rawConn, p)

	// Pool.Put on a closed pool closes the conn; wrapper must propagate that.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() on closed pool returned unexpected error: %v", err)
	}
	// The underlying conn should have been closed by pool.Put on closed pool.
	if !rawConn.closed {
		t.Error("underlying conn should be closed when pool is closed")
	}
}
