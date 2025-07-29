package pool

import (
	"net"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string { return m.network }
func (m *mockAddr) String() string  { return m.address }

func newMockConn(remoteAddr string) *mockConn {
	return &mockConn{
		localAddr:  &mockAddr{network: "tcp", address: "127.0.0.1:0"},
		remoteAddr: &mockAddr{network: "tcp", address: remoteAddr},
	}
}

func TestNewConnPool(t *testing.T) {
	tests := []struct {
		name   string
		config *PoolConfig
	}{
		{
			name:   "with config",
			config: &PoolConfig{MaxSize: 5, MaxAge: time.Hour, MaxIdle: time.Minute},
		},
		{
			name:   "with nil config (defaults)",
			config: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewConnPool(tt.config)
			if pool == nil {
				t.Error("NewConnPool returned nil")
			}

			defer pool.Close()

			if pool.closed {
				t.Error("Pool should not be closed initially")
			}

			if pool.conns == nil {
				t.Error("Pool connections map should be initialized")
			}
		})
	}
}

func TestConnPool_PutAndGet(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 2,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Test putting a connection
	conn1 := newMockConn("127.0.0.1:8080")
	err := pool.Put(conn1)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Test getting the connection back
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Error("Get returned nil for available connection")
	}

	// Test getting when no connection is available
	retrieved2 := pool.Get("127.0.0.1:8080")
	if retrieved2 != nil {
		t.Error("Get should return nil when connection is in use")
	}

	// Test getting for non-existent address
	retrieved3 := pool.Get("127.0.0.1:9090")
	if retrieved3 != nil {
		t.Error("Get should return nil for non-existent address")
	}
}

func TestConnPool_Release(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 2,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Fatal("Get returned nil")
	}

	// Release the connection
	pool.Release("127.0.0.1:8080", conn1)

	// Should be able to get it again
	retrieved2 := pool.Get("127.0.0.1:8080")
	if retrieved2 == nil {
		t.Error("Get should return connection after release")
	}
}

func TestConnPool_MaxSize(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 1,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	conn2 := newMockConn("127.0.0.1:8080")

	// First connection should succeed
	err1 := pool.Put(conn1)
	if err1 != nil {
		t.Fatalf("First Put failed: %v", err1)
	}

	// Second connection should be rejected (exceeds max size)
	err2 := pool.Put(conn2)
	if err2 != nil {
		t.Fatalf("Second Put failed: %v", err2)
	}

	// Should only have one connection available
	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Errorf("Expected 1 total connection, got %d", stats["total"])
	}

	// Verify conn2 was closed due to max size limit
	if !conn2.closed {
		t.Error("Connection should be closed when exceeding max size")
	}
}

func TestConnPool_Stats(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Add some connections
	conn1 := newMockConn("127.0.0.1:8080")
	conn2 := newMockConn("127.0.0.1:9090")

	pool.Put(conn1)
	pool.Put(conn2)

	// Get one connection (mark as in use)
	pool.Get("127.0.0.1:8080")

	stats := pool.Stats()

	expectedTotal := 2
	expectedInUse := 1
	expectedAvailable := 1
	expectedAddresses := 2

	if stats["total"] != expectedTotal {
		t.Errorf("Expected total %d, got %d", expectedTotal, stats["total"])
	}
	if stats["in_use"] != expectedInUse {
		t.Errorf("Expected in_use %d, got %d", expectedInUse, stats["in_use"])
	}
	if stats["available"] != expectedAvailable {
		t.Errorf("Expected available %d, got %d", expectedAvailable, stats["available"])
	}
	if stats["addresses"] != expectedAddresses {
		t.Errorf("Expected addresses %d, got %d", expectedAddresses, stats["addresses"])
	}
}

func TestConnPool_Close(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	// Close the pool
	err := pool.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify connection was closed
	if !conn1.closed {
		t.Error("Connection should be closed when pool is closed")
	}

	// Verify pool is marked as closed
	if !pool.closed {
		t.Error("Pool should be marked as closed")
	}

	// Verify new operations are rejected
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved != nil {
		t.Error("Get should return nil after pool is closed")
	}

	conn2 := newMockConn("127.0.0.1:9090")
	err = pool.Put(conn2)
	if err != nil {
		t.Fatalf("Put after close failed: %v", err)
	}

	// Verify conn2 was closed immediately
	if !conn2.closed {
		t.Error("Connection should be closed immediately when put in closed pool")
	}
}

func TestPoolConnWrapper(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	// Get wrapped connection
	wrapped := pool.Get("127.0.0.1:8080")
	if wrapped == nil {
		t.Fatal("Get returned nil")
	}

	// Verify wrapper functionality
	if wrapped.RemoteAddr().String() != "127.0.0.1:8080" {
		t.Error("Wrapper should delegate RemoteAddr to underlying connection")
	}

	// Close wrapped connection (should release to pool)
	err := wrapped.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Should be able to get the connection again
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Error("Connection should be available after wrapper close")
	}
}

func TestConnPool_NilConnection(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	err := pool.Put(nil)
	if err == nil {
		t.Error("Put should fail with nil connection")
	}
}
