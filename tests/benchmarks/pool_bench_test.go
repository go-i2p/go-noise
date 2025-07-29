package benchmarks

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/pool"
)

// mockConn implements net.Conn for benchmarking
type mockConn struct {
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return len(b), nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &mockAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string {
	if m.addr != "" {
		return m.addr
	}
	return "127.0.0.1:8080"
}

func newMockConn(addr string) *mockConn {
	return &mockConn{
		remoteAddr: &mockAddr{addr: addr},
	}
}

func BenchmarkConnPool_Put(b *testing.B) {
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 1000,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conns := make([]*mockConn, b.N)
	for i := 0; i < b.N; i++ {
		conns[i] = newMockConn("127.0.0.1:8080")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Put(conns[i])
	}
}

func BenchmarkConnPool_Get(b *testing.B) {
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 1000,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Pre-populate pool
	for i := 0; i < 100; i++ {
		conn := newMockConn("127.0.0.1:8080")
		pool.Put(conn)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := pool.Get("127.0.0.1:8080")
		if conn != nil {
			pool.Release("127.0.0.1:8080", conn)
		}
	}
}

func BenchmarkConnPool_PutGet(b *testing.B) {
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 100,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := newMockConn("127.0.0.1:8080")
		pool.Put(conn)

		retrieved := pool.Get("127.0.0.1:8080")
		if retrieved != nil {
			pool.Release("127.0.0.1:8080", retrieved)
		}
	}
}

func BenchmarkConnPool_Concurrent(b *testing.B) {
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 50,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Pre-populate pool
	for i := 0; i < 25; i++ {
		conn := newMockConn("127.0.0.1:8080")
		pool.Put(conn)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn := pool.Get("127.0.0.1:8080")
			if conn != nil {
				// Simulate some work
				time.Sleep(time.Microsecond)
				pool.Release("127.0.0.1:8080", conn)
			} else {
				// Create new connection if pool is empty
				newConn := newMockConn("127.0.0.1:8080")
				pool.Put(newConn)
			}
		}
	})
}

func BenchmarkConnPool_Stats(b *testing.B) {
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 100,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Pre-populate pool with various addresses
	for i := 0; i < 50; i++ {
		for j := 0; j < 2; j++ {
			conn := newMockConn("127.0.0.1:" + string(rune(8080+i)))
			pool.Put(conn)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Stats()
	}
}
