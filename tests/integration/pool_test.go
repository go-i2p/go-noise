package integration

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/pool"
)

func TestConnPoolIntegration(t *testing.T) {
	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Handle connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			// Echo server - read and write back
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Create connection pool
	pool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 3,
		MaxAge:  time.Minute,
		MaxIdle: 30 * time.Second,
	})
	defer pool.Close()

	// Test 1: Create and pool connections
	t.Run("pool_real_connections", func(t *testing.T) {
		// Create first connection
		conn1, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}

		// Test the connection works
		testData := []byte("hello")
		conn1.Write(testData)

		buf := make([]byte, len(testData))
		conn1.Read(buf)

		if string(buf) != string(testData) {
			t.Errorf("Expected echo %s, got %s", testData, buf)
		}

		// Put connection in pool
		err = pool.Put(conn1)
		if err != nil {
			t.Fatalf("Failed to put connection in pool: %v", err)
		}

		// Verify pool stats
		stats := pool.Stats()
		if stats["total"] != 1 {
			t.Errorf("Expected 1 connection in pool, got %d", stats["total"])
		}
	})

	// Test 2: Retrieve and reuse pooled connection
	t.Run("reuse_pooled_connection", func(t *testing.T) {
		// Get connection from pool
		pooledConn := pool.Get(serverAddr)
		if pooledConn == nil {
			t.Fatal("Failed to get connection from pool")
		}

		// Test the pooled connection still works
		testData := []byte("world")
		pooledConn.Write(testData)

		buf := make([]byte, len(testData))
		pooledConn.Read(buf)

		if string(buf) != string(testData) {
			t.Errorf("Expected echo %s, got %s", testData, buf)
		}

		// Release connection back to pool
		pooledConn.Close() // This should release, not close

		// Verify connection is available again
		retrievedAgain := pool.Get(serverAddr)
		if retrievedAgain == nil {
			t.Error("Connection should be available after release")
		}
	})

	// Test 3: Pool behavior under load
	t.Run("concurrent_pool_usage", func(t *testing.T) {
		const numGoroutines = 5
		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				// Try to get a connection from pool first
				conn := pool.Get(serverAddr)

				// If not available, create new connection
				if conn == nil {
					var err error
					conn, err = net.Dial("tcp", serverAddr)
					if err != nil {
						t.Errorf("Goroutine %d: Failed to dial: %v", id, err)
						return
					}

					// Put it in pool when done
					defer pool.Put(conn)
				} else {
					// Release pooled connection when done
					defer conn.Close()
				}

				// Use the connection
				testData := []byte("concurrent")
				conn.Write(testData)

				buf := make([]byte, len(testData))
				conn.Read(buf)

				if string(buf) != string(testData) {
					t.Errorf("Goroutine %d: Expected echo %s, got %s", id, testData, buf)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			<-done
		}

		// Check final pool stats
		stats := pool.Stats()
		t.Logf("Final pool stats: %+v", stats)

		if stats["total"] > 3 {
			t.Errorf("Pool should not exceed MaxSize of 3, got %d", stats["total"])
		}
	})
}
