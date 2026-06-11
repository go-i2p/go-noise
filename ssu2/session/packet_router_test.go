package session

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewPacketRouter tests the creation of a new PacketRouter.
func TestNewPacketRouter(t *testing.T) {
	t.Run("WithHandler", func(t *testing.T) {
		handler := func(addr *net.UDPAddr, pkt *SSU2Packet) (*SSU2Conn, error) {
			return nil, nil
		}

		router := NewPacketRouter(handler)

		assert.NotNil(t, router)
		assert.NotNil(t, router.sessions)
		assert.NotNil(t, router.newSessionHandler)
		assert.Equal(t, 0, router.SessionCount())
	})

	t.Run("WithoutHandler", func(t *testing.T) {
		router := NewPacketRouter(nil)

		assert.NotNil(t, router)
		assert.NotNil(t, router.sessions)
		assert.Nil(t, router.newSessionHandler)
		assert.Equal(t, 0, router.SessionCount())
	})
}

// TestPacketRouter_AddSession tests adding sessions to the router.
func TestPacketRouter_AddSession(t *testing.T) {
	t.Run("ValidSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Create a valid connection
		conn := createMockSSU2Conn(t, 12345)

		err := router.AddSession(conn)
		require.NoError(t, err)
		assert.Equal(t, 1, router.SessionCount())

		// Verify session can be retrieved
		retrieved := router.GetSession(12345)
		assert.Equal(t, conn, retrieved)
	})

	t.Run("NilConnection", func(t *testing.T) {
		router := NewPacketRouter(nil)

		err := router.AddSession(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection cannot be nil")
		assert.Equal(t, 0, router.SessionCount())
	})

	t.Run("NilSSU2Addr", func(t *testing.T) {
		router := NewPacketRouter(nil)

		conn := &SSU2Conn{
			ssu2Addr: nil,
		}

		err := router.AddSession(conn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection must have SSU2Addr")
		assert.Equal(t, 0, router.SessionCount())
	})

	t.Run("DuplicateConnectionID", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Add first connection
		conn1 := createMockSSU2Conn(t, 12345)
		err := router.AddSession(conn1)
		require.NoError(t, err)

		// Try to add second connection with same ID
		conn2 := createMockSSU2Conn(t, 12345)
		err = router.AddSession(conn2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection ID already registered")
		assert.Equal(t, 1, router.SessionCount())

		// Verify first connection is still registered
		retrieved := router.GetSession(12345)
		assert.Equal(t, conn1, retrieved)
	})

	t.Run("MultipleSessions", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Add multiple sessions with different IDs
		conn1 := createMockSSU2Conn(t, 100)
		conn2 := createMockSSU2Conn(t, 200)
		conn3 := createMockSSU2Conn(t, 300)

		require.NoError(t, router.AddSession(conn1))
		require.NoError(t, router.AddSession(conn2))
		require.NoError(t, router.AddSession(conn3))

		assert.Equal(t, 3, router.SessionCount())

		// Verify all can be retrieved
		assert.Equal(t, conn1, router.GetSession(100))
		assert.Equal(t, conn2, router.GetSession(200))
		assert.Equal(t, conn3, router.GetSession(300))
	})
}

// TestPacketRouter_RemoveSession tests removing sessions from the router.
func TestPacketRouter_RemoveSession(t *testing.T) {
	t.Run("ExistingSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		conn := createMockSSU2Conn(t, 12345)
		require.NoError(t, router.AddSession(conn))
		assert.Equal(t, 1, router.SessionCount())

		router.RemoveSession(12345)
		assert.Equal(t, 0, router.SessionCount())
		assert.Nil(t, router.GetSession(12345))
	})

	t.Run("NonExistentSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Removing non-existent session should not panic
		router.RemoveSession(99999)
		assert.Equal(t, 0, router.SessionCount())
	})

	t.Run("RemoveOneOfMany", func(t *testing.T) {
		router := NewPacketRouter(nil)

		conn1 := createMockSSU2Conn(t, 100)
		conn2 := createMockSSU2Conn(t, 200)
		conn3 := createMockSSU2Conn(t, 300)

		require.NoError(t, router.AddSession(conn1))
		require.NoError(t, router.AddSession(conn2))
		require.NoError(t, router.AddSession(conn3))

		// Remove middle session
		router.RemoveSession(200)

		assert.Equal(t, 2, router.SessionCount())
		assert.NotNil(t, router.GetSession(100))
		assert.Nil(t, router.GetSession(200))
		assert.NotNil(t, router.GetSession(300))
	})
}

// TestPacketRouter_GetSession tests retrieving sessions from the router.
func TestPacketRouter_GetSession(t *testing.T) {
	t.Run("ExistingSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		conn := createMockSSU2Conn(t, 12345)
		require.NoError(t, router.AddSession(conn))

		retrieved := router.GetSession(12345)
		assert.Equal(t, conn, retrieved)
	})

	t.Run("NonExistentSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		retrieved := router.GetSession(99999)
		assert.Nil(t, retrieved)
	})
}

// TestPacketRouter_ExtractConnectionID tests connection ID extraction from headers.
func TestPacketRouter_ExtractConnectionID(t *testing.T) {
	router := NewPacketRouter(nil)

	t.Run("ValidShortHeader", func(t *testing.T) {
		// Create 16-byte header with destination connection ID in bytes 0-7
		header := make([]byte, 16)
		// Set connection ID to 0x0123456789ABCDEF
		header[0] = 0x01
		header[1] = 0x23
		header[2] = 0x45
		header[3] = 0x67
		header[4] = 0x89
		header[5] = 0xAB
		header[6] = 0xCD
		header[7] = 0xEF

		connID, err := router.ExtractConnectionID(header)
		require.NoError(t, err)
		assert.Equal(t, uint64(0x0123456789ABCDEF), connID)
	})

	t.Run("ValidLongHeader", func(t *testing.T) {
		// Create 32-byte header with destination connection ID in bytes 0-7
		header := make([]byte, 32)
		// Set connection ID to 0xFEDCBA9876543210
		header[0] = 0xFE
		header[1] = 0xDC
		header[2] = 0xBA
		header[3] = 0x98
		header[4] = 0x76
		header[5] = 0x54
		header[6] = 0x32
		header[7] = 0x10

		connID, err := router.ExtractConnectionID(header)
		require.NoError(t, err)
		assert.Equal(t, uint64(0xFEDCBA9876543210), connID)
	})

	t.Run("HeaderTooShort", func(t *testing.T) {
		header := make([]byte, 8) // Less than 16 bytes

		connID, err := router.ExtractConnectionID(header)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header too short")
		assert.Equal(t, uint64(0), connID)
	})

	t.Run("EmptyHeader", func(t *testing.T) {
		header := []byte{}

		connID, err := router.ExtractConnectionID(header)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header too short")
		assert.Equal(t, uint64(0), connID)
	})

	t.Run("ZeroConnectionID", func(t *testing.T) {
		// Connection ID 0 is valid (used during handshake)
		header := make([]byte, 16)
		// Leave bytes 8-15 as zeros

		connID, err := router.ExtractConnectionID(header)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), connID)
	})
}

// TestPacketRouter_IsHandshakePacket tests handshake packet detection.
func TestPacketRouter_IsHandshakePacket(t *testing.T) {
	router := NewPacketRouter(nil)

	tests := []struct {
		name     string
		msgType  uint8
		expected bool
	}{
		{"SessionRequest", MessageTypeSessionRequest, true},
		{"TokenRequest", MessageTypeTokenRequest, true},
		{"SessionCreated", MessageTypeSessionCreated, false},
		{"SessionConfirmed", MessageTypeSessionConfirmed, false},
		{"Data", MessageTypeData, false},
		{"PeerTest", MessageTypePeerTest, false},
		{"Retry", MessageTypeRetry, false},
		{"HolePunch", MessageTypeHolePunch, false},
		{"InvalidType", uint8(255), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := router.IsHandshakePacket(tt.msgType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPacketRouter_RoutePacket tests packet routing logic.
func TestPacketRouter_RoutePacket(t *testing.T) {
	t.Run("NilPacket", func(t *testing.T) {
		router := NewPacketRouter(nil)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(nil, addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "packet cannot be nil")
	})

	t.Run("NilRemoteAddr", func(t *testing.T) {
		router := NewPacketRouter(nil)
		packet := createMockPacket(t, MessageTypeData, 12345)

		err := router.RoutePacket(packet, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remote address cannot be nil")
	})

	t.Run("ExistingSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Add session
		conn := createMockSSU2Conn(t, 12345)
		require.NoError(t, router.AddSession(conn))

		// Route packet to existing session
		packet := createMockPacket(t, MessageTypeData, 12345)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(packet, addr)
		require.NoError(t, err)
	})

	t.Run("NoSessionNoHandler", func(t *testing.T) {
		router := NewPacketRouter(nil)

		packet := createMockPacket(t, MessageTypeSessionRequest, 12345)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(packet, addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no handler registered for new sessions")
	})

	t.Run("HandshakePacketCreatesSession", func(t *testing.T) {
		var handlerCalled bool
		var receivedAddr *net.UDPAddr
		var receivedPacket *SSU2Packet

		var router *PacketRouter
		// Production newSessionHandler is responsible for registering the
		// session in the router (via registerAndQueueConn → AddSession).
		// RoutePacket no longer calls AddSession itself (AUDIT 1.2 / 3.2).
		handler := func(addr *net.UDPAddr, pkt *SSU2Packet) (*SSU2Conn, error) {
			handlerCalled = true
			receivedAddr = addr
			receivedPacket = pkt
			conn := createMockSSU2Conn(t, 12345)
			// Mimic production: handler registers the session.
			if err := router.AddSession(conn); err != nil {
				return nil, err
			}
			return conn, nil
		}

		router = NewPacketRouter(handler)

		packet := createMockPacket(t, MessageTypeSessionRequest, 12345)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(packet, addr)
		require.NoError(t, err)

		assert.True(t, handlerCalled)
		assert.Equal(t, addr, receivedAddr)
		assert.Equal(t, packet, receivedPacket)
		assert.Equal(t, 1, router.SessionCount())
	})

	t.Run("NonHandshakePacketNoSession", func(t *testing.T) {
		router := NewPacketRouter(nil)

		packet := createMockPacket(t, MessageTypeData, 99999)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(packet, addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no session found for connection ID")
	})

	t.Run("InvalidHeader", func(t *testing.T) {
		router := NewPacketRouter(nil)

		// Create packet with invalid header (too short)
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Header:      make([]byte, 8), // Too short
		}
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		err := router.RoutePacket(packet, addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header too short")
	})
}

// TestPacketRouter_Concurrent tests thread safety with concurrent operations.
func TestPacketRouter_Concurrent(t *testing.T) {
	router := NewPacketRouter(nil)
	numGoroutines := 100
	numOpsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				// Start from 1 to avoid connection ID 0 (reserved for handshake)
				connID := uint64(id*numOpsPerGoroutine + j + 1)
				conn := createMockSSU2Conn(t, connID)
				_ = router.AddSession(conn)
			}
		}(i)
	}

	wg.Wait()

	// Verify sessions were added (some may have failed due to duplicates, but most should succeed)
	count := router.SessionCount()
	assert.Greater(t, count, 0)

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				connID := uint64(id*numOpsPerGoroutine + j + 1)
				_ = router.GetSession(connID)
			}
		}(i)
	}

	wg.Wait()

	// Concurrent removes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				connID := uint64(id*numOpsPerGoroutine + j + 1)
				router.RemoveSession(connID)
			}
		}(i)
	}

	wg.Wait()

	// After all removes, count should be 0
	assert.Equal(t, 0, router.SessionCount())
}

// createMockSSU2Conn creates a mock SSU2Conn for testing purposes.
func createMockSSU2Conn(t *testing.T, connID uint64) *SSU2Conn {
	t.Helper()

	routerHash := generateRandomHash()

	addr, err := NewSSU2Addr(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555},
		routerHash,
		connID,
		"initiator",
	)
	require.NoError(t, err)

	return &SSU2Conn{
		ssu2Addr: addr,
	}
}

// createMockPacket creates a mock SSU2Packet for testing purposes.
func createMockPacket(t *testing.T, msgType uint8, connID uint64) *SSU2Packet {
	t.Helper()

	// Create header with destination connection ID in bytes 0-7 (big-endian)
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[0:8], connID)

	return &SSU2Packet{
		MessageType: msgType,
		Header:      header,
		Payload:     make([]byte, 0),
		MAC:         make([]byte, 16),
	}
}
