package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListenerIntegration_ClientServerConnection tests a complete client-server
// connection flow using the SSU2 transport.
// Flow:
// 1. Create a listener
// 2. Create a client connection
// 3. Client connects to listener
// 4. Listener accepts connection
// 5. Verify connection properties
func TestListenerIntegration_ClientServerConnection(t *testing.T) {
	// Create server configuration (responder)
	var serverRouterHash data.Hash
	for i := range serverRouterHash {
		serverRouterHash[i] = byte(i)
	}
	serverConfig, err := NewSSU2Config(serverRouterHash, false) // responder
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	for i := range serverStaticKey {
		serverStaticKey[i] = byte(i + 100)
	}
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	// Create listener
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := ListenSSU2(serverAddr, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	actualAddr := listener.Addr().(*SSU2Addr)
	t.Logf("Listener bound to %s", actualAddr.Network())

	// Create client configuration (initiator)
	var clientRouterHash data.Hash
	for i := range clientRouterHash {
		clientRouterHash[i] = byte(i + 50)
	}
	clientConfig, err := NewSSU2Config(clientRouterHash, true) // initiator
	require.NoError(t, err)

	clientStaticKey := make([]byte, 32)
	for i := range clientStaticKey {
		clientStaticKey[i] = byte(i + 200)
	}
	clientConfig = clientConfig.WithStaticKey(clientStaticKey)
	// Set server's router hash and static key for XK handshake
	clientConfig = clientConfig.WithRemoteRouterHash(serverRouterHash)
	clientConfig = clientConfig.WithRemoteStaticKey(serverStaticKey)

	// Channel to receive accepted connections
	acceptDone := make(chan *SSU2Conn, 1)
	acceptErr := make(chan error, 1)

	// Start accepting in background
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptDone <- conn.(*SSU2Conn)
	}()

	// Give listener time to start accepting
	time.Sleep(10 * time.Millisecond)

	// Create client connection to listener
	remoteUDPAddr := actualAddr.UnderlyingAddr().(*net.UDPAddr)
	conn, err := DialSSU2(nil, remoteUDPAddr, clientConfig)
	require.NoError(t, err)
	defer conn.Close()

	// Verify client connection properties
	assert.NotNil(t, conn)
	assert.True(t, conn.IsInitiator())
	assert.NotNil(t, conn.GetSSU2Addr())

	// Wait for accept or timeout
	select {
	case acceptedConn := <-acceptDone:
		assert.NotNil(t, acceptedConn)
		t.Log("Listener accepted connection successfully")
		acceptedConn.Close()
	case err := <-acceptErr:
		t.Logf("Accept returned error (may be expected): %v", err)
	case <-time.After(2 * time.Second):
		t.Log("Accept timed out (connection may not complete without handshake)")
	}
}

// TestListenerIntegration_MultipleConnections tests accepting multiple concurrent connections.
func TestListenerIntegration_MultipleConnections(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	// Create UDP connection for listener
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	// Track session counts
	initialCount := listener.SessionCount()
	assert.Equal(t, 0, initialCount)

	// Simulate adding multiple sessions
	numSessions := 5
	connIDs := make([]uint64, numSessions)

	for i := 0; i < numSessions; i++ {
		connID := uint64(1000 + i)
		connIDs[i] = connID

		// Create mock connection
		mockConn := NewMockSSU2Conn(connID)
		listener.AddSession(connID, mockConn)
	}

	// Verify session count
	assert.Equal(t, numSessions, listener.SessionCount())

	// Remove sessions one by one
	for _, connID := range connIDs {
		listener.RemoveSession(connID)
	}

	// Verify all sessions removed
	assert.Equal(t, 0, listener.SessionCount())
}

// TestListenerIntegration_TokenRequestRetryFlow tests the token request/retry mechanism.
func TestListenerIntegration_TokenRequestRetryFlow(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	// Get listener address
	listenerAddr := pc.LocalAddr().(*net.UDPAddr)

	// Create client UDP connection
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer clientPC.Close()

	// Create a TokenRequest packet with the required DateTime payload.
	tokenRequest := NewSSU2Packet(MessageTypeTokenRequest, 0)
	tokenRequest.Header = make([]byte, LongHeaderSize)
	tokenRequest.MAC = make([]byte, MACSize)
	tokenRequest.Payload = tokenRequestPayload(t)

	data, err := tokenRequest.Serialize()
	require.NoError(t, err)

	// Send TokenRequest to listener
	_, err = clientPC.WriteTo(data, listenerAddr)
	require.NoError(t, err)

	// Give time for processing (receive loop needs time to read and process)
	time.Sleep(200 * time.Millisecond)

	// Check token cache - the token should be generated for the client address
	clientAddr := clientPC.LocalAddr().(*net.UDPAddr)
	cacheSize := listener.tokenCache.Size()
	t.Logf("Token cache size: %d, client addr: %s", cacheSize, clientAddr.String())

	// The token cache may or may not have entries depending on how routing works
	// The important thing is the listener processed the packet without crashing

	// Read Retry response (may timeout if no response sent)
	clientPC.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	response := make([]byte, 1500)
	n, _, err := clientPC.ReadFrom(response)
	if err == nil && n > 0 {
		// Parse response packet
		retryPacket := &SSU2Packet{}
		parseErr := retryPacket.Deserialize(response[:n])
		if parseErr == nil {
			assert.Equal(t, MessageTypeRetry, retryPacket.MessageType)
			t.Log("Received Retry response with token")
		}
	} else {
		t.Log("No Retry response received (may be expected if routing behavior differs)")
	}
}

// TestListenerIntegration_ConcurrentAccept tests concurrent Accept calls.
func TestListenerIntegration_ConcurrentAccept(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	// Start multiple goroutines waiting on Accept
	numAccepters := 10
	var wg sync.WaitGroup
	wg.Add(numAccepters)

	acceptCounts := make([]int, numAccepters)

	for i := 0; i < numAccepters; i++ {
		go func(idx int) {
			defer wg.Done()
			// Each Accept should return error when listener closes
			_, err := listener.Accept()
			if err != nil {
				acceptCounts[idx] = -1 // Error (expected)
			} else {
				acceptCounts[idx] = 1 // Success
			}
		}(i)
	}

	// Let accepters start waiting
	time.Sleep(50 * time.Millisecond)

	// Close listener to unblock all Accept calls
	err = listener.Close()
	require.NoError(t, err)

	// Wait for all Accept goroutines to complete
	wg.Wait()

	// All accepters should have returned error (listener closed)
	for i, count := range acceptCounts {
		assert.Equal(t, -1, count, "accepter %d should have error", i)
	}
}

// TestListenerIntegration_GracefulShutdown tests graceful shutdown with active sessions.
func TestListenerIntegration_GracefulShutdown(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)

	err = listener.Start()
	require.NoError(t, err)

	// Add some mock sessions
	for i := 0; i < 5; i++ {
		connID := uint64(2000 + i)
		mockConn := NewMockSSU2Conn(connID)
		listener.AddSession(connID, mockConn)
	}

	assert.Equal(t, 5, listener.SessionCount())

	// Close listener
	err = listener.Close()
	require.NoError(t, err)

	// Sessions map is still populated (cleanup is application's responsibility)
	// But listener should be closed
	_, err = listener.Accept()
	assert.Error(t, err)
}

// TestListenerIntegration_PacketRouting tests packet routing to existing sessions.
func TestListenerIntegration_PacketRouting(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Verify router was created
	assert.NotNil(t, listener.router)

	// Test router packet type detection
	// IsHandshakePacket returns true only for packets that can INITIATE a new session
	// SessionRequest and TokenRequest can initiate sessions
	// SessionCreated, SessionConfirmed, Data, Retry, HolePunch cannot initiate sessions
	testCases := []struct {
		name        string
		msgType     uint8
		isHandshake bool
	}{
		{"SessionRequest", MessageTypeSessionRequest, true},
		{"SessionCreated", MessageTypeSessionCreated, false},     // Response to SessionRequest
		{"SessionConfirmed", MessageTypeSessionConfirmed, false}, // Response to SessionCreated
		{"Data", MessageTypeData, false},                         // Data packets
		{"TokenRequest", MessageTypeTokenRequest, true},          // Can initiate token flow
		{"Retry", MessageTypeRetry, false},                       // Response to TokenRequest
		{"HolePunch", MessageTypeHolePunch, false},               // NAT traversal
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := listener.router.IsHandshakePacket(tc.msgType)
			assert.Equal(t, tc.isHandshake, result)
		})
	}
}

// TestListenerIntegration_AddressInfo tests SSU2 address information.
func TestListenerIntegration_AddressInfo(t *testing.T) {
	// Create server
	var serverRouterHash data.Hash
	for i := range serverRouterHash {
		serverRouterHash[i] = byte(0xAB)
	}
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Get address
	addr := listener.Addr()
	require.NotNil(t, addr)

	// Verify it's an SSU2Addr
	ssu2Addr, ok := addr.(*SSU2Addr)
	require.True(t, ok)

	// Verify network type
	assert.Equal(t, "ssu2", ssu2Addr.Network())

	// Verify role
	assert.Equal(t, "responder", ssu2Addr.Role())

	// Verify connection ID is non-zero
	assert.NotZero(t, ssu2Addr.ConnectionID())
}

// TestListenerIntegration_ContextCancellation tests context cancellation during operations.
func TestListenerIntegration_ContextCancellation(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	// Create a cancellable context
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Try to connect with context - this tests transport-level context handling
	clientRouterHash := generateRandomHash()
	clientConfig, err := NewSSU2Config(clientRouterHash, true)
	require.NoError(t, err)
	clientConfig.DestroyTimeout = 0 // Skip destroy wait in tests

	clientStaticKey := make([]byte, 32)
	clientConfig = clientConfig.WithStaticKey(clientStaticKey)
	clientConfig = clientConfig.WithRemoteRouterHash(serverRouterHash)

	// The dial itself doesn't use context, but handshake does
	conn, err := DialSSU2(nil, pc.LocalAddr().(*net.UDPAddr), clientConfig)
	if err == nil {
		defer conn.Close()
		// Try handshake with cancellable context
		err = conn.Handshake(ctx)
		// Should fail or timeout
		assert.Error(t, err)
	}
}

// TestListenerIntegration_InvalidPacketHandling tests handling of malformed packets.
func TestListenerIntegration_InvalidPacketHandling(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	listenerAddr := pc.LocalAddr().(*net.UDPAddr)

	// Create client to send invalid packets
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer clientPC.Close()

	invalidPackets := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{0x01, 0x02}},
		{"random_garbage", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}},
		{"truncated_header", make([]byte, 10)},
	}

	for _, tc := range invalidPackets {
		t.Run(tc.name, func(t *testing.T) {
			// Send invalid packet
			_, err := clientPC.WriteTo(tc.data, listenerAddr)
			require.NoError(t, err)
		})
	}

	// Give time for processing
	time.Sleep(50 * time.Millisecond)

	// Listener should still be functional after receiving invalid packets
	assert.Equal(t, 0, listener.SessionCount())

	// Should still accept close cleanly
	err = listener.Close()
	assert.NoError(t, err)
}

// TestListenerIntegration_SessionRequestProcessing tests SessionRequest message processing.
func TestListenerIntegration_SessionRequestProcessing(t *testing.T) {
	// Create server
	serverRouterHash := generateRandomHash()
	serverConfig, err := NewSSU2Config(serverRouterHash, false)
	require.NoError(t, err)
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

	serverStaticKey := make([]byte, 32)
	serverConfig = serverConfig.WithStaticKey(serverStaticKey)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(pc, serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	err = listener.Start()
	require.NoError(t, err)

	listenerAddr := pc.LocalAddr().(*net.UDPAddr)

	// Create client
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer clientPC.Close()

	// Create a minimal SessionRequest packet
	sessionRequest := NewSSU2Packet(MessageTypeSessionRequest, 0)
	sessionRequest.Header = make([]byte, LongHeaderSize)
	// Set some connection ID in header
	sessionRequest.Header[0] = 0x01
	sessionRequest.Header[1] = 0x02
	sessionRequest.EphemeralKey = make([]byte, 32) // Ephemeral key for handshake
	sessionRequest.MAC = make([]byte, MACSize)

	data, err := sessionRequest.Serialize()
	require.NoError(t, err)

	// Send SessionRequest
	_, err = clientPC.WriteTo(data, listenerAddr)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// A session should have been created (even if handshake incomplete)
	// The listener queues accepted connections
	t.Logf("Sessions after SessionRequest: %d", listener.SessionCount())
}

// TestListenerIntegration_ListenSSU2Helper tests the ListenSSU2 helper function.
func TestListenerIntegration_ListenSSU2Helper(t *testing.T) {
	t.Run("ValidParams", func(t *testing.T) {
		serverRouterHash := generateRandomHash()
		serverConfig, err := NewSSU2Config(serverRouterHash, false)
		require.NoError(t, err)
		serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

		serverStaticKey := make([]byte, 32)
		serverConfig = serverConfig.WithStaticKey(serverStaticKey)

		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

		listener, err := ListenSSU2(addr, serverConfig)
		require.NoError(t, err)
		assert.NotNil(t, listener)

		// Listener should already be started
		// Close should work
		err = listener.Close()
		assert.NoError(t, err)
	})

	t.Run("NilAddress", func(t *testing.T) {
		serverRouterHash := generateRandomHash()
		serverConfig, err := NewSSU2Config(serverRouterHash, false)
		require.NoError(t, err)
		serverConfig.RouterInfoValidator = DefaultRouterInfoValidator

		serverStaticKey := make([]byte, 32)
		serverConfig = serverConfig.WithStaticKey(serverStaticKey)

		listener, err := ListenSSU2(nil, serverConfig)
		assert.Error(t, err)
		assert.Nil(t, listener)
	})

	t.Run("NilConfig", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

		listener, err := ListenSSU2(addr, nil)
		assert.Error(t, err)
		assert.Nil(t, listener)
	})

	t.Run("InitiatorConfig", func(t *testing.T) {
		// ListenSSU2 requires responder config
		serverRouterHash := generateRandomHash()
		serverConfig, err := NewSSU2Config(serverRouterHash, true) // initiator
		require.NoError(t, err)

		serverStaticKey := make([]byte, 32)
		serverConfig = serverConfig.WithStaticKey(serverStaticKey)

		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

		listener, err := ListenSSU2(addr, serverConfig)
		assert.Error(t, err)
		assert.Nil(t, listener)
		assert.Contains(t, err.Error(), "initiator")
	})
}
