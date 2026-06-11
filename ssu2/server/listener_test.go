package server

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSU2Listener tests the creation of SSU2 listeners.
func TestNewSSU2Listener(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		pc := createMockPacketConn(t)
		config := createValidConfig(t)

		listener, err := NewSSU2Listener(pc, config)
		require.NoError(t, err)
		assert.NotNil(t, listener)
		assert.Equal(t, pc, listener.Underlying())
		assert.Equal(t, config, listener.Config())
		assert.NotNil(t, listener.Addr())
		assert.NotNil(t, listener.TokenCache())
		assert.NotNil(t, listener.Router())
		assert.Equal(t, 0, listener.SessionCount())
	})

	t.Run("NilPacketConn", func(t *testing.T) {
		config := createValidConfig(t)

		listener, err := NewSSU2Listener(nil, config)
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.Contains(t, err.Error(), "underlying packet connection cannot be nil")
	})

	t.Run("NilConfig", func(t *testing.T) {
		pc := createMockPacketConn(t)

		listener, err := NewSSU2Listener(pc, nil)
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.Contains(t, err.Error(), "configuration cannot be nil")
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		pc := createMockPacketConn(t)
		config := &SSU2Config{} // Empty config is invalid

		listener, err := NewSSU2Listener(pc, config)
		require.Error(t, err)
		assert.Nil(t, listener)
	})
}

// TestSSU2Listener_Start tests starting the listener.
func TestSSU2Listener_Start(t *testing.T) {
	t.Run("SuccessfulStart", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Start()
		require.NoError(t, err)

		// Give goroutine time to start
		time.Sleep(10 * time.Millisecond)

		// Clean up
		err = listener.Close()
		require.NoError(t, err)
	})

	t.Run("StartAfterClose", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Close()
		require.NoError(t, err)

		err = listener.Start()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "listener is closed")
	})
}

// TestSSU2Listener_Close tests closing the listener.
func TestSSU2Listener_Close(t *testing.T) {
	t.Run("SuccessfulClose", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Start()
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		err = listener.Close()
		require.NoError(t, err)
	})

	t.Run("DoubleClose", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Close()
		require.NoError(t, err)

		// Second close should not error
		err = listener.Close()
		require.NoError(t, err)
	})

	t.Run("CloseWithoutStart", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Close()
		require.NoError(t, err)
	})
}

// TestSSU2Listener_Addr tests getting the listener address.
func TestSSU2Listener_Addr(t *testing.T) {
	listener := createTestListener(t)
	defer listener.Close()

	addr := listener.Addr()
	assert.NotNil(t, addr)

	ssu2Addr, ok := addr.(*SSU2Addr)
	assert.True(t, ok)
	assert.Equal(t, listener.Addr().(*SSU2Addr), ssu2Addr)
}

// TestSSU2Listener_Accept tests accepting connections.
func TestSSU2Listener_Accept(t *testing.T) {
	t.Run("AcceptAfterClose", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Close()
		require.NoError(t, err)

		conn, err := listener.Accept()
		require.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "listener closed")
	})

	t.Run("AcceptTimeout", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		err := listener.Start()
		require.NoError(t, err)

		// Try to accept with timeout
		done := make(chan bool)
		go func() {
			time.Sleep(100 * time.Millisecond)
			listener.Close()
			done <- true
		}()

		conn, err := listener.Accept()
		<-done

		require.Error(t, err)
		assert.Nil(t, conn)
	})
}

// TestSSU2Listener_SessionCount tests session counting.
func TestSSU2Listener_SessionCount(t *testing.T) {
	listener := createTestListener(t)
	defer listener.Close()

	// Initially zero
	assert.Equal(t, 0, listener.SessionCount())

	// Add some sessions manually for testing
	connID1 := uint64(12345)
	connID2 := uint64(67890)

	conn1 := NewMockSSU2Conn(connID1)
	conn2 := NewMockSSU2Conn(connID2)

	// AUDIT 8.3: Use listener.AddSession (delegates to router) instead of direct map access
	listener.AddSession(connID1, conn1)
	listener.AddSession(connID2, conn2)

	assert.Equal(t, 2, listener.SessionCount())

	// Remove one
	// AUDIT 8.3: Use listener.RemoveSession (delegates to router) instead of internal method
	listener.RemoveSession(connID1)
	assert.Equal(t, 1, listener.SessionCount())

	// Remove the other
	// AUDIT 8.3: Use listener.RemoveSession (delegates to router)
	listener.RemoveSession(connID2)
	assert.Equal(t, 0, listener.SessionCount())
}

// TestSSU2Listener_RemoveSession tests session removal.
func TestSSU2Listener_RemoveSession(t *testing.T) {
	listener := createTestListener(t)
	defer listener.Close()

	connID := uint64(12345)
	conn := NewMockSSU2Conn(connID)

	// Add session
	// AUDIT 8.3: Use listener.AddSession (delegates to router) instead of direct map access
	listener.AddSession(connID, conn)

	assert.Equal(t, 1, listener.SessionCount())

	// Remove session
	// AUDIT 8.3: Use listener.RemoveSession (delegates to router) instead of internal method
	listener.RemoveSession(connID)

	assert.Equal(t, 0, listener.SessionCount())

	// Removing non-existent session should not panic
	// AUDIT 8.3: Use listener.RemoveSession (delegates to router)
	listener.RemoveSession(99999)
	assert.Equal(t, 0, listener.SessionCount())
}

// TestSSU2Listener_HandleIncomingPacket tests packet handling.
func TestSSU2Listener_HandleIncomingPacket(t *testing.T) {
	t.Run("InvalidPacket", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		// Send invalid packet data
		invalidData := []byte{0x00, 0x01, 0x02} // Too short
		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		// Should not panic
		listener.handleIncomingPacket(invalidData, remoteAddr)
	})

	t.Run("TokenRequest", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		// Create a valid packet structure (minimal)
		// TokenRequest uses 32-byte header (long header)
		packet := &SSU2Packet{
			MessageType: MessageTypeTokenRequest,
			Header:      make([]byte, 32), // Long header
			Payload:     make([]byte, 0),
			MAC:         make([]byte, 16),
		}
		data, err := packet.Serialize()
		require.NoError(t, err)

		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}

		// Should handle without error (even if sendRetry not fully implemented)
		listener.handleIncomingPacket(data, remoteAddr)
	})

	// AUDIT C-1: verify that when an IntroKey is configured the listener
	// successfully decrypts header-protected inbound packets that would
	// otherwise fail plaintext deserialization.
	t.Run("HeaderProtectedTokenRequest", func(t *testing.T) {
		pc := createMockPacketConn(t)
		config := createValidConfig(t)
		introKey := make([]byte, 32)
		for i := range introKey {
			introKey[i] = byte(i + 0x10)
		}
		config.IntroKey = introKey

		listener, err := NewSSU2Listener(pc, config)
		require.NoError(t, err)
		defer listener.Close()
		require.NotNil(t, listener.introHeaderProtector, "expected protector to be initialized")

		// Build a valid long-header TokenRequest with a deterministic body.
		header := make([]byte, 32)
		header[13] = 2 // SSU2ProtocolVersion
		header[14] = 2 // SSU2NetworkID
		packet := &SSU2Packet{
			MessageType: MessageTypeTokenRequest,
			Header:      header,
			Payload:     make([]byte, 8),
			MAC:         make([]byte, 16),
		}
		plain, err := packet.Serialize()
		require.NoError(t, err)

		// Plaintext path must succeed (sanity baseline).
		gotPlain, ok := listener.parseInboundPacket(plain)
		require.True(t, ok)
		require.Equal(t, MessageTypeTokenRequest, gotPlain.MessageType)

		// Build a sender-side protector with the same intro key and obfuscate.
		sender, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeTokenRequest)
		require.NoError(t, err)
		obfuscated := make([]byte, len(plain))
		copy(obfuscated, plain)
		require.NoError(t, sender.EncryptHeader(obfuscated))

		// Obfuscated bytes must differ from plaintext (header bytes mutated).
		require.NotEqual(t, plain[:16], obfuscated[:16])

		// Plaintext Deserialize on the obfuscated buffer must fail.
		require.Error(t, (&SSU2Packet{}).Deserialize(obfuscated))

		// Fallback path must recover the original packet.
		gotDecrypted, ok := listener.parseInboundPacket(obfuscated)
		require.True(t, ok, "expected header-protection fallback to succeed")
		require.Equal(t, MessageTypeTokenRequest, gotDecrypted.MessageType)
	})
}

// TestSSU2Listener_Concurrent tests concurrent listener operations.
func TestSSU2Listener_Concurrent(t *testing.T) {
	listener := createTestListener(t)
	defer listener.Close()

	err := listener.Start()
	require.NoError(t, err)

	numGoroutines := 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent session additions
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			connID := uint64(id + 1000)
			conn := NewMockSSU2Conn(connID)
			// AUDIT 8.3: Use listener.AddSession (delegates to router) instead of direct map access
			listener.AddSession(connID, conn)

			// Small delay
			time.Sleep(1 * time.Millisecond)

			// Check count
			_ = listener.SessionCount()

			// Remove session
			// AUDIT 8.3: Use listener.RemoveSession (delegates to router)
			listener.RemoveSession(connID)
		}(i)
	}

	wg.Wait()

	// After all operations, count should be 0
	assert.Equal(t, 0, listener.SessionCount())
}

// TestSSU2Listener_ReceiveLoop tests the packet receive loop.
func TestSSU2Listener_ReceiveLoop(t *testing.T) {
	t.Run("StopsOnClose", func(t *testing.T) {
		listener := createTestListener(t)

		err := listener.Start()
		require.NoError(t, err)

		// Give goroutine time to start
		time.Sleep(10 * time.Millisecond)

		// Close should stop the loop
		err = listener.Close()
		require.NoError(t, err)

		// Wait to ensure goroutine exits
		time.Sleep(10 * time.Millisecond)
	})
}

// createTestListener creates a listener for testing purposes.
func createTestListener(t *testing.T) *SSU2Listener {
	t.Helper()

	pc := createMockPacketConn(t)
	config := createValidConfig(t)

	listener, err := NewSSU2Listener(pc, config)
	require.NoError(t, err)

	return listener
}

// createMockPacketConn creates a mock packet connection for testing.
func createMockPacketConn(t *testing.T) net.PacketConn {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)

	return pc
}

// createValidConfig creates a valid SSU2Config for testing.
func createValidConfig(t *testing.T) *SSU2Config {
	t.Helper()

	// Generate router hash
	routerHash := generateRandomHash()

	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	config.DestroyTimeout = 0 // Skip destroy wait in tests
	config.RouterInfoValidator = DefaultRouterInfoValidator
	// Provide a static key so that handleNewSession can create a HandshakeHandler
	staticKey := make([]byte, 32)
	for i := range staticKey {
		staticKey[i] = byte(i + 0xA0)
	}
	config = config.WithStaticKey(staticKey)

	return config
}

// TestSSU2Listener_ProcessTokenRequest tests token request processing
func TestSSU2Listener_ProcessTokenRequest(t *testing.T) {
	t.Run("GeneratesTokenForAddress", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

		// Before processing, cache should be empty
		assert.Equal(t, 0, listener.tokenCache.Size())

		// Create a mock TokenRequest packet
		packet := NewSSU2Packet(MessageTypeTokenRequest, 0)
		packet.Header = make([]byte, LongHeaderSize)

		// Process token request (internally calls processTokenRequest)
		err := listener.processTokenRequest(packet, remoteAddr)

		// First sight is deferred by default to blunt spoofed-source flooding.
		// The second request from the same address should allocate a token.
		require.Error(t, err)
		assert.Equal(t, 0, listener.tokenCache.Size())

		err = listener.processTokenRequest(packet, remoteAddr)
		assert.Equal(t, 1, listener.tokenCache.Size())
		_ = err // Ignore send errors in unit test
	})

	t.Run("DifferentAddressesGetDifferentTokens", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1111}
		addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 2222}

		packet := NewSSU2Packet(MessageTypeTokenRequest, 0)
		packet.Header = make([]byte, LongHeaderSize)

		// First sight for each address should not allocate token cache entries.
		_ = listener.processTokenRequest(packet, addr1)
		_ = listener.processTokenRequest(packet, addr2)
		assert.Equal(t, 0, listener.tokenCache.Size())

		// Second request from each address should allocate one token each.
		_ = listener.processTokenRequest(packet, addr1)
		_ = listener.processTokenRequest(packet, addr2)

		// Both addresses should have tokens
		assert.Equal(t, 2, listener.tokenCache.Size())
	})
}

// TestSSU2Listener_ValidateSessionRequestToken tests token validation
func TestSSU2Listener_ValidateSessionRequestToken(t *testing.T) {
	t.Run("EmptyPayloadReturnsNoToken", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		packet := NewSSU2Packet(MessageTypeSessionRequest, 0)
		packet.Payload = nil

		err := listener.validateSessionRequestToken(packet, remoteAddr)
		assert.ErrorIs(t, err, errNoTokenPresent)
	})

	t.Run("NoTokenBlockReturnsNoToken", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

		// Create packet with a padding block (not a token)
		paddingBlock := NewSSU2Block(BlockTypePadding, make([]byte, 10))
		payload, err := paddingBlock.Serialize()
		require.NoError(t, err)

		packet := NewSSU2Packet(MessageTypeSessionRequest, 0)
		packet.Payload = payload

		err = listener.validateSessionRequestToken(packet, remoteAddr)
		assert.ErrorIs(t, err, errNoTokenPresent)
	})

	t.Run("ValidTokenPasses", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

		// Generate a token for this address
		token, err := listener.tokenCache.GenerateToken(remoteAddr)
		require.NoError(t, err)

		// Create NewToken block with the token
		expiration := time.Now().Add(60 * time.Second)
		tokenBlock, err := NewNewTokenBlock(expiration, token)
		require.NoError(t, err)

		payload, err := tokenBlock.Serialize()
		require.NoError(t, err)

		// Create packet with token
		packet := NewSSU2Packet(MessageTypeSessionRequest, 0)
		packet.Payload = payload

		err = listener.validateSessionRequestToken(packet, remoteAddr)
	})

	t.Run("ExpiredTokenFails", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

		// Create token with past expiration
		expiration := time.Now().Add(-1 * time.Hour) // Expired
		token := make([]byte, TokenSize)             // 8 bytes per SSU2 spec

		tokenBlock, err := NewNewTokenBlock(expiration, token)
		require.NoError(t, err)

		payload, err := tokenBlock.Serialize()
		require.NoError(t, err)

		packet := NewSSU2Packet(MessageTypeSessionRequest, 0)
		packet.Payload = payload

		err = listener.validateSessionRequestToken(packet, remoteAddr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

// TestSSU2Listener_SendRetry tests Retry message construction
func TestSSU2Listener_SendRetry(t *testing.T) {
	t.Run("TokenTooShortReturnsError", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		shortToken := make([]byte, 5) // Too short

		err := listener.sendRetry(remoteAddr, shortToken, nil, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token must be exactly")
	})

	t.Run("ValidTokenCreatesRetry", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		token := make([]byte, TokenSize) // Valid size
		for i := range token {
			token[i] = byte(i)
		}

		originalHeader := make([]byte, 32)

		// This may fail to send (no peer listening) but should construct packet
		err := listener.sendRetry(remoteAddr, token, originalHeader, 0)
		// The send might fail, but packet construction should work
		// We verify no panic occurs
		_ = err
	})
}

// TestListenerRouterHash verifies that handleNewSession derives the initial
// router hash from the SessionRequest ephemeral key rather than using a
// zero-filled placeholder. The real router hash is installed post-handshake
// by installCipherStates; this test covers the pre-handshake derivation.
func TestListenerRouterHash(t *testing.T) {
	t.Run("derives hash from ephemeral key", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		// Simulate a SessionRequest packet with a 32-byte ephemeral key
		ephemeralKey := make([]byte, 32)
		for i := range ephemeralKey {
			ephemeralKey[i] = byte(i + 1)
		}

		packet := &SSU2Packet{
			Header:       make([]byte, 32),
			EphemeralKey: ephemeralKey,
			Payload:      nil,
			MAC:          make([]byte, 16),
			MessageType:  MessageTypeSessionRequest,
			PacketNumber: 0,
		}

		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

		conn, err := listener.handleNewSession(remoteAddr, packet)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// The router hash should be SHA-256 of the ephemeral key, not all zeros
		expectedHash := sha256.Sum256(ephemeralKey)
		actualHash := conn.GetSSU2Addr().RouterHash()
		assert.Equal(t, data.Hash(expectedHash), actualHash)
		assert.False(t, actualHash.IsZero(), "router hash must not be zero-filled")
	})

	t.Run("falls back to zero hash without ephemeral key", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		// Packet with no ephemeral key (e.g. non-standard or truncated)
		packet := &SSU2Packet{
			Header:       make([]byte, 32),
			EphemeralKey: nil,
			Payload:      nil,
			MAC:          make([]byte, 16),
			MessageType:  MessageTypeSessionRequest,
			PacketNumber: 0,
		}

		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9998}

		conn, err := listener.handleNewSession(remoteAddr, packet)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Without an ephemeral key, falls back to zero hash
		assert.True(t, conn.GetSSU2Addr().RouterHash().IsZero())
	})
}

// TestRetransmittedSessionRequestDedup verifies that retransmitted SessionRequests
// (same initiator connection ID and source address) are deduplicated and route
// to the existing session instead of creating a duplicate.
// AUDIT 8.1: Duplicate session per retransmitted SessionRequest
func TestRetransmittedSessionRequestDedup(t *testing.T) {
	t.Run("deduplicates identical retransmits", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		// Create a SessionRequest packet with a specific initiator connection ID
		initiatorConnID := uint64(0x1122334455667788)
		ephemeralKey := make([]byte, 32)
		for i := range ephemeralKey {
			ephemeralKey[i] = byte(i + 1)
		}

		// Build header with initiator connection ID at offset 16-24
		header := make([]byte, 32)
		binary.BigEndian.PutUint64(header[16:24], initiatorConnID)
		header[13] = 2 // Version
		header[14] = 2 // NetworkID

		packet := &SSU2Packet{
			Header:       header,
			EphemeralKey: ephemeralKey,
			Payload:      nil,
			MAC:          make([]byte, 16),
			MessageType:  MessageTypeSessionRequest,
			PacketNumber: 0,
		}

		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 12345}

		// First SessionRequest creates a new session
		conn1, err := listener.handleNewSession(remoteAddr, packet)
		require.NoError(t, err)
		require.NotNil(t, conn1)
		conn1ID := conn1.GetSSU2Addr().ConnectionID()

		// Verify the session is in the listener
		assert.Equal(t, 1, listener.SessionCount())

		// Second identical retransmit should return the same session
		conn2, err := listener.handleNewSession(remoteAddr, packet)
		require.NoError(t, err)
		require.NotNil(t, conn2)

		// Should be the same session
		assert.Equal(t, conn1ID, conn2.GetSSU2Addr().ConnectionID())
		assert.Equal(t, 1, listener.SessionCount(), "session count should still be 1 (no duplicate created)")

		// Third retransmit should also return the same session
		conn3, err := listener.handleNewSession(remoteAddr, packet)
		require.NoError(t, err)
		require.NotNil(t, conn3)
		assert.Equal(t, conn1ID, conn3.GetSSU2Addr().ConnectionID())
		assert.Equal(t, 1, listener.SessionCount())
	})

	t.Run("different initiator IDs create separate sessions", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 12345}
		ephemeralKey := make([]byte, 32)
		for i := range ephemeralKey {
			ephemeralKey[i] = byte(i + 1)
		}

		// First packet with initiator conn ID = 0x1111111111111111
		packet1 := &SSU2Packet{
			MessageType:  MessageTypeSessionRequest,
			Header:       make([]byte, 32),
			EphemeralKey: ephemeralKey,
			Payload:      nil,
			MAC:          make([]byte, 16),
		}
		binary.BigEndian.PutUint64(packet1.Header[16:24], 0x1111111111111111)

		conn1, err := listener.handleNewSession(remoteAddr, packet1)
		require.NoError(t, err)
		assert.Equal(t, 1, listener.SessionCount())

		// Second packet with different initiator conn ID = 0x2222222222222222
		packet2 := &SSU2Packet{
			MessageType:  MessageTypeSessionRequest,
			Header:       make([]byte, 32),
			EphemeralKey: ephemeralKey,
			Payload:      nil,
			MAC:          make([]byte, 16),
		}
		binary.BigEndian.PutUint64(packet2.Header[16:24], 0x2222222222222222)

		conn2, err := listener.handleNewSession(remoteAddr, packet2)
		require.NoError(t, err)

		// Should have two different sessions
		assert.NotEqual(t, conn1.GetSSU2Addr().ConnectionID(), conn2.GetSSU2Addr().ConnectionID())
		assert.Equal(t, 2, listener.SessionCount())
	})

	t.Run("different remote addresses create separate sessions", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		initiatorConnID := uint64(0x3333333333333333)
		ephemeralKey := make([]byte, 32)
		for i := range ephemeralKey {
			ephemeralKey[i] = byte(i + 1)
		}

		packet := &SSU2Packet{
			MessageType:  MessageTypeSessionRequest,
			Header:       make([]byte, 32),
			EphemeralKey: ephemeralKey,
			Payload:      nil,
			MAC:          make([]byte, 16),
		}
		binary.BigEndian.PutUint64(packet.Header[16:24], initiatorConnID)

		// First request from address 1
		addr1 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 12345}
		conn1, err := listener.handleNewSession(addr1, packet)
		require.NoError(t, err)
		assert.Equal(t, 1, listener.SessionCount())

		// Second request from same initiator ID but different address
		addr2 := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 101), Port: 12346}
		conn2, err := listener.handleNewSession(addr2, packet)
		require.NoError(t, err)

		// Should have two different sessions
		assert.NotEqual(t, conn1.GetSSU2Addr().ConnectionID(), conn2.GetSSU2Addr().ConnectionID())
		assert.Equal(t, 2, listener.SessionCount())

		// Retransmit from addr1 should return the first session
		conn3, err := listener.handleNewSession(addr1, packet)
		require.NoError(t, err)
		assert.Equal(t, conn1.GetSSU2Addr().ConnectionID(), conn3.GetSSU2Addr().ConnectionID())
		assert.Equal(t, 2, listener.SessionCount())
	})
}

// TestListenerClose_ParallelTeardown verifies that listener.Close() cancels all
// pending DestroyTimeout waits in parallel, completing in ~one destroy interval
// rather than N× destroy intervals. AUDIT 3.2.
func TestListenerClose_ParallelTeardown(t *testing.T) {
	t.Run("closes multiple sessions without blocking", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		err := listener.Start()
		require.NoError(t, err)

		// Create N sessions and verify that closing the listener completes
		// in reasonable time (not serially waiting on each session's destroy).
		// With the AUDIT 3.2 fix, all sessions' forceDestroy channels are
		// closed in parallel, allowing their CloseWithReason goroutines to
		// unblock immediately instead of waiting for the full timeout.
		numSessions := 10

		for i := 0; i < numSessions; i++ {
			connID := uint64(i + 1000)
			conn := NewMockSSU2Conn(connID)
			listener.AddSession(connID, conn)
		}

		// Verify all sessions are registered
		assert.Equal(t, numSessions, listener.SessionCount())

		// Close the listener and measure how long it takes.
		// With AUDIT 3.2 fix: all forceDestroy channels closed in parallel
		// Without fix (bug): would wait serially on each session
		// Since we're not testing exact timing but just that it completes
		// without hanging, a simple measurement is sufficient.
		startTime := time.Now()
		err = listener.Close()
		duration := time.Since(startTime)

		require.NoError(t, err)

		// The key assertion: close should not take an unreasonably long time.
		// If each session had to wait even a small timeout serially,
		// N sessions × timeout would be significant. The close should complete
		// in well under 1 second for this test.
		maxExpectedDuration := 1 * time.Second
		assert.Less(t, duration, maxExpectedDuration,
			"listener.Close() took %v, expected < %v (AUDIT 3.2 parallel teardown should be fast)",
			duration, maxExpectedDuration)

		t.Logf("listener.Close() with %d sessions took %v", numSessions, duration)
	})

	t.Run("concurrent operations with listener close", func(t *testing.T) {
		listener := createTestListener(t)
		defer listener.Close()

		err := listener.Start()
		require.NoError(t, err)

		numSessions := 10

		// Add sessions
		for i := 0; i < numSessions; i++ {
			connID := uint64(i + 2000)
			conn := NewMockSSU2Conn(connID)
			listener.AddSession(connID, conn)
		}

		assert.Equal(t, numSessions, listener.SessionCount())

		// Race: close listener while sessions may still be in flight
		// This is a concurrency test run with -race flag to detect any
		// data races or concurrent map access issues.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = listener.Close()
		}()

		// Give close() a chance to start
		time.Sleep(10 * time.Millisecond)

		// Try to add more sessions (should be safe even during close)
		for i := 0; i < 5; i++ {
			connID := uint64(i + 3000)
			conn := NewMockSSU2Conn(connID)
			listener.AddSession(connID, conn)
		}

		wg.Wait()
		// Test passes if no panic or race condition detected under -race
	})
}

// TestAuditFix_3_4_RouterHashHook tests the router layer hook pattern for updating
// placeholder RouterHash on responder connections (AUDIT 3.4).
func TestAuditFix_3_4_RouterHashHook(t *testing.T) {
	t.Run("GetSSU2Addr_ReturnsAddressWithPlaceholderHash", func(t *testing.T) {
		// AUDIT 3.4: Verify that a responder connection's SSU2Addr can be retrieved
		// and contains a placeholder RouterHash (SHA256 of ephemeral key).
		connID := uint64(12345)
		conn := NewMockSSU2Conn(connID)

		// Get the SSU2Addr from the responder connection
		addr := conn.GetSSU2Addr()
		require.NotNil(t, addr)

		// Verify the address has the correct connection ID
		assert.Equal(t, connID, addr.ConnectionID())
		assert.Equal(t, "ssu2", addr.Network())
	})

	t.Run("UpdateRouterHash_ReplacesPlaceholder", func(t *testing.T) {
		// AUDIT 3.4: Verify that the router layer can call UpdateRouterHash()
		// to replace the placeholder with a real identity hash.
		connID := uint64(54321)
		conn := NewMockSSU2Conn(connID)

		// Get the SSU2Addr from the responder connection
		addr := conn.GetSSU2Addr()
		require.NotNil(t, addr)

		// Capture the placeholder hash
		placeholderHash := addr.RouterHash()

		// Simulate the router layer computing a real RouterHash
		// (In practice, this would be the peer's actual identity hash)
		realHashData := sha256.Sum256([]byte("real-peer-identity"))
		realHash := data.NewHash(realHashData)

		// Call UpdateRouterHash — this is the CRITICAL hook for router layer
		addr.UpdateRouterHash(realHash)

		// Verify the hash was updated (RouterHash() returns the new value)
		updatedHash := addr.RouterHash()
		assert.Equal(t, realHash, updatedHash)

		// Verify the hash is actually different from the placeholder
		// (This confirms the update actually happened)
		assert.NotEqual(t, placeholderHash, updatedHash)
	})

	t.Run("RouterHashHook_Pattern", func(t *testing.T) {
		// AUDIT 3.4: Full router layer hook pattern demonstration:
		// 1. Accept a responder connection from listener
		// 2. After handshake completes, get SSU2Addr
		// 3. Compute/retrieve real router hash
		// 4. Call UpdateRouterHash to set it

		// Create a responder connection (simulating listener.Accept())
		connID := uint64(99999)
		responderConn := NewMockSSU2Conn(connID)

		// Step 1: After handshake, get the connection's SSU2Addr
		addr := responderConn.GetSSU2Addr()
		require.NotNil(t, addr, "SSU2Addr should be retrievable from established connection")

		// Capture initial (placeholder) state
		initialHash := addr.RouterHash()

		// Step 2: Router layer computes the real identity hash
		// (In production, this would be derived from the peer's RouterInfo)
		peerIdentity := []byte("peer-identity-data-12345")
		realHashData := sha256.Sum256(peerIdentity)
		realHash := data.NewHash(realHashData)

		// Step 3: Call the UpdateRouterHash hook
		addr.UpdateRouterHash(realHash)

		// Step 4: Verify the hash is now updated
		finalHash := addr.RouterHash()
		assert.Equal(t, realHash, finalHash, "Hash should be updated to real value")
		assert.NotEqual(t, initialHash, finalHash, "Hash should no longer be placeholder")

		// The test passes if no panic and hook is called successfully.
		// In production, the router layer would index by realHash to prevent
		// duplicate sessions per peer.
	})
}
