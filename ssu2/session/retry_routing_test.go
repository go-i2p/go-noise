package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/stretchr/testify/require"
)

// TestProcessInboundPacket_RetryIsRoutedToHandshakeQueue is the focused
// regression test for the SSU2 initiator Retry bug.
//
// Root cause: processInboundPacket's type switch handled Data and the three
// Noise handshake messages (SessionRequest/SessionCreated/SessionConfirmed)
// but had NO case for MessageTypeRetry (9). The listener deobfuscates an
// inbound Retry with the responder's intro key (retryProtector) and delivers
// it to conn.ProcessInboundPacket, but the Retry fell through the switch and
// was silently dropped — it never reached recvQueue. awaitSessionCreated's
// first wait therefore timed out, retransmitted the initial token=0
// SessionRequest, and the peer (i2pd) looped on "SessionRequest token
// mismatch" until the handshake failed with
// "failed to receive SessionCreated: handshake timeout after 3 retransmits".
//
// This test pins the routing fix directly: a deobfuscated Retry packet fed to
// ProcessInboundPacket must be enqueued on recvQueue (where handleRetryResponse
// reads it), not dropped. Before the fix the recvQueue stayed empty.
func TestProcessInboundPacket_RetryIsRoutedToHandshakeQueue(t *testing.T) {
	initConn, respConn, initPriv, _, respPub, _ := setupConnPair(t)
	_ = respConn

	config := createTestConfig(t)
	config.IntroKey = make([]byte, HeaderKeySize)
	copy(config.IntroKey, testLocalStaticKey(t))
	config.RemoteIntroKey = make([]byte, HeaderKeySize)
	copy(config.RemoteIntroKey, testLocalStaticKey(t))

	conn, err := NewSSU2Conn(initConn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Build a deobfuscated Retry packet exactly as the listener hands it to the
	// session: dest conn ID = our source ID (so handleRetryResponse's injection
	// guard passes), type byte = Retry, token in header bytes 24-31.
	retry := &SSU2Packet{
		Header:       make([]byte, LongHeaderSize),
		MessageType:  MessageTypeRetry,
		PacketNumber: 0x1234,
	}
	binary.BigEndian.PutUint64(retry.Header[0:8], config.ConnectionID) // dest = our source ID
	retry.Header[12] = MessageTypeRetry
	retry.Header[13] = wire.SSU2ProtocolVersion
	retry.Header[14] = wire.MainNetworkID
	token := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	copy(retry.Header[24:32], token)

	conn.ProcessInboundPacket(retry)

	select {
	case got := <-conn.recvQueue:
		require.Equal(t, MessageTypeRetry, got.MessageType, "Retry must be routed to the handshake queue")
		require.Equal(t, token, got.Header[24:32], "token must survive routing intact in header bytes 24-31")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Retry was dropped: it never reached recvQueue (the processInboundPacket Retry-routing regression)")
	}
}
