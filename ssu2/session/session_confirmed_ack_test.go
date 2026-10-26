package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ackWriteTimeout bounds how long a test waits for a datagram to leave the
// connection; sends are synchronous so this only guards against a regression.
const ackWriteTimeout = 500 * time.Millisecond

// TestSendSessionConfirmedACK_FirstResponderPacketIsPN0 covers
// ssu2.rst §"Packet Numbering": "For Bob, outbound packet numbering starts at 0
// with first Data packet, which should be an ACK of the Session Confirmed."
// and §"Session Confirmed ACK": Bob must acknowledge Alice's Session Confirmed
// (her packet 0) as soon as possible after receiving it.
func TestSendSessionConfirmedACK_FirstResponderPacketIsPN0(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9002})
	config := createTestConfig(t)
	config.ConnectionID = 0x1122334455667788

	// initiator=false => responder ("Bob")
	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001},
		config,
		false,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	conn.sendSessionConfirmedACK()

	pkt := requireWritten(t, underlying)
	require.GreaterOrEqual(t, len(pkt.data), ShortHeaderSize+MACSize)

	// Packet number lives in header bytes 8-11 and must be Bob's first
	// outbound data-phase number: 0.
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(pkt.data[8:12]),
		"responder's Session Confirmed ACK must be packet 0")

	// Header byte 12 is the message type; the ACK rides in a Data message.
	assert.Equal(t, byte(MessageTypeData), pkt.data[12])

	// Destination connection ID (bytes 0-7) must address the peer.
	assert.Equal(t, conn.remoteConnectionID.Load(), binary.BigEndian.Uint64(pkt.data[0:8]))

	// The ACK must cover the peer's packet 0: "Ack-through = 0, acnt = 0"
	// (ssu2.rst §"Ack"). No cipher is installed in this fixture, so the payload
	// is the serialized (unsealed) blocks.
	blocks, err := DeserializeBlocks(payloadOf(t, pkt.data))
	require.NoError(t, err)

	ack := findBlock(t, blocks, BlockTypeACK)
	require.GreaterOrEqual(t, len(ack.Data), 5)
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(ack.Data[0:4]), "ack-through must be 0")
	assert.Equal(t, byte(0), ack.Data[4], "acnt must be 0")

	// A second ACK takes packet number 1, proving the first consumed 0.
	conn.sendSessionConfirmedACK()
	pkt2 := requireWritten(t, underlying)
	assert.Equal(t, uint32(1), binary.BigEndian.Uint32(pkt2.data[8:12]))
}

// TestHandleReadyDataPacket_AcksPeerPacketZero guards the removal of the old
// "PacketNumber > 0" filter: a peer's data-phase packet 0 must be ackable,
// otherwise the first Data packet of a session is never acknowledged.
func TestHandleReadyDataPacket_AcksPeerPacketZero(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9006})
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9005},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)
	drainWrites(underlying)

	conn.handleReadyDataPacket(&SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: 0,
		Header:       make([]byte, ShortHeaderSize),
		MAC:          make([]byte, MACSize),
	})

	// handleReadyDataPacket either fired an immediate ACK (a datagram on the
	// wire) or left packet 0 pending in the ACK handler. Both must describe
	// peer packet 0.
	var ack *SSU2Block
	select {
	case pkt := <-underlying.writeChan:
		blocks, berr := DeserializeBlocks(payloadOf(t, pkt.data))
		require.NoError(t, berr)
		ack = findBlock(t, blocks, BlockTypeACK)
	default:
		generated, gerr := conn.ackHandler.GenerateACK()
		require.NoError(t, gerr)
		require.NotNil(t, generated, "peer packet 0 must be pending an ACK")
		ack = generated
	}

	require.GreaterOrEqual(t, len(ack.Data), 5)
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(ack.Data[0:4]),
		"peer packet 0 must be acknowledged")
}

// TestProcessHandshakePacket_RecordsOnlySessionConfirmed covers ssu2.rst
// §"Packet Numbering": every handshake message except Session Confirmed carries
// a random, ignored packet number, so recording those would inject numbers the
// peer never assigned into the ACK set.
func TestProcessHandshakePacket_RecordsOnlySessionConfirmed(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9010})
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9009},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)
	drainWrites(underlying)

	for _, msgType := range []uint8{MessageTypeSessionRequest, MessageTypeSessionCreated} {
		conn.processHandshakePacket(&SSU2Packet{
			MessageType:  msgType,
			PacketNumber: 0xDEADBEEF,
			Header:       make([]byte, LongHeaderSize),
			MAC:          make([]byte, MACSize),
		})
	}

	ack, err := conn.ackHandler.GenerateACK()
	require.NoError(t, err)
	assert.Nil(t, ack, "random handshake packet numbers must not be recorded for ACK")

	conn.processHandshakePacket(&SSU2Packet{
		MessageType:  MessageTypeSessionConfirmed,
		PacketNumber: 0,
		Header:       make([]byte, LongHeaderSize),
		MAC:          make([]byte, MACSize),
	})

	ack, err = conn.ackHandler.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, ack, "Session Confirmed (peer packet 0) must be recorded for ACK")
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(ack.Data[0:4]))
}

func requireWritten(t *testing.T, c *mockPacketConn) mockPacket {
	t.Helper()
	select {
	case pkt := <-c.writeChan:
		return pkt
	case <-time.After(ackWriteTimeout):
		t.Fatal("expected a datagram to be written")
		return mockPacket{}
	}
}

func drainWrites(c *mockPacketConn) {
	for {
		select {
		case <-c.writeChan:
		default:
			return
		}
	}
}

// payloadOf returns the payload section of a serialized short-header Data
// packet: header (16 bytes), then payload, then the trailing 16-byte MAC.
func payloadOf(t *testing.T, data []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(data), ShortHeaderSize+MACSize)
	return data[ShortHeaderSize : len(data)-MACSize]
}

func findBlock(t *testing.T, blocks []*SSU2Block, blockType uint8) *SSU2Block {
	t.Helper()
	for _, b := range blocks {
		if b != nil && b.Type == blockType {
			return b
		}
	}
	t.Fatalf("no block of type %d found in %d blocks", blockType, len(blocks))
	return nil
}

// TestReserveInitiatorDataSequence_FirstDataPacketIsPN1 covers
// ssu2.md §"Packet Numbering": "For Alice, outbound packet numbering starts at 0
// with Session Confirmed", with the worked example pairing "SessionConfirmed (0)"
// and "Data (1)", and §"Packet Number": "Each packet number may only be used
// once."
//
// Session Confirmed is sent with packet number 0
// (SSU2Conn.sendSessionConfirmed -> CreateSessionConfirmedFragments(..., 0, ...)),
// so the data-phase counter must skip 0. Without the reservation, Alice's first
// Data packet reuses number 0 and a conformant peer drops it as a duplicate —
// Java marks 0 received for inbound sessions (PeerState2.java:146) and starts its
// own counter at 1 for outbound ones (PeerState2.java:150).
func TestReserveInitiatorDataSequence_FirstDataPacketIsPN1(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9020})
	config := createTestConfig(t)
	config.ConnectionID = 0x1122334455667788

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9021},
		config,
		true, // initiator ("Alice")
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	// Before the reservation the counter is at its zero value, i.e. the number
	// Session Confirmed already used.
	conn.sendSeqMutex.Lock()
	require.Equal(t, uint32(0), conn.sendSequence)
	conn.sendSeqMutex.Unlock()

	conn.reserveInitiatorDataSequence()

	// After it, the first data-phase packet number is 1, matching the spec
	// example's "Data (1)".
	conn.sendSeqMutex.Lock()
	assert.Equal(t, uint32(1), conn.sendSequence)
	conn.sendSeqMutex.Unlock()

	// Reserving twice must not advance past 1: the reservation is a floor, not an
	// increment, so a retransmitted Session Confirmed cannot shift numbering.
	conn.reserveInitiatorDataSequence()
	conn.sendSeqMutex.Lock()
	assert.Equal(t, uint32(1), conn.sendSequence)
	conn.sendSeqMutex.Unlock()
}

// TestMarkPeerConfirmedPacketSeen_ResponderRejectsPeerPN0 covers the responder
// half of ssu2.md §"Packet Numbering": Alice's Session Confirmed is her packet 0,
// so Bob's inbound filter must treat number 0 as consumed and not deliver a peer
// data-phase packet 0 (or a retransmitted Session Confirmed routed to the data
// path) as fresh data.
func TestMarkPeerConfirmedPacketSeen_ResponderRejectsPeerPN0(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9030})
	config := createTestConfig(t)
	config.ConnectionID = 0x1122334455667788

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9031},
		config,
		false, // responder ("Bob")
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	confirmed := []*SSU2Packet{{PacketNumber: 0, MessageType: MessageTypeSessionConfirmed}}
	conn.markPeerConfirmedPacketSeen(confirmed)

	// A peer data packet numbered 0 is now a duplicate and must be filtered.
	dup := &SSU2Packet{
		Header:       make([]byte, ShortHeaderSize),
		Payload:      []byte("stale"),
		MAC:          make([]byte, MACSize),
		MessageType:  MessageTypeData,
		PacketNumber: 0,
	}
	ready := conn.collectReadyDataPackets(dup)
	assert.Empty(t, ready, "peer packet number 0 must be filtered after Session Confirmed used it")

	// Number 1 is still eligible.
	fresh := &SSU2Packet{
		Header:       make([]byte, ShortHeaderSize),
		Payload:      []byte("data"),
		MAC:          make([]byte, MACSize),
		MessageType:  MessageTypeData,
		PacketNumber: 1,
	}
	ready = conn.collectReadyDataPackets(fresh)
	assert.Len(t, ready, 1, "peer packet number 1 must still be accepted")
}

// TestSealPacket_IPv4DatagramBudget covers ssu2.md §"Max I2NP Message Size":
// "IPv4: … Max message size is MTU - 28 … IPv6: … Max message size is MTU - 48."
// With a 1500-byte MTU the datagram ceiling is 1472 over IPv4 but only 1452 over
// IPv6, so the same 1460-byte packet is legal to one peer and illegal to the
// other. sealPacket must stamp the destination family before serializing.
func TestSealPacket_IPv4DatagramBudget(t *testing.T) {
	newDataPacket := func(t *testing.T, total int) *SSU2Packet {
		t.Helper()
		require.Greater(t, total, ShortHeaderSize+MACSize)
		return &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: 1,
			Header:       make([]byte, ShortHeaderSize),
			Payload:      make([]byte, total-ShortHeaderSize-MACSize),
			MAC:          make([]byte, MACSize),
		}
	}

	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9040})
	config := createTestConfig(t)
	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9041},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	v4 := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 9042}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9043}

	// 1460 bytes: over the IPv6 budget, within the IPv4 budget.
	if _, _, err := conn.sealPacket(newDataPacket(t, 1460), v4); err != nil {
		t.Errorf("1460-byte packet to an IPv4 peer must be sent (limit %d): %v", MaxPacketSizeIPv4, err)
	}
	if _, _, err := conn.sealPacket(newDataPacket(t, 1460), v6); err == nil {
		t.Errorf("1460-byte packet to an IPv6 peer must be refused (limit %d)", MaxPacketSizeIPv6)
	}

	// 1452 bytes is legal to both.
	if _, _, err := conn.sealPacket(newDataPacket(t, MaxPacketSizeIPv6), v4); err != nil {
		t.Errorf("1452-byte packet to an IPv4 peer must be sent: %v", err)
	}
	if _, _, err := conn.sealPacket(newDataPacket(t, MaxPacketSizeIPv6), v6); err != nil {
		t.Errorf("1452-byte packet to an IPv6 peer must be sent: %v", err)
	}
}

// TestSendSessionConfirmedACK_CarriesNewTokenBlock covers ssu2.md §"Tokens":
// "New Token blocks … would typically be sent at least once, during or soon
// after session establishment. Due to validation checks of the RouterInfo in
// the Session Confirmed message, Bob should not send a New Token block in the
// Session Created message, it may be sent with the ACK 0 and Router Info after
// the Session Confirmed is received and validated."
//
// Without a token, Alice can never satisfy §"Session Establishment"'s fast path
// ("when Alice has a valid token previously received from Bob") and every
// reconnection pays a Token Request / Retry round trip.
func TestSendSessionConfirmedACK_CarriesNewTokenBlock(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9012})
	config := createTestConfig(t)
	config.TokenIssuer = wire.NewTokenCacheWithMaxSize(wire.RetryTokenTTL, 16)

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9011},
		config,
		false,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	conn.sendSessionConfirmedACK()

	pkt := requireWritten(t, underlying)
	blocks, err := DeserializeBlocks(payloadOf(t, pkt.data))
	require.NoError(t, err)

	require.NotNil(t, findBlock(t, blocks, BlockTypeACK), "ACK must still be present")
	token := findBlock(t, blocks, BlockTypeNewToken)
	require.NotNil(t, token, "Bob's first data packet must carry a New Token block")

	parsed, err := ParseNewTokenBlock(token)
	require.NoError(t, err)
	require.Len(t, parsed.Token, 8, "§\"New Token\": token :: 8 bytes")

	// expires :: unsigned big-endian seconds, and must be in the future and
	// inside the configured lifetime (§"Tokens": "several minutes minimum").
	assert.Greater(t, int64(parsed.Expiration), time.Now().Unix()-1)
	assert.LessOrEqual(t, int64(parsed.Expiration), time.Now().Add(wire.DefaultSessionTokenLifetime+time.Minute).Unix())

	// §"Tokens": "Routers should assume that only the last token received is
	// valid" — the same peer on the same local address gets one entry.
	assert.Equal(t, 1, config.TokenIssuer.Size())

	// The issued token must be one this listener would actually accept in a
	// later Session Request — otherwise the New Token block is decoration and
	// Alice still pays the Token Request / Retry round trip.
	local, ok := underlying.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.True(t, config.TokenIssuer.ConsumeToken(parsed.Token, conn.GetRemoteAddr(), local),
		"the New Token block must carry a token the issuer will honor")
}

// TestSendSessionConfirmedACK_NoIssuerSendsNoToken proves the New Token block is
// simply omitted when the session cannot issue tokens, rather than emitting an
// empty or malformed block.
func TestSendSessionConfirmedACK_NoIssuerSendsNoToken(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9014})
	config := createTestConfig(t)
	config.TokenIssuer = nil

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9013},
		config,
		false,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	conn.sendSessionConfirmedACK()

	pkt := requireWritten(t, underlying)
	blocks, err := DeserializeBlocks(payloadOf(t, pkt.data))
	require.NoError(t, err)
	require.NotNil(t, findBlock(t, blocks, BlockTypeACK))
	for _, b := range blocks {
		assert.NotEqual(t, BlockTypeNewToken, b.Type,
			"no issuer configured must mean no New Token block, not a bogus one")
	}
}
