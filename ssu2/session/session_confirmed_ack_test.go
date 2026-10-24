package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

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
		make([]byte, 32),
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
		make([]byte, 32),
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
		make([]byte, 32),
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
