// Tests for the data-phase outbound immediate-ack flag.
//
// ssu2.md §"Congestion Control" -> §"Immediate ACK Flag": the sender sets the
// data short-header flag byte bit 0 (header[13] & 0x01) to request that the
// receiver ACK within min(rtt/16, 5) ms. The flag is only "necessary on data
// packets containing I2NP messages or message fragments", and Java I2P sets it
// when the send window is over 2/3 full (PeerState.shouldRequestImmediateAck).

package session

import (
	"testing"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

func newTestSendCipher(t *testing.T) *noise.CipherState {
	t.Helper()
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	var key [32]byte
	return noise.UnsafeNewCipherState(cs, key, 0)
}

// immAckConn returns an established conn with a send cipher installed and a
// congestion window of cwnd bytes.
func immAckConn(t *testing.T, cwnd int) *SSU2Conn {
	t.Helper()
	conn, initConn := establishedConnForTermination(t)
	conn.cipherMutex.Lock()
	conn.sendCipher = newTestSendCipher(t)
	conn.cipherMutex.Unlock()
	conn.congestionController.SetCWND(cwnd)
	t.Cleanup(func() { conn.SetOwnsUnderlying(false); _ = initConn })
	return conn
}

func dataPacketWithBlocks(t *testing.T, blocks []*SSU2Block) *SSU2Packet {
	t.Helper()
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)
	hdr := make([]byte, ShortHeaderSize)
	return &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: 1,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
		Payload:      payload,
	}
}

func i2npBlock() *SSU2Block {
	return &SSU2Block{Type: BlockTypeI2NPMessage, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}
}

func ackOnlyBlock() *SSU2Block {
	return &SSU2Block{Type: BlockTypeACK, Data: []byte{0, 0, 0, 0, 0, 0, 0, 0}}
}

// TestEncryptDataPayload_SetsImmediateAckWhenWindowFull proves the flag is set
// on an I2NP packet once the send window is over 2/3 consumed.
func TestEncryptDataPayload_SetsImmediateAckWhenWindowFull(t *testing.T) {
	cwnd := 3000
	conn := immAckConn(t, cwnd)
	// In flight > 2/3 of cwnd => available < cwnd/3.
	conn.congestionController.OnPacketSent(cwnd) // fully packed

	pkt := dataPacketWithBlocks(t, []*SSU2Block{i2npBlock()})
	_, err := conn.encryptDataPayload(pkt)
	require.NoError(t, err)

	require.NotZero(t, pkt.Header[13]&0x01,
		"immediate-ack flag must be set on an I2NP packet when the window is over 2/3 full")
}

// TestEncryptDataPayload_NoImmediateAckWhenWindowOpen proves the flag stays
// clear while the window has room.
func TestEncryptDataPayload_NoImmediateAckWhenWindowOpen(t *testing.T) {
	cwnd := 3000
	conn := immAckConn(t, cwnd)
	conn.congestionController.OnPacketSent(100) // well under 2/3

	pkt := dataPacketWithBlocks(t, []*SSU2Block{i2npBlock()})
	_, err := conn.encryptDataPayload(pkt)
	require.NoError(t, err)

	require.Zero(t, pkt.Header[13]&0x01,
		"immediate-ack flag must stay clear when the window is mostly open")
}

// TestEncryptDataPayload_NoImmediateAckOnAckOnlyPacket proves the flag is not
// requested on packets that carry no I2NP data, even with a full window.
func TestEncryptDataPayload_NoImmediateAckOnAckOnlyPacket(t *testing.T) {
	cwnd := 3000
	conn := immAckConn(t, cwnd)
	conn.congestionController.OnPacketSent(cwnd) // fully packed

	pkt := dataPacketWithBlocks(t, []*SSU2Block{ackOnlyBlock()})
	_, err := conn.encryptDataPayload(pkt)
	require.NoError(t, err)

	require.Zero(t, pkt.Header[13]&0x01,
		"immediate-ack flag is only for packets carrying I2NP messages/fragments")
}

// TestShouldRequestImmediateAck covers the window heuristic directly.
func TestShouldRequestImmediateAck(t *testing.T) {
	conn := immAckConn(t, 3000)
	require.False(t, conn.shouldRequestImmediateAck(), "empty window must not request")

	conn.congestionController.OnPacketSent(2000) // available 1000 == cwnd/3, not <
	require.False(t, conn.shouldRequestImmediateAck(), "exactly 2/3 full must not request")

	conn.congestionController.OnPacketSent(1) // available 999 < 1000
	require.True(t, conn.shouldRequestImmediateAck(), "over 2/3 full must request")
}
