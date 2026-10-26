package session

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCCFixture returns a responder-role conn (handshake not run) plus its mock
// socket. No cipher is installed, so sealPacket leaves the payload in the clear
// and the wire size is exactly header + payload + MAC.
func newCCFixture(t *testing.T, localPort, remotePort int) (*SSU2Conn, *mockPacketConn) {
	t.Helper()
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort})
	config := createTestConfig(t)
	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		config,
		false,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, underlying
}

// sendDataPacket sends one data packet built from blocks and returns the datagram.
func sendDataPacket(t *testing.T, conn *SSU2Conn, underlying *mockPacketConn, blocks ...*SSU2Block) []byte {
	t.Helper()
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	packet := conn.newDataPacket()
	packet.Payload = payload
	require.NoError(t, conn.sendPacketDirect(packet))
	return requireWritten(t, underlying).data
}

// ackBlockThrough builds an ACK whose consecutive run covers packets 0..through.
func ackBlockThrough(through uint32) *SSU2Block {
	data := make([]byte, 5)
	data[0] = byte(through >> 24)
	data[1] = byte(through >> 16)
	data[2] = byte(through >> 8)
	data[3] = byte(through)
	data[4] = byte(through) // acnt: the run through..0
	return NewSSU2Block(BlockTypeACK, data)
}

// TestCongestion_ByteAccountingOnSendAndAck covers ssu2.md §"Congestion
// Control": "It is recommended that the congestion control be based on byte
// count, not packet count." Before this wiring OnPacketSent/OnAck had no
// callers, so bytesInFlight stayed 0 forever, no window was ever enforced, and
// the immediate-ACK heuristic that reads AvailableWindow() was permanently false.
func TestCongestion_ByteAccountingOnSendAndAck(t *testing.T) {
	conn, underlying := newCCFixture(t, 9032, 9031)

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 100))
	wire := sendDataPacket(t, conn, underlying, i2np)

	assert.Equal(t, len(wire), conn.congestionController.GetBytesInFlight(),
		"bytes in flight must equal the wire size of the outstanding packet")

	acked, nacked, err := conn.ackHandler.ProcessACKWithNacks(ackBlockThrough(0))
	require.NoError(t, err)
	assert.Equal(t, []uint32{0}, acked)
	assert.Empty(t, nacked)
	conn.retireAckedPackets(acked)

	assert.Equal(t, 0, conn.congestionController.GetBytesInFlight(),
		"an acknowledged packet must leave the in-flight total")
	assert.Equal(t, conn.congestionController.GetCWND(), conn.congestionController.AvailableWindow())
}

// TestCongestion_AckOnlyPacketsAreExempt covers §"Congestion Control": "ACK-only
// data packets should not count for bytes or packets in-flight and are not
// congestion-controlled."
func TestCongestion_AckOnlyPacketsAreExempt(t *testing.T) {
	conn, underlying := newCCFixture(t, 9036, 9035)

	// sendSessionConfirmedACK records a received packet first, otherwise
	// GenerateACK has nothing to acknowledge and sends nothing at all.
	conn.sendSessionConfirmedACK()
	requireWritten(t, underlying)

	assert.Equal(t, 0, conn.congestionController.GetBytesInFlight(),
		"an ACK-only packet must not be counted in flight")

	// A packet carrying only an ACK is never blocked by the window.
	ackPacket := conn.newDataPacket()
	ackPacket.Payload, _ = SerializeBlocks([]*SSU2Block{ackBlockThrough(0)})
	conn.congestionController.OnPacketSent(conn.congestionController.GetCWND())
	assert.False(t, conn.congestionBlocked(ackPacket),
		"§\"Congestion Control\": ACK-only packets are not congestion-controlled")
}

// TestCongestion_ImmediateACKFlagWhenWindowNearlyFull covers ssu2.md §"Immediate
// ACK Flag": one listed strategy is "Set whenver the send window is almost full,
// for example over 2/3 full". With no byte accounting the window was never
// observed as full, so it never fired.
func TestCongestion_ImmediateACKFlagWhenWindowNearlyFull(t *testing.T) {
	conn, underlying := newCCFixture(t, 9040, 9039)

	assert.False(t, conn.shouldRequestImmediateAck(), "a fresh window is not nearly full")

	// Drive more than a third of the window with in-flight bytes. Sent through
	// the real send path (two full-size datagrams) so the accounting being
	// tested is the accounting the send path performs.
	cwnd := conn.congestionController.GetCWND()
	// Each datagram is capped at MaxPacketSizeIPv4 (1472), so several are needed
	// to push the in-flight total past two thirds of the initial window (3×MTU).
	body := make([]byte, 1200)
	i2np := NewSSU2Block(BlockTypeI2NPMessage, body)
	for i := 0; i < 4; i++ {
		sendDataPacket(t, conn, underlying, i2np)
	}

	assert.Greater(t, conn.congestionController.GetBytesInFlight(), cwnd/3,
		"fixture must put over a third of the window in flight")
	assert.True(t, conn.shouldRequestImmediateAck(),
		"an over-2/3-full window must request an immediate ACK")
}

// TestCongestion_NACKReportsLossOnce covers §"Congestion Control" -> §"Packet
// Numbers": "When a packet is ACKed or NACKed, the transmitter must determine
// what I2NP messages and fragments were in that packet, to decide what to
// retransmit." A NACK is the spec's loss signal, and RFC 9002 §6.5 (the general
// guidance ssu2.md cites) counts one congestion event per lost packet.
func TestCongestion_NACKReportsLossOnce(t *testing.T) {
	conn, underlying := newCCFixture(t, 9044, 9043)

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 200))
	sendDataPacket(t, conn, underlying, i2np)

	before := conn.congestionController.GetCWND()

	// ack-through 1, acnt 0 (packet 1 acked), then a range of 1 nack / 0 acks
	// marking packet 0 missing.
	block := NewSSU2Block(BlockTypeACK, []byte{0, 0, 0, 1, 0, 1, 0})
	acked, nums, err := conn.ackHandler.ProcessACKWithNacks(block)
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, acked)
	assert.Equal(t, []uint32{0}, nums)

	conn.notePacketLosses(nums)
	after := conn.congestionController.GetCWND()
	assert.Less(t, after, before, "a loss must reduce the congestion window")

	conn.notePacketLosses(nums)
	assert.Equal(t, after, conn.congestionController.GetCWND(),
		"a packet already reported lost must not trigger a second congestion event")
}

// TestCongestion_WindowGateBlocksSend covers ssu2.md §"Congestion Control" ->
// RFC 9002 §7.2: a sender does not send new packets while the window is full,
// except that it "can send a packet larger than the congestion window if it has
// no outstanding packets".
func TestCongestion_WindowGateBlocksSend(t *testing.T) {
	conn, _ := newCCFixture(t, 9048, 9047)

	dataPacket := conn.newDataPacket()
	dataPacket.Payload = []byte{BlockTypeI2NPMessage, 0, 200}

	// Nothing in flight: the oversized-packet exemption applies.
	assert.False(t, conn.congestionBlocked(dataPacket),
		"RFC 9002 §7.2: a sender with no outstanding packets may send")

	conn.congestionController.OnPacketSent(conn.congestionController.GetCWND())
	assert.True(t, conn.congestionBlocked(dataPacket),
		"a full window must block new data packets")
}

// TestCongestion_WaitForWindowReleasedByAck proves the gate waits and is
// released by the ACK that frees room, rather than dropping the packet.
func TestCongestion_WaitForWindowReleasedByAck(t *testing.T) {
	conn, _ := newCCFixture(t, 9052, 9051)

	conn.congestionController.OnPacketSent(conn.congestionController.GetCWND())

	packet := conn.newDataPacket()
	packet.Payload = []byte{BlockTypeI2NPMessage, 0, 200}

	done := make(chan error, 1)
	go func() { done <- conn.waitForWindow(packet) }()

	select {
	case err := <-done:
		t.Fatalf("waitForWindow returned before the window opened: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	conn.congestionController.OnAck(conn.congestionController.GetCWND())
	conn.signalWindowOpen()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("waitForWindow did not return after the window opened")
	}
}

// TestCongestion_RetransmitReleasesAccountingOnAbandon covers §"Congestion
// Control": a packet abandoned after exhausting its retries must not stay in the
// in-flight total, or the window would remain closed for traffic the peer will
// never acknowledge.
func TestCongestion_RetransmitReleasesAccountingOnAbandon(t *testing.T) {
	conn, underlying := newCCFixture(t, 9056, 9055)

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 100))
	sendDataPacket(t, conn, underlying, i2np)
	require.Equal(t, conn.congestionController.GetBytesInFlight() > 0, true)

	// Force the entry to its retry limit with its deadline already passed.
	conn.pendingMutex.Lock()
	require.Len(t, conn.pendingPackets, 1)
	for _, entry := range conn.pendingPackets {
		entry.Retries = maxPacketRetries
		entry.NextRetry = time.Now().Add(-time.Second)
	}
	conn.pendingMutex.Unlock()

	conn.retransmitExpired()

	assert.Equal(t, 0, conn.congestionController.GetBytesInFlight(),
		"an abandoned packet must be removed from bytes-in-flight")
}
