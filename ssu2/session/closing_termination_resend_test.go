package session

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closingFixture returns a conn plus its mock socket, in the closing phase.
//
// CloseWithReason holds the session in StateClosing for the destroy window
// (ssu2.md §"Session Termination": "the session should enter the closing phase for
// some maximum period of time") and only then tears down, so the close runs in a
// goroutine while the test drives inbound traffic through that window.
func closingFixture(t *testing.T, localPort, remotePort int) (*SSU2Conn, *mockPacketConn, []byte) {
	t.Helper()

	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort})
	config := createTestConfig(t)
	config.DestroyTimeout = 5 * time.Second

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		config,
		false,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	closeDone := make(chan struct{})
	go func() {
		_ = conn.CloseWithReason(TerminationNormalClose, nil)
		close(closeDone)
	}()

	// The termination packet itself — returned so a test can compare a
	// retransmission against it byte for byte.
	termination := requireWritten(t, underlying)
	require.Eventually(t, func() bool { return conn.GetState() == StateClosing },
		time.Second, 10*time.Millisecond, "the session must sit in the closing phase")

	t.Cleanup(func() {
		conn.CloseImmediate()
		select {
		case <-closeDone:
		case <-time.After(6 * time.Second):
		}
	})
	return conn, underlying, termination.data
}

// TestClosingState_ResendsTermination covers ssu2.md §"Session Termination" ->
// §"Data phase": "A session in the closing state sends a packet containing a
// Termination block in response to any incoming packet that it attributes to the
// session", and "sessions may … send the exact same packet with the same packet
// number as-is in response to any received packet".
//
// Without it, one lost termination packet leaves the peer half-open answering
// nothing back.
func TestClosingState_ResendsTermination(t *testing.T) {
	conn, underlying, original := closingFixture(t, 9062, 9061)

	conn.ProcessInboundPacket(&SSU2Packet{
		MessageType:  MessageTypeData,
		Header:       make([]byte, ShortHeaderSize),
		PacketNumber: 7,
	})

	repeat := requireWritten(t, underlying)
	assert.Equal(t, original, repeat.data,
		"the closing state must re-send the exact same packet, same packet number")
}

// TestClosingState_RateLimited covers the same section: "A session should limit
// the rate at which it generates packets in the closing state. For instance, an
// session could wait for a progressively increasing number of received packets or
// amount of time before responding to received packets."
func TestClosingState_RateLimited(t *testing.T) {
	conn, underlying, _ := closingFixture(t, 9066, 9065)

	inbound := &SSU2Packet{
		MessageType:  MessageTypeData,
		Header:       make([]byte, ShortHeaderSize),
		PacketNumber: 1,
	}

	responses := 0
	for i := 0; i < 300; i++ {
		conn.ProcessInboundPacket(inbound)
		select {
		case <-underlying.writeChan:
			responses++
		default:
		}
	}

	assert.Greater(t, responses, 0, "a closing session must answer inbound traffic")
	assert.LessOrEqual(t, responses, closingPhaseResponseLimit,
		"a flood of packets must not draw one termination per packet")
}

// TestClosingState_StopsAfterTerminationReceived covers "After receiving a
// Termination block with the reason \"Termination Received\", the session may exit
// the closing phase."
func TestClosingState_StopsAfterTerminationReceived(t *testing.T) {
	conn, underlying, _ := closingFixture(t, 9070, 9069)

	// The peer acknowledged our termination.
	conn.closingPeerAcked.Store(true)

	conn.ProcessInboundPacket(&SSU2Packet{
		MessageType:  MessageTypeData,
		Header:       make([]byte, ShortHeaderSize),
		PacketNumber: 2,
	})

	select {
	case pkt := <-underlying.writeChan:
		t.Fatalf("an acknowledged closing session must stop responding, sent %d bytes", len(pkt.data))
	case <-time.After(100 * time.Millisecond):
	}
}
