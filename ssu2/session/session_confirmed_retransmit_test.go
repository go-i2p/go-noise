package session

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionConfirmedRetransmit_ByteIdentical covers ssu2.md §"Handshake
// Retransmission" -> §"Session Confirmed": option 2 is the recommended
// implementation — "send data messages immediately, but also retransmit Session
// Confirmed until a data message is received" — and "When retransmitting
// Session Confirmed, maintain same source and connection IDs, ephemeral key,
// and packet number. Or, just retain the encrypted packet. Packet number must
// not be incremented, because that would change the chained hash value which is
// an input for the split() function."
func TestSessionConfirmedRetransmit_ByteIdentical(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9022})
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9021},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)
	defer conn.Close()

	datagram := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dest conn ID
		0x00, 0x00, 0x00, 0x00, // packet number 0
		0x02,       // type = Session Confirmed
		0x01,       // frag: 0 of 1
		0x00, 0x00, // moreflags
		0xde, 0xad, 0xbe, 0xef,
	}
	// Store only: the loop's first interval is 1.25 s, so drive the retransmit
	// itself to keep the test fast and deterministic.
	require.True(t, conn.storeSessionConfirmed([][]byte{datagram}))

	require.True(t, conn.retransmitSessionConfirmed())

	pkt := requireWritten(t, underlying)
	assert.Equal(t, datagram, pkt.data,
		"the retransmit must be the identical datagram, not a re-sealed packet")

	// The spec's stop condition: a data message arrived.
	conn.markSessionConfirmedAcked()
	assert.False(t, conn.retransmitSessionConfirmed(),
		"retransmission must stop once a data message is received")
}

// TestSessionConfirmedRetransmit_StopsOnDataMessage proves the loop exits when
// the peer's first data message arrives (option 2's "until a data message is
// received"), rather than running the full schedule.
func TestSessionConfirmedRetransmit_StopsOnDataMessage(t *testing.T) {
	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9026})
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9025},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.True(t, conn.storeSessionConfirmed([][]byte{{0x01, 0x02, 0x03}}))
	done := make(chan struct{})
	conn.wg.Add(1) // the loop calls wg.Done itself
	go func() {
		conn.retransmitSessionConfirmedLoop(time.Now().Add(10 * time.Second))
		close(done)
	}()

	conn.markSessionConfirmedAcked()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Session Confirmed retransmit loop did not stop on the data message")
	}
}
