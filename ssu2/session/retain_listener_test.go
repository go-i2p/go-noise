package session

import (
	"net"
	"testing"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"

	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
)

// Finding 012 addendum, listener path: a datagram arriving on the shared listener
// socket before that session's data-phase header protector is installed cannot be
// deobfuscated, and dropping it leaves the session deaf because the resend lands
// under a new packet number in the same protector-less entry. The connection's own
// read loop already had a bounded retention buffer for this; the listener did not,
// because a listener-multiplexed session never runs that loop.

// completedInitiatorHandler drives a real XK handshake through message 3, so that
// the initiator holds transport cipher states. That is the condition
// RetainListenerDatagram requires before it will hold anything.
//
// Note where the cipher states actually land for an initiator: ProcessSessionCreated
// leaves them unset (handshake/session_created.go only derives the SessionConfirmed
// header key), and they appear when CreateSessionConfirmed runs the final WriteMessage
// (handshake/session_confirmed.go). So the helper has to build SessionConfirmed, which
// is also what the real initiator does just before finalizeHandshake.
func completedInitiatorHandler(t *testing.T) *ssu2hs.HandshakeHandler {
	t.Helper()

	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	initiator, err := ssu2hs.NewHandshakeHandlerWithKeys(true, initDH, respDH.Public, nil)
	require.NoError(t, err)
	responder, err := ssu2hs.NewHandshakeHandlerWithKeys(false, respDH, nil, nil)
	require.NoError(t, err)
	responder.SetPeerAddress(net.ParseIP("203.0.113.10"), 51500)

	request, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(request)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(22222, 11111)
	require.NoError(t, err)
	require.NoError(t, initiator.ProcessSessionCreated(created))

	require.False(t, initiator.IsHandshakeComplete(),
		"precondition: an initiator's cipher states come from SessionConfirmed, not Session Created")

	_, err = initiator.CreateSessionConfirmed(55555, 1, testRouterInfoFor(t, initDH.Public))
	require.NoError(t, err)

	require.True(t, initiator.IsHandshakeComplete(),
		"precondition: the initiator must hold cipher states after Session Confirmed")
	return initiator
}

func retainedCount(conn *SSU2Conn) int {
	conn.pendingHandshakeDataMutex.Lock()
	defer conn.pendingHandshakeDataMutex.Unlock()
	return len(conn.pendingHandshakeDatagrams)
}

// TestRetainListenerDatagram_HoldsAfterHandshakeComplete is the positive case: the
// handshake has read everything it can wait for, so the only thing left to lose is
// the peer's first data-phase packet, and it is held.
func TestRetainListenerDatagram_HoldsAfterHandshakeComplete(t *testing.T) {
	conn, _ := initiatorFixture(t, 9612, 9611, 0)

	conn.stateMutex.Lock()
	conn.state = StateHandshaking
	conn.stateMutex.Unlock()
	conn.handshakeHandler = completedInitiatorHandler(t)

	datagram := make([]byte, ShortHeaderSize+24+16)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9611}

	require.True(t, conn.RetainListenerDatagram(datagram, addr),
		"a data-phase datagram that arrives before the protector is installed must be held")
	require.Equal(t, 1, retainedCount(conn))
}

// TestRetainListenerDatagram_RefusesToStrandAnIncompleteHandshake is the deadlock
// guard, and the reason this is not simply "retain while handshaking".
//
// A listener-multiplexed initiator's SessionCreated protector is installed on the
// listener's own schedule, so a SessionCreated can fail every deobfuscation stage
// and reach the retention fallback. If it were held there, the initiator would be
// waiting in awaitSessionCreated for a packet that is sitting in a buffer drained
// only by finalizeHandshake — a self-inflicted hang, strictly worse than the drop
// it replaced. Requiring the transport cipher states means every handshake message
// this connection could still be waiting for has already arrived.
func TestRetainListenerDatagram_RefusesToStrandAnIncompleteHandshake(t *testing.T) {
	conn, _ := initiatorFixture(t, 9622, 9621, 0)

	conn.stateMutex.Lock()
	conn.state = StateHandshaking
	conn.stateMutex.Unlock()
	// The fixture's handler has processed nothing yet: the initiator is still
	// waiting for Session Created.
	require.False(t, conn.handshakeHandler.IsHandshakeComplete())

	datagram := make([]byte, ShortHeaderSize+24+16)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9621}

	require.False(t, conn.RetainListenerDatagram(datagram, addr),
		"nothing may be retained while the handshake still has a message to read")
	require.Zero(t, retainedCount(conn))
}

// TestRetainListenerDatagram_RefusesOnceEstablished: after finalizeHandshake the
// protector is installed and the normal path works, so the buffer must not start
// absorbing ordinary traffic.
func TestRetainListenerDatagram_RefusesOnceEstablished(t *testing.T) {
	conn, _ := initiatorFixture(t, 9632, 9631, 0)

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()
	conn.handshakeHandler = completedInitiatorHandler(t)

	require.False(t, conn.RetainListenerDatagram(make([]byte, ShortHeaderSize+24+16),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9631}))
	require.Zero(t, retainedCount(conn))
}

// TestRetainListenerDatagram_RefusesUndecodableSize bounds what a flood can cost:
// a datagram too short to carry a header-protection sample can be attributed to no
// session and must not fill the buffer.
func TestRetainListenerDatagram_RefusesUndecodableSize(t *testing.T) {
	conn, _ := initiatorFixture(t, 9642, 9641, 0)

	conn.stateMutex.Lock()
	conn.state = StateHandshaking
	conn.stateMutex.Unlock()
	conn.handshakeHandler = completedInitiatorHandler(t)

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9641}
	require.False(t, conn.RetainListenerDatagram(make([]byte, ShortHeaderSize+23), addr))

	// A full-size datagram is accepted, so the refusal above is about size.
	require.True(t, conn.RetainListenerDatagram(make([]byte, ShortHeaderSize+24), addr))

	// And the buffer stays bounded.
	for range pendingHandshakeDataMax * 2 {
		conn.RetainListenerDatagram(make([]byte, ShortHeaderSize+24), addr)
	}
	require.Equal(t, pendingHandshakeDataMax, retainedCount(conn),
		"retention must stay bounded so the race window cannot be used to pile up state")
}
