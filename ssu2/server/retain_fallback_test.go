package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/internal/testri"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"

	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/session"
)

// Finding 012 addendum, listener side. A router runs one shared listen socket, and
// the sessions on it never own that socket's read loop, so the retention a connection
// does for its own dedicated socket does not cover them. A datagram that arrives
// before the session's data-phase header protector reaches AcceptedSessionRegistry
// fails every deobfuscation stage and used to be dropped; because SSU2 resends under a
// fresh packet number, losing the peer's first data packet left the session deaf for
// its whole life.
//
// parseInboundPacket now ends with a stage that recovers the destination connection ID
// using the listener's own introduction key (k_header_1 masks bytes 0-7 and is not
// secret to the listener — only k_header_2 is) and hands the raw datagram to that
// session's bounded retention buffer. Two predicates gate it and both are needed: the
// registry's, which decides whether the connection ID names a session in the race
// window without risking that a held packet is one its handshake is waiting for, and
// the connection's, which refuses to hold anything while its own handshake still has
// a message to read.

// completeInitiatorHandler builds a real initiator handshake through message 3, so the
// handler reports IsHandshakeComplete. That is the condition under which retention is
// safe: it means the handshake has read every message it can still be waiting for, so
// a held datagram cannot be one finalizeHandshake is blocked on.
func completeInitiatorHandler(t *testing.T) *ssu2hs.HandshakeHandler {
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

	// An initiator's transport cipher states arrive with Session Confirmed, not with
	// Session Created, so this is the step that makes the handshake complete.
	aliceRI := testri.New(t, &testri.Options{StaticKey: initDH.Public})
	_, err = initiator.CreateSessionConfirmed(55555, 1, aliceRI.Bytes)
	require.NoError(t, err)
	require.True(t, initiator.IsHandshakeComplete())

	return initiator
}

// incompleteInitiatorHandler is an initiator that has sent Session Request and is still
// waiting for Session Created — the state in which holding a packet could strand it.
func incompleteInitiatorHandler(t *testing.T) *ssu2hs.HandshakeHandler {
	t.Helper()

	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	initiator, err := ssu2hs.NewHandshakeHandlerWithKeys(true, initDH, respDH.Public, nil)
	require.NoError(t, err)
	_, err = initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	require.False(t, initiator.IsHandshakeComplete())

	return initiator
}

// protectedDataDatagram builds a data-phase datagram addressed to destConnID,
// header-protected the way a peer protects inbound Data: k_header_1 is the receiver's
// introduction key, which the listener holds. k_header_2 is the session's
// recvDataHeader2, which the listener does NOT hold until the protector lands — that
// is precisely the race window, so the caller's key here only has to be some 32 bytes
// the listener cannot try.
func protectedDataDatagram(t *testing.T, receiverIntroKey []byte, destConnID uint64) []byte {
	t.Helper()

	// Short header (16) + a payload + the 24-byte header-protection sample that the
	// masks are drawn from.
	pkt := make([]byte, 16+24+24)
	binary.BigEndian.PutUint64(pkt[0:8], destConnID)
	binary.BigEndian.PutUint32(pkt[8:12], 0) // packet number
	pkt[12] = MessageTypeData
	pkt[13] = 0x01 // frag 0 of 1

	// A protector over the receiver's intro key alone is enough to mask bytes 0-7 the
	// way the spec does; a short header has no ChaCha20 extension.
	hp, err := NewHeaderProtectorFromIntroKey(receiverIntroKey, HeaderTypeData)
	require.NoError(t, err)
	require.NoError(t, hp.EncryptHeader(pkt))

	return pkt
}

// newParseTestListener builds a listener with a bound socket and an introduction key,
// without starting its accept loop, so a test can drive parseInboundPacket directly.
func newParseTestListener(t *testing.T) (*SSU2Listener, []byte) {
	t.Helper()

	introKey := randomKey(t)
	config, err := NewSSU2Config(generateRandomHash(), false)
	require.NoError(t, err)
	config.WithStaticKey(testStaticKey())
	config.IntroKey = introKey
	config.WithHandshakeTimeout(2 * time.Second)

	l, err := ListenSSU2(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	require.NotNil(t, l.introHeaderProtector.Load(), "listener must have built its intro-key protector")
	return l, introKey
}

// TestParseInboundPacket_RetainsDataForSessionAwaitingProtector is the wiring test for
// the listener fallback: it drives the real parse cascade with a datagram the listener
// provably cannot read, and asserts the session was handed the bytes instead of the
// datagram being dropped. Delete the fallback stage and this fails.
func TestParseInboundPacket_RetainsDataForSessionAwaitingProtector(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0xC0FFEE)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), true)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))

	datagram := protectedDataDatagram(t, introKey, connID)

	packet, ok := l.parseInboundPacket(datagram, testPeerAddr())
	require.False(t, ok, "a datagram with no installed protector must not be reported as parsed")
	require.Nil(t, packet)

	require.Equal(t, uint64(1), conn.RecvStats()["handshake_retained"],
		"the listener must hand an unattributable-but-addressed datagram to the session's retention buffer")
}

// TestParseInboundPacket_DropsDataForUnknownConnID bounds what the fallback costs an
// attacker: a datagram addressed to a session the listener has never heard of is
// dropped exactly as before, and nothing accumulates anywhere.
func TestParseInboundPacket_DropsDataForUnknownConnID(t *testing.T) {
	l, introKey := newParseTestListener(t)

	datagram := protectedDataDatagram(t, introKey, 0xDEADBEEF)

	packet, ok := l.parseInboundPacket(datagram, testPeerAddr())
	require.False(t, ok)
	require.Nil(t, packet)
}

// TestParseInboundPacket_DoesNotRetainForEstablishedSession proves the fallback stays
// off the steady-state path. Once the protector is installed, a datagram that still
// fails to deobfuscate is a genuine failure — buffering it would hide an attack and
// let a flood pile up state on a live session.
func TestParseInboundPacket_DoesNotRetainForEstablishedSession(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0xBEEF)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), true)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))

	hp, err := NewHeaderProtectorFromIntroKey(randomKey(t), HeaderTypeData)
	require.NoError(t, err)
	require.NoError(t, l.acceptedSessions.SetDataPhaseProtector(connID, hp))

	// Protected with the listener's intro key, which is not the installed protector's
	// key, so every stage declines it.
	packet, ok := l.parseInboundPacket(protectedDataDatagram(t, introKey, connID), testPeerAddr())
	require.False(t, ok)
	require.Nil(t, packet)
	require.Zero(t, conn.RecvStats()["handshake_retained"],
		"a session whose protector is installed has no race window left to cover")
}

// TestParseInboundPacket_RetainsForResponderOnlyAfterSessionConfirmedStage is the
// deadlock guard seen from the listener.
//
// A responder IS waiting for Session Confirmed, and that message fails every
// deobfuscation stage when its protector is missing. Retaining it would put the very
// packet finalizeHandshake is blocked on into a buffer only finalizeHandshake drains —
// a self-inflicted hang, strictly worse than the drop it replaced. So the registry
// declines a responder whose SessionConfirmed stage does not exist, and only once that
// stage exists (Session Confirmed is then claimed earlier, by its own stage) is a
// responder eligible.
func TestParseInboundPacket_RetainsForResponderOnlyAfterSessionConfirmedStage(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0xF00D)

	// Responder role, no SessionConfirmed protector: ineligible.
	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), false)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))

	_, ok := l.parseInboundPacket(protectedDataDatagram(t, introKey, connID), testPeerAddr())
	require.False(t, ok)
	require.Zero(t, conn.RecvStats()["handshake_retained"],
		"a responder that has not been offered its Session Confirmed stage may not retain")

	// Install its SessionConfirmed stage: now the Session Confirmed itself cannot reach
	// the fallback, so retention is safe.
	schp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionConfirmed)
	require.NoError(t, err)
	require.NoError(t, l.acceptedSessions.SetSessionConfirmedProtector(connID, schp))

	_, ok = l.parseInboundPacket(protectedDataDatagram(t, introKey, connID), testPeerAddr())
	require.False(t, ok)
	require.Equal(t, uint64(1), conn.RecvStats()["handshake_retained"],
		"once Session Confirmed has its own stage, a responder's data-phase datagram is retained")
}

// TestParseInboundPacket_RefusesToStrandAListenerDialedInitiator covers the other half
// of the same hazard. A listener-dialed initiator is still waiting for Session Created,
// whose protector is installed asynchronously, so a Session Created really can reach
// the fallback. The registry gate is role-based and does find the entry; the connection
// then refuses to hold it.
func TestParseInboundPacket_RefusesToStrandAListenerDialedInitiator(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0x1234)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, incompleteInitiatorHandler(t), true)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))

	_, ok := l.parseInboundPacket(protectedDataDatagram(t, introKey, connID), testPeerAddr())
	require.False(t, ok)
	require.Zero(t, conn.RecvStats()["handshake_retained"],
		"retention must refuse while the handshake still has a message to read")
}

// TestParseInboundPacket_RetentionStaysBounded proves the race window cannot be used to
// make a session accumulate unbounded state.
func TestParseInboundPacket_RetentionStaysBounded(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0x5A5A)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), true)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))

	datagram := protectedDataDatagram(t, introKey, connID)
	for range 64 {
		l.parseInboundPacket(datagram, testPeerAddr())
	}

	require.LessOrEqual(t, conn.RecvStats()["handshake_retained"], uint64(8),
		"retention must stay bounded so the race window cannot be used to pile up state")
}
