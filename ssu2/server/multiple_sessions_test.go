package server

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	i2pcrand "github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/internal/testri"
	"github.com/go-i2p/go-noise/ssu2/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multiSessionHarness is a live listener plus the Alice identity that dials it, so
// a test can establish two sessions with one peer — the situation ssu2.md
// §"Multiple Sessions" is written about.
type multiSessionHarness struct {
	listener  *SSU2Listener
	serverCfg *SSU2Config
	aliceRI   []byte

	aliceStaticPriv []byte
	aliceStaticPub  []byte
	aliceIntroKey   []byte
	serverIntroKey  []byte
}

func newMultiSessionHarness(t *testing.T) *multiSessionHarness {
	t.Helper()

	serverHash := generateRandomHash()
	serverStaticPriv := randomKey(t)
	serverIntroKey := randomKey(t)
	aliceStaticPriv := randomKey(t)
	aliceStaticPub := mustDerivePublic(t, aliceStaticPriv)
	aliceIntroKey := randomKey(t)

	serverConfig, err := NewSSU2Config(serverHash, false)
	require.NoError(t, err)
	serverConfig.WithStaticKey(serverStaticPriv)
	serverConfig.IntroKey = serverIntroKey
	serverConfig.RouterInfoValidator = DefaultRouterInfoValidator
	serverConfig.WithHandshakeTimeout(5 * time.Second).WithDestroyTimeout(100 * time.Millisecond)

	listener, err := ListenSSU2(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	// §"Session Confirmed" -> §"Notes": Session Confirmed carries Alice's full
	// signed RouterInfo, whose "i" option Bob installs as data-phase k_header_1.
	aliceRI := testri.New(t, &testri.Options{
		StaticKey: aliceStaticPub,
		IntroKey:  aliceIntroKey,
		Host:      "127.0.0.1",
	})

	return &multiSessionHarness{
		listener:        listener,
		serverCfg:       serverConfig,
		aliceRI:         aliceRI.Bytes,
		aliceStaticPriv: aliceStaticPriv,
		aliceStaticPub:  aliceStaticPub,
		aliceIntroKey:   aliceIntroKey,
		serverIntroKey:  serverIntroKey,
	}
}

// dialAlice establishes one session as Alice and returns both ends. Each call uses
// a fresh socket and a fresh initiator connection ID, but the same static key and
// RouterInfo, so Bob sees the same peer every time.
func (h *multiSessionHarness) dialAlice(t *testing.T) (initiator, responder *SSU2Conn, socket *net.UDPConn) {
	t.Helper()

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { socket.Close() })

	var idBuf [8]byte
	_, err = i2pcrand.Read(idBuf[:])
	require.NoError(t, err)

	serverHash := h.listener.Addr().(*SSU2Addr).RouterHash()
	config, err := NewSSU2Config(generateRandomHash(), true)
	require.NoError(t, err)
	config = config.
		WithStaticKey(h.aliceStaticPriv).
		WithConnectionID(binary.BigEndian.Uint64(idBuf[:]) | 1).
		WithRemoteRouterHash(serverHash).
		WithRemoteStaticKey(mustDerivePublic(t, h.serverCfg.StaticKey)).
		WithLocalRouterInfo(h.aliceRI).
		WithDestroyTimeout(100 * time.Millisecond).
		WithHandshakeTimeout(5 * time.Second)
	config.IntroKey = h.aliceIntroKey
	config.RemoteIntroKey = h.serverIntroKey

	respAddr := h.listener.Addr().(*SSU2Addr).UnderlyingAddr().(*net.UDPAddr)

	accepted := make(chan *SSU2Conn, 1)
	go func() {
		conn, aerr := h.listener.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		sc := conn.(*SSU2Conn)
		hctx, hcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer hcancel()
		_ = sc.Handshake(hctx)
		accepted <- sc
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	initiator, err = DialSSU2WithConn(socket, respAddr, config)
	require.NoError(t, err)
	require.NoError(t, initiator.Handshake(ctx), "initiator handshake must complete")

	responder = <-accepted
	require.NotNil(t, responder, "the listener must accept the connection")
	return initiator, responder, socket
}

// TestMultipleSessions_ReplacesOldSession covers ssu2.md §"Multiple Sessions":
// "If Bob has an existing session with Alice, when Bob receives the Session
// Confirmed from Alice, completing the handshake and establishing a new session,
// Bob should: … Send a termination with reason code 22 on the old session [and]
// Remove the old session and replace it with the new one."
//
// Without it Bob keeps serving a session Alice has abandoned — she may have moved
// to a new address — and the stale entry holds a slot and a set of goroutines until
// it times out on its own.
func TestMultipleSessions_ReplacesOldSession(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	oldConnID := first.GetSSU2Addr().ConnectionID()

	// The peer index is written at Session-Confirmed completion.
	require.Eventually(t, func() bool { return h.listener.peerSessionCount() == 1 },
		3*time.Second, 20*time.Millisecond,
		"an established session must be indexed by peer router hash")

	_, second, _ := h.dialAlice(t)
	newConnID := second.GetSSU2Addr().ConnectionID()
	require.NotEqual(t, oldConnID, newConnID, "the sessions must be distinct")

	// Bullet 3: "Remove the old session and replace it with the new one."
	require.Eventually(t, func() bool {
		return h.listener.router.GetSession(oldConnID) == nil
	}, 5*time.Second, 50*time.Millisecond,
		"the old session must be removed once the new one completes")

	assert.NotEqual(t, session.StateEstablished, first.GetState(),
		"the superseded session must not remain established")

	// One index entry for one peer, pointing at the replacement.
	require.Eventually(t, func() bool {
		if h.listener.peerSessionCount() != 1 {
			return false
		}
		h.listener.sessionMutex.RLock()
		defer h.listener.sessionMutex.RUnlock()
		for _, id := range h.listener.sessionsByPeer {
			return id == newConnID
		}
		return false
	}, 3*time.Second, 20*time.Millisecond,
		"the peer index must hold exactly the replacement session")
}

// TestMultipleSessions_TerminatesOldWithReason22 covers bullet 2: "Send a
// termination with reason code 22 on the old session."
func TestMultipleSessions_TerminatesOldWithReason22(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	require.Nil(t, first.CloseReason(), "an established session has not closed")

	_, _, _ = h.dialAlice(t)

	require.Eventually(t, func() bool { return first.CloseReason() != nil },
		5*time.Second, 50*time.Millisecond,
		"the superseded session must be closed")

	reason := first.CloseReason()
	assert.Equal(t, TerminationReplacedByNewSession, *reason,
		"the old session must be terminated with reason 22, not a generic close")
}

// TestMultipleSessions_MigratesUnacknowledgedMessages covers bullet 1: "Migrate any
// unsent or unacknowledged outbound I2NP messages from the old session to the new
// one." Bob's outbound I2NP — tunnel builds and replies — must not be lost when his
// session is replaced underneath him.
func TestMultipleSessions_MigratesUnacknowledgedMessages(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	oldConnID := first.GetSSU2Addr().ConnectionID()

	// Queue an outbound I2NP message on Bob's first session and leave it
	// unacknowledged: Write goes through the send queue, and startDataLoops is
	// running, so it seals and records without any peer acknowledging it.
	_, err := first.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	require.NoError(t, err)
	// Recording happens when the send loop seals the packet, not at Write.
	require.Eventually(t, func() bool { return first.MigrationTracker().Len() == 1 },
		3*time.Second, 20*time.Millisecond,
		"an unacknowledged outbound I2NP packet must be tracked")

	_, second, _ := h.dialAlice(t)

	require.Eventually(t, func() bool {
		return h.listener.router.GetSession(oldConnID) == nil
	}, 5*time.Second, 50*time.Millisecond, "the old session must be replaced")

	// The migrated message is replayed on the new session, so the new session has
	// an outstanding I2NP packet of its own.
	require.Eventually(t, func() bool {
		tracker := second.MigrationTracker()
		return tracker != nil && tracker.Len() >= 1
	}, 5*time.Second, 50*time.Millisecond,
		"the unacknowledged message must be re-sent on the replacement session")

	assert.Zero(t, first.MigrationTracker().Len(),
		"the old session's backlog must be drained, not duplicated")
}

// TestPeerIndexKeyedByRouterHash proves the index keys on the peer's identity, not
// the address: §"Multiple Sessions" applies "whether SSU 1 or 2, or with the same or
// different IP addresses".
func TestPeerIndexKeyedByRouterHash(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	peerKey := first.GetSSU2Addr().RouterHash()
	require.False(t, peerKey.IsZero(), "an established session must carry an authenticated peer hash")

	connID := first.GetSSU2Addr().ConnectionID()
	// The index is written from the established hook, which runs as the handshake
	// completes; give it the same leeway the other tests here do.
	require.Eventually(t, func() bool {
		h.listener.sessionMutex.RLock()
		defer h.listener.sessionMutex.RUnlock()
		indexed, ok := h.listener.sessionsByPeer[peerKey]
		return ok && indexed == connID
	}, 3*time.Second, 20*time.Millisecond,
		"the session must be indexed under the peer router hash")

	// A zero hash is never indexed: an unauthenticated peer cannot be deduped.
	var zero data.Hash
	h.listener.sessionMutex.RLock()
	_, hasZero := h.listener.sessionsByPeer[zero]
	h.listener.sessionMutex.RUnlock()
	assert.False(t, hasZero, "a session without an authenticated peer hash must not be indexed")
}

// TestSupersedePeerSession_IdempotentForSameSession: the hook runs at completion,
// and re-registering the same session must not terminate it.
func TestSupersedePeerSession_IdempotentForSameSession(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	before := first.GetState()

	h.listener.supersedePeerSession(first) // second call for the same conn
	h.listener.supersedePeerSession(first)

	assert.Equal(t, before, first.GetState(),
		"a session replacing itself must be left alone")
	assert.Equal(t, 1, h.listener.peerSessionCount())
}

// TestUnindexPeerSession_KeepsReplacement: a superseded session's teardown must not
// delete its replacement's index entry.
func TestUnindexPeerSession_KeepsReplacement(t *testing.T) {
	h := newMultiSessionHarness(t)

	_, first, _ := h.dialAlice(t)
	key := first.GetSSU2Addr().RouterHash()
	firstID := first.GetSSU2Addr().ConnectionID()
	require.Eventually(t, func() bool {
		h.listener.sessionMutex.RLock()
		defer h.listener.sessionMutex.RUnlock()
		return h.listener.sessionsByPeer[key] == firstID
	}, 3*time.Second, 20*time.Millisecond, "the first session must be indexed")

	_, second, _ := h.dialAlice(t)
	newID := second.GetSSU2Addr().ConnectionID()
	require.NotEqual(t, firstID, newID)

	// The old session's close hook finally runs.
	h.listener.unindexPeerSession(first)

	h.listener.sessionMutex.RLock()
	current, ok := h.listener.sessionsByPeer[key]
	h.listener.sessionMutex.RUnlock()

	assert.True(t, ok, "the replacement's entry must survive the old session's teardown")
	assert.Equal(t, newID, current)
}
