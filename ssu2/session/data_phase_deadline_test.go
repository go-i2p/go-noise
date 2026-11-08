package session

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Finding 012: an SSU2 initiator treated a handshake the peer never completed as
// an established session, retransmitted into it forever, and never timed out.
// The three defects were independent, so each gets its own test.

// initiatorFixture builds an initiator conn with a short data-phase deadline and
// no destroy wait, so a watchdog test can observe the close without paying the
// spec's 11 s closing period.
//
// A send cipher is installed so payloads are really sealed: without one
// encryptDataPayload returns a nil plaintext, and a retransmission would then be
// re-tracked with nothing to resend, which is not the path these tests are about.
func initiatorFixture(t *testing.T, localPort, remotePort int, dataPhaseTimeout time.Duration) (*SSU2Conn, *mockPacketConn) {
	t.Helper()

	underlying := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort})
	config := createTestConfig(t)
	config.DestroyTimeout = 0
	config.DataPhaseTimeout = dataPhaseTimeout

	conn, err := NewSSU2Conn(
		underlying,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		config,
		true,
		testLocalStaticKey(t),
		config.RemoteStaticKey,
	)
	require.NoError(t, err)

	conn.cipherMutex.Lock()
	conn.sendCipher = newTestSendCipher(t)
	conn.cipherMutex.Unlock()

	t.Cleanup(func() { conn.CloseImmediate() })
	return conn, underlying
}

// transmitQueued sends whatever retransmitExpired re-enqueued, the way sendLoop
// would. Without this the new packet never reaches sendPacketDirect, the
// re-tracking path is never taken, and a test of the retry budget proves nothing.
func transmitQueued(t *testing.T, conn *SSU2Conn, underlying *mockPacketConn) int {
	t.Helper()

	sent := 0
	for {
		select {
		case packet := <-conn.sendQueue:
			require.NoError(t, conn.sendPacketDirect(packet))
			requireWritten(t, underlying)
			sent++
		default:
			return sent
		}
	}
}

// TestRetransmitExpired_RetryBudgetCarriesAcrossResends covers the retransmission
// half of finding 012. ssu2.md §"Packet Numbering" requires each resend to use a
// fresh packet number, which the old code read as licence to restart the retry
// count at zero — so maxPacketRetries was unreachable and contents no peer ever
// acknowledged were retransmitted for the life of the session.
func TestRetransmitExpired_RetryBudgetCarriesAcrossResends(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9312, 9311, 0)

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 40))
	sendDataPacket(t, conn, underlying, i2np)

	conn.pendingMutex.Lock()
	require.Len(t, conn.pendingPackets, 1)
	conn.pendingMutex.Unlock()

	// Drive the scan until the contents are abandoned. Each pass re-enqueues the
	// payload under a new packet number; the count must ride with it.
	passes := maxPacketRetries + 1
	for range passes {
		conn.pendingMutex.Lock()
		for _, entry := range conn.pendingPackets {
			entry.NextRetry = time.Now().Add(-time.Second)
		}
		conn.pendingMutex.Unlock()

		conn.retransmitExpired()
		if transmitQueued(t, conn, underlying) == 0 {
			// Nothing was re-enqueued, which means the entry was abandoned. With
			// the budget carried across resends that cannot happen before the
			// cap, so record where it stopped for the assertion below.
			break
		}
	}

	conn.pendingMutex.Lock()
	remaining := len(conn.pendingPackets)
	conn.pendingMutex.Unlock()
	assert.Zero(t, remaining,
		"unacknowledged contents must be abandoned once the retry cap is reached, "+
			"however many packet numbers they were retransmitted under (passes=%d)", passes)
}

// TestRetransmitExpired_ResendUsesFreshPacketNumber proves the fix does not break
// the spec rule sitting next to it: ssu2.md §"Packet Numbering" — "Data Packets
// are never retransmitted with the same packet number."
func TestRetransmitExpired_ResendUsesFreshPacketNumber(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9316, 9315, 0)

	block := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 40))
	sendDataPacket(t, conn, underlying, block)

	conn.pendingMutex.Lock()
	require.Len(t, conn.pendingPackets, 1)
	var original uint32
	for pn, entry := range conn.pendingPackets {
		original = pn
		entry.NextRetry = time.Now().Add(-time.Second)
	}
	conn.pendingMutex.Unlock()

	conn.retransmitExpired()
	require.Equal(t, 1, transmitQueued(t, conn, underlying),
		"one expired packet must produce exactly one resend")

	conn.pendingMutex.Lock()
	defer conn.pendingMutex.Unlock()
	require.Len(t, conn.pendingPackets, 1, "the resend must be tracked")
	for pn, entry := range conn.pendingPackets {
		assert.NotEqual(t, original, pn,
			"a retransmission must use a fresh packet number")
		assert.Equal(t, 1, entry.Retries,
			"the resend must carry the retry count of the contents it resends")
	}
}

// TestSendPacketDirect_ResendDoesNotRefreshActivity covers the idle-timer half of
// finding 012: every resend refreshed lastActivity, so the idle timeout could
// never fire on the one session that needed it.
func TestSendPacketDirect_ResendDoesNotRefreshActivity(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9322, 9321, 0)

	block := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 40))
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	fresh := conn.newDataPacket()
	fresh.Payload = payload
	conn.lastActivityLock.Lock()
	conn.lastActivity = time.Now().Add(-time.Minute)
	conn.lastActivityLock.Unlock()

	require.NoError(t, conn.sendPacketDirect(fresh))
	requireWritten(t, underlying)

	conn.lastActivityLock.RLock()
	afterFresh := conn.lastActivity
	conn.lastActivityLock.RUnlock()
	assert.True(t, afterFresh.After(time.Now().Add(-time.Second)),
		"a fresh send must still refresh the idle timer")

	resend := conn.newDataPacket()
	resend.Payload = payload
	resend.ResendCount = 1

	require.NoError(t, conn.sendPacketDirect(resend))
	requireWritten(t, underlying)

	conn.lastActivityLock.RLock()
	afterResend := conn.lastActivity
	conn.lastActivityLock.RUnlock()
	assert.Equal(t, afterFresh, afterResend,
		"a retransmission must not refresh the idle timer")
}

// TestStartDataPhaseWatchdog_TeardownWhenPeerNeverAnswers is the headline of
// finding 012: a responder that accepts a SessionRequest, answers Session
// Created, and then sends nothing left the initiator with a session that
// reported itself established forever.
func TestStartDataPhaseWatchdog_TeardownWhenPeerNeverAnswers(t *testing.T) {
	conn, _ := initiatorFixture(t, 9332, 9331, 100*time.Millisecond)

	conn.startDataPhaseWatchdog()
	assert.False(t, conn.PeerDataReceived(), "no peer data has arrived")

	require.Eventually(t, func() bool {
		state := conn.GetState()
		return state == StateClosing || state == StateClosed
	}, 3*time.Second, 10*time.Millisecond,
		"a handshake the peer never completed must be torn down")

	reason := conn.CloseReason()
	require.NotNil(t, reason)
	assert.Equal(t, TerminationSessionConfirmedError, *reason,
		"the teardown must report the Session Confirmed as the problem")
}

// TestStartDataPhaseWatchdog_PeerDataCancelsTeardown proves the deadline does not
// fire for a session the peer did complete.
func TestStartDataPhaseWatchdog_PeerDataCancelsTeardown(t *testing.T) {
	conn, _ := initiatorFixture(t, 9342, 9341, 100*time.Millisecond)

	conn.startDataPhaseWatchdog()
	require.True(t, conn.notePeerDataPacket(),
		"the first peer data packet must be reported as new")

	time.Sleep(400 * time.Millisecond)
	assert.Equal(t, StateInit, conn.GetState(),
		"a session whose peer answered must not be torn down")
	assert.True(t, conn.PeerDataReceived())
}

// TestProcessInboundPacket_DataPacketDisarmsWatchdog is the wiring test: the
// deadline is only correct if the receive path actually marks the peer as heard
// from. An empty payload skips the AEAD open, so the packet reaches the data
// handler exactly as a decrypted one would.
func TestProcessInboundPacket_DataPacketDisarmsWatchdog(t *testing.T) {
	conn, _ := initiatorFixture(t, 9346, 9345, 150*time.Millisecond)

	conn.recvWindow = NewReceiveWindow(0, DefaultMaxWindowSize)
	conn.startDataPhaseWatchdog()
	require.False(t, conn.PeerDataReceived())

	conn.ProcessInboundPacket(&SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: 0,
		Header:       make([]byte, ShortHeaderSize),
	})

	assert.True(t, conn.PeerDataReceived(),
		"an inbound data-phase packet must count as the peer completing the handshake")

	// The watchdog must not fire afterwards.
	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()
	time.Sleep(500 * time.Millisecond)
	assert.NotEqual(t, StateClosed, conn.GetState(),
		"a session whose peer has answered must not be closed by the deadline")
}

// TestNotePeerDataPacket_StopsSessionConfirmedRetransmission ties the two
// mechanisms to the one spec condition: ssu2.md §"Handshake Retransmission" ->
// §"Session Confirmed" option 2 retransmits "until a data message is received".
func TestNotePeerDataPacket_StopsSessionConfirmedRetransmission(t *testing.T) {
	conn, _ := initiatorFixture(t, 9352, 9351, 0)

	require.True(t, conn.storeSessionConfirmed([][]byte{{0x01, 0x02, 0x03}}))
	require.True(t, conn.retransmitSessionConfirmed())

	conn.notePeerDataPacket()
	assert.False(t, conn.retransmitSessionConfirmed(),
		"the first authenticated data packet must end Session Confirmed retransmission")
}

// TestRetainHandshakeDatagram_ReplayedAfterKeysInstalled covers the addendum: a
// data packet arriving before finalizeHandshake installs the data-phase keys used
// to be dropped, and the peer never reuses that packet number, so the session
// never recovered.
func TestRetainHandshakeDatagram_ReplayedAfterKeysInstalled(t *testing.T) {
	conn, _ := initiatorFixture(t, 9362, 9361, 0)

	datagram := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dest conn ID
		0x00, 0x00, 0x00, 0x01, // packet number
		0x06,       // type = Data
		0x00,       // frag: 0 of 1
		0x00, 0x00, // moreflags
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9361}

	conn.retainHandshakeDatagram(datagram, addr)

	conn.pendingHandshakeDataMutex.Lock()
	retained := len(conn.pendingHandshakeDatagrams)
	conn.pendingHandshakeDataMutex.Unlock()
	assert.Equal(t, 1, retained, "a handshaking initiator must retain what it cannot parse")

	// Replaying a datagram that is not a real sealed packet must not panic or
	// deliver anything; it simply fails the AEAD open and is dropped there.
	conn.flushPendingHandshakeDatagrams()

	conn.pendingHandshakeDataMutex.Lock()
	after := len(conn.pendingHandshakeDatagrams)
	conn.pendingHandshakeDataMutex.Unlock()
	assert.Zero(t, after, "the buffer must be drained by the flush")
}

// TestRetainHandshakeDatagram_IgnoredOnceEstablished proves the retention is
// scoped to the handshake race window and stays off the steady-state path.
func TestRetainHandshakeDatagram_IgnoredOnceEstablished(t *testing.T) {
	conn, _ := initiatorFixture(t, 9372, 9371, 0)

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	conn.retainHandshakeDatagram([]byte{0x01, 0x02, 0x03}, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 9371,
	})

	conn.pendingHandshakeDataMutex.Lock()
	retained := len(conn.pendingHandshakeDatagrams)
	conn.pendingHandshakeDataMutex.Unlock()
	assert.Zero(t, retained,
		"an established session has no future key install to wait for, so it drops as before")
}

// TestReadOnePacket_HandshakingInitiatorRetainsUnparsableDatagram is the wiring
// test for the retention: it drives the real read path, so dropping the call from
// readOnePacket is caught rather than only the helper's own behaviour.
func TestReadOnePacket_HandshakingInitiatorRetainsUnparsableDatagram(t *testing.T) {
	conn, _ := initiatorFixture(t, 9392, 9391, 0)

	// Too short to be any valid SSU2 packet, so the parse cannot succeed.
	datagram := []byte{0x00, 0x01, 0x02}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9391}

	require.False(t, conn.readOnePacket(datagram, addr),
		"a datagram that cannot be parsed must not be reported as processed")

	conn.pendingHandshakeDataMutex.Lock()
	retained := len(conn.pendingHandshakeDatagrams)
	var stored []byte
	if retained == 1 {
		stored = conn.pendingHandshakeDatagrams[0].data
	}
	conn.pendingHandshakeDataMutex.Unlock()

	require.Equal(t, 1, retained, "the read path must hand an unparsed datagram to retention")
	assert.Equal(t, datagram, stored,
		"the retained bytes must be the wire copy, not the header the failed parse left behind")
}

// TestRetainHandshakeDatagram_Bounded proves the retention window cannot be used
// to make a session accumulate unbounded state.
func TestRetainHandshakeDatagram_Bounded(t *testing.T) {
	conn, _ := initiatorFixture(t, 9382, 9381, 0)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9381}

	for range pendingHandshakeDataMax * 2 {
		conn.retainHandshakeDatagram([]byte{0xde, 0xad, 0xbe, 0xef}, addr)
	}

	conn.pendingHandshakeDataMutex.Lock()
	retained := len(conn.pendingHandshakeDatagrams)
	conn.pendingHandshakeDataMutex.Unlock()
	assert.Equal(t, pendingHandshakeDataMax, retained,
		"the handshake race window must stay bounded")
}

// lastActivityAge returns how long ago the connection last recorded activity.
func lastActivityAge(conn *SSU2Conn) time.Duration {
	conn.lastActivityLock.RLock()
	defer conn.lastActivityLock.RUnlock()
	return time.Since(conn.lastActivity)
}

// TestResendDoesNotRefreshIdleClock is the regression guard for the idle-timeout
// half of finding 012. sendPacketDirect used to call updateActivity unconditionally,
// so every retransmission pushed lastActivity forward and the 5-minute idle check
// could never fire — the lab saw a 104-minute session that never timed out because
// it was constantly resending into a peer that had rejected the handshake.
//
// A resend must therefore leave the idle clock alone: it is not evidence the peer
// is alive, only that we are still shouting at it.
func TestResendDoesNotRefreshIdleClock(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9412, 9411, 0)

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 40))
	sendDataPacket(t, conn, underlying, i2np)

	// Pull the idle clock back so a refresh would be obvious.
	conn.lastActivityLock.Lock()
	conn.lastActivity = time.Now().Add(-30 * time.Second)
	conn.lastActivityLock.Unlock()

	// Force the pending packet due and drive one resend through the real path.
	conn.pendingMutex.Lock()
	for _, entry := range conn.pendingPackets {
		entry.NextRetry = time.Now().Add(-time.Second)
	}
	conn.pendingMutex.Unlock()
	conn.retransmitExpired()
	require.Positive(t, transmitQueued(t, conn, underlying),
		"the expired packet must actually be retransmitted for this test to mean anything")

	assert.Greater(t, lastActivityAge(conn), 25*time.Second,
		"a retransmission must not refresh the idle clock")
}

// TestIdleKeepalive_IsANoOpWhenNothingToAck documents why the idle timeout is in
// fact reachable: the keepalive sends an ACK-only packet, and GenerateACK returns
// nil when no inbound packets are pending, so a purely idle session emits nothing
// and never refreshes lastActivity. The earlier belief that "the keepalive ACK is a
// fresh send that refreshes the clock every interval" was wrong for the idle case.
func TestIdleKeepalive_IsANoOpWhenNothingToAck(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9422, 9421, 0)

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	conn.lastActivityLock.Lock()
	conn.lastActivity = time.Now().Add(-30 * time.Second)
	conn.lastActivityLock.Unlock()

	drainWrites(underlying)
	conn.sendImmediateACK()

	select {
	case written := <-underlying.writeChan:
		t.Fatalf("keepalive wrote %d bytes on a session with nothing to acknowledge", len(written.data))
	default:
	}

	assert.Greater(t, lastActivityAge(conn), 25*time.Second,
		"an idle keepalive must not refresh the idle clock")
}

// TestKeepaliveLoop_ReapsSilentSession proves the idle timeout fires end-to-end for
// a session that has stopped hearing from its peer, which is the recovery the
// finding asked for.
func TestKeepaliveLoop_ReapsSilentSession(t *testing.T) {
	conn, _ := initiatorFixture(t, 9432, 9431, 0)
	conn.config.IdleTimeout = 100 * time.Millisecond
	conn.config.KeepaliveInterval = 20 * time.Millisecond

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	conn.lastActivityLock.Lock()
	conn.lastActivity = time.Now().Add(-time.Minute)
	conn.lastActivityLock.Unlock()

	conn.wg.Add(1)
	go conn.keepaliveLoop()

	require.Eventually(t, func() bool {
		s := conn.GetState()
		return s == StateClosing || s == StateClosed
	}, 2*time.Second, 10*time.Millisecond, "an idle session must be reaped by the idle timeout")
}

// TestKeepaliveLoop_ReapsSessionWithStuckResends is the scenario the lab observed:
// a session continually retransmitting into a peer that answers nothing. With the
// resend no longer refreshing the idle clock, the timeout still reaps it.
func TestKeepaliveLoop_ReapsSessionWithStuckResends(t *testing.T) {
	conn, underlying := initiatorFixture(t, 9442, 9441, 0)
	conn.config.IdleTimeout = 400 * time.Millisecond
	conn.config.KeepaliveInterval = 20 * time.Millisecond

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	i2np := NewSSU2Block(BlockTypeI2NPMessage, make([]byte, 40))
	sendDataPacket(t, conn, underlying, i2np)

	conn.wg.Add(1)
	go conn.keepaliveLoop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn.pendingMutex.Lock()
		for _, entry := range conn.pendingPackets {
			entry.NextRetry = time.Now().Add(-time.Second)
		}
		conn.pendingMutex.Unlock()
		conn.retransmitExpired()
		transmitQueued(t, conn, underlying)

		s := conn.GetState()
		if s == StateClosing || s == StateClosed {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("a session stuck retransmitting to a silent peer was never reaped (state %v)", conn.GetState())
}
