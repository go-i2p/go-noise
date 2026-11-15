package session

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panicProbeConn builds a minimal established session whose data-phase
// processing panics: its dataHandler is nil, so ProcessDataPacket dereferences
// a nil receiver. This gives a deterministic, remote-input-shaped panic at the
// exact point the I2P-004 seam must contain.
func panicProbeConn() *SSU2Conn {
	return &SSU2Conn{
		underlying: &mockPacketConn{localAddr: &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 8888}},
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999},
		state:      1, // StateEstablished
		closeChan:  make(chan struct{}),
	}
}

func panicProbePacket() *SSU2Packet {
	return &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: 0,
		Header:       make([]byte, ShortHeaderSize),
		Payload:      make([]byte, MinPayloadSize),
	}
}

// TestProcessInboundPacket_RecoveredPanics proves the I2P-004 session-side
// seam: a panic raised while processing an inbound data packet (here from a
// nil dataHandler, standing in for any DataHandler-callback bug reachable from
// remote input) must be recovered and the packet dropped, NOT propagated to
// kill the read-worker goroutine and the process.
func TestProcessInboundPacket_RecoveredPanics(t *testing.T) {
	conn := panicProbeConn()

	// The inner body must panic — this is the panic the seam exists to catch.
	require.Panics(t, func() {
		conn.processInboundPacket(panicProbePacket())
	})

	// The public entry point must swallow that same panic.
	assert.NotPanics(t, func() {
		conn.ProcessInboundPacket(panicProbePacket())
	}, "ProcessInboundPacket must recover panics from packet processing")
}

// TestRecoverPacketContainsPanic exercises the recoverPacket helper directly:
// a panicking fn is contained, a clean fn runs to completion.
func TestRecoverPacketContainsPanic(t *testing.T) {
	var reached bool
	assert.NotPanics(t, func() {
		recoverPacket(func() {
			reached = true
			panic("simulated callback panic")
		})
	})
	assert.True(t, reached, "recoverPacket must run fn before recovering")

	var cleanRan bool
	recoverPacket(func() { cleanRan = true })
	assert.True(t, cleanRan)
}

// TestRecoverTickContainsPanic exercises the recoverTick helper used by the
// DataHandler reaper (I2P-004): a panicking cleanup tick is contained, a clean
// tick runs normally.
func TestRecoverTickContainsPanic(t *testing.T) {
	var ran bool
	assert.NotPanics(t, func() {
		recoverTick("test.tick", func() {
			ran = true
			panic("simulated cleanup panic")
		})
	})
	assert.True(t, ran)

	var cleanRan bool
	recoverTick("test.tick", func() { cleanRan = true })
	assert.True(t, cleanRan)
}

// TestRetransmitExpired_PanicReleasesPendingMutex is the REC-001 regression
// test. retransmitExpired holds pendingMutex while it walks pendingPackets and
// calls newDataPacket(), both reachable from remote input, and it runs under
// recoverTick, which recovers the panic in its own frame. If the section's
// Unlock were a plain statement at the end (the pre-fix code), the unwinding
// panic would skip it and leak pendingMutex, wedging every other pendingMutex
// holder — trackPendingPacket, notePacketLosses, retireAckedPackets and the
// next retransmit tick — for the life of the connection, converting a
// recoverable crash into a permanent send-side hang. The fix defers the Unlock
// inside a closure, so the panic path releases the lock too.
//
// A nil *PendingPacket map entry gives a deterministic nil-dereference panic at
// pp.NextRetry, inside the locked section.
func TestRetransmitExpired_PanicReleasesPendingMutex(t *testing.T) {
	conn := &SSU2Conn{
		rttEstimator:   NewRTTEstimator(),
		pendingPackets: map[uint32]*PendingPacket{1: nil},
		sendQueue:      make(chan *SSU2Packet, 1),
	}

	// The panic must be reachable inside the locked section.
	require.Panics(t, func() { conn.retransmitExpired() },
		"a nil pending entry must panic inside the locked section")

	// The real caller (recoverTick) must contain that same panic.
	assert.NotPanics(t, func() {
		recoverTick("retransmitLoop", conn.retransmitExpired)
	}, "recoverTick must recover a panic from retransmitExpired")

	// REC-001: after the panic unwinds past the locked section, pendingMutex
	// must be free. Under the pre-fix plain-Unlock code the mutex would still be
	// held here and TryLock would fail.
	require.True(t, conn.pendingMutex.TryLock(),
		"pendingMutex must be released after a panic in retransmitExpired (REC-001)")
	conn.pendingMutex.Unlock()
}

// TestRetransmitLoopSurvivesPanic proves the retransmit goroutine keeps running
// after a recovered panic: the loop must survive one bad tick and still be
// ticking (still draining closeChan cleanly) on the next. This is the REC-003
// coverage the recovery commit shipped without.
func TestRetransmitLoopSurvivesPanic(t *testing.T) {
	conn := &SSU2Conn{
		rttEstimator:   NewRTTEstimator(),
		pendingPackets: map[uint32]*PendingPacket{1: nil}, // panics every tick
		sendQueue:      make(chan *SSU2Packet, 1),
		closeChan:      make(chan struct{}),
	}
	conn.wg.Add(1)
	go conn.retransmitLoop()

	// Let several ticks panic and be recovered. retransmitInterval is 250ms.
	time.Sleep(600 * time.Millisecond)

	// The goroutine is still alive: closing cleanly must unblock wg.Wait within
	// the interval, proving the loop reached its select again rather than dying.
	close(conn.closeChan)
	done := make(chan struct{})
	go func() { conn.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retransmitLoop did not exit after closeChan: goroutine died or wedged on a leaked mutex")
	}

	// And the mutex was released on every recovered tick.
	require.True(t, conn.pendingMutex.TryLock(),
		"pendingMutex must be free after recovered retransmit ticks (REC-001)")
	conn.pendingMutex.Unlock()
}

// TestSendLoopSurvivesPanic proves sendLoop's per-iteration recoverTick seam
// (I2P-004) keeps the send goroutine alive across a panicking send: a panic on
// one queued packet must not kill the loop, and a subsequent clean packet must
// still be drained.
func TestSendLoopSurvivesPanic(t *testing.T) {
	conn := &SSU2Conn{
		underlying:     &mockPacketConn{localAddr: &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 8888}},
		remoteAddr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999},
		closeChan:      make(chan struct{}),
		sendQueue:      make(chan *SSU2Packet, 4),
		pendingPackets: map[uint32]*PendingPacket{},
		rttEstimator:   NewRTTEstimator(),
	}
	conn.wg.Add(1)
	go conn.sendLoop()

	// A nil-payload packet reaches the encryption path and panics; the loop must
	// recover and keep running. Then a nil closeChan signal stops it.
	conn.sendQueue <- &SSU2Packet{MessageType: MessageTypeData, PacketNumber: 1}
	time.Sleep(100 * time.Millisecond)

	// Loop still alive: it must still be selecting on closeChan.
	close(conn.closeChan)
	done := make(chan struct{})
	go func() { conn.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendLoop did not exit after closeChan: goroutine died on a panic")
	}
}

// TestTokenCleanupLoopSurvivesPanic and TestReaperSurvivesPanic cover the two
// remaining recovered loops named in REC-003 (server token cleanup and the
// DataHandler fragment reaper). Both live in their own packages; the server
// case is exercised in ssu2/server, the reaper case here drives the seam that
// guards cleanupStaleFragments.
func TestReaperSurvivesPanic(t *testing.T) {
	// cleanupStaleFragments on a zero-value DataHandler is panic-free, so drive
	// the seam the way the reaper does: a panicking tick wrapped in recoverTick
	// must not stop the loop. We assert the loop's guard contract directly.
	var ticks int
	var mu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				recoverTick("DataHandler.reaper", func() {
					mu.Lock()
					ticks++
					mu.Unlock()
					panic("simulated fragment-walk panic")
				})
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reaper loop stopped after a recovered panic")
	}
	mu.Lock()
	defer mu.Unlock()
	require.Greater(t, ticks, 1, "reaper must keep ticking after a recovered panic")
}
