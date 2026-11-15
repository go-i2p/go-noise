package server

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleIncomingPacket_RecoveredPanics proves the I2P-004 listener-side
// seam: a panic raised while processing one inbound datagram on a packet
// worker — here from a nil PacketRouter reached via RoutePacket, standing in
// for any listener-level or path-manager callback bug triggered by remote
// input — must be recovered and the packet dropped, NOT propagated to kill the
// worker goroutine and the router process.
func TestHandleIncomingPacket_RecoveredPanics(t *testing.T) {
	introKey := randomKey(t)
	l := newTestListenerWithIntroKey(t, introKey)

	// A TokenRequest decodes through the intro-key protector and matches our
	// network ID, so handleIncomingPacket reaches RoutePacket. With the router
	// nil, RoutePacket dereferences its nil receiver and panics — the exact
	// class of failure the seam must contain.
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x1122334455667788,
		SourceConnID: 0x99aabbccddeeff00,
		Token:        make([]byte, TokenSize),
		Blocks:       []*SSU2Block{NewDateTimeBlock(), NewSSU2Block(BlockTypePadding, make([]byte, 24))},
	}
	wire, _, err := BuildIntroKeyMessage(introKey, spec)
	require.NoError(t, err)

	// Swap in a nil router to force a panic inside RoutePacket, and restore the
	// real one before the listener's Close() cleanup runs (Close dereferences
	// the router).
	origRouter := l.router
	l.router = nil
	defer func() { l.router = origRouter }()

	assert.NotPanics(t, func() {
		l.handleIncomingPacket(wire, testPeerAddr())
	}, "handleIncomingPacket must recover panics from packet processing")

	// The recovered panic is counted as a routing error so operators can see it.
	assert.NotZero(t, l.Stats()["routing_errors"],
		"a recovered panic must increment the routing_errors counter")
}

// TestTokenCleanupLoop_RecoveredPanics proves the I2P-004 seam guarding
// tokenCleanupLoop (REC-003): the tick body calls tokenCache.Cleanup() and
// firstSight.Cleanup(), both fed by remote input. A nil tokenCache dereferences
// its mutex and panics — the exact failure the seam must contain. recoverTick
// must swallow it so the cleanup goroutine survives to the next tick rather
// than killing the router.
func TestTokenCleanupLoop_RecoveredPanics(t *testing.T) {
	l := newTestListenerWithIntroKey(t, randomKey(t))

	origCache := l.tokenCache
	l.tokenCache = nil
	defer func() { l.tokenCache = origCache }()

	// The tick body must panic with a nil cache — this is the panic the seam catches.
	require.Panics(t, func() { l.tokenCache.Cleanup() })

	// The seam must contain that same panic.
	assert.NotPanics(t, func() {
		recoverTick("tokenCleanupLoop", func() {
			l.tokenCache.Cleanup()
			l.firstSight.Cleanup()
		})
	}, "recoverTick must recover a panic from the token-cleanup tick")
}

// TestTokenCleanupLoopSurvivesPanic proves the cleanup goroutine keeps ticking
// after a recovered panic. tokenCleanupInterval is 60s, too long to drive a
// live tick in-test, so this exercises the loop contract the seam provides: a
// ticker loop whose body panics every tick, guarded by recoverTick, must keep
// ticking rather than dying.
func TestTokenCleanupLoopSurvivesPanic(t *testing.T) {
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
				recoverTick("tokenCleanupLoop", func() {
					mu.Lock()
					ticks++
					mu.Unlock()
					panic("simulated token-cache panic")
				})
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("token cleanup loop stopped after a recovered panic")
	}
	mu.Lock()
	defer mu.Unlock()
	require.Greater(t, ticks, 1, "token cleanup loop must keep ticking after a recovered panic")
}
