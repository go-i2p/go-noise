package ratchet

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panicProbeSession returns a session whose CleanupExpiredSessions snapshot is
// guaranteed to panic inside the session.mu-locked section. expireRecvTagsets
// walks s.retiredRecv and dereferences each entry's expiresAt; a nil entry in a
// non-empty list gives a deterministic nil-pointer dereference at exactly the
// point the I2P-004 / GN-009 seam must release session.mu. The session is kept
// fresh (LastUsed = now) so the panic, not the expiry path, is what unwinds the
// locked section.
func panicProbeSession() *Session {
	return &Session{
		LastUsed:     time.Now(),
		lastSent:     time.Now(),
		lastReceived: time.Now(),
		// Non-empty list with a nil element: expireRecvTagsets passes its
		// len==0 guard, then dereferences the nil entry.
		retiredRecv: altTagsetList{nil},
	}
}

// registerSession inserts a session into the manager under its own hash.
func registerSession(sm *SessionManager, hash [32]byte, session *Session) {
	sm.mu.Lock()
	sm.sessions[hash] = session
	sm.mu.Unlock()
}

// TestRecoverTickContainsPanic exercises the ratchet recoverTick helper that
// guards the cleanup loop (I2P-004): a panicking cleanup tick is contained and
// the goroutine survives, while a clean tick runs to completion.
func TestRecoverTickContainsPanic(t *testing.T) {
	var ran bool
	assert.NotPanics(t, func() {
		recoverTick("test.tick", func() {
			ran = true
			panic("simulated cleanup panic")
		})
	})
	assert.True(t, ran, "recoverTick must run fn before recovering")

	var cleanRan bool
	recoverTick("test.tick", func() { cleanRan = true })
	assert.True(t, cleanRan, "recoverTick must not interfere with a clean tick")
}

// TestCleanupExpiredSessions_PanicReleasesSessionMutex is the GN-009 regression
// test. CleanupExpiredSessions holds session.mu while it calls expireRecvTagsets
// and isSessionValid, both of which walk remote-input-derived session state, and
// it runs under recoverTick, which recovers the panic in its own frame. If the
// section's Unlock were a plain statement at the end (the pre-fix code), the
// unwinding panic would skip it and leak session.mu, wedging every other
// session.mu holder — the encrypt/decrypt paths, destroyKeyMaterial, and every
// later cleanup tick — for the life of the session, turning a recoverable crash
// into a permanently stuck garlic session. The fix defers the Unlock inside a
// closure, so the panic path releases the lock too.
func TestCleanupExpiredSessions_PanicReleasesSessionMutex(t *testing.T) {
	sm := createTestSessionManager(t)

	session := panicProbeSession()
	var hash [32]byte
	hash[0] = 0x09
	registerSession(sm, hash, session)

	// The panic must be reachable inside the locked section.
	require.Panics(t, func() { sm.CleanupExpiredSessions() },
		"a nil retired tagset entry must panic inside the session.mu-locked section")

	// The real caller (recoverTick) must contain that same panic.
	assert.NotPanics(t, func() {
		recoverTick("ratchet.CleanupLoop", func() { sm.CleanupExpiredSessions() })
	}, "recoverTick must recover a panic from CleanupExpiredSessions")

	// GN-009: after the panic unwinds past the locked section, session.mu must be
	// free. Under the pre-fix plain-Unlock code the mutex would still be held here
	// and TryLock would fail.
	require.True(t, session.mu.TryLock(),
		"session.mu must be released after a panic in CleanupExpiredSessions (GN-009)")
	session.mu.Unlock()
}

// TestCleanupLoopSurvivesPanic proves the cleanup seam keeps releasing
// session.mu across repeated recovered ticks, not just the first. A panicking
// tick wrapped in recoverTick must leave the lock free every time, so a later
// legitimate holder (e.g. destroyKeyMaterial on Close) is never wedged. This is
// the multi-tick counterpart to the single-tick regression test above; it drives
// the seam on a fast ticker rather than the real 2-minute StartCleanupLoop.
func TestCleanupLoopSurvivesPanic(t *testing.T) {
	sm := createTestSessionManager(t)

	session := panicProbeSession()
	var hash [32]byte
	hash[0] = 0x0A
	registerSession(sm, hash, session)

	var mu sync.Mutex
	ticks := 0
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
				recoverTick("ratchet.CleanupLoop", func() {
					mu.Lock()
					ticks++
					mu.Unlock()
					sm.CleanupExpiredSessions()
				})
			}
		}
	}()

	// Let several ticks panic and be recovered.
	time.Sleep(120 * time.Millisecond)
	close(stop)
	<-done

	mu.Lock()
	observed := ticks
	mu.Unlock()
	require.Greater(t, observed, 1, "the loop must have ticked more than once")

	// Every recovered tick must have released session.mu.
	require.True(t, session.mu.TryLock(),
		"session.mu must be free after recovered cleanup ticks (GN-009)")
	session.mu.Unlock()
}
