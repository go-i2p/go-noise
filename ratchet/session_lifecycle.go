package ratchet

import (
	"context"
	"time"

	"github.com/go-i2p/logger"
)

// CleanupExpiredSessions removes sessions that have exceeded the timeout.
// Returns the number of sessions removed.
func (sm *SessionManager) CleanupExpiredSessions() int {
	flog("CleanupExpiredSessions").Debug("Cleaning up expired sessions")

	sm.mu.Lock()
	defer sm.mu.Unlock()

	removed := 0
	for hash, session := range sm.sessions {
		expired := false
		var tags [][8]byte
		var nsrTag *[8]byte

		// Snapshot session state under its lock
		session.mu.Lock()
		// Drop the retained previous inbound tag set once its ~3 minute grace
		// period has elapsed. Spec ref: ecies.md §"Parameters" - "Remove
		// previous ES tagset after: 3 minutes".
		session.expireRecvTagsets(sm.removeTagsFromIndex)
		if !sm.isSessionValid(session) {
			expired = true
			tags = session.pendingTags
			nsrTag = session.nsrTag
			for _, retired := range session.retiredRecv {
				tags = append(tags, retired.tags...)
			}
		}
		session.mu.Unlock()

		if expired {
			delete(sm.sessions, hash)
			for _, tag := range tags {
				delete(sm.tagIndex, tag)
				delete(sm.tagCounterIndex, tag)
			}
			if nsrTag != nil {
				delete(sm.nsrTagIndex, *nsrTag)
			}
			removed++
		}
	}

	if removed > 0 {
		flog("CleanupExpiredSessions", logger.Fields{"removed_sessions": removed, "remaining_sessions": len(sm.sessions), "remaining_indexed_tags": len(sm.tagIndex)}).Info("Expired sessions cleaned up")
	}

	return removed
}

// GetSessionCount returns the number of active sessions.
func (sm *SessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetPublicKey returns this session manager's X25519 public key.
func (sm *SessionManager) GetPublicKey() [32]byte {
	return sm.ourPublicKey
}

// Close stops the cleanup loop, removes all sessions, and zeroes the
// private key so it cannot be recovered from memory.
//
// It is safe to call Close multiple times.
func (sm *SessionManager) Close() error {
	sm.cancel()

	// Stop the NS replay cache cleanup goroutine.
	sm.nsReplayCache.Close()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clear all session state
	for k := range sm.sessions {
		delete(sm.sessions, k)
	}
	for k := range sm.tagIndex {
		delete(sm.tagIndex, k)
	}
	for k := range sm.tagCounterIndex {
		delete(sm.tagCounterIndex, k)
	}
	for k := range sm.nsrTagIndex {
		delete(sm.nsrTagIndex, k)
	}
	sm.nsReplayCache.Reset()

	// Zero the private key material
	for i := range sm.ourPrivateKey {
		sm.ourPrivateKey[i] = 0
	}

	flog("Close").Debug("SessionManager closed")
	return nil
}

// StartCleanupLoop starts periodic cleanup of expired sessions in a
// background goroutine. The loop runs every 2 minutes and stops when
// either of the following occurs:
//
//  1. The caller-supplied ctx is cancelled.
//  2. [SessionManager.Close] is called on this SessionManager (which
//     cancels the internal context regardless of the caller's ctx).
//
// Note: Close() can terminate the loop independently of the ctx supplied
// here. This is intentional — it prevents orphaned cleanup goroutines when
// the SessionManager is shut down. To stop only the loop without
// destroying the SessionManager, cancel the ctx passed here; to stop both
// the loop and the manager, call Close().
func (sm *SessionManager) StartCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.CleanupExpiredSessions()
			case <-ctx.Done():
				return
			case <-sm.ctx.Done():
				return
			}
		}
	}()

	flog("StartCleanupLoop", logger.Fields{"interval": "2m"}).Debug("Started garlic session cleanup loop")
}
