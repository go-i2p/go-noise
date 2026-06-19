package ratchet

import (
	"fmt"
	"time"

	"github.com/go-i2p/logger"
)

const (
	// MaxGarlicSessions is the upper bound on active garlic sessions.
	MaxGarlicSessions = 5000

	// MaxSessionsPerPeer caps the number of concurrent garlic sessions that
	// may exist for a single remote static public key. An attacker who can
	// replay many NS messages from a forged or reused identity cannot use up
	// more than this fraction of the global session table (AUDIT L-4).
	// When exceeded, the oldest session for that peer is evicted first,
	// protecting sessions from other honest peers from LRU churn.
	MaxSessionsPerPeer = 32
)

// removeSessionByPointer locates a session in sm.sessions by pointer equality
// and removes it along with all its tags from sm.tagIndex and sm.nsrTagIndex.
//
// This is used when we have a *Session reference (e.g., from a tag lookup)
// but not the session hash key. The linear scan is acceptable because it runs
// at most once per Termination block (a rare, session-lifetime event).
func (sm *SessionManager) removeSessionByPointer(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var foundHash [32]byte
	found := false
	for hash, s := range sm.sessions {
		if s == session {
			foundHash = hash
			found = true
			break
		}
	}
	if !found {
		return // already removed (e.g., by concurrent cleanup)
	}

	// Clean up all index entries for this session.
	sm.cleanupSessionIndexesLocked(session, foundHash)

	flog("removeSessionByPointer", logger.Fields{"remaining_count": len(sm.sessions)}).Debug("Session removed after termination")
}

// FindSessionByTag checks if a session tag matches a known session.
// Returns true if the tag was found (and consumed), false otherwise.
// This implements the TagResolver interface for independent tag-only resolution.
//
// Two-phase locking: the global index lookup (sm.mu) and per-session validation
// (session.mu) are performed in separate, non-overlapping critical sections.
// Tag replenishment (HKDF) is performed outside both locks.
func (sm *SessionManager) FindSessionByTag(tag [8]byte) bool {
	flog("FindSessionByTag").Debug("Finding session by tag")
	sm.mu.Lock()
	session, _ := sm.lookupSessionByTag(tag)
	sm.mu.Unlock()

	if session == nil {
		return false
	}

	valid, needsReplenish := sm.validateAndConsumeTagFromSession(session, tag)
	if !valid {
		return false
	}

	if needsReplenish {
		sm.replenishTagWindowOutsideLock(session)
	}
	return true
}

// lookupSessionByTag locates the session for tag and atomically removes it
// from sm.tagIndex and sm.tagCounterIndex. Must be called with sm.mu held
// (write lock).
//
// Returns the session and a counter hint. If the counter is non-nil, it is
// the ES message counter associated with this tag, enabling O(1) AEAD
// decryption in decryptExistingSession instead of a window scan.
//
// Design — two-phase lock separation:
// This function intentionally does NOT acquire session.mu. Validation and
// pendingTags cleanup are deferred to validateAndConsumeTagFromSession, which
// the caller invokes AFTER releasing sm.mu. Keeping the locks separate
// eliminates the nested sm.mu → session.mu acquisition that would deadlock if
// any future session callback re-enters SessionManager under session.mu.
//
// Tag removal from the global index happens here (under sm.mu) so that no
// other goroutine can claim the same tag between the lookup and the per-session
// validation step.
func (sm *SessionManager) lookupSessionByTag(tag [8]byte) (*Session, *uint32) {
	flog("lookupSessionByTag").Debug("Looking up session by tag in index")
	session, counterHint, exists := sm.lookupSessionTaggedLocked(tag)
	if !exists {
		return nil, nil
	}
	// Remove from global index now, under sm.mu, to prevent double-consumption.
	delete(sm.tagIndex, tag)
	if counterHint != nil {
		delete(sm.tagCounterIndex, tag)
		return session, counterHint
	}
	return session, nil
}

// validateAndConsumeTagFromSession checks whether session is still valid (not
// expired) and removes tag from session.pendingTags. Must be called AFTER
// sm.mu has been released, so that sm.mu and session.mu are never held
// simultaneously.
//
// Returns:
//
//	valid          — false if the session has expired; callers should discard it.
//	needsReplenish — true when pendingTags falls below tagReplenishThreshold.
func (sm *SessionManager) validateAndConsumeTagFromSession(session *Session, tag [8]byte) (valid, needsReplenish bool) {
	flog("validateAndConsumeTagFromSession").Debug("Validating and consuming tag from session")
	session.mu.Lock()
	defer session.mu.Unlock()

	if !sm.isSessionValid(session) {
		return false, false
	}
	sm.removeTagFromPendingList(tag, session)
	return true, len(session.pendingTags) < tagReplenishThreshold
}

func (sm *SessionManager) isSessionValid(session *Session) bool {
	return time.Since(session.LastUsed) <= sm.sessionTimeout
}

func (sm *SessionManager) removeTagFromPendingList(tag [8]byte, session *Session) {
	flog("removeTagFromPendingList", logger.Fields{"pending_count": len(session.pendingTags)}).Debug("Removing tag from session pending list")
	for i, pendingTag := range session.pendingTags {
		if pendingTag == tag {
			session.pendingTags[i] = session.pendingTags[len(session.pendingTags)-1]
			session.pendingTags = session.pendingTags[:len(session.pendingTags)-1]
			return
		}
	}
	// The tag was present in the manager's tag index but absent from this
	// session's pendingTags, violating the invariant tagIndex ⊆ pendingTags.
	// Surface it at Warn so CI under WARNFAIL_I2P catches any future
	// desynchronization between the two structures.
	flog("removeTagFromPendingList").Warn("tag not found in session pending list; tagIndex/pendingTags out of sync")
}

// bytesLess returns true if a is lexicographically less than b.
// Used as a deterministic tiebreaker for LRU eviction when timestamps are equal.
func bytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

// evictLRUSessionLocked removes the least-recently-used session.
// Must be called with sm.mu held for writing.
//
// Tiebreaker: When multiple sessions have identical LastUsed timestamps,
// the session with the lexicographically smallest session hash is evicted
// to ensure deterministic behavior (avoids map iteration order dependency).
func (sm *SessionManager) evictLRUSessionLocked() {
	var oldestHash [32]byte
	var oldestTime time.Time
	first := true

	for hash, session := range sm.sessions {
		// Select this session if:
		// 1. It's the first session we've seen, OR
		// 2. It has an older LastUsed time, OR
		// 3. It has the same LastUsed time but a lexicographically smaller hash (deterministic tiebreaker)
		if first || session.LastUsed.Before(oldestTime) ||
			(session.LastUsed.Equal(oldestTime) && bytesLess(hash[:], oldestHash[:])) {
			oldestHash = hash
			oldestTime = session.LastUsed
			first = false
		}
	}

	if !first {
		if evicted, ok := sm.sessions[oldestHash]; ok {
			sm.cleanupSessionIndexesLocked(evicted, oldestHash)
			flog("evictLRUSessionLocked", logger.Fields{"last_used":       oldestTime, "remaining_count": len(sm.sessions)}).Warn("Evicted least-recently-used garlic session")
		}
	}
}

// enforcePerPeerQuotaLocked enforces the MaxSessionsPerPeer cap for the given
// remote public key. If a peer is already at or above the cap, the oldest
// session belonging to that peer is evicted first. This protects sessions
// from other honest peers from being evicted via LRU churn when a single
// hostile identity floods the manager with NS messages (AUDIT L-4).
//
// Eviction bias: Prefer evicting established sessions (handshakeState == nil)
// over initiator sessions awaiting NSR (nsrTag != nil). This prevents self-DoS
// when a caller repeatedly creates outbound sessions to the same destination.
// If all sessions for a peer are awaiting NSR, the oldest is evicted.
//
// Must be called with sm.mu held for writing.
func (sm *SessionManager) enforcePerPeerQuotaLocked(remotePubKey [32]byte) {
	count := 0
	for _, session := range sm.sessions {
		if session.RemotePublicKey == remotePubKey {
			count++
		}
	}

	if count < MaxSessionsPerPeer {
		return
	}

	// Find oldest session overall for this peer
	oldestHash, _, haveOldest := sm.selectOldestSession(
		func(s *Session) bool { return s.RemotePublicKey == remotePubKey },
	)

	// Guard against zero-hash eviction: if the iteration found no sessions
	// matching remotePubKey (e.g., due to concurrent deletion or edge case),
	// haveOldest will be false and hashToEvict will remain zero. We must not
	// attempt to delete sm.sessions[zero], as this could evict an unrelated
	// session if the zero hash happens to be in use.
	if !haveOldest {
		return
	}

	// Find oldest established session (prefer evicting these over pending initiator sessions)
	hashToEvict, _, haveOldestEstablished := sm.selectOldestSession(
		func(s *Session) bool {
			return s.RemotePublicKey == remotePubKey &&
				s.nsrTag == nil &&
				s.handshakeState == nil
		},
	)

	if !haveOldestEstablished {
		hashToEvict = oldestHash
	}

	if evicted, ok := sm.sessions[hashToEvict]; ok {
		sm.cleanupSessionIndexesLocked(evicted, hashToEvict)
		flog("enforcePerPeerQuotaLocked", logger.Fields{"remote_pubkey":      fmt.Sprintf("%x", remotePubKey[:8]), "evicted_hash":       fmt.Sprintf("%x", hashToEvict[:8]), "remaining_count":    len(sm.sessions), "remaining_for_peer": count - 1}).Warn("Evicted oldest session for peer to enforce MaxSessionsPerPeer quota")
	}
}

// selectOldestSession finds the oldest session in the session manager's session map
// that matches the given predicate. Returns the session hash, last-used time, and a
// boolean indicating if any matching session was found.
//
// The predicate function is called for each session to determine if it should be
// considered for selection. The session with the earliest LastUsed time among matches
// is selected.
//
// Must be called with sm.mu held for reading or writing.
func (sm *SessionManager) selectOldestSession(predicate func(*Session) bool) ([32]byte, time.Time, bool) {
	var oldestHash [32]byte
	var oldestTime time.Time
	found := false

	for hash, session := range sm.sessions {
		if !predicate(session) {
			continue
		}

		if !found || session.LastUsed.Before(oldestTime) {
			oldestHash = hash
			oldestTime = session.LastUsed
			found = true
		}
	}

	return oldestHash, oldestTime, found
}

// cleanupSessionIndexesLocked removes session index entries for tag tracking,
// NSR tag tracking, and the session itself. Must be called with sm.mu held.
// This consolidates the repetitive 4-line cleanup pattern used in multiple
// session removal and eviction code paths.
func (sm *SessionManager) cleanupSessionIndexesLocked(session *Session, hash [32]byte) {
	for _, tag := range session.pendingTags {
		delete(sm.tagIndex, tag)
		delete(sm.tagCounterIndex, tag)
	}
	if session.nsrTag != nil {
		delete(sm.nsrTagIndex, *session.nsrTag)
	}
	delete(sm.sessions, hash)
}
