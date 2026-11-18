package ratchet

import (
	"context"
	"time"

	"github.com/go-i2p/go-noise/internal/securemem"
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

		// Snapshot session state under its lock.
		//
		// I2P-004 / GN-009: expireRecvTagsets and isSessionValid walk session
		// state derived from remote input, so a panic here is reachable. The
		// cleanup loop runs this under recoverTick, which recovers in its own
		// frame; a plain Unlock at the end of the section would be skipped by
		// the unwinding panic and leak session.mu, wedging every other
		// session.mu holder (the decrypt/encrypt paths, destroyKeyMaterial, and
		// every later cleanup tick) for the life of the session — turning a
		// recoverable crash into a permanently stuck garlic session. The section
		// therefore runs in a closure whose Unlock is deferred, so the panic
		// path releases the lock too. The slow removal work below stays outside
		// the section, so the lock still releases before it.
		func() {
			session.mu.Lock()
			defer session.mu.Unlock()
			// Drop the retained previous inbound tag set once its ~3 minute grace
			// period has elapsed. Spec ref: ecies.md §"Parameters" - "Remove
			// previous ES tagset after: 3 minutes".
			session.expireRecvTagsets(sm.removeTagsFromIndex)
			if !sm.isSessionValid(session) {
				expired = true
				tags = session.pendingTags
				for _, retired := range session.retiredRecv {
					tags = append(tags, retired.tags...)
				}
			}
		}()

		if expired {
			delete(sm.sessions, hash)
			for _, tag := range tags {
				delete(sm.tagIndex, tag)
				delete(sm.tagCounterIndex, tag)
			}
			// Remove the full registered reply window, not just the first tag.
			// sm.mu is already held by this function.
			sm.clearNSRTagsLocked(session)
			session.destroyKeyMaterial()
			removed++
		}
	}

	// Evict one-time garlic reply keys whose build reply never arrived. A key is
	// consumed on decrypt; a failed, dropped, or abandoned build leaves it here
	// forever, so a peer that triggers many inbound builds grows the map without
	// bound. sm.mu is already held.
	evictedOneTime := sm.evictExpiredOneTimeKeysLocked(time.Now())

	if removed > 0 || evictedOneTime > 0 {
		flog("CleanupExpiredSessions", logger.Fields{
			"removed_sessions":        removed,
			"remaining_sessions":      len(sm.sessions),
			"remaining_indexed_tags":  len(sm.tagIndex),
			"evicted_one_time_keys":   evictedOneTime,
			"remaining_one_time_keys": len(sm.oneTimeKeys),
		}).Info("Expired sessions cleaned up")
	}

	return removed
}

// evictExpiredOneTimeKeysLocked deletes one-time garlic reply keys older than
// oneTimeKeyTTL, zeroing their key material. The caller must hold sm.mu.
// Returns the number of keys evicted.
func (sm *SessionManager) evictExpiredOneTimeKeysLocked(now time.Time) int {
	if len(sm.oneTimeKeys) == 0 {
		return 0
	}
	evicted := 0
	for tag, entry := range sm.oneTimeKeys {
		if now.Sub(entry.created) > oneTimeKeyTTL {
			// Zero key material before removal (forward-secrecy hygiene, matching
			// the consumption path in tryDecryptOneTimeKey).
			sm.oneTimeKeys[tag] = oneTimeKeyEntry{}
			delete(sm.oneTimeKeys, tag)
			evicted++
		}
	}
	return evicted
}

// GetSessionCount returns the number of active sessions.
func (sm *SessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// OneTimeKeyCount returns the number of registered one-time garlic reply keys
// currently held. Exposed for observability and testing: it lets callers assert
// that the count stays bounded under sustained inbound-build load rather than
// growing with every build whose reply never arrives.
func (sm *SessionManager) OneTimeKeyCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.oneTimeKeys)
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

	// Clear all session state, destroying each session's key material first:
	// dropping the map reference alone leaves chain keys and DH private keys
	// recoverable from the heap until the GC reuses it.
	for k, session := range sm.sessions {
		delete(sm.sessions, k)
		session.destroyKeyMaterial()
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
				// I2P-004: this cleanup loop runs unrecovered and walks garlic
				// session state derived from remote input; a panic would kill the
				// router. recoverTick skips one cleanup interval instead.
				recoverTick("ratchet.CleanupLoop", func() { sm.CleanupExpiredSessions() })
			case <-ctx.Done():
				return
			case <-sm.ctx.Done():
				return
			}
		}
	}()

	flog("StartCleanupLoop", logger.Fields{"interval": "2m"}).Debug("Started garlic session cleanup loop")
}

// destroyKeyMaterial zeroes every piece of key state this session holds.
//
// Dropping the map reference is not enough: the chain keys, tag ratchets, root
// keys, DH private keys and pre-derived message keys stay in the heap until the
// garbage collector reuses that memory, so a later memory disclosure still
// reveals a "closed" session's keys. ecies.md §"Defense" and the §"Notes"
// requirement that superseded sessions be "destroyed immediately" are about the
// key material, not the index entries.
//
// The upstream ratchets carry their own Zero(); this method is the single place
// that reaches every field this package owns, including the ones upstream cannot
// see (the per-direction DH state and the receive cache).
//
// Lock order is sm.mu then session.mu, matching the rest of the manager, so this
// is safe to call while the manager lock is held.
func (s *Session) destroyKeyMaterial() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.SymmetricRatchet != nil {
		s.SymmetricRatchet.Zero()
	}
	if s.TagRatchet != nil {
		s.TagRatchet.Zero()
	}
	if s.RecvSymmetricRatchet != nil {
		s.RecvSymmetricRatchet.Zero()
	}
	if s.RecvTagRatchet != nil {
		s.RecvTagRatchet.Zero()
	}

	securemem.SecureZero(s.sendRootKey[:])
	securemem.SecureZero(s.recvRootKey[:])

	if s.sendDir != nil {
		securemem.SecureZero(s.sendDir.ourPriv[:])
		securemem.SecureZero(s.sendDir.remote[:])
		s.sendDir.hasKey = false
	}
	if s.recvDir != nil {
		securemem.SecureZero(s.recvDir.ourPriv[:])
		securemem.SecureZero(s.recvDir.remote[:])
		s.recvDir.hasKey = false
	}

	// Pre-derived inbound message keys and the tags that address them.
	for counter := range s.recvKeyCache {
		entry := s.recvKeyCache[counter]
		securemem.SecureZero(entry[:])
		delete(s.recvKeyCache, counter)
	}
	s.recvTagCounter = nil

	// Retained previous tag sets: their ratchets and receive caches are separate
	// objects, so zeroing the primary inbound ratchet does not reach them.
	for _, retired := range s.retiredRecv {
		if retired.tagRatchet != nil {
			retired.tagRatchet.Zero()
		}
		if retired.symRatchet != nil {
			retired.symRatchet.Zero()
		}
		for counter, key := range retired.keyCache {
			securemem.SecureZero(key[:])
			delete(retired.keyCache, counter)
		}
	}
	s.retiredRecv = nil

	// Handshake states awaiting an NSR (or an NS reply) carry their own chaining
	// key, ephemeral private key and tag ratchet. clearNSRReplyQueue zeroes the NSR
	// tag ratchets and releases the states; zeroHandshakeSecrets covers the fields
	// it does not know about, and has to run first.
	s.zeroHandshakeSecrets()
	s.clearNSRReplyQueue()

	s.pendingTags = nil
}

// zeroHandshakeSecrets clears the secret material of every Noise handshake state
// this session still holds: the head state, the queued additional New Session
// states, and the reply states registered by tag.
//
// Must be called with session.mu held.
func (s *Session) zeroHandshakeSecrets() {
	states := make([]*noiseHandshakeState, 0, 1+len(s.awaitingNSRReplies)+len(s.pendingNSRs))
	states = append(states, s.handshakeState)
	states = append(states, s.awaitingNSRReplies...)
	for _, hs := range s.pendingNSRs {
		states = append(states, hs)
	}
	for _, hs := range states {
		if hs == nil {
			continue
		}
		securemem.SecureZero(hs.h)
		securemem.SecureZero(hs.ck)
		securemem.SecureZero(hs.localEphPriv)
		securemem.SecureZero(hs.remoteEphPub[:])
		hs.remoteStaticPub = [32]byte{}
	}
}
