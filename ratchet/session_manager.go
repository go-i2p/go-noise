package ratchet

import (
	"context"
	"fmt"
	"sync"
	"time"

	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/go-noise/mod/replaycache"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface checks.
var (
	_ GarlicSessionManager = (*SessionManager)(nil)
	_ TagResolver          = (*SessionManager)(nil)
)

// Constants moved to session_freshness.go and session_table.go

// SessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic encryption.
// It maintains session state for ongoing encrypted communication with remote
// destinations, using [32]byte keys throughout (no I2P-specific types).
//
// Session lifecycle:
//  1. New Session: First message uses ephemeral-static DH (ECIES)
//  2. Existing Session: Subsequent messages use ratchet for forward secrecy
//  3. Session Expiry: Sessions expire after inactivity timeout
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[[32]byte]*Session
	tagIndex map[[8]byte]*Session
	// nsrTagIndex maps the expected NSR tag (derived from the NS chain key) to the
	// initiator session waiting for the corresponding New Session Reply. Unlike
	// tagIndex (which tracks Existing Session tags), nsrTagIndex is keyed on the
	// unique 8-byte NSR tag that the responder will prefix on its NSR message.
	nsrTagIndex     map[[8]byte]*Session
	tagCounterIndex map[[8]byte]uint32
	// oneTimeKeys holds one-time symmetric garlic keys derived from STBM Noise
	// transcript hashes via HKDF("AttachLayerEncryption"). Each key is used
	// exactly once to decrypt the OBEP's garlic-wrapped ShortTunnelBuildReply,
	// then deleted. Keyed by the last 8 bytes of the 32-byte HKDF output.
	oneTimeKeys    map[[8]byte][32]byte
	ourPrivateKey  [32]byte
	ourPublicKey   [32]byte
	sessionTimeout time.Duration
	ctx            context.Context
	cancel         context.CancelFunc

	// nsMaxPastAge is the maximum acceptable age for NS DateTime freshness.
	nsMaxPastAge time.Duration
	// nsMaxFutureAge is the maximum acceptable future skew for NS DateTime freshness.
	nsMaxFutureAge time.Duration

	// nsReplayCache tracks recently-seen NS ephemeral keys (first 32 bytes of the
	// NS message) to prevent replay attacks within the freshness window.
	// Spec ref: ratchet.md §"DateTime" — "Bob must implement a Bloom filter or
	// other mechanism to prevent replay attacks, if the time is valid."
	nsReplayCache *replaycache.TTLCache
}

// Lock ordering invariant for ratchet session code:
// 1) Acquire sm.mu before any session.mu when both are needed.
// 2) Never acquire sm.mu while holding session.mu.
// 3) Expensive ratchet/HKDF work should run under session.mu only, then install
//    results under a brief sm.mu critical section.
// This order is required to avoid deadlocks across tag lookup, replenishment,
// and session cleanup paths.

// NewSessionManager creates a new session manager with the given private key.
func NewSessionManager(privateKey [32]byte, opts ...SessionManagerOption) (*SessionManager, error) {
	flog("NewSessionManager").Debug("Creating new garlic session manager")

	var publicKey [32]byte
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(privateKey[:])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create private key for public key derivation")
	}
	pubKeyIface, err := privKey.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive public key from private key")
	}
	copy(publicKey[:], pubKeyIface.Bytes())

	ctx, cancel := context.WithCancel(context.Background())

	sm := &SessionManager{
		sessions:        make(map[[32]byte]*Session),
		tagIndex:        make(map[[8]byte]*Session),
		nsrTagIndex:     make(map[[8]byte]*Session),
		tagCounterIndex: make(map[[8]byte]uint32),
		oneTimeKeys:     make(map[[8]byte][32]byte),
		ourPrivateKey:   privateKey,
		ourPublicKey:    publicKey,
		sessionTimeout:  10 * time.Minute,
		nsMaxPastAge:    defaultNSMaxPastAge,
		nsMaxFutureAge:  defaultNSMaxFutureAge,
		ctx:             ctx,
		cancel:          cancel,
	}

	for _, opt := range opts {
		opt(sm)
	}

	sm.nsReplayCache = replaycache.New(replaycache.Config{
		TTL:             nsReplayCacheTTL(sm.nsMaxPastAge, sm.nsMaxFutureAge),
		MaxSize:         nsReplayCacheMaxSize,
		CleanupInterval: nsReplayCacheCleanupInterval,
		NowFunc:         nowFunc,
	})

	return sm, nil
}

// GenerateSessionManager creates a session manager with a freshly generated key pair.
func GenerateSessionManager() (*SessionManager, error) {
	flog("GenerateSessionManager").Debug("Generating new session manager with fresh key pair")
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session manager key pair")
	}

	var privateKey [32]byte
	copy(privateKey[:], privBytes)
	return NewSessionManager(privateKey)
}

// EncryptGarlicMessage, encryptNewSession, storeNewSessionState,
// encryptExistingSession, EncryptUnboundGarlicMessage, and EncryptNewSessionReply
// are defined in session_encrypt.go.

// DecryptGarlicMessage, decryptNewSession, initializeInboundRatchetState,
// registerNSRTagLocked, decryptIncomingNSR, applyNSRKeysToSessionWhileLocked,
// decryptExistingSession, tryCounterHintDecrypt, scanWindowDecrypt,
// processDecryptedESBlocks, processAckRequest, and processAck
// are defined in session_decrypt.go.

// RegisterOneTimeKey registers a one-time symmetric garlic key derived from a
// STBM Noise transcript hash via HKDF("AttachLayerEncryption"). The OBEP will
// use the corresponding key to wrap its ShortTunnelBuildReply in a garlic
// message; this key is looked up by tag and deleted after a single use.
//
// tag is garlicKeyMaterial[24:32] (last 8 bytes of the 32-byte HKDF output).
// key is garlicKeyMaterial[0:32] (the full 32-byte output used as the ChaCha20 key).
func (sm *SessionManager) RegisterOneTimeKey(tag [8]byte, key [32]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.oneTimeKeys[tag] = key
	flog("RegisterOneTimeKey", logger.Fields{"tag": fmt.Sprintf("%x", tag)}).Debug("Registered one-time garlic reply key")
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *SessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	session, err := sm.lookupLockedSession(sessionTag)
	if err != nil {
		return err
	}
	defer session.mu.Unlock()

	if err := session.DHRatchet.UpdateKeys(newRemotePubKey[:]); err != nil {
		return oops.Wrapf(err, "failed to update remote DH public key")
	}

	if err := applyRecvRatchetKeys(session); err != nil {
		return err
	}

	session.RemotePublicKey = newRemotePubKey

	flog("ProcessIncomingDHRatchet", logger.Fields{"message_counter": session.MessageCounter}).Debug("Processed incoming DH ratchet from peer")

	return nil
}

// tagReplenishThreshold is the minimum number of pending tags remaining after
// which replenishment is triggered. Checked after releasing sm.mu so that the
// HKDF derivation does not block the global write lock.
const tagReplenishThreshold = tagWindowSize / 2

// replenishTagWindowOutsideLock, installGeneratedTagsLocked,
// and generateTagWindow are tag management methods retained in this file for orchestration.

// replenishTagWindowOutsideLock generates new session tags and installs them
// without holding sm.mu during the cryptographic (HKDF) work.
//
// Design: tag derivation (the slow path) runs under session.mu only, then the
// results are installed into sm.tagIndex under a brief sm.mu write lock.
// This prevents the global write lock from serialising all goroutines for the
// duration of SHA-256 / HKDF rounds at high message rates.
//
// Collision handling: if installGeneratedTagsLocked skips some tags due to
// cross-session hash collisions, the window can end up under-sized after the
// first install pass.  We retry up to maxReplenishAttempts times so that the
// window reaches tagWindowSize despite isolated collisions.  If the window is
// still under-sized after all retries, a warning is logged so the condition is
// visible rather than silent.
func (sm *SessionManager) replenishTagWindowOutsideLock(session *Session) {
	const maxReplenishAttempts = 3

	for attempt := 0; attempt < maxReplenishAttempts; attempt++ {
		// Phase 1: derive tags under session lock only — sm.mu is NOT held here.
		session.mu.Lock()
		stillNeeded := tagWindowSize - len(session.pendingTags)
		if stillNeeded <= 0 {
			session.mu.Unlock()
			return // already full; another goroutine may have replenished already
		}
		newTags, err := generateTagsOutsideLock(session)
		session.mu.Unlock()

		if err != nil {
			// Anonymity: do not include the peer-identifying remote_pubkey prefix
			// in the Warn-level log (a stable per-session correlator); it remains
			// available at Debug level for local troubleshooting only.
			flog("replenishTagWindowOutsideLock", logger.Fields{"remote_pubkey": fmt.Sprintf("%x", session.RemotePublicKey[:8]), "attempt": attempt + 1, "error": err.Error()}).Debug("Failed to generate tags during replenishment")
			flog("replenishTagWindowOutsideLock", logger.Fields{"attempt": attempt + 1, "error": err.Error()}).Warn("Failed to generate tags during replenishment")
			return
		}
		if len(newTags) == 0 {
			return
		}

		// Phase 2: install pre-derived tags — brief sm.mu write lock, no HKDF.
		sm.mu.Lock()
		session.mu.Lock()
		sm.installGeneratedTagsLocked(session, newTags)
		remaining := tagWindowSize - len(session.pendingTags)
		session.mu.Unlock()
		sm.mu.Unlock()

		if remaining <= 0 {
			return // window fully replenished
		}
		// Window still under-sized due to collisions; retry with a fresh batch.
	}

	// All attempts exhausted: check final state and warn if still under-sized.
	session.mu.Lock()
	finalRemaining := tagWindowSize - len(session.pendingTags)
	session.mu.Unlock()

	if finalRemaining > 0 {
		// Anonymity: keep the remote_pubkey prefix out of the Warn-level log
		// (a stable per-session correlator); it remains available at Debug
		// level for local troubleshooting only.
		flog("replenishTagWindowOutsideLock", logger.Fields{"remote_pubkey": fmt.Sprintf("%x", session.RemotePublicKey[:8]), "missing_tags": finalRemaining, "max_attempts": maxReplenishAttempts}).Debug("Tag window still under-sized after max replenishment attempts due to hash collisions; incoming ES messages may fail until next replenishment")
		flog("replenishTagWindowOutsideLock", logger.Fields{"missing_tags": finalRemaining, "max_attempts": maxReplenishAttempts}).Warn("Tag window still under-sized after max replenishment attempts due to hash collisions; incoming ES messages may fail until next replenishment")
	}
}

// tagWithCounter pairs a pre-derived session tag with the ES message counter
// it corresponds to. Used to transfer tag→counter mappings between the
// generation phase (under session.mu) and the installation phase (under sm.mu).
type tagWithCounter struct {
	tag     [8]byte
	counter uint32
}

// generateTagsOutsideLock advances session.RecvTagRatchet to produce the tags
// needed to refill the window up to tagWindowSize. The caller must hold
// session.mu but must NOT hold sm.mu; the HKDF derivations run here.
// Returns the new tags with their associated counters, which are not yet
// registered in sm.tagIndex or sm.tagCounterIndex.
func generateTagsOutsideLock(session *Session) ([]tagWithCounter, error) {
	flog("generateTagsOutsideLock", logger.Fields{"pending_count": len(session.pendingTags), "window_size": tagWindowSize}).Debug("Generating tags outside lock")
	if session.RecvTagRatchet == nil {
		return nil, oops.Errorf("RecvTagRatchet is nil for session — cannot replenish incoming tag window")
	}
	needed := tagWindowSize - len(session.pendingTags)
	if needed <= 0 {
		return nil, nil
	}
	newTags := make([]tagWithCounter, 0, needed)
	for i := 0; i < needed; i++ {
		tag, err := session.RecvTagRatchet.GenerateNextTag()
		if err != nil {
			return newTags, oops.Wrapf(err, "failed to generate session tag at index %d", i)
		}
		counter := session.nextRecvTagCounter
		session.nextRecvTagCounter++
		newTags = append(newTags, tagWithCounter{tag: tag, counter: counter})
	}
	return newTags, nil
}

// installGeneratedTagsLocked writes pre-derived tags into sm.tagIndex,
// sm.tagCounterIndex, and session.pendingTags.  Tags that collide with a
// different session are logged and skipped.  Must be called with both
// sm.mu (write) and session.mu held.
func (sm *SessionManager) installGeneratedTagsLocked(session *Session, newTags []tagWithCounter) {
	for _, tc := range newTags {
		if len(session.pendingTags) >= tagWindowSize {
			// Another goroutine may have already replenished; stop early.
			break
		}
		if existing, ok := sm.tagIndex[tc.tag]; ok && existing != session {
			flog("installGeneratedTagsLocked", logger.Fields{"tag": fmt.Sprintf("%x", tc.tag)}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tc.tag)
		sm.tagIndex[tc.tag] = session
		sm.tagCounterIndex[tc.tag] = tc.counter
	}
}

// generateTagWindow pre-generates a window of session tags for a session.
// If a generated tag collides with an existing tag from another session,
// the collision is logged and the colliding tag is skipped to avoid
// silently overwriting another session's tag slot.
// Returns an error if RecvTagRatchet is nil; using the send-direction TagRatchet
// as a fallback would populate the tag index with outgoing tags, causing all
// incoming existing-session messages to fail lookup silently.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) generateTagWindow(session *Session) error {
	tagRatchet := session.RecvTagRatchet
	if tagRatchet == nil {
		return oops.Errorf("RecvTagRatchet is nil for session — cannot populate incoming tag index")
	}
	for len(session.pendingTags) < tagWindowSize {
		tag, err := tagRatchet.GenerateNextTag()
		if err != nil {
			return oops.Wrapf(err, "failed to generate session tag")
		}
		counter := session.nextRecvTagCounter
		session.nextRecvTagCounter++
		if existing, ok := sm.tagIndex[tag]; ok && existing != session {
			flog("generateTagWindow", logger.Fields{"tag": fmt.Sprintf("%x", tag)}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tag)
		sm.tagIndex[tag] = session
		sm.tagCounterIndex[tag] = counter
	}
	return nil
}

// evictLRUSessionLocked, enforcePerPeerQuotaLocked, bytesLess are defined in session_table.go.
// CleanupExpiredSessions, GetSessionCount, GetPublicKey, Close, StartCleanupLoop are defined in session_lifecycle.go.
