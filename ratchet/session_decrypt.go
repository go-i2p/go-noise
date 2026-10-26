package ratchet

import (
	"time"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DecryptGarlicMessage decrypts an encrypted garlic message.
//
// It automatically detects and handles all three message types: New Session
// (a fresh handshake), New Session Reply (the handshake reply), and Existing
// Session (the fast path for an established session).
//
// Returns:
//   - plaintext: the decrypted garlic payload.
//   - sessionTag: the 8-byte tag used to identify the session (zero for New
//     Session and New Session Reply messages).
//   - sessionHash: SHA-256 of the initiator's static public key for New
//     Session messages; nil otherwise. Callers that need to send a New
//     Session Reply must pass this value to
//     [SessionManager.EncryptNewSessionReply].
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
func (sm *SessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, *[32]byte, error) {
	flog("DecryptGarlicMessage", logger.Fields{"message_len": len(encryptedGarlic)}).Debug("Decrypting garlic message")
	if len(encryptedGarlic) < 8 {
		return nil, [8]byte{}, nil, oops.Errorf("encrypted garlic message too short: %d bytes", len(encryptedGarlic))
	}

	var msgTag [8]byte
	copy(msgTag[:], encryptedGarlic[0:8])

	// Check Existing Session first (most common path).
	if plaintext, sessionTag, err, ok := sm.tryDecryptExisting(msgTag, encryptedGarlic); ok {
		return plaintext, sessionTag, nil, err
	}

	// Check NSR tag index: initiator receiving a reply to its New Session.
	if plaintext, err, ok := sm.tryDecryptNSR(msgTag, encryptedGarlic); ok {
		return plaintext, [8]byte{}, nil, err
	}

	// Check one-time symmetric keys: STBM ShortTunnelBuildReply garlic.
	if plaintext, err, ok := sm.tryDecryptOneTimeKey(msgTag, encryptedGarlic); ok {
		return plaintext, [8]byte{}, nil, err
	}

	// Fallthrough: New Session (Noise IK / ECIES).
	plaintext, sessionHash, err := sm.decryptNewSession(encryptedGarlic)
	if err != nil {
		return nil, [8]byte{}, nil, oops.Wrapf(err, "failed to decrypt garlic message")
	}
	return plaintext, [8]byte{}, sessionHash, nil
}

// tryDecryptExisting attempts to decrypt as an Existing Session message.
// Returns ok=true if a matching session was found (even if decryption failed).
func (sm *SessionManager) tryDecryptExisting(msgTag [8]byte, encryptedGarlic []byte) ([]byte, [8]byte, error, bool) {
	flog("tryDecryptExisting", logger.Fields{"message_len": len(encryptedGarlic)}).Debug("Trying to decrypt as Existing Session message")
	sm.mu.Lock()
	session, counterHint := sm.lookupSessionByTag(msgTag)
	sm.mu.Unlock()

	var needsReplenish bool
	if session != nil {
		var valid bool
		valid, needsReplenish = sm.validateAndConsumeTagFromSession(session, msgTag)
		if !valid {
			session = nil
		}
	}
	if session == nil {
		return nil, [8]byte{}, nil, false
	}

	plaintext, sessionTag, usedCounter, ackTagSetID, err := sm.decryptExistingSession(session, encryptedGarlic[8:], msgTag, counterHint)
	if needsReplenish {
		sm.replenishTagWindowOutsideLock(session)
	}
	if err == nil {
		sm.processDecryptedESBlocks(session, plaintext, usedCounter, ackTagSetID)
		plaintext = stripECIESControlBlocks(plaintext)
	}
	return plaintext, sessionTag, err, true
}

// tryDecryptNSR attempts to decrypt as a New Session Reply message.
// Returns ok=true if a matching NSR tag was found (even if decryption failed).
func (sm *SessionManager) tryDecryptNSR(msgTag [8]byte, encryptedGarlic []byte) ([]byte, error, bool) {
	flog("tryDecryptNSR", logger.Fields{"message_len": len(encryptedGarlic)}).Debug("Trying to decrypt as New Session Reply")
	sm.mu.Lock()
	nsrSession, isNSR := sm.nsrTagIndex[msgTag]
	var hs *noiseHandshakeState
	if isNSR {
		delete(sm.nsrTagIndex, msgTag)
		nsrSession.mu.Lock()
		hs = nsrSession.pendingNSRs[msgTag]
		delete(nsrSession.pendingNSRs, msgTag)
		if nsrSession.nsrTag != nil && *nsrSession.nsrTag == msgTag {
			nsrSession.nsrTag = nil
		}
		nsrSession.mu.Unlock()
	}
	sm.mu.Unlock()

	if !isNSR || nsrSession == nil {
		return nil, nil, false
	}
	plaintext, err := sm.decryptIncomingNSR(nsrSession, msgTag, hs, encryptedGarlic)
	return plaintext, err, true
}

// tryDecryptOneTimeKey attempts to decrypt a one-time symmetric garlic message.
// These are used for STBM ShortTunnelBuildReply delivery: the OBEP wraps its
// reply in a garlic message encrypted with a one-time key derived from the Noise
// transcript hash via HKDF("AttachLayerEncryption").
//
// Wire format: [8-byte tag] || [ciphertext] || [16-byte poly1305 tag]
// Key:         one-time key registered via RegisterOneTimeKey
// Nonce:       12 bytes of zeros
// AD:          nil
//
// Returns ok=true if a matching one-time key was found (even if decryption failed).
// The key is deleted before decryption is attempted (single-use regardless of outcome).
func (sm *SessionManager) tryDecryptOneTimeKey(msgTag [8]byte, msg []byte) ([]byte, error, bool) {
	flog("tryDecryptOneTimeKey", logger.Fields{"message_len": len(msg)}).Debug("Trying to decrypt as one-time symmetric garlic message")
	sm.mu.Lock()
	key, found := sm.oneTimeKeys[msgTag]
	if found {
		// Zero the key material in the map before deleting to prevent recovery
		// from memory dumps. The ratchet's forward secrecy guarantees rely on
		// securely destroying keys.
		var zeroKey [32]byte
		sm.oneTimeKeys[msgTag] = zeroKey
		delete(sm.oneTimeKeys, msgTag)
	}
	sm.mu.Unlock()

	if !found {
		return nil, nil, false
	}

	// body = msg[8:] = ciphertext || 16-byte poly1305 tag
	body := msg[8:]
	if len(body) < 16 {
		return nil, oops.Errorf("one-time garlic message body too short: %d bytes", len(body)), true
	}
	ciphertext := body[:len(body)-16]
	authTag := body[len(body)-16:]

	aead, err := chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create one-time key AEAD"), true
	}

	// AD = first 8 bytes of the garlic message (the session tag), matching
	// i2pd SymmetricKeyTagSet::HandleNextMessage which uses buf[0:8] as AD.
	var nonce [12]byte // all zeros per spec
	plaintext, err := aead.Decrypt(ciphertext, authTag, msg[:8], nonce[:])
	if err != nil {
		return nil, oops.Wrapf(err, "one-time garlic decryption failed"), true
	}

	flog("tryDecryptOneTimeKey", logger.Fields{"plaintext_len": len(plaintext)}).Debug("One-time garlic key decryption succeeded")
	return plaintext, nil, true
}

// decryptNewSession decrypts a New Session message using the Noise IK handshake.
// Handles both the bound (IK, with initiator static key) and unbound (N-pattern,
// flags section = all-zeros) variants.
//
// For bound messages: stores inbound ratchet state and returns
// SHA-256(initiatorStaticPub) so the caller can dispatch a New Session Reply.
// For unbound messages: no session state is stored (non-repliable) and
// sessionHash is nil.
func (sm *SessionManager) decryptNewSession(msg []byte) ([]byte, *[32]byte, error) {
	result, err := readNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, msg,
	)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to process Noise IK New Session message")
	}

	// Freshness + replay checks apply to EVERY New Session message, bound or
	// unbound. ecies.rst §1c/§1d require "Payload must contain a DateTime
	// block" for the unbound/one-time formats too, and §"DateTime" requires
	// "Bob must validate that the message is recent". Returning before these
	// checks would let a captured unbound NS be replayed indefinitely.

	// Spec §1b / replay-prevention: reject NS messages whose DateTime block
	// is too old or too far in the future. A captured NS can otherwise be
	// replayed to reset the active session keyed on the initiator's static key.
	if err := sm.validateNSDateTimeFreshness(result.plaintext); err != nil {
		return nil, nil, oops.Wrapf(err, "New Session message rejected")
	}

	// Spec §"DateTime": "Bob must implement a Bloom filter or other mechanism
	// to prevent replay attacks, if the time is valid."
	// Check the NS ephemeral key (first 32 bytes) against the replay cache.
	// The ephemeral key is on the wire (Elligator2-encoded) for unbound
	// messages as well, so this guard covers both variants.
	if len(msg) >= 32 {
		var ephKey [32]byte
		copy(ephKey[:], msg[:32])
		if sm.nsReplayCache.CheckAndAdd(ephKey) {
			return nil, nil, oops.Errorf(
				"NS replay detected: ephemeral key %x has been seen within the freshness window",
				ephKey[:8],
			)
		}
	}

	// Unbound sessions establish no replyable session: the initiator sent no
	// static key, so there is no identity to key the session on and no NSR can
	// be sent. Spec §1c: "Bob ratchets once when creating an unbound inbound
	// session, and does not create a corresponding outbound session." The
	// payload is still returned so the caller can process the (fresh,
	// non-replayed) one-time message.
	if result.isUnbound {
		flog("decryptNewSession").Debug("Received unbound (N-pattern) New Session message — no session state stored")
		return result.plaintext, nil, nil
	}

	if err := sm.initializeInboundRatchetState(result.initiatorStaticPub, result.keys, result.hs); err != nil {
		return nil, nil, err
	}

	sessionHash := types.SHA256(result.initiatorStaticPub[:])
	return result.plaintext, &sessionHash, nil
}

// initializeInboundRatchetState creates and stores ratchet state for incoming
// sessions, or queues an additional New Session for an existing peer.
//
// A responder must keep the handshake state for EVERY NS it receives until an ES
// message arrives, and reply to each with its own NSR built from that NS's state
// and tagset.
//
// Spec ref: ecies.md §"Multiple NSR Messages" - "For each NS message received,
// until an ES message is received, Bob must reply with a new NSR ... Each NSR
// uses the handshake state and tagset corresponding to the incoming NS. Bob must
// maintain the handshake state and tagset for all NS messages received, until an
// ES message is received."
func (sm *SessionManager) initializeInboundRatchetState(remotePubKey [32]byte, keys *sessionKeys, hs *noiseHandshakeState) error {
	sessionHash := types.SHA256(remotePubKey[:])

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if existing, exists := sm.sessions[sessionHash]; exists {
		// Spec: "Replace session if NS received after: 3 minutes" - Java
		// RatchetSKM.addSession() restarts an inbound session only once it is
		// older than SESSION_REPLACE_AGE; a fresh duplicate NS is a retransmit
		// and must be answered with a NEW NSR rather than by discarding the
		// session and dropping the NS.
		if time.Since(existing.Established) > sessionReplaceAge {
			flog("initializeInboundRatchetState", logger.Fields{"age": time.Since(existing.Established).String()}).
				Debug("Peer restarted with the same key - replacing the stale inbound session")
			sm.cleanupSessionIndexesLocked(existing, sessionHash)
		} else {
			return sm.queueAdditionalNSReplyLocked(existing, hs)
		}
	}

	session, err := createSession(remotePubKey, keys, sm.ourPrivateKey, false)
	if err != nil {
		return oops.Wrapf(err, "failed to create inbound session")
	}

	session.handshakeState = hs
	session.isInitiator = false

	// Enforce MaxGarlicSessions to prevent memory exhaustion from malicious peers
	// sending many New Session messages with different ephemeral keys.
	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}
	// Enforce per-peer quota so one hostile identity cannot starve honest
	// peers via LRU churn.
	sm.enforcePerPeerQuotaLocked(remotePubKey)

	sm.sessions[sessionHash] = session

	// Receipt of an NS requires an NSR response.
	// Spec ref: ecies.md §"Ratchet-layer Responses" - "Receipt of NS and NSR
	// messages require a response"; §"Multiple NSR Messages" - "For each NS message
	// received, until an ES message is received, Bob must reply with a new NSR".
	// The handshake timeout is shorter than the ES one, per the same section:
	// "It may also be appropriate for an even shorter timeout for responses to NS
	// and NSR messages, to shift the traffic to the efficient ES messages as soon
	// as possible."
	session.oweResponse("new session", responseTimerHandshake)

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate inbound tag window")
	}

	flog("initializeInboundRatchetState", logger.Fields{"session_count": len(sm.sessions), "tag_count": len(sm.tagIndex)}).Debug("Inbound ratchet session stored")

	return nil
}

// queueNSReplyLocked retains an additional NS handshake state so a matching NSR
// can be produced later. Oldest state is answered first, matching the spec's
// "reply with a new NSR" per NS.
//
// Must be called with sm.mu held for writing.
func (sm *SessionManager) queueAdditionalNSReplyLocked(session *Session, hs *noiseHandshakeState) error {
	if hs == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	if len(session.awaitingNSRReplies) >= maxPendingNSReplies {
		// Spec §"Multiple NSR Messages" explicitly permits limiting the number of
		// NSR replies, and §"Multiple NS Messages" permits dropping NS under load,
		// to avoid a resource-exhaustion attack.
		flog("queueAdditionalNSReplyLocked", logger.Fields{"queued": len(session.awaitingNSRReplies)}).
			Debug("NSR reply queue full, dropping additional NS")
		return nil
	}
	session.awaitingNSRReplies = append(session.awaitingNSRReplies, hs)
	// Each additional NS requires its own NSR (§"Multiple NSR Messages").
	session.oweResponse("new session", responseTimerHandshake)
	flog("queueAdditionalNSReplyLocked", logger.Fields{"queued": len(session.awaitingNSRReplies)}).
		Debug("Queued additional NS for a separate NSR reply")
	return nil
}

// registerNSRTagLocked derives the expected NSR tag for an initiator session
// and registers it in sm.nsrTagIndex. Must be called with sm.mu held for writing.
// The tag is derived from the same chain key that the responder will use when
// constructing its NSR, ensuring both sides agree on the routing tag.
func (sm *SessionManager) registerNSRTagLocked(session *Session, hs *noiseHandshakeState) error {
	flog("registerNSRTagLocked").Debug("Registering NSR tag for initiator session")
	nsrTagRatchet, err := deriveNSRTagRatchet(hs.ck)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR tag ratchet for initiator registration")
	}
	tag, err := nsrTagRatchet.GenerateNextTag()
	if err != nil {
		return oops.Wrapf(err, "failed to generate NSR tag for initiator registration")
	}
	// Allocate a new [8]byte on the heap and copy the tag value to avoid
	// taking the address of a stack-local variable.
	session.nsrTag = new([8]byte)
	*session.nsrTag = tag
	sm.nsrTagIndex[tag] = session
	if session.pendingNSRs == nil {
		session.pendingNSRs = make(map[[8]byte]*noiseHandshakeState)
	}
	session.pendingNSRs[tag] = hs
	return nil
}

// decryptIncomingNSR processes a received New Session Reply for an initiator session.
// It verifies the responder's Noise IK message 2, then replaces the NS-derived
// ratchet roots with the post-handshake NSR keys, providing ee forward secrecy.
func (sm *SessionManager) decryptIncomingNSR(session *Session, nsrTag [8]byte, hs *noiseHandshakeState, message []byte) ([]byte, error) {
	// Phase 1: read handshake state and run NSR crypto under session lock only.
	session.mu.Lock()
	if hs == nil {
		// Fall back to the primary state for a session whose NS was sent before
		// the pending-NSR set existed.
		hs = session.handshakeState
	}
	if hs == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("no pending handshake state for NSR: session may have already processed NSR")
	}
	// Whichever NSR arrives first establishes the session; the remaining pending
	// NS/NSR states are retired. Spec §"Multiple NS Messages": "Alice continues
	// sending New Session (NS) messages to Bob until receiving one of Bob's New
	// Session Reply (NSR) messages."
	session.handshakeState = nil
	siblingTags := make([][8]byte, 0, len(session.pendingNSRs))
	for tag := range session.pendingNSRs {
		if tag != nsrTag {
			siblingTags = append(siblingTags, tag)
		}
		delete(session.pendingNSRs, tag)
	}
	session.mu.Unlock()

	// The manager tag index is only mutated under sm.mu.
	if len(siblingTags) > 0 {
		sm.mu.Lock()
		for _, tag := range siblingTags {
			delete(sm.nsrTagIndex, tag)
		}
		sm.mu.Unlock()
	}

	plaintext, nsrKeys, err := readNoiseIKMessage2(hs, sm.ourPrivateKey, message)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to process New Session Reply")
	}

	// Phase 2: apply NSR keys — requires sm.mu (write) + session.mu.
	// Initiator sends in keyAB direction (A→B) and receives in keyBA direction (B→A).
	sm.mu.Lock()
	session.mu.Lock()
	if applyErr := sm.applyNSRKeysToSessionWhileLocked(session, nsrKeys, true); applyErr != nil {
		session.mu.Unlock()
		sm.mu.Unlock()
		return nil, oops.Wrapf(applyErr, "failed to apply NSR keys to initiator session ratchets")
	}
	session.LastUsed = time.Now()
	session.lastReceived = time.Now()
	// Receipt of an NSR requires a response.
	// Spec ref: ecies.md §"Multiple NSR Messages" - "Once Alice receives an NSR,
	// Alice does a split() to derive the ES session keys. Alice should set a timer,
	// and send an empty ES message if the higher layer does not send any traffic,
	// typically within one second."
	session.oweResponse("new session reply", responseTimerES)
	session.mu.Unlock()
	sm.mu.Unlock()

	flog("decryptIncomingNSR").Debug("New Session Reply received, ratchets updated with NSR keys")

	return plaintext, nil
}

// applyNSRKeysToSessionWhileLocked replaces a session's NS-derived ratchet roots
// with the NSR post-handshake directional keys. Must be called with both
// sm.mu (write) and session.mu held.
//
// nsrSessionKeys.keyAB is the initiator→responder direction key;
// nsrSessionKeys.keyBA is the responder→initiator direction key.
// If isInitiator is true, sendKey = keyAB and recvKey = keyBA; vice versa otherwise.
func (sm *SessionManager) applyNSRKeysToSessionWhileLocked(session *Session, nsrKeys *nsrSessionKeys, isInitiator bool) error {
	flog("applyNSRKeysToSessionWhileLocked", logger.Fields{"is_initiator": isInitiator}).Debug("Applying NSR keys to session ratchets")
	var sendKey, recvKey [32]byte
	if isInitiator {
		sendKey = nsrKeys.keyAB // A sends to B
		recvKey = nsrKeys.keyBA // A receives from B
	} else {
		sendKey = nsrKeys.keyBA // B sends to A
		recvKey = nsrKeys.keyAB // B receives from A
	}

	// Copy the chain key before zeroing the directional keys. The chain key is
	// the input to DH_INITIALIZE for each direction.
	chainKey := nsrKeys.chainKey

	// Zero the NSR directional keys immediately after copying to prevent
	// recovery from memory dumps. The ratchet's forward secrecy guarantees
	// rely on securely destroying keys after use.
	securemem.SecureZero(nsrKeys.keyAB[:])
	securemem.SecureZero(nsrKeys.keyBA[:])

	// Each direction gets its own DH_INITIALIZE(chainKey, k) + TagAndKeyGenKeys.
	// Spec ref: ecies.rst §"Data Phase" — tagset_ab/ba = DH_INITIALIZE(chainKey, k_ab/k_ba).
	_, sendTagKey, sendSymKey, err := deriveDirectionalTagSet(chainKey, sendKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR send-direction ratchet keys")
	}
	_, recvTagKey, recvSymKey, err := deriveDirectionalTagSet(chainKey, recvKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR recv-direction ratchet keys")
	}

	// Purge old NS-derived recv tags from tagIndex before replacing the ratchet.
	// When the caller has already archived the current tag set (an additional
	// NSR reply), pendingTags is nil and the retired tags must stay indexed, so
	// this loop is a no-op in that case.
	for _, tag := range session.pendingTags {
		delete(sm.tagIndex, tag)
		delete(sm.tagCounterIndex, tag)
	}
	session.pendingTags = nil

	// Install post-handshake ratchets.
	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendSymKey)
	session.TagRatchet = ratchet.NewTagRatchet(sendTagKey)
	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(recvSymKey)
	session.RecvTagRatchet = ratchet.NewTagRatchet(recvTagKey)

	// Reset message counters: the ES counter space restarts at 0 with the
	// NSR-derived ratchets, because these are a brand-new tagset whose first
	// tag (tag_0) must pair with nonce 0.
	session.MessageCounter = 0
	resetRecvWindow(session)

	// Regenerate recv tag window with the new NSR-derived recv ratchet.
	return sm.generateTagWindow(session)
}

// decryptExistingSession decrypts an Existing Session message using ratchet state.
//
// It implements a receive window to handle out-of-order delivery without
// desynchronising the receive counter.  The window covers
// [recvWindowBase, recvWindowBase+recvWindowSize) counters.  Message keys are
// pre-derived for every counter in the window; on a successful decrypt the used
// key is removed and the window base is advanced past any trailing consumed
// counters.
//
// counterHint, when non-nil, provides the ES message counter associated with
// the session tag (from tagCounterIndex). This enables O(1) AEAD decryption
// by trying the exact counter first, avoiding the window scan. A nil hint
// falls back to the full window scan for robustness.
//
// Spec basis: ecies.md §"Message Numbers" requires out-of-order handling via the
// tag ratchet; the size of this counter window is an implementation choice (see
// recvWindowSize in helpers.go), not a spec constant.
func (sm *SessionManager) decryptExistingSession(
	session *Session,
	msg []byte,
	sessionTag [8]byte,
	counterHint *uint32,
) ([]byte, [8]byte, uint32, uint16, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	ciphertext, tag, err := parseExistingSessionMessage(msg)
	if err != nil {
		return nil, [8]byte{}, 0, 0, err
	}

	// Ensure the key cache covers the full current window.
	// Guard against uint32 overflow: cap windowEnd to recvFillMark + recvWindowSize
	// to prevent multi-billion iteration loops when session lifetime approaches MaxUint32.
	windowEnd := session.recvWindowBase + recvWindowSize
	if windowEnd < session.recvWindowBase {
		// Overflow: cap at recvFillMark + recvWindowSize instead of saturating
		// to MaxUint32, which would cause fillRecvKeyCache to iterate billions
		// of times on long-lived sessions.
		windowEnd = session.recvFillMark + recvWindowSize
	}
	if err := fillRecvKeyCache(session, windowEnd); err != nil {
		return nil, [8]byte{}, 0, 0, err
	}

	plaintext, usedCounter, found := tryCounterHintDecrypt(session, counterHint, ciphertext, tag, sessionTag, windowEnd)
	if !found {
		plaintext, usedCounter, found = scanWindowDecrypt(session, ciphertext, tag, sessionTag, windowEnd)
	}
	var fromPrevTagset bool
	// ackTagSetID is the inbound tag set the message was decrypted on; an Ack
	// for this message must report that ID (ecies.md §"Ack": "tagsetid ... from
	// the message being acked").
	ackTagSetID := session.recvTagSetID
	if !found {
		// The peer may still be sending on the inbound tag set that a receiving
		// DH ratchet just superseded. ecies.md §"DH RATCHET MESSAGE FLOW":
		// "the receiver should listen for tags in both tagsets, and delete the
		// old tagset after a short time, about 3 minutes".
		plaintext, usedCounter, ackTagSetID, found = decryptRetiredTagset(session, sessionTag, ciphertext, tag)
		fromPrevTagset = found
	}
	if !found {
		return nil, [8]byte{}, 0, 0, oops.Errorf(
			"decrypt failed: message does not match any counter in recv window [%d, %d)",
			session.recvWindowBase, windowEnd,
		)
	}

	// Consume the key and advance the window base past any leading gap of
	// already-consumed counters. A message decrypted on the retained previous
	// tagset has already consumed its key inside decryptPrevTagset.
	if !fromPrevTagset {
		delete(session.recvKeyCache, usedCounter)
		for session.recvWindowBase < session.recvFillMark {
			if _, stillPending := session.recvKeyCache[session.recvWindowBase]; stillPending {
				break
			}
			session.recvWindowBase++
		}
	}

	// The reverse NextKey block is only acknowledged once the peer is actually
	// using the new inbound tag set - i.e. a tag from it decrypts successfully.
	//
	// i2pd ECIESX25519AEADRatchetSession.cpp:808:
	//   if (m_SendReverseKey && receiveTagset->GetTagSetID () ==
	//       m_NextReceiveRatchet->GetReceiveTagSetID ())
	//       m_SendReverseKey = false; // tag received on new tagset
	// Spec ref: ecies.md §"DH RATCHET MESSAGE FLOW" - "(repeat until tag
	// received on new tagset)".
	if session.recvDir != nil && session.recvDir.owed &&
		session.recvTagSetID == session.recvDir.receiveTagSetID() {
		session.recvDir.owed = false
	}

	// GAP-3: Clear the responder's awaitingFirstES flag upon successfully
	// decrypting the first inbound ES message from the initiator.
	if !session.isInitiator && session.awaitingFirstES {
		session.awaitingFirstES = false
		flog("decryptExistingSession", logger.Fields{"counter": usedCounter}).Debug("First inbound ES received; responder may now send ES")
	}

	session.LastUsed = time.Now()
	session.lastReceived = time.Now()
	return plaintext, sessionTag, usedCounter, ackTagSetID, nil
}

// tryCounterHintDecrypt attempts O(1) AEAD decryption using the counter hint
// from the tag→counter index. Returns plaintext, counter used, and whether
// decryption succeeded.
func tryCounterHintDecrypt(
	session *Session,
	counterHint *uint32,
	ciphertext []byte,
	tag [16]byte,
	sessionTag [8]byte,
	windowEnd uint32,
) ([]byte, uint32, bool) {
	flog("tryCounterHintDecrypt", logger.Fields{"window_base": session.recvWindowBase, "window_end": windowEnd}).Debug("Attempting counter-hint AEAD decryption")
	if counterHint == nil {
		return nil, 0, false
	}
	c := *counterHint
	if c < session.recvWindowBase || c >= windowEnd {
		return nil, 0, false
	}
	messageKey, inCache := session.recvKeyCache[c]
	if !inCache {
		return nil, 0, false
	}
	pt, decErr := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, c)
	if decErr != nil {
		return nil, 0, false
	}
	return pt, c, true
}

// scanWindowDecrypt performs a linear scan over the receive window, attempting
// trial AEAD decryption with each cached key. Returns plaintext, counter used,
// and whether decryption succeeded.
func scanWindowDecrypt(
	session *Session,
	ciphertext []byte,
	tag [16]byte,
	sessionTag [8]byte,
	windowEnd uint32,
) ([]byte, uint32, bool) {
	flog("scanWindowDecrypt", logger.Fields{"window_base": session.recvWindowBase, "window_end": windowEnd}).Debug("Scanning receive window for AEAD decryption")
	for counter := session.recvWindowBase; counter < windowEnd; counter++ {
		messageKey, inCache := session.recvKeyCache[counter]
		if !inCache {
			continue
		}
		pt, decErr := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, counter)
		if decErr != nil {
			continue
		}
		return pt, counter, true
	}
	return nil, 0, false
}

// processDecryptedESBlocks inspects a decrypted Existing Session payload for
// control blocks that require session-level side effects:
//
//   - BlockTermination: signals session teardown. The session is removed from
//     sm.sessions and sm.tagIndex. Per ecies.rst §"Unencrypted data", a
//     Termination block in an ES message means the peer is closing the session.
//
//   - BlockMessageNumber: carries the PN value (previous tag set message count).
//     Per ecies.rst §"Message Numbers", on receiving a MessageNumber block the
//     recipient should trim pre-derived keys beyond PN from the previous tag set
//     to bound memory.
//
//   - BlockAckRequest: the peer is requesting acknowledgment. An Ack block is
//     queued for inclusion in the next outgoing ES message.
//     Spec ref: ecies.rst §"Ack Request".
//
//   - BlockAck: the peer is acknowledging previously received messages. The
//     ack entries are stored on the session for caller inspection.
//     Spec ref: ecies.rst §"Ack".
//
// This function is called from DecryptGarlicMessage after decryptExistingSession
// returns successfully, with neither sm.mu nor session.mu held.
func (sm *SessionManager) processDecryptedESBlocks(session *Session, plaintext []byte, counter uint32, tagSetID uint16) {
	// Lenient parse: control blocks we prepended (or the peer prepended) sit at
	// the front of the payload, and a caller-supplied body that is not itself a
	// block sequence must not hide them.
	blocks := ParsePayloadLenient(plaintext)

	for _, block := range blocks {
		switch block.Type {
		case BlockTermination:
			reason, _, _ := block.TerminationInfo()
			sm.removeSessionByPointer(session)
			flog("processDecryptedESBlocks", logger.Fields{"reason": reason}).Info("Session terminated by peer via Termination block")
			return // no further block processing after teardown

		case BlockMessageNumber:
			pn, pnErr := block.MessageNumber()
			if pnErr != nil {
				flog("processDecryptedESBlocks").WithError(pnErr).Warn("Malformed MessageNumber block in ES payload")
				continue
			}
			trimRecvWindowByPN(session, pn)

		case BlockAckRequest:
			sm.processAckRequest(session, counter, tagSetID)

		case BlockAck:
			sm.processAck(session, block)

		case BlockNextKey:
			// ecies.md §"4a) DH Ratchet": "Alice and Bob each do a DH ratchet
			// for every NextKey block received." Without this dispatch the
			// inbound NextKey signaling is parsed and then silently dropped, so
			// neither side ever completes a rekey.
			info, err := block.NextKey()
			if err != nil {
				flog("processDecryptedESBlocks").WithError(err).Warn("Malformed NextKey block in ES payload")
				continue
			}
			if err := sm.handleNextKeyBlock(session, info); err != nil {
				flog("processDecryptedESBlocks", logger.Fields{"key_id": info.KeyID, "reverse": info.Reverse}).
					WithError(err).Warn("Failed to process NextKey block")
			}
		}
	}
}

// handleNextKeyBlock applies a received NextKey block to the session, taking the
// session lock and refreshing the inbound tag window under the manager lock.
func (sm *SessionManager) handleNextKeyBlock(session *Session, info NextKeyInfo) error {
	session.mu.Lock()
	// Receipt of a NextKey block requires a response: either the reverse block or
	// the first message on the new outbound tag set.
	// Spec ref: ecies.md §"Ratchet-layer Responses" - "receipt of ACK Request and
	// Next Key blocks also require a response".
	session.oweResponse("next key", responseTimerES)
	var err error
	if info.Reverse {
		err = session.applyReverseNextKey(info)
	} else {
		err = session.applyForwardNextKey(info)
	}
	// A forward block installs a new inbound tag set whose tags are not in the
	// index yet; a reverse block does not touch the inbound side.
	regen := !info.Reverse
	session.mu.Unlock()
	if err != nil {
		return err
	}
	if regen {
		sm.mu.Lock()
		session.mu.Lock()
		err = sm.generateTagWindow(session)
		session.mu.Unlock()
		sm.mu.Unlock()
	}
	return err
}

// processAckRequest records an Ack entry for the message that carried the
// AckRequest block.
//
// i2pd (ECIESX25519AEADRatchetSession.cpp:365-370) pushes exactly
// {receiveTagset->GetTagSetID(), index} - the inbound tag set ID and the message
// number of the message containing the request - and emits them later as a
// single Ack block.
//
// Spec ref: ecies.md §"5) Payload" -> §"Ack": "tagsetid :: 2 bytes, big endian,
// from the message being acked ... N :: 2 bytes, big endian, from the message
// being acked". The tag set ID is defined by §"KEY AND TAG SET IDS" as
// (1 + sender key ID + receiver key ID), NOT the key ID alone - the previous
// implementation put the key ID in this field (audit finding R-09).
func (sm *SessionManager) processAckRequest(session *Session, counter uint32, tagSetID uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()

	entry := AckEntry{
		TagSetID: tagSetID,
		N:        uint16(min(uint64(counter), uint64(MaxMessageNumber))),
	}
	// Accumulate into one Ack block rather than one block per request, matching
	// i2pd's m_AckRequests vector and the spec's Ack size field
	// ("size :: 4 * number of acks").
	if len(session.pendingAcks) > 0 {
		if info, err := session.pendingAcks[0].Acks(); err == nil {
			session.pendingAcks[0] = NewAckBlock(append(info, entry))
			flog("processAckRequest", logger.Fields{"tag_set_id": entry.TagSetID, "n": entry.N, "queued": len(info) + 1}).
				Debug("Added Ack entry")
			return
		}
	}
	session.pendingAcks = append(session.pendingAcks, NewAckBlock([]AckEntry{entry}))
	flog("processAckRequest", logger.Fields{"tag_set_id": entry.TagSetID, "n": entry.N}).Debug("Queued Ack block in response to AckRequest")
}

// processAck records Ack entries received from the peer.
//
// Spec ref: ecies.rst §"Ack" — acknowledgment of received messages.
func (sm *SessionManager) processAck(session *Session, block PayloadBlock) {
	acks, err := block.Acks()
	if err != nil {
		flog("processAck").WithError(err).Warn("Malformed Ack block in ES payload")
		return
	}

	session.mu.Lock()
	session.lastAckedEntries = acks
	session.mu.Unlock()

	flog("processAck", logger.Fields{"count": len(acks)}).Debug("Received Ack block from peer")
}

// decryptRetiredTagset tries to decrypt an ES message against one of the
// retained inbound tag sets. The tag set has its own tagset-local message-number chain, so
// its counter comes from the tag->counter map archived with it, not from the
// current window.
//
// Spec ref: ecies.md §"4b) Session Tag Ratchet" (N is per-chain) and
// §"DH RATCHET MESSAGE FLOW" (listen on both tagsets for ~3 minutes).
//
// Must be called with session.mu held.
func decryptRetiredTagset(session *Session, sessionTag [8]byte, ciphertext []byte, tag [16]byte) ([]byte, uint32, uint16, bool) {
	for _, prev := range session.retiredRecv {
		if pt, counter, tagSetID, ok := tryRetiredTagset(prev, session, sessionTag, ciphertext, tag); ok {
			return pt, counter, tagSetID, true
		}
	}
	return nil, 0, 0, false
}

func tryRetiredTagset(prev *prevRecvTagset, session *Session, sessionTag [8]byte, ciphertext []byte, tag [16]byte) ([]byte, uint32, uint16, bool) {
	counter, known := prev.tagCounter[sessionTag]
	if !known {
		return nil, 0, 0, false
	}
	windowEnd := prev.windowBase + recvWindowSize
	if windowEnd < prev.windowBase {
		windowEnd = prev.fillMark + recvWindowSize
	}
	if counter < prev.windowBase || counter >= windowEnd {
		return nil, 0, 0, false
	}
	if err := prev.fillKeyCache(session, windowEnd); err != nil {
		return nil, 0, 0, false
	}
	key, ok := prev.keyCache[counter]
	if !ok {
		return nil, 0, 0, false
	}
	plaintext, err := decryptWithSessionTag(key, ciphertext, tag, sessionTag, counter)
	if err != nil {
		return nil, 0, 0, false
	}
	delete(prev.keyCache, counter)
	for prev.windowBase < prev.fillMark {
		if _, stillPending := prev.keyCache[prev.windowBase]; stillPending {
			break
		}
		prev.windowBase++
	}
	flog("decryptRetiredTagset", logger.Fields{"tag_set_id": prev.tagSetID, "counter": counter}).
		Debug("Decrypted ES message on retained previous inbound tag set")
	return plaintext, counter, prev.tagSetID, true
}

// stripECIESControlBlocks removes the ECIES-layer signaling blocks from a
// decrypted ES payload, returning only the caller's data.
//
// NextKey, Ack, AckRequest, Padding, Termination and MessageNumber blocks are
// consumed by the ratchet layer itself (ecies.md §"5) Payload"), so they must
// not be handed to the higher layer. i2pd does exactly this: HandlePayload
// dispatches each block type and copies only eECIESx25519BlkGarlicClove blocks
// into the resulting message.
//
// Blocks are removed from the front of the payload, which is where
// prependPendingNextKeys places them. If the payload does not parse as a block
// sequence, it is returned unchanged.
func stripECIESControlBlocks(plaintext []byte) []byte {
	blocks := ParsePayloadLenient(plaintext)
	if len(blocks) == 0 {
		return plaintext
	}
	// Strip a contiguous prefix of signaling blocks; everything after the last
	// one belongs to the caller (it may be a block sequence or opaque data).
	offset := 0
	for _, b := range blocks {
		switch b.Type {
		case BlockNextKey, BlockAck, BlockAckRequest, BlockPadding, BlockTermination, BlockMessageNumber:
			offset += blockHeaderSize + len(b.Data)
		default:
			return plaintext[offset:]
		}
	}
	// Every parsed block was signaling: return whatever bytes follow them.
	return plaintext[offset:]
}
