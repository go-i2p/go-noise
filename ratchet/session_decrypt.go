package ratchet

import (
	"time"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DecryptGarlicMessage decrypts an encrypted garlic message.
// Handles New Session, New Session Reply, and Existing Session message types.
//
// Returns:
//   - plaintext: the decrypted garlic payload
//   - sessionTag: the 8-byte tag used to identify the session (zero for NS and NSR)
//   - sessionHash: SHA-256(initiatorStaticPub) for New Session messages; nil otherwise.
//     Callers that need to send a New Session Reply must pass this value to EncryptNewSessionReply.
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

	plaintext, sessionTag, err := sm.decryptExistingSession(session, encryptedGarlic[8:], msgTag, counterHint)
	if needsReplenish {
		sm.replenishTagWindowOutsideLock(session)
	}
	if err == nil {
		sm.processDecryptedESBlocks(session, plaintext)
	}
	return plaintext, sessionTag, err, true
}

// tryDecryptNSR attempts to decrypt as a New Session Reply message.
// Returns ok=true if a matching NSR tag was found (even if decryption failed).
func (sm *SessionManager) tryDecryptNSR(msgTag [8]byte, encryptedGarlic []byte) ([]byte, error, bool) {
	flog("tryDecryptNSR", logger.Fields{"message_len": len(encryptedGarlic)}).Debug("Trying to decrypt as New Session Reply")
	sm.mu.Lock()
	nsrSession, isNSR := sm.nsrTagIndex[msgTag]
	if isNSR {
		delete(sm.nsrTagIndex, msgTag)
		if nsrSession.nsrTag != nil && *nsrSession.nsrTag == msgTag {
			nsrSession.nsrTag = nil
		}
	}
	sm.mu.Unlock()

	if !isNSR || nsrSession == nil {
		return nil, nil, false
	}
	plaintext, err := sm.decryptIncomingNSR(nsrSession, encryptedGarlic)
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
	plaintext, initiatorStaticPub, keys, hs, isUnbound, err := readNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, msg,
	)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to process Noise IK New Session message")
	}

	// Unbound sessions are non-repliable: the initiator sent no static key,
	// so there is no identity to key the session on and no NSR can be sent.
	// Spec §1c: "Bob ratchets once when creating an unbound inbound session,
	// and does not create a corresponding outbound session."
	if isUnbound {
		flog("decryptNewSession").Debug("Received unbound (N-pattern) New Session message — no session state stored")
		return plaintext, nil, nil
	}

	// Spec §1b / replay-prevention: reject NS messages whose DateTime block
	// is too old or too far in the future. A captured NS can otherwise be
	// replayed to reset the active session keyed on the initiator's static key.
	if err := sm.validateNSDateTimeFreshness(plaintext); err != nil {
		return nil, nil, oops.Wrapf(err, "New Session message rejected")
	}

	// Spec §"DateTime": "Bob must implement a Bloom filter or other mechanism
	// to prevent replay attacks, if the time is valid."
	// Check the NS ephemeral key (first 32 bytes) against the replay cache.
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

	if err := sm.initializeInboundRatchetState(initiatorStaticPub, keys, hs); err != nil {
		return nil, nil, err
	}

	sessionHash := types.SHA256(initiatorStaticPub[:])
	return plaintext, &sessionHash, nil
}

// initializeInboundRatchetState creates and stores ratchet state for incoming sessions.
func (sm *SessionManager) initializeInboundRatchetState(remotePubKey [32]byte, keys *sessionKeys, hs *noiseHandshakeState) error {
	session, err := createSession(remotePubKey, keys, sm.ourPrivateKey, false)
	if err != nil {
		return oops.Wrapf(err, "failed to create inbound session")
	}

	session.handshakeState = hs
	session.isInitiator = false

	sessionHash := types.SHA256(remotePubKey[:])

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Enforce MaxGarlicSessions to prevent memory exhaustion from malicious peers
	// sending many New Session messages with different ephemeral keys.
	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}
	// Enforce per-peer quota so one hostile identity cannot starve honest
	// peers via LRU churn (AUDIT L-4).
	sm.enforcePerPeerQuotaLocked(remotePubKey)

	sm.sessions[sessionHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate inbound tag window")
	}

	flog("initializeInboundRatchetState", logger.Fields{"session_count": len(sm.sessions), "tag_count":     len(sm.tagIndex)}).Debug("Inbound ratchet session stored")

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
	// taking the address of a stack-local variable (AUDIT M-3).
	session.nsrTag = new([8]byte)
	*session.nsrTag = tag
	sm.nsrTagIndex[tag] = session
	return nil
}

// decryptIncomingNSR processes a received New Session Reply for an initiator session.
// It verifies the responder's Noise IK message 2, then replaces the NS-derived
// ratchet roots with the post-handshake NSR keys, providing ee forward secrecy.
func (sm *SessionManager) decryptIncomingNSR(session *Session, message []byte) ([]byte, error) {
	// Phase 1: read handshake state and run NSR crypto under session lock only.
	session.mu.Lock()
	if session.handshakeState == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("no pending handshake state for NSR: session may have already processed NSR")
	}
	hs := session.handshakeState
	session.handshakeState = nil // consume immediately; duplicate NSRs are rejected
	session.mu.Unlock()

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

	// Zero the NSR keys immediately after copying to prevent recovery from
	// memory dumps. The ratchet's forward secrecy guarantees rely on securely
	// destroying keys after use.
	zero32(&nsrKeys.keyAB)
	zero32(&nsrKeys.keyBA)

	sendTagKey, sendSymKey, err := deriveTagAndSymKeysFromChainKey(sendKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR send-direction ratchet keys")
	}
	recvTagKey, recvSymKey, err := deriveTagAndSymKeysFromChainKey(recvKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR recv-direction ratchet keys")
	}

	// Purge old NS-derived recv tags from tagIndex before replacing the ratchet.
	for _, tag := range session.pendingTags {
		delete(sm.tagIndex, tag)
		delete(sm.tagCounterIndex, tag)
	}
	session.pendingTags = session.pendingTags[:0]

	// Install post-handshake ratchets.
	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendSymKey)
	session.TagRatchet = ratchet.NewTagRatchet(sendTagKey)
	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(recvSymKey)
	session.RecvTagRatchet = ratchet.NewTagRatchet(recvTagKey)

	// Reset message counters: the session restarts at 1 with NSR keys.
	session.MessageCounter = 1
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
// Spec ref: ratchet.md §"Existing Session" — "Maintain handling of out-of-order
// messages", window ≤128.
func (sm *SessionManager) decryptExistingSession(
	session *Session,
	msg []byte,
	sessionTag [8]byte,
	counterHint *uint32,
) ([]byte, [8]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	ciphertext, tag, err := parseExistingSessionMessage(msg)
	if err != nil {
		return nil, [8]byte{}, err
	}

	// Ensure the key cache covers the full current window.
	// Use saturating addition to prevent uint32 overflow (AUDIT M-8).
	// Cap windowEnd to recvFillMark + recvWindowSize to prevent multi-billion
	// iteration loops when session lifetime approaches MaxUint32 (AUDIT M-2).
	windowEnd := session.recvWindowBase + recvWindowSize
	if windowEnd < session.recvWindowBase {
		// Overflow: cap at recvFillMark + recvWindowSize instead of saturating
		// to MaxUint32, which would cause fillRecvKeyCache to iterate billions
		// of times on long-lived sessions.
		windowEnd = session.recvFillMark + recvWindowSize
	}
	if err := fillRecvKeyCache(session, windowEnd); err != nil {
		return nil, [8]byte{}, err
	}

	plaintext, usedCounter, found := tryCounterHintDecrypt(session, counterHint, ciphertext, tag, sessionTag, windowEnd)
	if !found {
		plaintext, usedCounter, found = scanWindowDecrypt(session, ciphertext, tag, sessionTag, windowEnd)
	}
	if !found {
		return nil, [8]byte{}, oops.Errorf(
			"decrypt failed: message does not match any counter in recv window [%d, %d)",
			session.recvWindowBase, windowEnd,
		)
	}

	// Consume the key and advance the window base past any leading gap of
	// already-consumed counters.
	delete(session.recvKeyCache, usedCounter)
	for session.recvWindowBase < session.recvFillMark {
		if _, stillPending := session.recvKeyCache[session.recvWindowBase]; stillPending {
			break
		}
		session.recvWindowBase++
	}

	// GAP-3: Clear the responder's awaitingFirstES flag upon successfully
	// decrypting the first inbound ES message from the initiator.
	if !session.isInitiator && session.awaitingFirstES {
		session.awaitingFirstES = false
		flog("decryptExistingSession", logger.Fields{"counter": usedCounter}).Debug("First inbound ES received; responder may now send ES")
	}

	session.LastUsed = time.Now()
	return plaintext, sessionTag, nil
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
//     sm.sessions and sm.tagIndex. Per ratchet.md §"Unencrypted data", a
//     Termination block in an ES message means the peer is closing the session.
//
//   - BlockMessageNumber: carries the PN value (previous tag set message count).
//     Per ratchet.md §"Message Numbers", on receiving a MessageNumber block the
//     recipient should trim pre-derived keys beyond PN from the previous tag set
//     to bound memory.
//
//   - BlockAckRequest: the peer is requesting acknowledgment. An Ack block is
//     queued for inclusion in the next outgoing ES message.
//     Spec ref: ratchet.md §"Ack Request".
//
//   - BlockAck: the peer is acknowledging previously received messages. The
//     ack entries are stored on the session for caller inspection.
//     Spec ref: ratchet.md §"Ack".
//
// This function is called from DecryptGarlicMessage after decryptExistingSession
// returns successfully, with neither sm.mu nor session.mu held.
func (sm *SessionManager) processDecryptedESBlocks(session *Session, plaintext []byte) {
	blocks, err := ParsePayload(plaintext)
	if err != nil {
		// Non-fatal: the payload was already AEAD-authenticated, so a parse
		// failure here is a local framing bug, not a security issue.
		flog("processDecryptedESBlocks").WithError(err).Warn("Failed to parse decrypted ES payload for control blocks")
		return
	}

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
			sm.processAckRequest(session)

		case BlockAck:
			sm.processAck(session, block)
		}
	}
}

// processAckRequest queues an Ack block for the next outgoing ES message.
// The ack acknowledges the current recv window state: it reports the recv key ID
// and the highest consumed message counter.
//
// Spec ref: ratchet.md §"Ack Request" — on receiving request, queue an Ack response.
func (sm *SessionManager) processAckRequest(session *Session) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Build an Ack that reports our recvKeyID and the highest consumed counter
	// (recvWindowBase - 1, since recvWindowBase is the next expected counter).
	highestConsumed := uint16(0)
	if session.recvWindowBase > 1 {
		base := session.recvWindowBase - 1
		if base > uint32(MaxMessageNumber) {
			base = uint32(MaxMessageNumber)
		}
		highestConsumed = uint16(base)
	}
	ackBlock := NewAckBlock([]AckEntry{{
		TagSetID: session.recvKeyID,
		N:        highestConsumed,
	}})
	session.pendingAcks = append(session.pendingAcks, ackBlock)

	flog("processAckRequest", logger.Fields{"recv_key":  session.recvKeyID, "highest_n": highestConsumed}).Debug("Queued Ack block in response to AckRequest")
}

// processAck records Ack entries received from the peer.
//
// Spec ref: ratchet.md §"Ack" — acknowledgment of received messages.
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
