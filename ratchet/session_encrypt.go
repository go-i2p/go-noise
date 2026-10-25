package ratchet

import (
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// EncryptGarlicMessage encrypts a plaintext garlic message for the given
// destination.
//
// A garlic message is the unit of data sent over I2P: it is a sequence of
// encrypted "cloves" that can be routed through multiple tunnels. This
// method picks the right encryption path automatically: if a session with
// the destination already exists, it uses the fast Existing Session format;
// otherwise it starts a new session with the Noise IK handshake.
//
// An empty plaintext is allowed and required for Existing Session messages:
// ecies.md §"Retransmissions and State Transistions" -> §"Ratchet-layer
// Responses" instructs implementations to "generate an 'empty' (no Garlic Clove
// block) response at the ECIES layer if no reverse traffic is sent in a short
// period of time", and §"Multiple NSR Messages" says Alice "should set a timer,
// and send an empty ES message". New Session messages still require a payload
// (the mandatory DateTime block), which ValidateNewSessionPayload enforces.
//
// Thread safety: when an existing session is found, sm.mu.RLock is held
// through the entire encryptExistingSession call. This prevents concurrent
// CleanupExpiredSessions or evictLRUSessionLocked (which require sm.mu.Lock)
// from removing the session and its tags between lookup and encryption,
// which would produce ES messages with unregistered tags that the receiver
// cannot match.
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
func (sm *SessionManager) EncryptGarlicMessage(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	flog("EncryptGarlicMessage", logger.Fields{"plaintext_size": len(plaintextGarlic)}).Debug("Encrypting garlic message")

	// Hold RLock through the encrypt dispatch to prevent concurrent session
	// eviction. encryptExistingSession is CPU-only (no network I/O), so
	// holding RLock during encryption does not create a bottleneck.
	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	// An initiator whose NSR has not arrived yet must keep retransmitting New
	// Session messages rather than attempt Existing Session traffic.
	//
	// Spec ref: ecies.md §"4a) DH Ratchet" - "Alice continues sending New
	// Session (NS) messages to Bob until receiving one of Bob's New Session
	// Reply (NSR) messages. She then uses the NSR's Payload Section KDF results
	// as inputs for the session ratchets ... and begins sending Existing Session
	// (ES) messages."
	//
	// Each retransmission uses a fresh ephemeral key, so each produces a
	// different NSR tag and the responder can answer all of them
	// (§"Multiple NS Messages").
	needsNS := false
	if exists {
		session.mu.Lock()
		needsNS = session.isInitiator && session.handshakeState != nil
		session.mu.Unlock()
	}
	sm.mu.RUnlock()

	if exists && !needsNS {
		return sm.encryptExistingSession(session, plaintextGarlic)
	}

	return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
}

// encryptNewSession creates a new session and encrypts using the Noise IK handshake.
// The payload must begin with a DateTime block per ecies.rst §1b; ValidateNewSessionPayload
// is called here to surface non-compliant payloads immediately rather than silently
// producing an interoperability-breaking message.
func (sm *SessionManager) encryptNewSession(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	flog("encryptNewSession", logger.Fields{"plaintext_len": len(plaintextGarlic)}).Debug("Encrypting new session message")
	if err := ValidateNewSessionPayload(plaintextGarlic); err != nil {
		// A caller whose NSR has not arrived yet is routed here to retransmit NS
		// (§"4a) DH Ratchet"). If its payload is not an NS payload it was trying
		// to send ES, so report the ordering violation that actually explains the
		// problem.
		if oopsErr := sm.pendingInitiatorESAttemptError(destinationHash); oopsErr != nil {
			return nil, oopsErr
		}
		return nil, oops.Wrapf(err, "new session payload rejected")
	}

	msg, keys, hs, err := writeNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, destinationPubKey, plaintextGarlic,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Noise IK New Session message")
	}

	if err := sm.storeNewSessionState(destinationHash, destinationPubKey, keys, hs, true); err != nil {
		return nil, err
	}

	return msg, nil
}

// storeNewSessionState initializes and stores ratchet state for future messages.
func (sm *SessionManager) storeNewSessionState(
	destinationHash, destinationPubKey [32]byte,
	keys *sessionKeys,
	hs *noiseHandshakeState,
	isInitiator bool,
) error {
	session, err := createSession(destinationPubKey, keys, sm.ourPrivateKey, isInitiator)
	if err != nil {
		return oops.Wrapf(err, "failed to create outbound session")
	}

	session.handshakeState = hs
	session.isInitiator = isInitiator

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// A retransmitted New Session must NOT replace the session of an NS that is
	// still unanswered: each NS carries a fresh ephemeral key, so each produces a
	// different NSR tag, and the initiator must be able to accept whichever NSR
	// arrives. Replacing the state meant only the last NS could ever be answered.
	//
	// Spec ref: ecies.md §"4a) DH Ratchet" - "Alice continues sending New Session
	// (NS) messages to Bob until receiving one of Bob's New Session Reply (NSR)
	// messages"; §"Multiple NS Messages" - "Each NSR uses the handshake state and
	// tagset corresponding to the incoming NS."
	if isInitiator {
		if existing, ok := sm.sessions[destinationHash]; ok && existing.isInitiator && existing.handshakeState != nil {
			return sm.addInitiatorNSLocked(existing, hs)
		}
	}

	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}
	// Enforce per-peer quota on outbound sessions too, so a bug or caller
	// loop that keeps re-initiating to the same destination cannot displace
	// sessions for other peers.
	sm.enforcePerPeerQuotaLocked(destinationPubKey)

	if session.pendingNSRs == nil {
		session.pendingNSRs = make(map[[8]byte]*noiseHandshakeState)
	}

	// Register the expected NSR tag for initiator sessions BEFORE storing the
	// session, so that if NSR tag registration fails, we don't create an unusable
	// session that would deadlock the initiator.
	if isInitiator && hs != nil {
		if err := sm.registerNSRTagLocked(session, hs); err != nil {
			return oops.Wrapf(err, "failed to register NSR tag for initiator session")
		}
	}

	sm.sessions[destinationHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate tag window")
	}

	flog("storeNewSessionState", logger.Fields{"session_count": len(sm.sessions)}).Debug("New session state stored")

	return nil
}

// addInitiatorNSLocked records an additional retransmitted New Session on an
// existing initiator session, keeping its handshake state and expected NSR tag
// alongside the previous ones.
//
// Must be called with sm.mu held for writing.
func (sm *SessionManager) addInitiatorNSLocked(session *Session, hs *noiseHandshakeState) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if len(session.pendingNSRs) >= maxPendingNSReplies {
		// Spec §"Multiple NS Messages" permits limiting NS sends to avoid a
		// resource-exhaustion attack; the caller's NS is dropped.
		flog("addInitiatorNSLocked", logger.Fields{"pending": len(session.pendingNSRs)}).
			Debug("Initiator NSR pending set full, not retransmitting state for this NS")
		return nil
	}
	if err := sm.registerNSRTagLocked(session, hs); err != nil {
		return oops.Wrapf(err, "failed to register NSR tag for retransmitted NS")
	}
	flog("addInitiatorNSLocked", logger.Fields{"pending": len(session.pendingNSRs)}).
		Debug("Registered additional NSR tag for retransmitted New Session")
	return nil
}

// pendingInitiatorESAttemptError returns the §1g ordering error when an
// established initiator session is still awaiting its New Session Reply, or nil
// when that is not the case.
func (sm *SessionManager) pendingInitiatorESAttemptError(destinationHash [32]byte) error {
	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	sm.mu.RUnlock()
	if !exists {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.isInitiator && session.handshakeState != nil {
		return oops.Errorf(
			"spec violation (ecies.md §1g): initiator must receive New Session Reply before sending Existing Session messages",
		)
	}
	return nil
}

// encryptExistingSession encrypts using ratchet state for an established session.
func (sm *SessionManager) encryptExistingSession(
	session *Session,
	plaintextGarlic []byte,
) ([]byte, error) {
	flog("encryptExistingSession", logger.Fields{"plaintext_len": len(plaintextGarlic)}).Debug("Encrypting existing session message")
	session.mu.Lock()
	defer session.mu.Unlock()

	// Spec §1g: the initiator must not send Existing Session messages before it
	// has received the New Session Reply from the responder. The NSR completes
	// the initial Noise IK handshake and installs the ee forward-secrecy keys;
	// sending ES on the pre-NSR NS-derived ratchet is a spec violation that would
	// also break receiver key synchronisation.
	//
	// handshakeState is consumed (set to nil) when NSR is processed in
	// decryptIncomingNSR, so a non-nil value here means NSR has not arrived yet.
	if session.isInitiator && session.handshakeState != nil {
		return nil, oops.Errorf(
			"spec violation (ecies.rst §1g): initiator must receive New Session Reply before sending Existing Session messages",
		)
	}

	// Spec §"Notes" after §1g: Bob must receive an ES message from Alice before
	// sending ES messages. This ensures the initiator has processed the NSR and
	// can decrypt ES from the responder. The flag is set after EncryptNewSessionReply
	// and cleared when the first inbound ES is decrypted for this session.
	if !session.isInitiator && session.awaitingFirstES {
		return nil, oops.Errorf(
			"spec violation (ecies.rst §Notes): responder must receive an ES message from initiator before sending ES",
		)
	}

	messageKey, sessionTag, err := advanceRatchets(session)
	if err != nil {
		return nil, err
	}

	// Spec §"Next DH Ratchet Public Key": if a DH ratchet rotation occurred,
	// the resulting NextKey blocks must be serialized into the encrypted payload
	// so the peer can process the key rotation and maintain forward secrecy.
	payload, err := prependPendingNextKeys(session, plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to prepend NextKey blocks to payload")
	}

	ciphertext, tag, err := encryptWithSessionKey(messageKey, payload, sessionTag, session.MessageCounter)
	if err != nil {
		return nil, err
	}

	msg := buildExistingSessionMessage(sessionTag, ciphertext, tag)

	session.LastUsed = time.Now()
	session.lastSent = time.Now()
	session.MessageCounter++

	return msg, nil
}

// EncryptUnboundGarlicMessage encrypts a plaintext garlic message as an
// unbound New Session without advertising the sender's static key. Use this
// for raw-datagram or one-time-send traffic where sender anonymity is
// required.
//
// "Unbound" means the message does not tie the sender to a persistent
// identity: the Noise handshake uses an ephemeral key instead of the
// sender's static key, so the recipient cannot link the message to the
// sender's long-term identity.
//
// Unlike [SessionManager.EncryptGarlicMessage], no session state is
// created: the message is always a fresh one-shot frame and no reply is
// possible. The caller must supply the recipient's raw X25519 public key.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
// details.
func (sm *SessionManager) EncryptUnboundGarlicMessage(
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	// An unbound New Session must carry a payload with the mandatory DateTime
	// block, so an empty plaintext is rejected here (ValidateNewSessionPayload
	// enforces the block requirement).
	if len(plaintextGarlic) == 0 {
		return nil, oops.Errorf("unbound new session plaintext must not be empty: an NS payload requires a DateTime block")
	}

	flog("EncryptUnboundGarlicMessage", logger.Fields{"plaintext_size": len(plaintextGarlic)}).Debug("Encrypting unbound garlic message")

	if err := ValidateNewSessionPayload(plaintextGarlic); err != nil {
		return nil, oops.Wrapf(err, "unbound new session payload rejected")
	}

	msg, _, err := writeNoiseIKMessage1Unbound(destinationPubKey, plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct unbound New Session message")
	}
	return msg, nil
}

// EncryptNewSessionReply constructs a New Session Reply (NSR) for a session
// that was created by receiving a New Session message. The responder calls
// this to send a reply back to the initiator, completing the Noise IK
// handshake.
//
// Parameters:
//   - sessionHash: identifies the session. Pass the *[32]byte returned by
//     [SessionManager.DecryptGarlicMessage] when it processed the peer's New
//     Session message (dereference to obtain the [32]byte value:
//     `*sessionHash`).
//   - payload: the reply plaintext.
//
// After sending the NSR, the session's ratchet state is updated with the
// post-handshake keys, replacing the keys derived from the New Session
// message and providing the ephemeral-ephemeral forward secrecy required by
// the spec.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
// details.
func (sm *SessionManager) EncryptNewSessionReply(
	sessionHash [32]byte,
	payload []byte,
) ([]byte, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionHash]
	sm.mu.RUnlock()

	if !exists {
		return nil, oops.Errorf("no session found for hash %x", sessionHash[:8])
	}

	// Phase 1: crypto under session lock only (no sm.mu needed for key derivation).
	session.mu.Lock()

	if session.isInitiator {
		session.mu.Unlock()
		return nil, oops.Errorf("only the responder can send a New Session Reply")
	}

	// Take the handshake state of the NS we are replying to: the original one
	// first, then each additional queued NS. Each NSR must use the state and
	// tagset of the NS it answers.
	//
	// Spec ref: ecies.md §"Multiple NSR Messages" - "Each NSR uses the handshake
	// state and tagset corresponding to the incoming NS."
	hs := session.handshakeState
	if hs == nil && len(session.awaitingNSRReplies) > 0 {
		hs = session.awaitingNSRReplies[0]
		session.awaitingNSRReplies = session.awaitingNSRReplies[1:]
	}
	if hs == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("session has no pending handshake state for NSR")
	}
	session.handshakeState = nil // the head NS is now answered

	_, wireMsg, nsrKeys, err := writeNoiseIKMessage2(hs, payload)
	session.mu.Unlock()

	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct New Session Reply")
	}

	// Phase 2: apply NSR-derived ratchet keys — requires sm.mu (write) + session.mu.
	// Responder sends in keyBA direction (B→A) and receives in keyAB direction (A→B).
	sm.mu.Lock()
	session.mu.Lock()
	// When replying to an ADDITIONAL NS, the inbound tag set derived from the
	// previous reply must keep being accepted: the initiator uses whichever NSR
	// arrives first, so until an ES message identifies the live one, every
	// reply's tag set has to be decryptable.
	//
	// Spec ref: ecies.md §"Multiple NS Messages" - "For each NS message received,
	// Bob creates a new inbound session, using the KDF results of the reply
	// Payload Section for inputs to the new inbound and outbound ES DH Ratchet."
	additionalReply := session.nsrSent
	if additionalReply {
		session.archiveRecvTagset()
	}
	session.nsrSent = true
	if applyErr := sm.applyNSRKeysToSessionWhileLocked(session, nsrKeys, false); applyErr != nil {
		session.mu.Unlock()
		sm.mu.Unlock()
		return nil, oops.Wrapf(applyErr, "failed to apply NSR keys to responder session ratchets")
	}
	session.awaitingFirstES = true
	session.LastUsed = time.Now()
	session.lastSent = time.Now()
	session.mu.Unlock()
	sm.mu.Unlock()

	flog("EncryptNewSessionReply", logger.Fields{"payload_size": len(payload)}).Debug("New Session Reply sent, ratchets updated with NSR keys")

	return wireMsg, nil
}
