package ratchet

import (
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// EncryptGarlicMessage encrypts a plaintext garlic message for the given destination.
// The plaintext must be non-empty; the I2P spec requires at least one payload block.
// Returns an error if plaintext is nil or zero-length.
//
// Thread safety: when an existing session is found, sm.mu.RLock is held through the
// entire encryptExistingSession call. This prevents concurrent CleanupExpiredSessions
// or evictLRUSessionLocked (which require sm.mu.Lock) from removing the session and
// its tags between lookup and encryption, which would produce ES messages with
// unregistered tags that the receiver cannot match.
func (sm *SessionManager) EncryptGarlicMessage(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	if len(plaintextGarlic) == 0 {
		return nil, oops.Errorf("plaintext must be non-empty: garlic messages require at least one payload block")
	}

	flog("EncryptGarlicMessage", logger.Fields{"plaintext_size": len(plaintextGarlic)}).Debug("Encrypting garlic message")

	// Hold RLock through the encrypt dispatch to prevent concurrent session
	// eviction. encryptExistingSession is CPU-only (no network I/O), so
	// holding RLock during encryption does not create a bottleneck.
	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	if exists {
		result, err := sm.encryptExistingSession(session, plaintextGarlic)
		sm.mu.RUnlock()
		return result, err
	}
	sm.mu.RUnlock()

	return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
}

// encryptNewSession creates a new session and encrypts using the Noise IK handshake.
// The payload must begin with a DateTime block per ratchet.md §1b; ValidateNewSessionPayload
// is called here to surface non-compliant payloads immediately rather than silently
// producing an interoperability-breaking message.
func (sm *SessionManager) encryptNewSession(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	flog("encryptNewSession", logger.Fields{"plaintext_len": len(plaintextGarlic)}).Debug("Encrypting new session message")
	if err := ValidateNewSessionPayload(plaintextGarlic); err != nil {
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

	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}
	// Enforce per-peer quota on outbound sessions too, so a bug or caller
	// loop that keeps re-initiating to the same destination cannot displace
	// sessions for other peers (AUDIT L-4).
	sm.enforcePerPeerQuotaLocked(destinationPubKey)

	// Register the expected NSR tag for initiator sessions BEFORE storing the
	// session, so that if NSR tag registration fails, we don't create an unusable
	// session (AUDIT M-7: non-fatal NSR registration → initiator deadlock).
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
			"spec violation (ratchet.md §1g): initiator must receive New Session Reply before sending Existing Session messages",
		)
	}

	// Spec §"Notes" after §1g: Bob must receive an ES message from Alice before
	// sending ES messages. This ensures the initiator has processed the NSR and
	// can decrypt ES from the responder. The flag is set after EncryptNewSessionReply
	// and cleared when the first inbound ES is decrypted for this session.
	if !session.isInitiator && session.awaitingFirstES {
		return nil, oops.Errorf(
			"spec violation (ratchet.md §Notes): responder must receive an ES message from initiator before sending ES",
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
	session.MessageCounter++

	return msg, nil
}

// EncryptUnboundGarlicMessage encrypts a plaintext garlic message as an
// unbound (N-pattern, §1c) New Session without advertising the sender's static
// key. Use this for raw-datagram or one-time-send traffic where sender anonymity
// is required.
//
// Unlike EncryptGarlicMessage, no session state is created: the message is
// always a fresh one-shot IK/N-pattern frame and no reply is possible. The
// caller must supply the recipient's raw X25519 public key.
func (sm *SessionManager) EncryptUnboundGarlicMessage(
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	if len(plaintextGarlic) == 0 {
		return nil, oops.Errorf("plaintext must be non-empty: garlic messages require at least one payload block")
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
// that was created by receiving a New Session message. The responder calls this
// to send a reply back to the initiator, completing the Noise IK handshake.
//
// sessionHash identifies the session. Pass the *[32]byte returned by
// DecryptGarlicMessage when it processed the peer's New Session message
// (dereference to obtain the [32]byte value: `*sessionHash`).
// payload is the reply plaintext.
//
// After sending the NSR, the session's ratchet state is updated with the
// post-handshake keys (kAB/kBA from the NSR split), replacing the NS-derived
// roots and providing the ephemeral-ephemeral forward secrecy required by the spec.
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

	if session.handshakeState == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("session has no pending handshake state for NSR")
	}
	if session.isInitiator {
		session.mu.Unlock()
		return nil, oops.Errorf("only the responder can send a New Session Reply")
	}

	_, wireMsg, nsrKeys, err := writeNoiseIKMessage2(session.handshakeState, payload)
	session.handshakeState = nil // consumed; NSR can only be sent once
	session.mu.Unlock()

	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct New Session Reply")
	}

	// Phase 2: apply NSR-derived ratchet keys — requires sm.mu (write) + session.mu.
	// Responder sends in keyBA direction (B→A) and receives in keyAB direction (A→B).
	sm.mu.Lock()
	session.mu.Lock()
	if applyErr := sm.applyNSRKeysToSessionWhileLocked(session, nsrKeys, false); applyErr != nil {
		session.mu.Unlock()
		sm.mu.Unlock()
		return nil, oops.Wrapf(applyErr, "failed to apply NSR keys to responder session ratchets")
	}
	session.awaitingFirstES = true
	session.LastUsed = time.Now()
	session.mu.Unlock()
	sm.mu.Unlock()

	flog("EncryptNewSessionReply", logger.Fields{"payload_size": len(payload)}).Debug("New Session Reply sent, ratchets updated with NSR keys")

	return wireMsg, nil
}
