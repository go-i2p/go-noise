package ratchet

// nextkey.go implements DH ratchet signaling via NextKey payload blocks.
//
// The I2P ECIES-X25519-AEAD-Ratchet spec signals DH ratchet key rotations
// using NextKey blocks in the encrypted payload of Existing Session messages.
// When a party's tag set is nearly exhausted, it generates a new DH key pair
// and sends a "forward" NextKey block. The peer responds with a "reverse"
// NextKey block containing its own new DH key. Both sides then perform a DH
// ratchet to derive a new tag set.
//
// Spec ref: ratchet.md §"Next DH Ratchet Public Key", §"DH Ratchet Message Flow".

import (
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// MaxKeyID is the maximum allowed key ID per the spec.
	// Spec ref: ratchet.md — "The maximum Key ID is 32767."
	MaxKeyID = 32767
)

// GetPendingNextKeys returns any NextKey blocks that should be included
// in the next outgoing Existing Session message. The returned blocks are
// removed from the session's pending queue.
//
// Callers should serialize these blocks into the message payload using
// PayloadBuilder before encryption.
//
// Must be called with session.mu held.
func (s *Session) GetPendingNextKeys() []PayloadBlock {
	if len(s.pendingNextKeys) == 0 {
		return nil
	}
	// Return a copy to avoid aliasing the backing array.
	result := append([]PayloadBlock(nil), s.pendingNextKeys...)
	s.pendingNextKeys = nil
	return result
}

// HasPendingNextKeys reports whether the session has NextKey blocks
// that need to be sent to the peer. This is useful for callers to
// decide whether to include NextKey signaling in the next message.
//
// Must be called with session.mu held.
func (s *Session) HasPendingNextKeys() bool {
	return len(s.pendingNextKeys) > 0
}

// ProcessReceivedNextKey handles a NextKey block received from a peer
// in a decrypted Existing Session message.
//
// There are two NextKey flows:
//  1. Forward key (bit 1 = 0): The peer generated a new DH key and sent it.
//     We update the peer's public key and perform a receiving DH ratchet.
//     If request-reverse is set, we generate our own new key and queue a
//     reverse NextKey block.
//  2. Reverse key (bit 1 = 1): The peer is responding to our forward key.
//     We update the peer's public key and perform a receiving DH ratchet.
//
// sessionTag identifies the session (used for lookup).
// info is the parsed NextKey block.
//
// Spec ref: ratchet.md §"DH Ratchet Message Flow".
func (sm *SessionManager) ProcessReceivedNextKey(sessionTag [8]byte, info NextKeyInfo) error {
	flog("ProcessReceivedNextKey", logger.Fields{"key_present": info.KeyPresent, "reverse": info.Reverse, "key_id": info.KeyID}).Debug("Processing received NextKey block")
	session, err := sm.lookupLockedSession(sessionTag)
	if err != nil {
		return err
	}
	defer session.mu.Unlock()

	if info.KeyPresent {
		return sm.processNextKeyWithKey(session, info)
	}
	return sm.processNextKeyAck(session, info)
}

// processNextKeyWithKey handles a NextKey block that contains a public key.
// This is either a forward key from the peer or a reverse key in response
// to our forward key.
func (sm *SessionManager) processNextKeyWithKey(session *Session, info NextKeyInfo) error {
	flog("processNextKeyWithKey", logger.Fields{"reverse": info.Reverse, "key_id": info.KeyID}).Debug("Processing NextKey block with key")
	if info.Reverse {
		return sm.processReverseNextKey(session, info)
	}
	return sm.processForwardNextKey(session, info)
}

// processForwardNextKey handles a forward NextKey from the peer.
// The peer has generated a new DH key and is signaling a ratchet.
// We update the receiving chain with the new key, and if requested,
// generate and queue a reverse key response.
func (sm *SessionManager) processForwardNextKey(session *Session, info NextKeyInfo) error {
	// Update the peer's key and ratchet the receiving chain.
	if err := sm.applyIncomingDHKey(session, info.PublicKey); err != nil {
		return oops.Wrapf(err, "failed to process forward NextKey (keyID=%d)", info.KeyID)
	}

	session.recvKeyID = info.KeyID

	flog("processForwardNextKey", logger.Fields{"recv_key_id": info.KeyID}).Debug("Processed forward NextKey from peer")

	// If the peer requests a reverse key, generate one and queue it.
	if info.RequestReverse {
		return sm.generateReverseNextKey(session)
	}

	return nil
}

// processReverseNextKey handles a reverse NextKey from the peer.
// This is the peer's response to our forward NextKey. We update the
// receiving chain and clear the awaitingReverseKey flag.
func (sm *SessionManager) processReverseNextKey(session *Session, info NextKeyInfo) error {
	if err := sm.applyIncomingDHKey(session, info.PublicKey); err != nil {
		return oops.Wrapf(err, "failed to process reverse NextKey (keyID=%d)", info.KeyID)
	}

	session.recvKeyID = info.KeyID
	session.awaitingReverseKey = false

	flog("processReverseNextKey", logger.Fields{"recv_key_id": info.KeyID}).Debug("Processed reverse NextKey from peer, DH ratchet exchange complete")

	return nil
}

// processNextKeyAck handles a NextKey block without a public key.
// This is an acknowledgment of a previously sent key (the peer reuses
// its existing key). We perform a DH ratchet with the known peer key.
func (sm *SessionManager) processNextKeyAck(session *Session, info NextKeyInfo) error {
	// No new key — peer is acknowledging our key with their existing one.
	// Ratchet with the current remote public key.
	if err := sm.applyIncomingDHKey(session, session.RemotePublicKey); err != nil {
		return oops.Wrapf(err, "failed to process NextKey ack (keyID=%d)", info.KeyID)
	}

	if info.Reverse {
		session.awaitingReverseKey = false
	}

	flog("processNextKeyAck", logger.Fields{"key_id":  info.KeyID, "reverse": info.Reverse}).Debug("Processed NextKey acknowledgment from peer")

	return nil
}

// applyIncomingDHKey updates the session's receiving ratchet state
// with a new (or existing) remote public key. This is the core
// operation shared by all NextKey processing paths.
func (sm *SessionManager) applyIncomingDHKey(session *Session, remotePubKey [32]byte) error {
	flog("applyIncomingDHKey").Debug("Applying incoming DH key to session ratchet")
	if err := session.DHRatchet.UpdateKeys(remotePubKey[:]); err != nil {
		return oops.Wrapf(err, "failed to update remote DH public key")
	}

	if err := applyRecvRatchetKeys(session); err != nil {
		return err
	}

	session.RemotePublicKey = remotePubKey

	return nil
}

// generateReverseNextKey generates a new DH key pair and queues a reverse
// NextKey block for the next outgoing message. The block carries the current
// sendKeyID value, and sendKeyID is incremented afterwards to prevent
// collision with the next forward NextKey block from performDHRatchetStep.
//
// Without the increment, a double-rotation scenario (forward rotation →
// reverse response → another forward rotation) would produce two blocks
// with the same sendKeyID, confusing the peer's keyID tracking.
func (sm *SessionManager) generateReverseNextKey(session *Session) error {
	if session.sendKeyID >= MaxKeyID {
		return oops.Errorf("send key ID %d has reached maximum %d", session.sendKeyID, MaxKeyID)
	}

	newPubKey, err := session.DHRatchet.GenerateNewKeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate reverse NextKey key pair")
	}

	// Queue a reverse NextKey block with the current sendKeyID.
	reverseBlock := NewNextKeyBlock(session.sendKeyID, &newPubKey, true, false)
	session.pendingNextKeys = append(session.pendingNextKeys, reverseBlock)

	session.newEphemeralPub = &newPubKey

	// Advance sendKeyID so the next forward block gets a distinct ID.
	// Safe: guarded >= MaxKeyID above.
	session.sendKeyID++

	flog("generateReverseNextKey", logger.Fields{"send_key_id": session.sendKeyID, "new_pub_key": fmt.Sprintf("%x", newPubKey[:8])}).Debug("Reverse NextKey block queued, sendKeyID advanced")

	return nil
}

// IncrementSendKeyID advances the session's send key ID after a successful
// DH ratchet exchange. Called after the peer has acknowledged our key.
//
// Must be called with session.mu held.
func (s *Session) IncrementSendKeyID() error {
	flog("IncrementSendKeyID", logger.Fields{"current_key_id": s.sendKeyID}).Debug("Incrementing send key ID")
	if s.sendKeyID >= MaxKeyID {
		return oops.Errorf("send key ID %d has reached maximum %d, must create new session", s.sendKeyID, MaxKeyID)
	}
	s.sendKeyID++
	return nil
}

// NextKeyState returns the current NextKey-related state for diagnostics
// and testing. Returns (sendKeyID, recvKeyID, awaitingReverse).
//
// Must be called with session.mu held.
func (s *Session) NextKeyState() (sendKeyID, recvKeyID uint16, awaitingReverse bool) {
	return s.sendKeyID, s.recvKeyID, s.awaitingReverseKey
}
