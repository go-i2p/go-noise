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
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// MaxKeyID is the maximum allowed key ID per the spec. A key ID is a
	// small number that identifies which DH key a NextKey block refers to.
	MaxKeyID = 32767
)

// GetPendingNextKeys returns the NextKey blocks that must accompany the next
// outgoing Existing Session message.
//
// The blocks are NOT consumed: ecies.md §"DH RATCHET MESSAGE FLOW" requires the
// sender to "(repeat until next key received)" and the receiver to "(repeat
// until tag received on new tagset)". i2pd implements this by re-emitting the
// block on every outgoing message while m_SendForwardKey / m_SendReverseKey is
// set (ECIESX25519AEADRatchetSession.cpp:1004-1035), clearing the flag only on
// the acknowledgement. A drain-once queue would lose the exchange whenever the
// carrying message is dropped.
//
// Callers serialize these blocks into the message payload using PayloadBuilder
// before encryption.
//
// Must be called with session.mu held.
func (s *Session) GetPendingNextKeys() []PayloadBlock {
	return s.pendingNextKeyBlocks()
}

// pendingNextKeyBlocks derives the outstanding NextKey blocks from the two
// direction states. At most two blocks exist per message (§"Next DH Ratchet
// Public Key": "In the rare case that the tag sets in both directions are
// ratcheting at the same time, a frame will contain two Next Key blocks, one for
// the forward key and one for the reverse key"), forward first to match i2pd's
// emission order.
func (s *Session) pendingNextKeyBlocks() []PayloadBlock {
	var blocks []PayloadBlock
	if s.sendDir != nil && s.sendDir.owed {
		blocks = append(blocks, buildForwardBlock(s.sendDir))
	}
	if s.recvDir != nil && s.recvDir.owed {
		blocks = append(blocks, buildReverseBlock(s.recvDir))
	}
	return blocks
}

// HasPendingNextKeys reports whether the session has NextKey blocks
// that need to be sent to the peer. This is useful for callers to
// decide whether to include NextKey signaling in the next message.
//
// Must be called with session.mu held.
func (s *Session) HasPendingNextKeys() bool {
	return len(s.pendingNextKeyBlocks()) > 0
}

// ProcessReceivedNextKey handles a NextKey block received from a peer in a
// decrypted Existing Session message.
//
// Two flows exist (ecies.md §"4a) DH Ratchet" -> §"DH RATCHET MESSAGE FLOW"):
//
//  1. Forward block (bit 1 = 0): the peer is the owner of the inbound tag set
//     and is starting a rekey. We generate our key if requested, do the single
//     receive-direction DH, install the new inbound tag set, and owe a reverse
//     block in reply.
//  2. Reverse block (bit 1 = 1): the peer is answering our forward block. We do
//     the single send-direction DH, install the new outbound tag set, and stop
//     owing the forward block.
//
// Neither flow performs a DH until a matching key has been received, which is
// exactly what the previous (shared-ratchet) implementation got wrong.
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.website/blob/main/content/en/docs/specs/ecies.md)
// for details.
func (sm *SessionManager) ProcessReceivedNextKey(sessionTag [8]byte, info NextKeyInfo) error {
	flog("ProcessReceivedNextKey", logger.Fields{"key_present": info.KeyPresent, "reverse": info.Reverse, "key_id": info.KeyID}).Debug("Processing received NextKey block")
	session, err := sm.lookupSessionForNextKey(sessionTag)
	if err != nil {
		return err
	}
	// handleNextKeyBlock acquires session.mu itself; the lookup helper released
	// the lock it took so the manager lock is not held during the DH work.
	return sm.handleNextKeyBlock(session, info)
}

// applyForwardNextKey handles a forward NextKey block - the peer initiated a
// rekey of the tag set it sends us on.
//
// Mirrors the non-reverse branch of i2pd HandleNextKey (line 420) and Java's
// RatchetSKM inbound NextKey handling.
func (s *Session) applyForwardNextKey(info NextKeyInfo) error {
	// i2pd: newKey = flag & REQUEST_REVERSE. The peer sets request-reverse only
	// when it wants a fresh key from us; otherwise it is acking our existing key.
	newKey := info.RequestReverse

	// ecies.md §"Next DH Ratchet Public Key": "Public Key :: ... Only if bit 0
	// is 1". A block that requests a new key must carry the peer's key, except
	// for the reuse-acknowledgement case where the peer's key is already known.
	handled, err := s.prepareRecv(info.KeyID, newKey, info.PublicKey, info.KeyPresent)
	if err != nil {
		return oops.Wrapf(err, "failed to process forward NextKey (keyID=%d)", info.KeyID)
	}
	if !handled {
		return nil // duplicate notification, nothing to do
	}

	// "(generate new key #N, do DH, create IB Tagset #N)"
	tagSetID := s.recvDir.receiveTagSetID()
	if err := s.installRecvTagset(tagSetID); err != nil {
		return oops.Wrapf(err, "failed to install inbound tag set %d", tagSetID)
	}
	// The new inbound tag set has no tags registered in the manager's tag index
	// yet; the caller must run generateTagWindow under sm.mu (see
	// needsRecvTags) because index mutation cannot happen under session.mu alone.
	flog("applyForwardNextKey", logger.Fields{"recv_key_id": s.recvKeyID, "recv_tag_set_id": s.recvTagSetID}).
		Debug("Processed forward NextKey; inbound tag set created, reverse block queued")
	return nil
}

// applyReverseNextKey handles a reverse NextKey block - the peer's reply to our
// forward block. It is the only point at which the send direction does its DH.
//
// Mirrors the reverse branch of i2pd HandleNextKey (line 394), including its
// key-ID acceptance rule.
func (s *Session) applyReverseNextKey(info NextKeyInfo) error {
	// Guard: i2pd line 399 "if (!m_SendForwardKey || !m_NextSendRatchet) return;".
	// A reverse block we did not ask for is ignored rather than treated as an
	// error, because blocks are re-sent until acknowledged.
	if s.sendDir == nil || !s.sendDir.owed {
		flog("applyReverseNextKey", logger.Fields{"key_id": info.KeyID}).Debug("Unexpected reverse NextKey ignored")
		return nil
	}

	dir := s.sendDir
	// i2pd lines 401-403 acceptance rule:
	//   ((!newKey || !keyID) && keyID == send.keyID) || (newKey && keyID == send.keyID-1)
	matches := (!dir.newKey || dir.keyID == 0) && info.KeyID == dir.keyID ||
		(dir.newKey && info.KeyID == dir.keyID-1)
	if !matches {
		flog("applyReverseNextKey", logger.Fields{"key_id": info.KeyID, "send_key_id": dir.keyID}).
			Debug("Unexpected next key ID, ignoring")
		return nil
	}
	if info.KeyPresent {
		dir.remote = info.PublicKey
	}

	// Spec ref: ecies.md §"KEY AND TAG SET IDS" - "the tag set number is
	// (1 + sender key id + receiver key id)". i2pd line 410:
	// newTagset->SetTagSetID (1 + m_NextSendRatchet->keyID + keyID).
	tagSetID := uint16(1) + dir.keyID + info.KeyID
	if err := s.installSendTagset(tagSetID); err != nil {
		return oops.Wrapf(err, "failed to install outbound tag set %d", tagSetID)
	}
	// "(do DH, create OB Tagset #N)" - the forward block is now acknowledged.
	dir.owed = false
	flog("applyReverseNextKey", logger.Fields{"send_key_id": s.sendKeyID, "send_tag_set_id": s.sendTagSetID}).
		Debug("Processed reverse NextKey; outbound tag set created")
	return nil
}

// ClearNextKeyOwed reports whether a direction is still waiting to have its
// NextKey block acknowledged. Exposed for diagnostics and tests.
//
// Must be called with session.mu held.
func (s *Session) ClearNextKeyOwed() (forwardOwed, reverseOwed bool) {
	if s.sendDir != nil {
		forwardOwed = s.sendDir.owed
	}
	if s.recvDir != nil {
		reverseOwed = s.recvDir.owed
	}
	return forwardOwed, reverseOwed
}

// NextKeyState returns the current NextKey-related state for diagnostics
// and testing. Returns (sendKeyID, recvKeyID, awaitingReverse).
//
// Must be called with session.mu held.
func (s *Session) NextKeyState() (sendKeyID, recvKeyID uint16, awaitingReverse bool) {
	awaitingReverse = s.sendDir != nil && s.sendDir.owed
	return s.sendKeyID, s.recvKeyID, awaitingReverse
}

// removeTagsFromIndex is the unregister callback used when a retained previous
// inbound tag set expires. It must be called with sm.mu held for writing.
func (sm *SessionManager) removeTagsFromIndex(tag [8]byte) {
	delete(sm.tagIndex, tag)
	delete(sm.tagCounterIndex, tag)
}


// lookupSessionForNextKey finds the session and releases its lock, so the
// caller can re-acquire it together with the manager lock in handleNextKeyBlock.
func (sm *SessionManager) lookupSessionForNextKey(sessionTag [8]byte) (*Session, error) {
	session, err := sm.lookupLockedSession(sessionTag)
	if err != nil {
		return nil, err
	}
	session.mu.Unlock()
	return session, nil
}
