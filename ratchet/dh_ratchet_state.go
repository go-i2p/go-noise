package ratchet

// This file models the per-direction DH ratchet state machine defined by
// ecies.md §"4a) DH Ratchet" -> §"DH RATCHET MESSAGE FLOW".
//
// The spec separates "ack of the received key" from "generating the new key",
// and - critically - each direction performs exactly ONE DH, and only once the
// matching key from the other side has arrived:
//
//	Tag Sender                              Tag Receiver
//	(generate new key #0)
//	Next Key, forward, request reverse, #0  -------->
//	                                  (generate new key #0, do DH, IB Tagset #1)
//	        <--------  Next Key, reverse, with key #0
//	(do DH, create OB Tagset #1)
//
// A single shared ratchet cannot express this: the tag sender's DH must wait
// for the tag receiver's key and vice versa. Both reference implementations
// therefore keep two independent per-direction states:
//
//	i2pd  ECIESX25519AEADRatchetSession.h:152
//	      struct DHRatchet { int keyID; X25519Keys* key; uint8_t remote[32]; bool newKey; }
//	      m_NextSendRatchet    + m_SendForwardKey
//	      m_NextReceiveRatchet + m_SendReverseKey
//	Java  RatchetSKM.java keeps the same outbound/inbound split per direction.
//
// The previous implementation used one shared ratchet and performed the send DH
// immediately with the peer's stale key, so the two peers derived different tag
// sets - an interop-breaking defect (audit finding R-02).

import (
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// dhDirection is one direction's pending DH-ratchet state, mirroring i2pd's
// struct DHRatchet plus its m_SendForwardKey / m_SendReverseKey flag.
type dhDirection struct {
	// keyID is the local key ID for this direction.
	// Spec ref: ecies.md §"Next DH Ratchet Public Key" - "an incrementing
	// counter for the local key used for that tag set, starting at 0".
	keyID uint16
	// newKey reports whether keyID refers to a freshly generated key. When
	// false, the existing key is reused and the block carries no public key.
	// i2pd: DHRatchet::newKey.
	newKey bool
	// ourPriv / ourPub are this direction's current X25519 key pair.
	ourPriv [32]byte
	ourPub  [32]byte
	// hasKey records whether ourPriv/ourPub have been generated yet. The spec
	// generates the key when the exchange starts, not at session creation.
	hasKey bool
	// remote is the last peer public key received for this direction. i2pd
	// retains the previous value when a block carries no key.
	remote [32]byte
	// owed reports whether a NextKey block for this direction still needs to be
	// sent. The block is re-sent on every outgoing message until the matching
	// key/tagset evidence arrives, which is what makes the exchange
	// loss-tolerant ("repeat until next key received" / "repeat until tag
	// received on new tagset"). i2pd: m_SendForwardKey / m_SendReverseKey.
	owed bool
}

// prepareSend advances the outbound tag-set sender's ratchet bookkeeping and
// queues the forward NextKey block. It performs NO DH: per the spec the sender's
// DH happens only when the peer's reverse key arrives (see applyReverseNextKey).
//
// Mirrors i2pd ECIESX25519AEADRatchetSession::NewNextSendRatchet (line 462),
// including its key-ID parity rule, which reproduces the spec's key progression
// table: key 0*, key 1*, key 1 (reuse), key 2*, key 2 (reuse), ...
func (s *Session) prepareSend() error {
	flog("prepareSend", logger.Fields{"send_key_id": s.sendKeyID}).Debug("Preparing forward NextKey (no DH yet)")

	// i2pd's DHRatchet is value-initialised with keyID = 0 and newKey = true
	// (ECIESX25519AEADRatchetSession.h:153-156), so the very first forward block
	// carries a freshly generated key #0 - matching the spec's
	// "(generate new key #0) / Next Key, forward, request reverse, with key #0".
	if s.sendDir == nil {
		s.sendDir = &dhDirection{keyID: 0, newKey: true}
	} else if !s.sendDir.newKey || s.sendDir.keyID == 0 {
		s.sendDir.keyID++
		s.sendDir.newKey = true
	} else {
		s.sendDir.newKey = false
	}
	s.sendKeyID = s.sendDir.keyID

	dir := s.sendDir
	if dir.newKey {
		// "(generate new key #N)" - a fresh X25519 pair for this direction.
		if err := dir.generateKeyPair(); err != nil {
			return oops.Wrapf(err, "failed to generate forward DH ratchet key")
		}
	} else if !dir.hasKey {
		return oops.Code("DH_STATE_MISSING").In("ratchet").
			Errorf("send direction has no key pair to reuse at key ID %d", dir.keyID)
	}
	// i2pd starts DHRatchet::remote at the last known peer key and only
	// overwrites it when a block carries KEY_PRESENT.
	if dir.remote == ([32]byte{}) {
		dir.remote = s.RemotePublicKey
	}

	// The block itself is derived from dir.owed on every outgoing message, so
	// setting the flag is all that is required.
	dir.owed = true
	return nil
}

// prepareRecv advances the inbound tag-set receiver's state for a forward block
// the peer just sent, and queues the reverse NextKey block. Mirrors the
// non-reverse branch of i2pd HandleNextKey (line 420).
//
// newKey is derived from the block's request-reverse flag: the peer only sets it
// when it wants a fresh key from us.
// It returns handled=false when the block is a duplicate of one already
// processed, so the caller skips the DH.
func (s *Session) prepareRecv(keyID uint16, newKey bool, remotePub [32]byte, keyPresent bool) (handled bool, err error) {
	if s.recvDir == nil {
		s.recvDir = &dhDirection{}
	} else if keyID == s.recvDir.keyID && newKey == s.recvDir.newKey {
		// i2pd line 428: duplicate new/old key notification for the same ID -
		// the forward block is re-sent until our reverse block lands, so this is
		// the normal loss-recovery path, not an error.
		flog("prepareRecv", logger.Fields{"key_id": keyID, "new_key": newKey}).Debug("Duplicate forward NextKey received, ignoring")
		return false, nil
	}
	// i2pd assigns the received key ID to the receive ratchet in both the
	// first-time and update cases; the reverse block's (keyID - 1) arithmetic
	// then reproduces the spec's "Next Key, reverse, id 0" acknowledgement.
	s.recvDir.keyID = keyID

	dir := s.recvDir
	dir.newKey = newKey
	if newKey {
		if err := dir.generateKeyPair(); err != nil {
			return false, oops.Wrapf(err, "failed to generate reverse DH ratchet key")
		}
	}
	if keyPresent {
		dir.remote = remotePub
	} else if dir.remote == ([32]byte{}) {
		dir.remote = s.RemotePublicKey
	}
	s.recvKeyID = dir.keyID

	dir.owed = true
	return true, nil
}

// generateKeyPair creates a fresh X25519 key pair for this direction.
func (d *dhDirection) generateKeyPair() error {
	pub, priv, err := curve25519.GenerateX25519KeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate DH ratchet key pair")
	}
	copy(d.ourPub[:], pub.Bytes())
	copy(d.ourPriv[:], priv.Bytes())
	d.hasKey = true
	return nil
}

// ratchet performs this direction's single DH and returns the new tag and
// symmetric key chain keys. It implements the spec's DH Ratchet KDF:
//
//	sharedSecret = DH(rask, rbpk)
//	tagsetKey    = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
//	rootKey      = nextRootKey   // from previous tagset in this direction
//	newTagSet    = DH_INITIALIZE(rootKey, tagsetKey)
//
// Spec ref: ecies.md §"DH Ratchet KDF". rootKey is the direction's persisted
// nextRootKey and is updated in place.
func (d *dhDirection) ratchet(rootKey *[32]byte) (tagKey, symKey [32]byte, err error) {
	if !d.hasKey {
		return tagKey, symKey, oops.Code("DH_STATE_MISSING").In("ratchet").
			Errorf("direction has no local DH key pair at key ID %d", d.keyID)
	}
	dh := ratchet.NewDHRatchet(*rootKey, d.ourPriv, d.remote)
	nextRootKey, chainKey, err := dh.PerformRatchet()
	if err != nil {
		return tagKey, symKey, oops.Wrapf(err, "failed to perform DH ratchet (key ID %d)", d.keyID)
	}
	*rootKey = nextRootKey
	return deriveTagAndSymKeysFromChainKey(chainKey)
}

// buildForwardBlock renders the forward NextKey block for the outbound
// tag-set sender.
//
// Flag rule (ecies.md §"Next DH Ratchet Public Key": bit 1 = reverse, bit 2 =
// request reverse "only set if bit 1 is 0"; i2pd lines 1023-1029):
//   - new key present -> KEY_PRESENT
//   - key reused      -> REQUEST_REVERSE (we ask the peer for its key)
//   - key ID 0        -> additionally REQUEST_REVERSE, i2pd's "for first key
//     only", so the peer replies with its key and tag set 1 is created in both
//     directions (spec table: tag set 1 = sender key 0*, receiver key 0*).
func buildForwardBlock(dir *dhDirection) PayloadBlock {
	requestReverse := !dir.newKey || dir.keyID == 0
	var pub *[32]byte
	if dir.newKey {
		p := dir.ourPub
		pub = &p
	}
	return NewNextKeyBlock(dir.keyID, pub, false, requestReverse)
}

// buildReverseBlock renders the reverse NextKey block for the inbound tag-set
// receiver.
//
// Mirrors i2pd lines 1005-1021: the block carries (keyID - 1), bumped back to
// keyID when a new key is present, so the peer can distinguish a reuse
// acknowledgement from a new-key reply.
func buildReverseBlock(dir *dhDirection) PayloadBlock {
	// i2pd uses signed arithmetic here: `int keyID = m_NextReceiveRatchet->keyID - 1;`
	// followed by `if (newKey) keyID++;`. Keeping it signed is what makes the
	// first reply carry key ID 0 (0 - 1 + 1) rather than 1, which is what the
	// spec's flow requires ("Next Key, reverse, with key #0").
	keyID := int32(dir.keyID) - 1
	if dir.newKey {
		keyID++
	}
	var pub *[32]byte
	if dir.newKey {
		p := dir.ourPub
		pub = &p
	}
	return NewNextKeyBlock(uint16(keyID), pub, true, false)
}

// receiveTagSetID computes the tag set ID for the inbound direction after a
// forward block. Spec ref: ecies.md §"KEY AND TAG SET IDS" - "the tag set number
// is (1 + sender key id + receiver key id)". i2pd expresses the same invariant
// as DHRatchet::GetReceiveTagSetID(): newKey ? 2*keyID+1 : 2*keyID.
func (d *dhDirection) receiveTagSetID() uint16 {
	if d.newKey {
		return 2*d.keyID + 1
	}
	return 2 * d.keyID
}
