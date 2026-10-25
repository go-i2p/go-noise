package ratchet

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// Returns an error if the message counter exceeds MaxMessageNumber (65535).
// Per the ECIES-Ratchet spec the maximum usable message number is 65535
// inclusive ("Maximum value is 65535. ... Higher values must never be used"),
// so the guard rejects only counters strictly greater than MaxMessageNumber.
func advanceRatchets(session *Session) (messageKey [32]byte, sessionTag [8]byte, err error) {
	flog("advanceRatchets", logger.Fields{"message_counter": session.MessageCounter}).Debug("advancing symmetric and tag ratchets")
	if session.MessageCounter > MaxMessageNumber {
		return [32]byte{}, [8]byte{}, oops.Errorf(
			"message number %d exceeds maximum %d, session must be ratcheted",
			session.MessageCounter, MaxMessageNumber,
		)
	}

	if err := attemptDHRatchetRotation(session); err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	messageKey, err = deriveMessageKey(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	sessionTag, err = generateAndTrackSessionTag(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	return messageKey, sessionTag, nil
}

// attemptDHRatchetRotation initiates a NextKey exchange when the outbound tag
// set is nearly exhausted.
//
// Spec ref: ecies.md §"Parameters" - "Send next key at tag: 4096";
// §"KEY AND TAG SET IDS" - "When a tag set is almost exhausted, the tag set
// sender must initiate a NextKey exchange."
//
// i2pd (ECIESX25519AEADRatchetSession.cpp:750) applies the identical rule
// immediately after encrypting an ES message:
//
//	if (index >= ECIESX25519_TAGSET_MAX_NUM_TAGS && !m_SendForwardKey)
//		NewNextSendRatchet ();
//
// The exchange is initiated at most once per tag set: while the forward block is
// still owed we must not ratchet again, or the peer would see a key ID jump.
//
// Note this replaces the previous fixed every-50-messages schedule. The spec
// does permit implementation-dependent ratchet frequency (§"4a) DH Ratchet"),
// but it makes the near-exhaustion trigger mandatory, and a cadence the peer
// cannot predict makes the tag-set/key-ID progression in §"KEY AND TAG SET IDS"
// impossible to reproduce.
func attemptDHRatchetRotation(session *Session) error {
	if session.usedTags < nextKeyTagThreshold {
		return nil
	}
	if session.sendDir != nil && session.sendDir.owed {
		return nil // forward block already queued, waiting for the peer's key
	}
	if session.sendKeyID >= MaxKeyID {
		// Spec ref: ecies.md §"KEY AND TAG SET IDS" - "The maximum key ID is
		// 32767. ... the tag set sender must initiate a new session".
		return oops.Errorf(
			"send key ID %d has reached maximum %d, session must be replaced",
			session.sendKeyID, MaxKeyID,
		)
	}
	if err := session.prepareSend(); err != nil {
		return oops.Wrapf(err, "failed to initiate NextKey exchange")
	}
	flog("attemptDHRatchetRotation", logger.Fields{"used_tags": session.usedTags, "send_key_id": session.sendKeyID}).
		Debug("Initiated forward NextKey exchange")
	return nil
}
