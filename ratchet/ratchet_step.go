package ratchet

import (
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// Returns an error if the message counter exceeds MaxMessageNumber (65535).
// Per the ECIES-Ratchet spec the maximum usable message number is 65535
// inclusive ("Maximum value is 65535. ... Higher values must never be used"),
// so the guard rejects only counters strictly greater than MaxMessageNumber.
func advanceRatchets(session *Session) (messageKey [32]byte, sessionTag [8]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "advanceRatchets", "message_counter": session.MessageCounter}).Debug("advancing symmetric and tag ratchets")
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

// attemptDHRatchetRotation checks whether a DH ratchet step is due.
func attemptDHRatchetRotation(session *Session) error {
	session.dhRatchetCounter++
	if session.dhRatchetCounter < DHRatchetInterval {
		return nil
	}

	if err := performDHRatchetStep(session); err != nil {
		session.consecutiveDHFailures++
		if session.consecutiveDHFailures >= MaxConsecutiveDHFailures {
			return oops.Wrapf(err,
				"DH ratchet failed %d consecutive times (max %d), forward secrecy compromised",
				session.consecutiveDHFailures, MaxConsecutiveDHFailures)
		}
		log.WithFields(logger.Fields{"pkg": "ratchet", "func": "attemptDHRatchetRotation", "consecutive_failures": session.consecutiveDHFailures}).WithError(err).
			Warn("DH ratchet rotation failed, continuing with symmetric ratchet")
	} else {
		session.dhRatchetCounter = 0
		session.consecutiveDHFailures = 0
	}
	return nil
}

func performDHRatchetStep(session *Session) error {
	// Refuse the step if the send key ID is already at the maximum.
	// The session must be replaced once all tag sets are exhausted.
	// Spec ref: ratchet.md §"Key and Tag Set IDs".
	if session.sendKeyID >= MaxKeyID {
		return oops.Errorf(
			"send key ID %d has reached maximum %d, session must be replaced",
			session.sendKeyID, MaxKeyID,
		)
	}

	newPubKey, err := session.DHRatchet.GenerateNewKeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate new ephemeral key pair")
	}

	if err := applySendRatchetKeys(session); err != nil {
		return err
	}

	session.newEphemeralPub = &newPubKey

	// Queue a NextKey block for the next outgoing message.
	// Even-numbered tag sets: sender sends new key, requests reverse.
	// Odd-numbered tag sets: sender reuses key, requests reverse.
	// For the first rotation (sendKeyID == 0): always send the key and request reverse.
	requestReverse := true
	nextKeyBlock := NewNextKeyBlock(session.sendKeyID, &newPubKey, false, requestReverse)
	session.pendingNextKeys = append(session.pendingNextKeys, nextKeyBlock)
	session.awaitingReverseKey = true

	// Advance the send key ID now that the NextKey block is committed.
	// The block carries the old ID (the peer uses it to key the reverse), and
	// subsequent outgoing messages belong to the new tag set.
	// Safe: guarded >= MaxKeyID above.
	session.sendKeyID++

	log.WithFields(logger.Fields{
		"pkg":             "ratchet",
		"func":            "performDHRatchetStep",
		"message_counter": session.MessageCounter,
		"send_key_id":     session.sendKeyID,
		"new_pub_key":     fmt.Sprintf("%x", newPubKey[:8]),
	}).Debug("DH ratchet rotation completed, NextKey block queued")

	return nil
}
