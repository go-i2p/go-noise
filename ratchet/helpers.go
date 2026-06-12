package ratchet

import (
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// sessionKeys holds the cryptographic keys derived from ECIES key exchange.
type sessionKeys struct {
	rootKey [32]byte
	symKey  [32]byte
	tagKey  [32]byte
}

const (
	// DHRatchetInterval is the number of messages between DH ratchet rotations.
	DHRatchetInterval = 50

	// MaxConsecutiveDHFailures is the maximum consecutive DH ratchet failures
	// before the session is considered degraded and should be reset.
	MaxConsecutiveDHFailures = 3

	// hkdfInfoDHRatchetStep is the HKDF info string for the DH initialization KDF.
	// Used to derive directional chain keys from a root key.
	// Spec ref: ratchet.md §"DH INITIALIZATION KDF" — HKDF(rootKey, k, "KDFDHRatchetStep", 64).
	hkdfInfoDHRatchetStep = "KDFDHRatchetStep"

	// hkdfInfoTagAndKeyGenKeys is the HKDF info string for deriving session tag
	// and symmetric key chain keys from a chain key after DH ratchet.
	// Spec ref: ratchet.md §"DH INITIALIZATION KDF" — HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64).
	hkdfInfoTagAndKeyGenKeys = "TagAndKeyGenKeys"

	// tagWindowSize is the number of pre-generated tags per session.
	// Spec ref: ratchet.md §"Parameters" — ES tagset 0 size: tsmin=24.
	tagWindowSize = 24

	// MaxMessageNumber is the maximum AEAD message number per the spec.
	// When reached, the session must be ratcheted. Spec ref: ratchet.md
	// §"AEAD (ChaChaPoly)" — "Maximum value is 65535."
	MaxMessageNumber = 65535

	// recvWindowSize is the number of ES message counters we pre-derive keys for
	// and accept out-of-order. Fixed at 128 per I2P spec ratchet.md §Existing Session.
	recvWindowSize = 128
)

// zero32 overwrites a 32-byte key with zeros. This should be called before
// discarding any cryptographic key material to prevent recovery from memory
// dumps or core files. The ratchet's forward secrecy guarantees rely on
// securely destroying keys after use.
func prependPendingNextKeys(session *Session, plaintext []byte) ([]byte, error) {
	nextKeyBlocks := session.GetPendingNextKeys()
	ackBlocks := session.GetPendingAcks()

	pendingBlocks := append(nextKeyBlocks, ackBlocks...)
	if len(pendingBlocks) == 0 {
		return plaintext, nil
	}

	// Calculate the total size needed for control block headers + data.
	controlSize := 0
	for _, block := range pendingBlocks {
		controlSize += block.SerializeSize()
	}

	// Build a combined payload: [control blocks...] + [original plaintext].
	combined := make([]byte, controlSize+len(plaintext))
	offset := 0
	for _, block := range pendingBlocks {
		n, err := block.Serialize(combined[offset:])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize control block (type %d)", block.Type)
		}
		offset += n
	}
	copy(combined[offset:], plaintext)

	log.WithFields(logger.Fields{
		"pkg":             "ratchet",
		"func":            "prependPendingNextKeys",
		"next_key_blocks": len(nextKeyBlocks),
		"ack_blocks":      len(ackBlocks),
		"control_bytes":   controlSize,
		"original_size":   len(plaintext),
		"combined_size":   len(combined),
	}).Debug("Prepended control blocks to ES payload")

	return combined, nil
}

// lookupLockedSession finds a session by its tag and acquires the session lock.
// The caller MUST defer session.mu.Unlock() after a successful call. This
// consolidates the repeated session-lookup-and-lock pattern used by
// ProcessReceivedNextKey and ProcessIncomingDHRatchet.
func (sm *SessionManager) lookupLockedSession(sessionTag [8]byte) (*Session, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "lookupLockedSession", "session_tag": fmt.Sprintf("%x", sessionTag)}).Debug("looking up session by tag")
	sm.mu.RLock()
	session, exists := sm.tagIndex[sessionTag]
	sm.mu.RUnlock()

	if !exists {
		return nil, oops.Errorf("no session found for tag %x", sessionTag)
	}

	session.mu.Lock()
	return session, nil
}
