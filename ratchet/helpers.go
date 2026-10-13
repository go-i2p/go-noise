package ratchet

import (
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// sessionKeys holds the keys derived from the Noise handshake chain key.
// chainKey is the final Noise handshake chain key (input to split).
// kAB and kBA are the directional keys from the spec split() operation:
//
//	keydata = HKDF(chainKey, ZEROLEN, "", 64)
//	k_ab = keydata[0:32]  (initiator → responder)
//	k_ba = keydata[32:64] (responder → initiator)
type sessionKeys struct {
	chainKey [32]byte
	kAB      [32]byte
	kBA      [32]byte
}

const (
	// DHRatchetInterval is the number of messages sent before the DH ratchet
	// rotates. A DH ratchet rotation uses X25519 to derive a fresh set of
	// keys, which is what gives the scheme forward secrecy.
	DHRatchetInterval = 50

	// MaxConsecutiveDHFailures is the maximum number of consecutive DH
	// ratchet failures before the session is considered degraded and should
	// be reset.
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
	// Each message in a session carries a counter; when the counter reaches
	// this value, the session must be ratcheted to derive fresh keys.
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

	flog("prependPendingNextKeys", logger.Fields{"next_key_blocks": len(nextKeyBlocks), "ack_blocks": len(ackBlocks), "control_bytes": controlSize, "original_size": len(plaintext), "combined_size": len(combined)}).Debug("Prepended control blocks to ES payload")

	return combined, nil
}

// lookupLockedSession finds a session by its tag and acquires the session lock.
// The caller MUST defer session.mu.Unlock() after a successful call. This
// consolidates the repeated session-lookup-and-lock pattern used by
// ProcessReceivedNextKey and ProcessIncomingDHRatchet.
func (sm *SessionManager) lookupLockedSession(sessionTag [8]byte) (*Session, error) {
	flog("lookupLockedSession", logger.Fields{"session_tag": fmt.Sprintf("%x", sessionTag)}).Debug("looking up session by tag")
	sm.mu.RLock()
	session, _, exists := sm.lookupSessionTaggedLocked(sessionTag)
	sm.mu.RUnlock()

	if !exists {
		return nil, oops.Errorf("no session found for tag %x", sessionTag)
	}

	session.mu.Lock()
	return session, nil
}

// lookupSessionTaggedLocked looks up a session and optional counter hint for a
// session tag. The caller must hold sm.mu (read or write) while calling this.
func (sm *SessionManager) lookupSessionTaggedLocked(tag [8]byte) (*Session, *uint32, bool) {
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil, nil, false
	}

	if counter, hasCounter := sm.tagCounterIndex[tag]; hasCounter {
		counterHint := counter
		return session, &counterHint, true
	}

	return session, nil, true
}
