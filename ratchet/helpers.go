package ratchet

import (
	"fmt"
	"time"

	"github.com/go-i2p/crypto/ratchet"
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
	// hkdfInfoDHRatchetStep is the HKDF info string for the DH initialization KDF.
	// Used to derive directional chain keys from a root key.
	// Spec ref: ecies.rst §"DH INITIALIZATION KDF" — HKDF(rootKey, k, "KDFDHRatchetStep", 64).
	hkdfInfoDHRatchetStep = "KDFDHRatchetStep"

	// hkdfInfoTagAndKeyGenKeys is the HKDF info string for deriving session tag
	// and symmetric key chain keys from a chain key after DH ratchet.
	// Spec ref: ecies.rst §"DH INITIALIZATION KDF" — HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64).
	hkdfInfoTagAndKeyGenKeys = "TagAndKeyGenKeys"

	// tagWindowMin is the minimum (initial) number of pre-generated tags per
	// session. The window grows dynamically as messages are consumed.
	// Spec ref: ecies.rst §"Parameters" — ES tagset 0 size: tsmin=24.
	tagWindowMin = 24

	// tagWindowMax is the maximum number of pre-generated tags per session.
	// Spec ref: ecies.rst §"Parameters" — ES tagset 0 size: tsmax=160.
	// Java I2P uses 320 (MAX_RCV_WINDOW_ES); we follow the spec value of 160.
	tagWindowMax = 160

	// tagWindowSize is the initial ES tag window size (alias for tagWindowMin,
	// kept for backward compatibility with existing tests).
	tagWindowSize = tagWindowMin

	// nextKeyTagThreshold is the tag number within a tagset at which the
	// sender must initiate a NextKey exchange.
	// Spec ref: ecies.rst §"Parameters" — "Send next key at tag: 4096".
	// Java I2P: LOW = 65535 - 4096 = 61439; getNextKey() triggers when
	// remaining() <= LOW, i.e. _lastTag >= 4096.
	nextKeyTagThreshold = 4096

	// MaxMessageNumber is the maximum AEAD message number per the spec,
	// inclusive: numbers 0..65535 are valid, so a tag set carries up to 65536
	// messages, and only a counter beyond this value requires a DH ratchet.
	// This aliases crypto/ratchet's constant rather than restating the value,
	// so the two implementations cannot drift apart.
	MaxMessageNumber = ratchet.MaxMessagesPerTagset

	// recvWindowSize is the number of ES message counters we pre-derive keys for
	// and accept out-of-order. Fixed at 128 per I2P spec ecies.rst §Existing Session.
	recvWindowSize = 128

	// maxPaddingSize is the maximum padding block size in bytes.
	// Spec ref: ecies.rst §"Parameters" — "Padding default is 0-15 bytes".
	// Java I2P: PaddingBlock takes arbitrary size (no bound in class).
	// i2pd: GetNextPaddingSize() returns rand() % 16 (0-15).
	maxPaddingSize = 15
)

// Session timeout constants per ecies.rst §"Parameters":
//   - ES tagset timeout (sender): 8 minutes
//   - ES tagset timeout (receiver): 10 minutes
//   - NSR tagset timeout (receiver): 3 minutes
//   - Remove previous ES tagset after: 3 minutes
//   - Replace session if NS received after: 3 minutes
//
// Java I2P reference (RatchetSKM.java):
//   - SESSION_TAG_DURATION_MS = 8 min (outbound/sender ES)
//   - SESSION_LIFETIME_MAX_MS = 10 min (inbound/receiver ES)
//   - SESSION_PENDING_DURATION_MS = 3 min (NSR)
//   - SESSION_REPLACE_AGE = 2 min (spec says 3; Java uses 2)
//
// i2pd reference (ECIESX25519AEADRatchetSession.h):
//   - ECIESX25519_SEND_EXPIRATION_TIMEOUT = 480s (8 min)
//   - ECIESX25519_RECEIVE_EXPIRATION_TIMEOUT = 600s (10 min)
//   - ECIESX25519_PREVIOUS_TAGSET_EXPIRATION_TIMEOUT = 180s (3 min)
//   - ECIESX25519_RESTART_TIMEOUT = 120s (2 min, matches Java)

const (
	// senderESTimeout is the inactivity timeout for outbound (sender) ES sessions.
	// Spec ref: ecies.rst §"Parameters" — "ES tagset timeout (sender): 8 minutes".
	senderESTimeout = 8 * time.Minute

	// receiverESTimeout is the inactivity timeout for inbound (receiver) ES sessions.
	// Spec ref: ecies.rst §"Parameters" — "ES tagset timeout (receiver): 10 minutes".
	receiverESTimeout = 10 * time.Minute

	// nsrPendingTimeout is the timeout for sessions waiting for NSR completion.
	// Spec ref: ecies.rst §"Parameters" — "NSR tagset timeout (receiver): 3 minutes".
	nsrPendingTimeout = 3 * time.Minute

	// sessionReplaceAge is the minimum age of an existing inbound session before
	// a new NS from the same peer will replace it. If the session is younger
	// than this, the new NS is rejected to prevent race-condition resets.
	// Spec ref: ecies.rst §"Parameters" — "Replace session if NS received after: 3 minutes".
	// Java I2P uses 2 min (SESSION_REPLACE_AGE); i2pd uses 2 min (RESTART_TIMEOUT).
	// We follow the spec value of 3 minutes.
	sessionReplaceAge = 3 * time.Minute
)

// targetTagWindowSize computes the desired tag window size based on the number
// of tags consumed in the current tagset. The window grows linearly with usage,
// capped at tagWindowMax.
//
// Spec ref: ecies.md §"Parameters" — "Tagset look ahead of tag N: min(tsmax, tsmin + N/4)".
//
// The two references differ from the dev spec here: Java I2P
// (RatchetTagSet.addTags, line 431) grows with N/2 and i2pd grows with 2N.
// The dev spec is authoritative for this implementation, so N/4 is used; the
// divergence is recorded as an open question in the compliance report because
// it only changes how eagerly a receiver pre-derives tags, not any wire value.
func targetTagWindowSize(usedTags uint32) int {
	growth := usedTags / 4
	size := tagWindowMin + int(growth)
	if size > tagWindowMax {
		size = tagWindowMax
	}
	return size
}

func prependPendingNextKeys(session *Session, plaintext []byte) ([]byte, error) {
	nextKeyBlocks := session.GetPendingNextKeys()
	ackBlocks := session.GetPendingAcks()

	pendingBlocks := append(nextKeyBlocks, ackBlocks...)
	if len(pendingBlocks) == 0 {
		return plaintext, nil
	}

	// Enforce the spec's block ordering rules on the control-block prefix, which
	// bypasses PayloadBuilder.validate():
	//   - ecies.md §"5) Payload" -> §"Block Ordering Rules": "There may be up to
	//     two Next Key blocks in a single frame" - one forward and one reverse.
	//   - §"Next DH Ratchet Public Key": "a frame will contain two Next Key
	//     blocks, one for the forward key and one for the reverse key".
	// The blocks are derived from the two direction flags, so at most two can
	// exist; assert it rather than trusting the invariant silently.
	if len(nextKeyBlocks) > 2 {
		return nil, oops.Errorf("payload would carry %d NextKey blocks, maximum is 2 (ecies.md §Block Ordering Rules)", len(nextKeyBlocks))
	}
	for i := 1; i < len(nextKeyBlocks); i++ {
		prev, err := nextKeyBlocks[i-1].NextKey()
		if err != nil {
			return nil, oops.Wrapf(err, "malformed queued NextKey block")
		}
		cur, err := nextKeyBlocks[i].NextKey()
		if err != nil {
			return nil, oops.Wrapf(err, "malformed queued NextKey block")
		}
		if prev.Reverse == cur.Reverse {
			return nil, oops.Errorf("payload would carry two %s NextKey blocks, maximum is one per direction",
				map[bool]string{true: "reverse", false: "forward"}[cur.Reverse])
		}
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
