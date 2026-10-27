package ratchet

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// fillRecvKeyCache pre-derives ES message keys for counters in [session.recvFillMark, upTo)
// and stores them in session.recvKeyCache.  The receiving symmetric ratchet is advanced
// once per counter, so the chain key stays in sync with the sender's sending chain.
//
// Must be called with session.mu held.
// Returns an error if RecvSymmetricRatchet is nil rather than silently falling back to
// the send-direction SymmetricRatchet, which would permanently desynchronise outgoing crypto.
// Spec ref: ecies.rst §"Existing Session" — symmetric ratchet advances once per message.
func fillRecvKeyCache(session *Session, upTo uint32) error {
	flog("fillRecvKeyCache", logger.Fields{"up_to": upTo, "fill_mark": session.recvFillMark}).Debug("pre-deriving recv message keys")
	recvRatchet := session.RecvSymmetricRatchet
	if recvRatchet == nil {
		return oops.Errorf("RecvSymmetricRatchet is nil: session ratchet state is uninitialised; " +
			"cannot derive recv keys without a valid recv ratchet")
	}
	for session.recvFillMark < upTo {
		key, _, err := recvRatchet.DeriveMessageKeyAndAdvance(session.recvFillMark)
		if err != nil {
			return oops.Wrapf(err, "failed to pre-derive recv key for counter %d", session.recvFillMark)
		}
		session.recvKeyCache[session.recvFillMark] = key
		session.recvFillMark++
	}
	return nil
}

// zeroAndClearMap zeroes the 32-byte value for every key in m, then returns a
// fresh empty map. Used to securely discard pre-derived ratchet key caches while
// preventing recovery from memory dumps (forward-secrecy requirement).
func zeroAndClearMap(m map[uint32][32]byte) map[uint32][32]byte {
	if m == nil {
		return make(map[uint32][32]byte)
	}
	for counter := range m {
		var zeroKey [32]byte
		m[counter] = zeroKey
	}
	return make(map[uint32][32]byte)
}

// resetRecvWindow reinitialises the receive-window fields after an NSR replaces
// the session ratchet state.  Must be called with session.mu held.
func resetRecvWindow(session *Session) {
	flog("resetRecvWindow").Debug("reinitialising receive-window fields")
	// 0-based, matching the ES counter rule in newSession (see session.go).
	session.recvWindowBase = 0
	session.recvFillMark = 0
	session.nextRecvTagCounter = 0
	// The inbound tag index is tagset-local (§"4b) Session Tag Ratchet"), so it
	// restarts with the window.
	session.usedRecvTags = 0
	session.recvKeyCache = zeroAndClearMap(session.recvKeyCache)
}

// fillPrevRecvKeyCache pre-derives message keys for the retained previous
// inbound tagset's window. Mirrors fillRecvKeyCache for s.prevRecv.
//
// Spec ref: ecies.md §"DH RATCHET MESSAGE FLOW" - the receiver keeps listening
// on the old tagset for ~3 minutes, which requires its key chain too.
//
// Must be called with session.mu held.
func (p *prevRecvTagset) fillKeyCache(session *Session, upTo uint32) error {
	if p.symRatchet == nil {
		return oops.Errorf("previous tagset has no receiving symmetric ratchet")
	}
	if p.keyCache == nil {
		p.keyCache = make(map[uint32][32]byte)
	}
	for p.fillMark < upTo {
		key, _, err := p.symRatchet.DeriveMessageKeyAndAdvance(p.fillMark)
		if err != nil {
			return oops.Wrapf(err, "failed to pre-derive previous-tagset recv key for counter %d", p.fillMark)
		}
		p.keyCache[p.fillMark] = key
		p.fillMark++
	}
	return nil
}

// trimRecvWindowByPN deletes the pre-derived message keys and tags of the
// PREVIOUS inbound tag set whose counters are higher than the PN value received
// in a Message Number block.
//
// ecies.md §"Message Numbers": "If the message contains a Message Number block
// with a PN value, the recipient can delete any tags higher than that value in
// the previous tag set, while retaining skipped tags from the previous tag set in
// case the skipped messages arrive later." §"Block Specifications" ->
// §"Message Numbers" states the same rule and its rationale: "PN :: 2 bytes big
// endian. The index of the last tag sent in the previous tag set … Receiver may
// immediately delete tags higher than PN from the previous tag set."
//
// PN is the peer's high-water mark for that tag set, so a counter above it can
// never arrive; every counter at or below it must be kept, because a skipped
// message with that counter may still turn up within the retention window.
//
// The keys live in the retired tag sets (Session.retiredRecv), not the live
// recvKeyCache: archiveRecvTagset moves the superseded window there, and the
// live cache holds only current-tagset keys, which this rule must never touch.
// Trimming the live cache instead — as this function previously attempted with a
// predicate that could not be satisfied — made the whole rule a no-op.
//
// This is safe to call from outside session.mu — it acquires the lock itself.
func trimRecvWindowByPN(session *Session, pn uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()

	pn32 := uint32(pn)
	trimmed := 0

	for _, retired := range session.retiredRecv {
		for counter := range retired.keyCache {
			if counter > pn32 {
				var zeroKey [32]byte
				retired.keyCache[counter] = zeroKey
				delete(retired.keyCache, counter)
				trimmed++
			}
		}
		// The tags above PN are deleted with their keys: they can no longer be
		// matched to a counter, so leaving them registered would only keep
		// dead entries in the manager's tag index.
		if len(retired.tagCounter) == 0 {
			continue
		}
		for tag, counter := range retired.tagCounter {
			if counter > pn32 {
				delete(retired.tagCounter, tag)
				retired.tags = removeTag(retired.tags, tag)
			}
		}
	}

	if trimmed > 0 {
		flog("trimRecvWindowByPN", logger.Fields{"pn": pn, "trimmed": trimmed}).Debug("Trimmed previous-tagset keys above PN")
	}
}

// removeTag returns tags without the given entry, preserving order.
func removeTag(tags [][8]byte, tag [8]byte) [][8]byte {
	if len(tags) == 0 {
		return tags
	}
	out := tags[:0]
	for _, t := range tags {
		if t != tag {
			out = append(out, t)
		}
	}
	return out
}
