package ratchet

// recv_tagset.go implements the inbound tag-set retention rule from ecies.md
// §"4a) DH Ratchet" -> §"DH RATCHET MESSAGE FLOW":
//
//	"After the DH ratchet is complete for an inbound tagset, and a new inbound
//	tagset is created, the receiver should listen for tags in both tagsets, and
//	delete the old tagset after a short time, about 3 minutes."
//
// and §"Parameters": "Remove previous ES tagset after: 3 minutes".
//
// Both references implement exactly this two-tagset window:
//
//	i2pd  ReceiveRatchetTagSet::Expire() (ECIESX25519AEADRatchetSession.cpp:455)
//	      -> m_PreviousTagsets.push_back(...), ECIESX25519_PREVIOUS_TAGSET_EXPIRATION_TIMEOUT = 180s
//	Java  RatchetSKM keeps oldTagSets / oldTagSetsTime with a 3-minute expiry.
//
// Without it, ES messages already in flight on the previous inbound tagset are
// dropped the instant a receiving DH ratchet lands, which loses traffic on every
// rekey (audit finding R-07).

import (
	"time"

	"github.com/go-i2p/crypto/ratchet"
)

// previousTagsetExpiry is the grace period for which the replaced inbound
// tagset keeps being accepted.
// Spec ref: ecies.md §"Parameters" - "Remove previous ES tagset after: 3 minutes".
const previousTagsetExpiry = 3 * time.Minute

// prevRecvTagset is a replaced inbound tagset kept alive for previousTagsetExpiry.
// altTagsetList is an ordered list of retained inbound tag sets, oldest first.
type altTagsetList []*prevRecvTagset

type prevRecvTagset struct {
	tagSetID uint16
	// expiresAt is when the tagset must be deleted.
	expiresAt time.Time
	// tagRatchet / symRatchet are the replaced inbound chains.
	tagRatchet *ratchet.TagRatchet
	symRatchet *ratchet.SymmetricRatchet
	// tagCounter maps each still-unconsumed tag of this tagset to its ES
	// message counter. The counter is tagset-local (ecies.md §"4b) Session Tag
	// Ratchet": "'N', the message number of the message in the current chain").
	tagCounter map[[8]byte]uint32
	// tags are the still-advertised tags of this tag set. They remain in the
	// manager's tag index so the peer can keep using the old tag set while it
	// has not yet received our reverse key.
	tags [][8]byte
	// windowBase / fillMark / keyCache mirror the primary inbound receive
	// window for this tagset.
	windowBase uint32
	fillMark   uint32
	keyCache   map[uint32][32]byte
}

// maxRetainedRecvTagsets bounds how many superseded inbound tag sets a session
// keeps. The spec needs one for a rekey ("listen for tags in both tagsets"), and
// a responder that has answered several New Session messages needs one per reply
// (§"Multiple NS Messages"). The cap prevents unbounded growth under an NS flood
// while staying generous for the two legitimate uses.
const maxRetainedRecvTagsets = 8

// archiveRecvTagset parks the session's current inbound tagset so its tags keep
// being accepted after a new tagset is installed.
//
// Spec ref: ecies.md §"DH RATCHET MESSAGE FLOW" - "the receiver should listen
// for tags in both tagsets, and delete the old tagset after a short time, about
// 3 minutes"; §"Multiple NS Messages" - each NS/NSR pair has its own tagset.
//
// Must be called with session.mu held.
func (s *Session) archiveRecvTagset() {
	if s.RecvTagRatchet == nil || s.RecvSymmetricRatchet == nil {
		return
	}
	retired := &prevRecvTagset{
		tagSetID:   s.recvTagSetID,
		expiresAt:  time.Now().Add(previousTagsetExpiry),
		tagRatchet: s.RecvTagRatchet,
		symRatchet: s.RecvSymmetricRatchet,
		tagCounter: s.recvTagCounter,
		tags:       s.pendingTags,
		windowBase: s.recvWindowBase,
		fillMark:   s.recvFillMark,
		keyCache:   s.recvKeyCache,
	}
	s.retiredRecv = s.retiredRecv.append(retired, maxRetainedRecvTagsets)

	// Move, don't copy: the session must start the new tag set with its own
	// empty window so a subsequent resetRecvWindow() cannot zero the archived
	// key cache the retired tag set still needs to decrypt in-flight messages.
	s.recvTagCounter = nil
	s.pendingTags = nil
	s.recvWindowBase = 0
	s.recvFillMark = 0
	s.recvKeyCache = nil
}

// expireRecvTagsets drops every retained inbound tagset whose grace period has
// elapsed, unregistering its tags from the manager's tag index.
//
// Must be called with session.mu held. sm.mu must be held for writing by the
// caller when tags are removed from the index.
func (s *Session) expireRecvTagsets(unregister func([8]byte)) {
	if len(s.retiredRecv) == 0 {
		return
	}
	now := time.Now()
	kept := s.retiredRecv[:0]
	for _, retired := range s.retiredRecv {
		if now.Before(retired.expiresAt) {
			kept = append(kept, retired)
			continue
		}
		for tag := range retired.tagCounter {
			unregister(tag)
		}
	}
	s.retiredRecv = kept
}

// append adds a retired tagset. When the list exceeds max, the oldest entries
// are marked immediately expired so the next expiry pass unregisters their tags
// and reclaims them - bounding growth under an NS flood without leaking index
// entries.
func (l altTagsetList) append(t *prevRecvTagset, max int) altTagsetList {
	l = append(l, t)
	if over := len(l) - max; over > 0 {
		for _, old := range l[:over] {
			if old.expiresAt.IsZero() {
				continue
			}
			old.expiresAt = time.Time{}
		}
	}
	return l
}
