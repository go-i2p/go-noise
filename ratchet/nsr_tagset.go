package ratchet

// nsr_tagset.go implements the New Session Reply tag set from ecies.md
// §"1g) New Session Reply format" -> §"KDF for Reply TagSet".
//
// The spec permits several replies for one New Session ("One or more New Session
// Replies may be sent in response to a single New Session message. Each reply is
// prepended by a tag, which is generated from a TagSet for the session"), which
// means the tags must come from ONE ratchet per NS and advance from reply to
// reply. Re-deriving a fresh ratchet for each reply — as this package previously
// did — makes every reply carry the same tag, so a peer consuming the second
// entry emits a tag its counterpart cannot route, and because the tag is mixed
// into the Noise transcript (§"KDF for Reply Key Section Encrypted Contents":
// "MixHash(tag)") the reply also fails AEAD.

import (
	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
)

// nsrTagsetMin/nsrTagsetMax are the NSR tag set bounds.
// Spec ref: ecies.md §"Parameters" — "NSR tagset size: 12 tsmin and tsmax".
// Unlike the ES tag sets they do not grow with N, so both bounds are 12.
const (
	nsrTagsetMin = 12
	nsrTagsetMax = 12
)

// nsrTagset is the tag ratchet for the replies to a single New Session message,
// plus the entries generated so far.
//
// It is owned by the noiseHandshakeState of that NS, so two NS messages from the
// same peer get two independent sets — matching §"Multiple NS Messages": "Each
// NSR uses the handshake state and tagset corresponding to the incoming NS."
type nsrTagset struct {
	ratchet *ratchet.TagRatchet
	// generated is the number of tags taken from the ratchet so far; it is also
	// the index of the next one, i.e. the tag set's LAST_INDEX + 1.
	generated int
}

// newNSRTagset initializes the NSR tag set from the New Session chain key.
//
// Spec ref: ecies.md §"KDF for Reply TagSet":
//
//	tagsetKey = HKDF(chainKey, ZEROLEN, "SessionReplyTags", 32)
//	tagset_nsr = DH_INITIALIZE(chainKey, tagsetKey)
func newNSRTagset(chainKey []byte) (*nsrTagset, error) {
	tagRatchet, err := deriveNSRTagRatchet(chainKey)
	if err != nil {
		return nil, err
	}
	return &nsrTagset{ratchet: tagRatchet}, nil
}

// nextTag returns the next NSR tag, extending the set by one entry when it is
// exhausted, per ecies.md §"TAGSET" -> GET_NEXT_ENTRY(): "EXTEND(1) is called if
// there are no remaining TAGSET_ENTRIES."
//
// The set is capped at nsrTagsetMax: once that many replies have been tagged for
// one NS, the peer is not routing our replies and generating more would grow the
// set past the spec's tsmax.
func (t *nsrTagset) nextTag() ([8]byte, error) {
	if t.ratchet == nil {
		return [8]byte{}, oops.Code("NSR_TAGSET_MISSING").In("ratchet").
			Errorf("NSR tag set has no tag ratchet")
	}
	if t.generated >= nsrTagsetMax {
		return [8]byte{}, oops.
			Code("NSR_TAGSET_EXHAUSTED").
			In("ratchet").
			With("generated", t.generated).
			With("max", nsrTagsetMax).
			Errorf("NSR tag set exhausted after %d replies (tsmax %d)", t.generated, nsrTagsetMax)
	}
	tag, err := t.ratchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Wrapf(err, "failed to generate NSR tag")
	}
	t.generated++
	return tag, nil
}

// fillTo generates entries until the set covers index, so that a tag the peer
// presents can be recognized. This is the receiving-side rule from ecies.md
// §"TAGSET" -> GET_ENTRY(tag): "If there are few TAGSET_ENTRIES remaining,
// EXTEND(n) is called."
//
// Returns the tags for indices [0, index] inclusive. Already-generated entries
// are not re-derived — the ratchet only moves forward.
func (t *nsrTagset) fillTo(index int) ([][8]byte, error) {
	if t.ratchet == nil {
		return nil, oops.Code("NSR_TAGSET_MISSING").In("ratchet").
			Errorf("NSR tag set has no tag ratchet")
	}
	if index >= nsrTagsetMax {
		return nil, oops.
			Code("NSR_TAG_INDEX_OUT_OF_RANGE").
			In("ratchet").
			With("index", index).
			With("max", nsrTagsetMax).
			Errorf("NSR tag index %d is outside the tag set (tsmax %d)", index, nsrTagsetMax)
	}
	for t.generated <= index {
		if _, err := t.nextTag(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// peekTags returns the next count tags without committing them, generating the
// set forward as needed. Used by the initiator to advertise the whole expected
// reply window up front, so any of the peer's replies can be routed.
//
// The returned tags are the entries at indices [generated, generated+count);
// calling peekTags again after that yields the following ones, so a caller that
// both registers a window and later consumes from the same set must use advance().
func (t *nsrTagset) peekTags(count int) ([][8]byte, error) {
	if t.ratchet == nil {
		return nil, oops.Code("NSR_TAGSET_MISSING").In("ratchet").
			Errorf("NSR tag set has no tag ratchet")
	}
	if count <= 0 {
		return nil, nil
	}
	if t.generated+count > nsrTagsetMax {
		count = nsrTagsetMax - t.generated
	}
	if count <= 0 {
		return nil, nil
	}
	tags := make([][8]byte, 0, count)
	for i := 0; i < count; i++ {
		tag, err := t.nextTag()
		if err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// generated returns how many entries the set has produced.
func (t *nsrTagset) count() int { return t.generated }

// zero clears the tag ratchet's key material.
func (t *nsrTagset) zero() {
	if t == nil {
		return
	}
	if t.ratchet != nil {
		t.ratchet.Zero()
	}
	t.generated = 0
}
