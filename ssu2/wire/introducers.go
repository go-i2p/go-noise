package wire

import (
	"strconv"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2 introducer publication in RouterAddress options.
//
// Per the I2P SSU2 specification (§Published Router Address) and the i2pd
// reference implementation (RouterInfo.cpp), introducers are published in a
// RouterAddress as a set of indexed options:
//
//	itag<i> = relay tag assigned by the introducer (decimal uint32, non-zero)
//	ih<i>   = introducer router identity hash (I2P Base64 of 32 raw bytes)
//	iexp<i> = introducer registration expiration (decimal seconds since epoch)
//
// where <i> is a zero-based index. A router publishes up to
// MaxPublishedIntroducers introducers so that peers which cannot reach it
// directly (e.g. behind a symmetric NAT) can establish a session through a
// relay. An introducer entry is only valid when its tag is non-zero, its hash
// is present, and (if an expiration is given) it has not yet expired.
const (
	// MaxPublishedIntroducers is the maximum number of SSU2 introducers that
	// may be published in a single RouterAddress per the I2P SSU2 spec.
	MaxPublishedIntroducers = 3

	// maxParsedIntroducerIndex bounds how many introducer indices are scanned
	// when parsing a RouterAddress. i2pd accepts indices 0-9; mirroring that
	// keeps work bounded on adversarial input while staying compatible.
	maxParsedIntroducerIndex = 9

	// introducerHashLen is the length in bytes of an I2P router identity hash.
	introducerHashLen = 32
)

// PublishedIntroducer is a single SSU2 introducer as published in, or parsed
// from, a RouterAddress options map.
type PublishedIntroducer struct {
	// RouterHash is the 32-byte I2P router identity hash of the introducer
	// (the "ih" option, Base64-encoded on the wire).
	RouterHash []byte

	// RelayTag is the relay tag (the "itag" option) assigned to us by the
	// introducer. It must be non-zero to be valid.
	RelayTag uint32

	// ExpiresAt is the introducer registration expiration (the "iexp" option).
	// On the wire it is encoded as whole seconds since the Unix epoch. A zero
	// value means no expiration was published and the entry never expires from
	// the wire format's perspective.
	ExpiresAt time.Time
}

// IsZeroHash reports whether the RouterHash is missing or all-zero, which the
// SSU2 spec treats as an invalid introducer.
func (p PublishedIntroducer) IsZeroHash() bool {
	if len(p.RouterHash) != introducerHashLen {
		return true
	}
	for _, b := range p.RouterHash {
		if b != 0 {
			return false
		}
	}
	return true
}

// IntroducersToRouterAddressOptions encodes introducers into RouterAddress
// option keys (itag<i>, ih<i>, iexp<i>) for publication.
//
// Only valid introducers are published: entries with a zero relay tag or a
// missing/all-zero router hash are skipped (matching i2pd, which omits
// introducers whose tag is zero). At most MaxPublishedIntroducers entries are
// emitted, indexed sequentially from 0. An entry whose RouterHash is present
// but not exactly 32 bytes is a programming error and returns an error rather
// than silently publishing a malformed hash.
//
// The returned map contains only the introducer options; callers merge it into
// the full RouterAddress options map.
func IntroducersToRouterAddressOptions(introducers []PublishedIntroducer) (map[string]string, error) {
	flog("IntroducersToRouterAddressOptions", logger.Fields{"count": len(introducers)}).Debug("Encoding introducers to RouterAddress options")
	options := make(map[string]string)

	idx := 0
	for _, intro := range introducers {
		if idx >= MaxPublishedIntroducers {
			break
		}
		// Skip invalid introducers: a zero tag marks an absent/removed entry.
		if intro.RelayTag == 0 {
			continue
		}
		if len(intro.RouterHash) == 0 {
			continue
		}
		if len(intro.RouterHash) != introducerHashLen {
			return nil, oops.
				Code("INVALID_INTRODUCER_HASH").
				With("len", len(intro.RouterHash)).
				Errorf("introducer router hash must be %d bytes, got %d", introducerHashLen, len(intro.RouterHash))
		}
		if intro.IsZeroHash() {
			continue
		}

		suffix := strconv.Itoa(idx)
		options["itag"+suffix] = strconv.FormatUint(uint64(intro.RelayTag), 10)
		options["ih"+suffix] = i2pbase64.I2PEncoding.EncodeToString(intro.RouterHash)
		// i2pd only writes iexp when a non-zero expiration is set.
		if !intro.ExpiresAt.IsZero() {
			options["iexp"+suffix] = strconv.FormatInt(intro.ExpiresAt.Unix(), 10)
		}
		idx++
	}

	return options, nil
}

// IntroducersFromRouterAddress parses introducer entries from a RouterAddress
// options map, returning them in index order.
//
// Indices 0..maxParsedIntroducerIndex are scanned. For each index:
//   - If none of itag<i>/ih<i>/iexp<i> are present, the index is skipped (gaps
//     are permitted).
//   - If the entry is present but its tag is zero, it is skipped (the spec
//     treats a zero tag as an absent introducer).
//   - Otherwise itag<i> and ih<i> are required and must be well-formed; iexp<i>
//     is optional. A malformed value (non-numeric tag/expiration, invalid
//     Base64 hash, or a hash that is not 32 bytes) returns an error identifying
//     the offending index.
func IntroducersFromRouterAddress(options map[string]string) ([]PublishedIntroducer, error) {
	flog("IntroducersFromRouterAddress").Debug("Parsing introducers from RouterAddress options")
	var result []PublishedIntroducer

	for i := 0; i <= maxParsedIntroducerIndex; i++ {
		suffix := strconv.Itoa(i)
		tagVal, hasTag := options["itag"+suffix]
		hashVal, hasHash := options["ih"+suffix]
		expVal, hasExp := options["iexp"+suffix]

		if !hasTag && !hasHash && !hasExp {
			continue // no entry at this index
		}

		intro, skip, err := parseIntroducerEntry(i, tagVal, hasTag, hashVal, hasHash, expVal, hasExp)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		result = append(result, intro)
	}

	return result, nil
}

// parseIntroducerEntry parses a single indexed introducer entry. It returns
// skip=true for entries that are present but invalid in a way the spec tolerates
// (a zero relay tag), and an error for malformed fields.
func parseIntroducerEntry(index int, tagVal string, hasTag bool, hashVal string, hasHash bool, expVal string, hasExp bool) (PublishedIntroducer, bool, error) {
	if !hasTag || tagVal == "" {
		return PublishedIntroducer{}, false, oops.
			Code("MISSING_INTRODUCER_TAG").
			With("index", index).
			Errorf("introducer %d has ih/iexp but is missing required itag%d", index, index)
	}

	tag, err := strconv.ParseUint(tagVal, 10, 32)
	if err != nil {
		return PublishedIntroducer{}, false, oops.
			Code("INVALID_INTRODUCER_TAG").
			With("index", index).
			Wrapf(err, "invalid itag%d value %q", index, tagVal)
	}
	if tag == 0 {
		// A zero tag marks an absent/removed introducer; tolerate and skip.
		return PublishedIntroducer{}, true, nil
	}

	if !hasHash || hashVal == "" {
		return PublishedIntroducer{}, false, oops.
			Code("MISSING_INTRODUCER_HASH").
			With("index", index).
			Errorf("introducer %d is missing required ih%d", index, index)
	}
	hash, err := i2pbase64.I2PEncoding.DecodeString(hashVal)
	if err != nil {
		return PublishedIntroducer{}, false, oops.
			Code("INVALID_INTRODUCER_HASH").
			With("index", index).
			Wrapf(err, "invalid Base64 in ih%d", index)
	}
	if len(hash) != introducerHashLen {
		return PublishedIntroducer{}, false, oops.
			Code("INVALID_INTRODUCER_HASH").
			With("index", index).
			Errorf("ih%d must decode to %d bytes, got %d", index, introducerHashLen, len(hash))
	}

	intro := PublishedIntroducer{RouterHash: hash, RelayTag: uint32(tag)}
	if hasExp && expVal != "" {
		exp, err := strconv.ParseInt(expVal, 10, 64)
		if err != nil {
			return PublishedIntroducer{}, false, oops.
				Code("INVALID_INTRODUCER_EXPIRATION").
				With("index", index).
				Wrapf(err, "invalid iexp%d value %q", index, expVal)
		}
		intro.ExpiresAt = time.Unix(exp, 0)
	}

	return intro, false, nil
}
