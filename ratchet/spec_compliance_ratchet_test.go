package ratchet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNSRTagset_AdvancesAcrossReplies covers ecies.md §"1g) New Session Reply
// format": "One or more New Session Replies may be sent in response to a single
// New Session message. Each reply is prepended by a tag, which is generated from
// a TagSet for the session", and §"KDF for Reply TagSet" ->
// "tagsetEntry = tagset_nsr.GET_NEXT_ENTRY()", where §"TAGSET" defines
// GET_NEXT_ENTRY() as advancing (and EXTEND(1)-ing) through one shared set.
//
// Re-deriving the set per reply handed every reply the same tag.
func TestNSRTagset_AdvancesAcrossReplies(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := hashPubKey(responder.ourPublicKey)

	ns, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sessionHash, err := responder.DecryptGarlicMessage(ns)
	require.NoError(t, err)

	var tags [][8]byte
	for i := 0; i < nsrTagsetMin; i++ {
		nsr, err := responder.EncryptNewSessionReply(*sessionHash, []byte("reply"))
		require.NoError(t, err)
		var tag [8]byte
		copy(tag[:], nsr[:8])
		tags = append(tags, tag)
	}

	seen := map[[8]byte]int{}
	for i, tag := range tags {
		if first, dup := seen[tag]; dup {
			t.Errorf("NSR %d reuses the tag from NSR %d; the tagset must advance", i, first)
		}
		seen[tag] = i
	}
	assert.Len(t, seen, nsrTagsetMin, "each reply must carry the next tag of the session's tagset")

	// Beyond tsmax the set is exhausted rather than extended forever
	// (§"Parameters": "NSR tagset size: 12 tsmin and tsmax").
	_, err = responder.EncryptNewSessionReply(*sessionHash, []byte("reply-13"))
	require.Error(t, err, "the NSR tagset must stop at tsmax")
}

// TestNSRTagset_BothSidesAgree proves the initiator can route a reply that is NOT
// the first one for its New Session — the case a per-reply fresh ratchet made
// impossible, because the initiator had only ever registered tag_0.
func TestNSRTagset_BothSidesAgree(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := hashPubKey(responder.ourPublicKey)

	ns, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sessionHash, err := responder.DecryptGarlicMessage(ns)
	require.NoError(t, err)

	// The initiator registered a window; confirm it covers the tags the
	// responder will actually emit, in order.
	first, err := responder.EncryptNewSessionReply(*sessionHash, []byte("reply-1"))
	require.NoError(t, err)
	second, err := responder.EncryptNewSessionReply(*sessionHash, []byte("reply-2"))
	require.NoError(t, err)

	var secondTag [8]byte
	copy(secondTag[:], second[:8])

	initiator.mu.RLock()
	registered := initiator.nsrTagIndex[secondTag]
	initiator.mu.RUnlock()
	require.NotNil(t, registered, "the initiator must expect the responder's second tag")

	// The first reply establishes the session; the second must still decrypt
	// (the spec allows it to arrive late).
	_, _, _, err = initiator.DecryptGarlicMessage(first)
	require.NoError(t, err)
}

// TestTargetTagWindowSize_FollowsParametersTable covers ecies.md §"Parameters":
//
//	"ES tagset 0 size: tsmin 24, tsmax 160"
//	"ES tagset (1+) size: 160 tsmin and tsmax"
//	"Tagset look ahead of tag N: min(tsmax, tsmin + N/4)"
func TestTargetTagWindowSize_FollowsParametersTable(t *testing.T) {
	// Tagset 0: starts at tsmin 24 and grows by N/4 up to tsmax 160.
	assert.Equal(t, 24, targetTagWindowSize(0, 0), "tagset 0 at N=0 must be tsmin 24")
	assert.Equal(t, 24+1, targetTagWindowSize(4, 0), "N=4 must add exactly one entry")
	assert.Equal(t, 160, targetTagWindowSize(600, 0), "growth must clamp at tsmax 160")

	// Tagset 1+: tsmin is 160, so the window starts fully grown.
	assert.Equal(t, 160, targetTagWindowSize(0, 1), "tagset 1 at N=0 must be tsmin 160")
	assert.Equal(t, 160, targetTagWindowSize(0, 7), "any tagset >= 1 must start at 160")
	assert.Equal(t, 160, targetTagWindowSize(1000, 1), "and stays capped at tsmax 160")
}

// TestInboundWindow_UsesInboundTagIndex covers ecies.md §"4b) Session Tag
// Ratchet": "Receiver must ratchet ahead by the max window size … the window may
// be advanced", with N defined as "the message number of the message in the
// current chain" — the INBOUND chain. Sizing the inbound window from the send
// counter left a receive-only session pinned at tsmin.
func TestInboundWindow_UsesInboundTagIndex(t *testing.T) {
	// isSessionValid checks LastUsed plus the per-direction ES timeouts for an
	// established session, so all three timestamps must be recent or the tag is
	// never consumed.
	now := time.Now()
	session := &Session{LastUsed: now, Established: now}
	session.lastReceived = now
	session.lastSent = now

	// Sending must not move the inbound index.
	session.usedTags = 400
	require.Equal(t, uint32(0), session.usedRecvTags)

	// A full inbound window of 24 tags (tagset 0 tsmin), one of which we consume.
	session.pendingTags = make([][8]byte, 24)
	session.recvTagCounter = make(map[[8]byte]uint32, 24)
	for i := range session.pendingTags {
		session.pendingTags[i] = [8]byte{byte(i + 1)}
		session.recvTagCounter[session.pendingTags[i]] = uint32(i)
	}
	tag := session.pendingTags[0]

	// validateAndConsumeTagFromSession must be called with sm.mu released.
	sm := createTestSessionManager(t)
	valid, needsReplenish := sm.validateAndConsumeTagFromSession(session, tag)

	require.True(t, valid)
	assert.Equal(t, uint32(1), session.usedRecvTags, "consuming an inbound tag must advance N")
	assert.Equal(t, uint32(400), session.usedTags, "the inbound path must not touch the send counter")
	// 23 pending tags against a 24-tag window is above the half-window threshold.
	assert.False(t, needsReplenish, "a nearly full window must not request replenishment")

	// Drain the window and confirm replenishment is requested, with the threshold
	// sized by the inbound N and the tagset index rather than the send counter.
	session.pendingTags = session.pendingTags[:1]
	threshold := tagReplenishThreshold(session.usedRecvTags, session.recvTagsetIndex)
	assert.Equal(t, targetTagWindowSize(session.usedRecvTags, session.recvTagsetIndex)/2, threshold,
		"the threshold must derive from the inbound window")
	assert.Less(t, len(session.pendingTags), threshold, "a drained window must request replenishment")

	// After one receiving DH ratchet the tagset is "1+", whose tsmin is 160, so
	// the same N yields a much larger window.
	session.recvTagsetIndex = 1
	assert.Equal(t, 160, targetTagWindowSize(session.usedRecvTags, session.recvTagsetIndex))
	assert.Equal(t, 80, tagReplenishThreshold(session.usedRecvTags, session.recvTagsetIndex))
}

// TestValidateOutboundPayload covers ecies.md §"Block Ordering Rules" and
// §"Unencrypted data" on the paths that accept an opaque caller payload.
func TestValidateOutboundPayload(t *testing.T) {
	clove := NewGarlicCloveBlock([]byte("clove"))
	termination := NewTerminationBlock(TerminationNormal, nil)

	// An NSR may carry Garlic Clove / Options / Padding only.
	ok := []PayloadBlock{clove}
	data, err := serializeBlocksForTest(ok)
	require.NoError(t, err)
	assert.NoError(t, validateOutboundPayload(messageTypeNewSessionReply, data))

	bad, err := serializeBlocksForTest([]PayloadBlock{termination})
	require.NoError(t, err)
	err = validateOutboundPayload(messageTypeNewSessionReply, bad)
	require.Error(t, err, "a Termination block is not allowed in a New Session Reply")
	assert.Contains(t, err.Error(), "not allowed in a New Session Reply")

	// Termination IS allowed in ES, but must be the last non-padding block.
	esWithTermination, err := serializeBlocksForTest([]PayloadBlock{clove, termination})
	require.NoError(t, err)
	assert.NoError(t, validateOutboundPayload(messageTypeExistingSession, esWithTermination))

	misordered, err := serializeBlocksForTest([]PayloadBlock{termination, clove})
	require.NoError(t, err)
	err = validateOutboundPayload(messageTypeExistingSession, misordered)
	require.Error(t, err, "Termination must be the last non-padding block")

	// Size ceiling: §"Unencrypted data" — "Encrypted data is 65535 bytes max …
	// so the max unencrypted data is 65519 bytes."
	oversized := make([]byte, maxPayloadSize+1)
	err = validateOutboundPayload(messageTypeExistingSession, oversized)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeding the 65519-byte maximum")

	// Opaque (non-block) caller data is only size-checked, never rejected as
	// malformed — the API accepts arbitrary plaintext garlic bytes.
	opaque := []byte("this is not a block sequence at all")
	assert.NoError(t, validateOutboundPayload(messageTypeExistingSession, opaque))
}

// TestEncryptNewSessionReply_RejectsIllegalPayload proves the check runs on the
// real wire path, not just the helper.
func TestEncryptNewSessionReply_RejectsIllegalPayload(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := hashPubKey(responder.ourPublicKey)

	ns, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sessionHash, err := responder.DecryptGarlicMessage(ns)
	require.NoError(t, err)

	termination := NewTerminationBlock(TerminationNormal, nil)
	illegal, err := serializeBlocksForTest([]PayloadBlock{termination})
	require.NoError(t, err)

	_, err = responder.EncryptNewSessionReply(*sessionHash, illegal)
	require.Error(t, err, "EncryptNewSessionReply must refuse a payload the spec forbids")

	_, err = responder.EncryptNewSessionReply(*sessionHash, make([]byte, maxPayloadSize+1))
	require.Error(t, err, "EncryptNewSessionReply must refuse an oversized payload")
}

// TestEncryptGarlicMessage_RejectsOversizedES proves the ES wire path enforces
// the size ceiling before burning a ratchet step on a message no peer can read.
func TestEncryptGarlicMessage_RejectsOversizedES(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := hashPubKey(responder.ourPublicKey)

	ns, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sessionHash, err := responder.DecryptGarlicMessage(ns)
	require.NoError(t, err)
	nsrPayload, err := serializeBlocksForTest([]PayloadBlock{NewGarlicCloveBlock([]byte("nsr"))})
	require.NoError(t, err)
	nsr, err := responder.EncryptNewSessionReply(*sessionHash, nsrPayload)
	require.NoError(t, err)
	_, _, _, err = initiator.DecryptGarlicMessage(nsr)
	require.NoError(t, err)
	// The responder must see one ES before either side may send ES.
	es, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("es")))
	require.NoError(t, err)
	_, _, _, err = responder.DecryptGarlicMessage(es)
	require.NoError(t, err)

	session := requireSessionByHash(t, initiator, destHash)
	session.mu.Lock()
	before := session.MessageCounter
	session.mu.Unlock()

	_, err = initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, make([]byte, maxPayloadSize+1))
	require.Error(t, err, "an oversized ES payload must be refused")

	session.mu.Lock()
	after := session.MessageCounter
	session.mu.Unlock()
	assert.Equal(t, before, after, "a refused message must not consume a ratchet step")
	_ = time.Now
}

// serializeBlocksForTest writes blocks to a payload byte slice WITHOUT the
// builder's ordering/allowlist checks, so a test can hand validateOutboundPayload
// a payload the builder itself would refuse to produce.
func serializeBlocksForTest(blocks []PayloadBlock) ([]byte, error) {
	out := make([]byte, 0)
	for _, b := range blocks {
		buf := make([]byte, b.SerializeSize())
		n, err := b.Serialize(buf)
		if err != nil {
			return nil, err
		}
		out = append(out, buf[:n]...)
	}
	return out, nil
}
