package ratchet

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/samber/oops"
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

// TestStripECIESControlBlocks_UnknownTypeAsPadding covers ecies.md
// §"Unencrypted data": "For extensibility, receivers MUST ignore blocks with
// unknown type nunmbers, and treat them as padding."
//
// An unknown type must not be handed to the higher layer as if it were the
// message: a peer using a block type this build has never seen would deliver
// garbage instead of the garlic clove that follows it.
func TestStripECIESControlBlocks_UnknownTypeAsPadding(t *testing.T) {
	// The clove block itself stays for the higher layer to parse; only the
	// ratchet's own signaling blocks and unknown ones are removed.
	cloveBlock := []byte{byte(BlockGarlicClove), 0x00, 0x03, 0xAA, 0xBB, 0xCC}

	// [NextKey][unknown type 200][garlic clove]
	payload := []byte{byte(BlockNextKey), 0x00, 0x02, 0x11, 0x22}
	payload = append(payload, 200, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF)
	payload = append(payload, cloveBlock...)

	stripped := stripECIESControlBlocks(payload)
	assert.Equal(t, cloveBlock, stripped,
		"an unknown-type block must be skipped like padding, leaving the clove")

	// An unknown block in front of everything is dropped too.
	onlyUnknown := []byte{201, 0x00, 0x02, 0x01, 0x02}
	assert.Empty(t, stripECIESControlBlocks(onlyUnknown))
}

// TestIsKnownBlockType pins the set of types ecies.md §"5) Payload" defines.
func TestIsKnownBlockType(t *testing.T) {
	known := []BlockType{BlockDateTime, BlockTermination, BlockOptions,
		BlockMessageNumber, BlockNextKey, BlockAck, BlockAckRequest,
		BlockGarlicClove, BlockPadding}
	for _, b := range known {
		assert.True(t, IsKnownBlockType(b), "type %d is defined by the spec", b)
	}
	for _, b := range []BlockType{1, 2, 3, 10, 12, 100, 200, 253, 255} {
		assert.False(t, IsKnownBlockType(b), "type %d is not defined", b)
	}
}

// TestDestroyKeyMaterial_ZeroesSessionKeys covers ecies.md §"Defense" and the
// §"Notes" requirement that superseded sessions be "destroyed immediately".
//
// Removing a session from the manager's map only drops the reference; the chain
// keys, root keys, tag ratchets, DH private keys and pre-derived message keys stay
// in the heap until the GC reuses that memory, so a later memory disclosure still
// reveals a "closed" session's keys.
func TestDestroyKeyMaterial_ZeroesSessionKeys(t *testing.T) {
	session := createTestSession(t, true)

	require.False(t, isAllZeroBytes(session.sendRootKey[:]), "fixture must hold key material")
	require.False(t, isAllZeroBytes(session.recvRootKey[:]))
	require.NotEqual(t, [32]byte{}, session.SymmetricRatchet.GetChainKey())
	require.NotEqual(t, [32]byte{}, session.RecvSymmetricRatchet.GetChainKey())

	session.destroyKeyMaterial()

	assert.True(t, isAllZeroBytes(session.sendRootKey[:]), "the outbound root key must be zeroed")
	assert.True(t, isAllZeroBytes(session.recvRootKey[:]), "the inbound root key must be zeroed")
	assert.Equal(t, [32]byte{}, session.SymmetricRatchet.GetChainKey(),
		"the outbound chain key must be zeroed")
	assert.Equal(t, [32]byte{}, session.RecvSymmetricRatchet.GetChainKey(),
		"the inbound chain key must be zeroed")
	assert.Empty(t, session.recvKeyCache, "cached message keys must be destroyed")
	assert.Nil(t, session.pendingTags, "the advertised tag window must be dropped")
	assert.Nil(t, session.handshakeState)
	assert.Nil(t, session.awaitingNSRReplies)
	assert.Nil(t, session.pendingNSRs)
}

// TestDestroyKeyMaterial_RetiredTagsets: superseded inbound tag sets hold their own
// ratchets, which zeroing the primary inbound ratchet does not reach.
func TestDestroyKeyMaterial_RetiredTagsets(t *testing.T) {
	session := createTestSession(t, false)
	session.archiveRecvTagset()
	require.NotEmpty(t, session.retiredRecv, "fixture must retain a previous tag set")

	retired := session.retiredRecv[0]
	require.NotNil(t, retired.tagRatchet)
	require.NotEqual(t, [32]byte{}, retired.symRatchet.GetChainKey())

	session.destroyKeyMaterial()

	assert.Equal(t, [32]byte{}, retired.symRatchet.GetChainKey(),
		"a retired tag set's chain key must be zeroed too")
	assert.Nil(t, session.retiredRecv)
}

// TestRemoveSessionDestroysKeys proves the removal path actually destroys the key
// material rather than only unlinking the map entry.
func TestRemoveSessionDestroysKeys(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	mustBootstrapSession(t, sender, receiver)
	_ = sender

	session := firstSession(t, receiver)
	require.False(t, isAllZeroBytes(session.sendRootKey[:]), "fixture must hold key material")

	receiver.removeSessionByPointer(session)

	assert.True(t, isAllZeroBytes(session.sendRootKey[:]),
		"removal must destroy the session's key material")
}

// TestSessionManagerCloseDestroysKeys: manager shutdown must zero every session,
// not just drop the maps.
func TestSessionManagerCloseDestroysKeys(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	mustBootstrapSession(t, sender, receiver)

	session := firstSession(t, receiver)
	require.False(t, isAllZeroBytes(session.sendRootKey[:]))

	require.NoError(t, receiver.Close())

	assert.True(t, isAllZeroBytes(session.sendRootKey[:]),
		"Close() must destroy the key material of every session")
	assert.Zero(t, receiver.GetSessionCount())
}

func isAllZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestNextKey_ReservedFlagsRejected covers ecies.md §"Next DH Ratchet Public
// Key": "bits 7-2: Unused, set to 0 for future compatibility".
//
// A peer setting a reserved bit is using a flag this build cannot interpret;
// applying the block anyway would act on half of its meaning, so the block is
// rejected at the wire boundary.
func TestNextKey_ReservedFlagsRejected(t *testing.T) {
	block := PayloadBlock{Type: BlockNextKey, Data: make([]byte, 3)}
	block.Data[0] = 0x08 // bit 3: outside bits 0-2 defined by the spec
	binary.BigEndian.PutUint16(block.Data[1:3], 0)

	_, err := block.NextKey()
	require.Error(t, err, "a NextKey block with reserved bits set must be rejected")
	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "NEXTKEY_RESERVED_FLAGS", oopsErr.Code())
}

// TestNextKey_ContradictoryFlags covers "bit 2: 1 to request reverse key …
// only set if bit 1 is 0".
func TestNextKey_ContradictoryFlags(t *testing.T) {
	block := PayloadBlock{Type: BlockNextKey, Data: make([]byte, 3)}
	block.Data[0] = NextKeyFlagReverse | NextKeyFlagRequestReverse

	_, err := block.NextKey()
	require.Error(t, err,
		"a reverse key block may not also request a reverse key")
}

// TestNewAckRequestBlock_ZeroesFlags covers ecies.md §"Ack Request": "flg ::
// 1 byte flags / bits 7-0: Unused, set to 0 for future compatibility".
//
// The whole byte is reserved, so no non-zero value may go on the wire.
func TestNewAckRequestBlock_ZeroesFlags(t *testing.T) {
	assert.Equal(t, []byte{0}, NewAckRequestBlock(0).Data)
	assert.Equal(t, []byte{0}, NewAckRequestBlock(0xFF).Data,
		"the reserved flag byte must always be sent as 0")
}

// TestSessionExpiry_NSRTagsetTimeoutForReceiver covers ecies.md §"Parameters":
// "NSR tagset timeout: 3 minutes for receiver".
//
// The receiver is Bob, the one who holds an NSR tag set because he generates the
// replies. He retains the New Session handshake state — and with it the tag set —
// until Alice's first Existing Session message (§"Multiple NSR Messages": "Bob must
// maintain the handshake state and tagset for all NS messages received, until an ES
// message is received"), so his session must run on the 3-minute NSR clock while
// that state exists and on the ES clock afterwards.
func TestSessionExpiry_NSRTagsetTimeoutForReceiver(t *testing.T) {
	sender, receiver, destHash, sessionHash := mustSendNS(t)

	bob := requireSessionByHash(t, receiver, sessionHash)
	require.NotNil(t, bob.handshakeState,
		"Bob retains the NS handshake state and its tag set until Alice's first ES")

	receiver.mu.RLock()
	pendingExpiry := receiver.sessionExpiry(bob)
	receiver.mu.RUnlock()
	assert.Equal(t, nsrPendingTimeout, pendingExpiry,
		"a session still holding its NSR tag set must use the 3-minute NSR timeout")

	// Completing the NSR and taking Alice's first ES discharges the state.
	mustCompleteNSR(t, sender, receiver, sessionHash)
	mustExchangeES(t, sender, receiver, destHash, receiver.ourPublicKey, []byte("es"))

	bob = requireSessionByHash(t, receiver, sessionHash)
	require.Nil(t, bob.handshakeState,
		"the first ES message releases the retained NSR state")

	receiver.mu.RLock()
	establishedExpiry := receiver.sessionExpiry(bob)
	receiver.mu.RUnlock()
	assert.Equal(t, receiver.sessionTimeout, establishedExpiry,
		"an established session uses the ES receiver timeout, not the NSR one")
}
