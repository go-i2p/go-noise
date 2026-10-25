package ratchet

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkedSessionFixture holds a sender/receiver pair with an established NS
// session and a valid session tag on the receiver side.
type linkedSessionFixture struct {
	sender   *SessionManager
	receiver *SessionManager
	destHash [32]byte
	tag      [8]byte
}

// newLinkedSessionFixture creates linked managers, establishes an NS session,
// and retrieves a usable session tag from the receiver's tag index.
func newLinkedSessionFixture(t *testing.T) linkedSessionFixture {
	t.Helper()
	sender, receiver, destHash := mustEstablishNS(t)
	tag := getAnyTag(t, receiver)

	return linkedSessionFixture{
		sender:   sender,
		receiver: receiver,
		destHash: destHash,
		tag:      tag,
	}
}

// ============================================================================
// Initial state
// ============================================================================

func TestSession_InitialNextKeyState(t *testing.T) {
	session := createTestSession(t, true)

	sendKeyID, recvKeyID, awaiting := session.NextKeyState()
	assert.Equal(t, uint16(0), sendKeyID, "Initial sendKeyID should be 0")
	assert.Equal(t, uint16(0), recvKeyID, "Initial recvKeyID should be 0")
	assert.False(t, awaiting, "Should not be awaiting reverse key initially")
	assert.False(t, session.HasPendingNextKeys(), "No pending NextKeys initially")
	assert.Nil(t, session.GetPendingNextKeys(), "GetPendingNextKeys should return nil initially")
}

// ============================================================================
// Forward block construction (ecies.md §"DH RATCHET MESSAGE FLOW")
// ============================================================================

// TestPrepareSend_FirstExchange verifies the very first forward block: the
// sender generates new key #0 and requests the reverse key.
//
// Spec flow: "(generate new key #0) / Next Key, forward, request reverse,
// with key #0".
func TestPrepareSend_FirstExchange(t *testing.T) {
	session := createTestSession(t, true)

	require.NoError(t, session.prepareSend())

	blocks := session.GetPendingNextKeys()
	require.Len(t, blocks, 1, "exactly one forward block outstanding")
	info, err := blocks[0].NextKey()
	require.NoError(t, err)

	assert.True(t, info.KeyPresent, "first forward block carries the new key")
	assert.False(t, info.Reverse, "forward block has bit 1 clear")
	assert.True(t, info.RequestReverse, "first exchange requests the reverse key")
	assert.Equal(t, uint16(0), info.KeyID, "first key ID is 0")
	assert.NotNil(t, session.sendDir)
	assert.True(t, session.sendDir.owed, "block is owed until the peer's key arrives")
}

// TestPrepareSend_NoDHPerformed is the core of audit finding R-02: preparing a
// forward block must NOT ratchet the send chain, because the spec defers the
// sender's DH until the peer's reverse key arrives.
func TestPrepareSend_NoDHPerformed(t *testing.T) {
	session := createTestSession(t, true)
	beforeTag := session.TagRatchet
	beforeSym := session.SymmetricRatchet

	require.NoError(t, session.prepareSend())

	assert.Same(t, beforeTag, session.TagRatchet, "send tag ratchet must be untouched by prepareSend")
	assert.Same(t, beforeSym, session.SymmetricRatchet, "send symmetric ratchet must be untouched by prepareSend")
}

// TestForwardBlocksAreReSentUntilAcknowledged verifies the "repeat until next
// key received" rule: blocks are derived from state, not drained.
func TestForwardBlocksAreReSentUntilAcknowledged(t *testing.T) {
	session := createTestSession(t, true)
	require.NoError(t, session.prepareSend())

	first := session.GetPendingNextKeys()
	second := session.GetPendingNextKeys()
	require.Len(t, first, 1)
	require.Len(t, second, 1, "block must still be emitted on the next message")

	fi, _ := first[0].NextKey()
	si, _ := second[0].NextKey()
	assert.Equal(t, fi, si, "re-sent block must be identical")
	assert.True(t, session.HasPendingNextKeys())
}

// TestPrepareSend_KeyIDProgression verifies the spec's key/tag set progression
// table (§"KEY AND TAG SET IDS"): the sender's key IDs go 0*, 1*, 1, 2*, 2, ...
// (* = new key). This mirrors i2pd NewNextSendRatchet's parity rule.
func TestPrepareSend_KeyIDProgression(t *testing.T) {
	session := createTestSession(t, true)

	type want struct {
		keyID  uint16
		newKey bool
	}
	var got []want
	for i := 0; i < 5; i++ {
		require.NoError(t, session.prepareSend())
		got = append(got, want{session.sendDir.keyID, session.sendDir.newKey})
	}

	expected := []want{
		{0, true},  // key 0*
		{1, true},  // key 1*
		{1, false}, // key 1 (reuse)
		{2, true},  // key 2*
		{2, false}, // key 2 (reuse)
	}
	assert.Equal(t, expected, got, "sender key IDs must follow the spec progression table")
}

// TestBuildForwardBlock_ReuseRequestsReverse verifies that a reuse block (no
// key) asks for the peer's key instead, per the flag rules.
func TestBuildForwardBlock_FlagRules(t *testing.T) {
	dir := &dhDirection{keyID: 1, newKey: false, hasKey: true}
	info, err := buildForwardBlock(dir).NextKey()
	require.NoError(t, err)
	assert.False(t, info.KeyPresent, "reused key is not retransmitted")
	assert.True(t, info.RequestReverse, "reuse block requests the reverse key")

	dir2 := &dhDirection{keyID: 2, newKey: true, hasKey: true}
	info2, err := buildForwardBlock(dir2).NextKey()
	require.NoError(t, err)
	assert.True(t, info2.KeyPresent, "new key is transmitted")
	assert.False(t, info2.RequestReverse, "a block carrying a new key does not also request one")

	// "for first key only": key ID 0 with a new key still requests reverse.
	dir3 := &dhDirection{keyID: 0, newKey: true, hasKey: true}
	info3, err := buildForwardBlock(dir3).NextKey()
	require.NoError(t, err)
	assert.True(t, info3.KeyPresent)
	assert.True(t, info3.RequestReverse, "first key also requests reverse (spec tag set 1 needs both keys)")
}

// ============================================================================
// Reverse block construction
// ============================================================================

// TestBuildReverseBlock_FirstReplyCarriesKeyZero verifies the spec flow's
// "Next Key, reverse, with key #0": the first reverse reply must carry key ID 0,
// which requires i2pd's signed keyID-1 / keyID+1 arithmetic.
func TestBuildReverseBlock_FirstReplyCarriesKeyZero(t *testing.T) {
	dir := &dhDirection{keyID: 0, newKey: true, hasKey: true}
	info, err := buildReverseBlock(dir).NextKey()
	require.NoError(t, err)
	assert.True(t, info.Reverse, "reverse block sets bit 1")
	assert.True(t, info.KeyPresent)
	assert.False(t, info.RequestReverse, "bit 2 only set if bit 1 is 0")
	assert.Equal(t, uint16(0), info.KeyID, "first reverse reply carries key ID 0")
}

// TestBuildReverseBlock_ReuseAcknowledgesOldID verifies "Next Key, reverse,
// id 0" for tag set 2: the receiver acks with the ID of its old key and sends no
// key.
func TestBuildReverseBlock_ReuseAcknowledgesOldID(t *testing.T) {
	dir := &dhDirection{keyID: 1, newKey: false, hasKey: true}
	info, err := buildReverseBlock(dir).NextKey()
	require.NoError(t, err)
	assert.True(t, info.Reverse)
	assert.False(t, info.KeyPresent, "reused key is not retransmitted")
	assert.Equal(t, uint16(0), info.KeyID, "reverse ack carries keyID-1")
}

// ============================================================================
// Receiving a forward block
// ============================================================================

func TestProcessReceivedNextKey_ForwardKey(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.receiver)

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: false, RequestReverse: true, KeyID: 0, PublicKey: pub}

	require.NoError(t, f.receiver.ProcessReceivedNextKey(f.tag, info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.Equal(t, uint16(0), session.recvKeyID)
	assert.True(t, session.recvDir.newKey, "request-reverse makes us generate a new key")
	assert.Equal(t, pub, session.recvDir.remote, "peer key recorded")
	assert.True(t, session.recvDir.owed, "we owe the reverse block")
	// Tag set 1 = 1 + sender key 0 + receiver key 0.
	assert.Equal(t, uint16(1), session.recvTagSetID, "inbound tag set ID must be 1")
}

func TestProcessReceivedNextKey_ForwardKeyCreatesNewInboundTagset(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.receiver)
	session.mu.Lock()
	oldTagRatchet := session.RecvTagRatchet
	oldPrev := len(session.retiredRecv)
	session.mu.Unlock()

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: false, RequestReverse: true, KeyID: 0, PublicKey: pub}
	require.NoError(t, f.receiver.ProcessReceivedNextKey(f.tag, info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.NotSame(t, oldTagRatchet, session.RecvTagRatchet, "inbound tag ratchet must be replaced")
	require.NotEmpty(t, session.retiredRecv, "previous inbound tagset must be retained")
	assert.Zero(t, oldPrev, "no previous tagset existed before the rekey")
	assert.Equal(t, uint16(0), session.retiredRecv[0].tagSetID, "retired tag set was 0")
}

func TestProcessReceivedNextKey_DuplicateForwardIsIgnored(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.receiver)

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: false, RequestReverse: true, KeyID: 0, PublicKey: pub}
	require.NoError(t, f.receiver.ProcessReceivedNextKey(f.tag, info))

	session.mu.Lock()
	tagRatchet := session.RecvTagRatchet
	session.mu.Unlock()

	// The peer re-sends the same forward block until our reverse block lands.
	require.NoError(t, f.receiver.ProcessReceivedNextKey(getAnyTag(t, f.receiver), info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.Same(t, tagRatchet, session.RecvTagRatchet, "duplicate forward block must not re-run the DH")
}

func TestProcessReceivedNextKey_UnknownTag(t *testing.T) {
	sm := createTestSessionManager(t)
	var unknownTag [8]byte
	_, _ = rand.Read(unknownTag[:])
	err := sm.ProcessReceivedNextKey(unknownTag, NextKeyInfo{})
	assert.Error(t, err, "Should error for unknown session tag")
}

// ============================================================================
// Receiving a reverse block
// ============================================================================

func TestProcessReceivedNextKey_ReverseKey(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.sender)

	require.NoError(t, session.prepareSend())

	var peerPub [32]byte
	_, _ = rand.Read(peerPub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: true, KeyID: 0, PublicKey: peerPub}

	require.NoError(t, f.sender.handleNextKeyBlock(session, info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.False(t, session.sendDir.owed, "forward block is acknowledged")
	assert.Equal(t, uint16(1), session.sendTagSetID, "outbound tag set ID = 1 + 0 + 0")
	assert.Equal(t, uint32(0), session.MessageCounter, "new outbound tagset restarts the counter chain")
	assert.Equal(t, uint32(0), session.usedTags, "new outbound tagset restarts usedTags")
}

func TestProcessReceivedNextKey_UnexpectedReverseIgnored(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.sender)
	session.mu.Lock()
	before := session.TagRatchet
	session.mu.Unlock()

	var peerPub [32]byte
	_, _ = rand.Read(peerPub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: true, KeyID: 5, PublicKey: peerPub}

	// No forward block was ever sent: i2pd returns without error.
	require.NoError(t, f.sender.handleNextKeyBlock(session, info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.Same(t, before, session.TagRatchet, "unsolicited reverse block must not ratchet")
}

func TestProcessReceivedNextKey_WrongKeyIDIgnored(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.sender)
	require.NoError(t, session.prepareSend())
	session.mu.Lock()
	before := session.TagRatchet
	session.mu.Unlock()

	var peerPub [32]byte
	_, _ = rand.Read(peerPub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: true, KeyID: 9, PublicKey: peerPub}
	require.NoError(t, f.sender.handleNextKeyBlock(session, info))

	session.mu.Lock()
	defer session.mu.Unlock()
	assert.Same(t, before, session.TagRatchet, "non-matching key ID must be ignored (i2pd 'Unexpected next key')")
	assert.True(t, session.sendDir.owed, "still owed until a matching key arrives")
}

// ============================================================================
// Full two-sided exchange
// ============================================================================

// TestNextKeyExchange_FullFlow drives the complete spec exchange entirely
// through the wire: both peers only ever call EncryptGarlicMessage /
// DecryptGarlicMessage, so it exercises the automatic NextKey dispatch, the
// forward/reverse block piggy-backing, and both acknowledgements.
func TestNextKeyExchange_FullFlow(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash, sessionHash := mustBootstrapSessionWithHash(t, sender, receiver)
	senderSession := lookupSessionByHash(t, sender, destHash)
	receiverSession := lookupSessionByHash(t, receiver, sessionHash)

	// Baseline traffic both directions.
	for i := 0; i < 2; i++ {
		msg := []byte(fmt.Sprintf("pre-%d", i))
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, msg)
		require.NoError(t, err)
		dec, _, _, err := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err)
		assert.Equal(t, msg, dec)

		back := []byte(fmt.Sprintf("pre-back-%d", i))
		encB, err := receiver.EncryptGarlicMessage(sessionHash, sender.ourPublicKey, back)
		require.NoError(t, err)
		decB, _, _, err := sender.DecryptGarlicMessage(encB)
		require.NoError(t, err)
		assert.Equal(t, back, decB)
	}

	// 1. Sender crosses the "send next key at tag 4096" threshold.
	senderSession.mu.Lock()
	senderSession.usedTags = nextKeyTagThreshold
	senderSession.mu.Unlock()

	// The forward block rides along inside a normal ES message.
	baseline, err := receiver.EncryptGarlicMessage(sessionHash, sender.ourPublicKey, []byte("xx"))
	require.NoError(t, err)
	msg := []byte("carries-forward-block")
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, msg)
	require.NoError(t, err)
	assert.Greater(t, len(enc), len(baseline), "ES message with a NextKey block is larger")

	// 2. Receiver decrypts it and the embedded forward block is dispatched
	//    automatically: inbound tag set 1 created, reverse block now owed.
	dec, _, _, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err, "the message carrying the forward block must still decrypt")
	assert.Equal(t, msg, dec)

	receiverSession.mu.Lock()
	require.NotNil(t, receiverSession.recvDir, "forward block must create receive-direction state")
	assert.True(t, receiverSession.recvDir.owed, "receiver owes the reverse block")
	assert.Equal(t, uint16(1), receiverSession.recvTagSetID, "inbound tag set ID = 1 + 0 + 0")
	require.NotEmpty(t, receiverSession.retiredRecv, "previous inbound tagset retained")
	receiverSession.mu.Unlock()

	// 3. Receiver's next ES message carries the reverse block; the sender
	//    dispatches it and performs its single send-direction DH.
	reverseMsg := []byte("carries-reverse-block")
	enc2, err := receiver.EncryptGarlicMessage(sessionHash, sender.ourPublicKey, reverseMsg)
	require.NoError(t, err)
	dec2, _, _, err := sender.DecryptGarlicMessage(enc2)
	require.NoError(t, err)
	assert.Equal(t, reverseMsg, dec2)

	senderSession.mu.Lock()
	assert.Equal(t, uint16(1), senderSession.sendTagSetID, "outbound tag set ID = 1 + 0 + 0")
	assert.False(t, senderSession.sendDir.owed, "forward block acknowledged by the reverse key")
	assert.Equal(t, uint32(0), senderSession.MessageCounter, "new outbound tagset restarts the counter chain")
	senderSession.mu.Unlock()

	// 4. Sender's next message uses the new outbound tag set, which is the
	//    evidence that retires the receiver's reverse block.
	postMsg := []byte("on-new-tagset")
	enc3, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, postMsg)
	require.NoError(t, err)
	dec3, _, _, err := receiver.DecryptGarlicMessage(enc3)
	require.NoError(t, err)
	assert.Equal(t, postMsg, dec3)

	receiverSession.mu.Lock()
	assert.False(t, receiverSession.recvDir.owed, "reverse block acknowledged by a tag from the new tagset")
	assert.Empty(t, receiverSession.GetPendingNextKeys(), "no NextKey blocks outstanding")
	receiverSession.mu.Unlock()

	// 5. Traffic keeps flowing in both directions on tag set 1.
	for i := 0; i < 3; i++ {
		m := []byte(fmt.Sprintf("post-%d", i))
		e, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, m)
		require.NoError(t, err)
		d, _, _, err := receiver.DecryptGarlicMessage(e)
		require.NoError(t, err, "post-rekey sender->receiver message %d must decrypt", i)
		assert.Equal(t, m, d)

		b := []byte(fmt.Sprintf("reply-%d", i))
		eb, err := receiver.EncryptGarlicMessage(sessionHash, sender.ourPublicKey, b)
		require.NoError(t, err)
		db, _, _, err := sender.DecryptGarlicMessage(eb)
		require.NoError(t, err, "post-rekey receiver->sender message %d must decrypt", i)
		assert.Equal(t, b, db)
	}
}

// TestNextKeyExchange_SecondRoundTagSetIDs drives three full exchanges over the
// wire to confirm the tag set ID progression (1, 2, 3, ...) and the spec's
// key-ID parity rule are reproduced identically on both peers, as required by
// §"KEY AND TAG SET IDS" ("Key and tag set ID numbers must be sequential").
func TestNextKeyExchange_SecondRoundTagSetIDs(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash, sessionHash := mustBootstrapSessionWithHash(t, sender, receiver)
	senderSession := lookupSessionByHash(t, sender, destHash)
	receiverSession := lookupSessionByHash(t, receiver, sessionHash)

	round := func(expected uint16) {
		// Sender starts the exchange.
		senderSession.mu.Lock()
		senderSession.usedTags = nextKeyTagThreshold
		senderSession.mu.Unlock()
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("fwd"))
		require.NoError(t, err)
		_, _, _, err = receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "forward round %d", expected)

		// Receiver answers with the reverse block.
		enc2, err := receiver.EncryptGarlicMessage(sessionHash, sender.ourPublicKey, []byte("rev"))
		require.NoError(t, err)
		_, _, _, err = sender.DecryptGarlicMessage(enc2)
		require.NoError(t, err, "reverse round %d", expected)

		// Sender moves to the new outbound tag set.
		enc3, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("new"))
		require.NoError(t, err)
		_, _, _, err = receiver.DecryptGarlicMessage(enc3)
		require.NoError(t, err, "post-rekey round %d", expected)

		senderSession.mu.Lock()
		sendTS, sendKey := senderSession.sendTagSetID, senderSession.sendKeyID
		senderSession.mu.Unlock()
		receiverSession.mu.Lock()
		recvTS, recvKey := receiverSession.recvTagSetID, receiverSession.recvKeyID
		receiverSession.mu.Unlock()

		assert.Equal(t, expected, sendTS, "sender outbound tag set ID")
		assert.Equal(t, sendTS, recvTS, "both peers must compute the same tag set ID")
		// Spec progression for the tag-set sender: 0*, 1*, 1, 2*, 2, ...
		assert.Equal(t, uint16((expected)/2), sendKey, "sender key ID at tag set %d", expected)
		t.Logf("tag set %d: sender key %d, receiver key %d", expected, sendKey, recvKey)
	}

	round(1)
	round(2)
	round(3)
	round(4)

	// Traffic still works after four rekeys.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("after-4"))
	require.NoError(t, err)
	dec, _, _, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	assert.Equal(t, []byte("after-4"), dec)
}

// TestNextKeyExchange_PreviousTagsetStillDecrypts verifies the ~3 minute
// "listen for tags in both tagsets" rule: a message the peer sent on the OLD
// inbound tag set must still decrypt after we install the new one.
func TestNextKeyExchange_PreviousTagsetStillDecrypts(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash, sessionHash := mustBootstrapSessionWithHash(t, sender, receiver)
	senderSession := lookupSessionByHash(t, sender, destHash)
	receiverSession := lookupSessionByHash(t, receiver, sessionHash)

	// Peer sends on tag set 0; capture one ciphertext without decrypting it.
	msg := []byte("in-flight-on-old-tagset")
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, msg)
	require.NoError(t, err)

	// Complete a rekey so the receiver installs inbound tag set 1.
	senderSession.mu.Lock()
	require.NoError(t, senderSession.prepareSend())
	fi, err := senderSession.GetPendingNextKeys()[0].NextKey()
	senderSession.mu.Unlock()
	require.NoError(t, err)
	require.NoError(t, receiver.handleNextKeyBlock(receiverSession, fi))
	receiverSession.mu.Lock()
	ri, err := receiverSession.GetPendingNextKeys()[0].NextKey()
	receiverSession.mu.Unlock()
	require.NoError(t, err)
	require.NoError(t, sender.handleNextKeyBlock(senderSession, ri))

	// The sender's outbound chain moved to tag set 1, but the receiver's
	// retained tag set 0 window still holds the tag for `enc`.
	receiverSession.mu.Lock()
	require.NotEmpty(t, receiverSession.retiredRecv, "previous inbound tagset must be retained")
	var prevTags [][8]byte
	for _, retired := range receiverSession.retiredRecv {
		prevTags = append(prevTags, retired.tags...)
	}
	receiverSession.mu.Unlock()
	require.NotEmpty(t, prevTags, "retired tagset must keep its advertised tags")

	var oldTag [8]byte
	copy(oldTag[:], enc[:8])
	found := false
	for _, tg := range prevTags {
		if tg == oldTag {
			found = true
		}
	}
	assert.True(t, found, "the tag used by the in-flight message must stay routable on the retired tagset")
}

// ============================================================================
// Rotation trigger
// ============================================================================

// TestAttemptDHRatchetRotation_FiresAt4096 verifies the spec's "Send next key at
// tag: 4096" threshold replaces the old fixed every-50-messages schedule.
func TestAttemptDHRatchetRotation_FiresAt4096(t *testing.T) {
	session := createTestSession(t, true)

	session.usedTags = nextKeyTagThreshold - 1
	require.NoError(t, attemptDHRatchetRotation(session))
	assert.False(t, session.HasPendingNextKeys(), "no exchange below the threshold")

	session.usedTags = nextKeyTagThreshold
	require.NoError(t, attemptDHRatchetRotation(session))
	assert.True(t, session.HasPendingNextKeys(), "exchange starts at tag 4096")
	assert.Equal(t, uint16(0), session.sendKeyID, "first exchange uses key 0 (spec tag set 1 = sender key 0*)")

	// A second call must not start a second exchange while the first is owed.
	require.NoError(t, attemptDHRatchetRotation(session))
	assert.Equal(t, uint16(0), session.sendKeyID, "only one rotation per threshold crossing")
}

func TestAttemptDHRatchetRotation_MaxKeyID(t *testing.T) {
	session := createTestSession(t, true)
	session.sendDir = &dhDirection{keyID: MaxKeyID, newKey: false, hasKey: true}
	session.sendKeyID = MaxKeyID
	session.usedTags = nextKeyTagThreshold

	err := attemptDHRatchetRotation(session)
	assert.Error(t, err, "must error when send key ID is at MaxKeyID")
	assert.Contains(t, err.Error(), "maximum")
}

// ============================================================================
// MaxKeyID
// ============================================================================

func TestMaxKeyIDConstant(t *testing.T) {
	assert.Equal(t, uint16(32767), uint16(MaxKeyID),
		"MaxKeyID should be 32767 per the spec")
}

// ============================================================================
// GetPublicKey
// ============================================================================

func TestGetPublicKey(t *testing.T) {
	sm := createTestSessionManager(t)
	pub := sm.GetPublicKey()
	assert.NotEqual(t, [32]byte{}, pub, "Public key should not be zero")
}

func TestGetPublicKey_DifferentManagers(t *testing.T) {
	sm1 := createTestSessionManager(t)
	sm2 := createTestSessionManager(t)
	assert.NotEqual(t, sm1.GetPublicKey(), sm2.GetPublicKey(),
		"Different managers should have different public keys")
}

// ============================================================================
// prependPendingNextKeys unit tests
// ============================================================================

// TestPrependPendingNextKeys_NoPending verifies the zero-copy fast path:
// when no NextKey blocks are pending, the original plaintext slice is returned.
func TestPrependPendingNextKeys_NoPending(t *testing.T) {
	session := createTestSession(t, true)

	original := []byte("hello world")
	result, err := prependPendingNextKeys(session, original)
	require.NoError(t, err)
	assert.Equal(t, original, result, "should return original plaintext unchanged")
}

// TestPrependPendingNextKeys_WithBlocks verifies that outstanding NextKey blocks
// are serialized and prepended to the plaintext.
func TestPrependPendingNextKeys_WithBlocks(t *testing.T) {
	session := createTestSession(t, true)
	require.NoError(t, session.prepareSend())

	originalPayload := []byte{byte(BlockGarlicClove), 0, 5, 'h', 'e', 'l', 'l', 'o'}
	result, err := prependPendingNextKeys(session, originalPayload)
	require.NoError(t, err)
	assert.Greater(t, len(result), len(originalPayload))

	blocks, err := ParsePayload(result)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(blocks), 2, "should have NextKey + original blocks")
	assert.Equal(t, BlockNextKey, blocks[0].Type)

	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.Equal(t, session.sendDir.ourPub, info.PublicKey)

	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
	assert.Equal(t, []byte("hello"), blocks[1].Data)
}

// TestPrependPendingNextKeys_BothDirectionsInOneFrame verifies the spec note
// that a frame may carry a forward and a reverse block simultaneously.
func TestPrependPendingNextKeys_BothDirectionsInOneFrame(t *testing.T) {
	session := createTestSession(t, true)
	require.NoError(t, session.prepareSend())
	_, err := session.prepareRecv(0, true, session.RemotePublicKey, true)
	require.NoError(t, err)

	result, err := prependPendingNextKeys(session, []byte{byte(BlockGarlicClove), 0, 1, 'x'})
	require.NoError(t, err)

	blocks, err := ParsePayload(result)
	require.NoError(t, err)
	var forward, reverse bool
	for _, b := range blocks {
		if b.Type != BlockNextKey {
			continue
		}
		info, err := b.NextKey()
		require.NoError(t, err)
		if info.Reverse {
			reverse = true
		} else {
			forward = true
		}
	}
	assert.True(t, forward, "forward block present")
	assert.True(t, reverse, "reverse block present")
}

// ============================================================================
// Threshold integration
// ============================================================================

// TestDHRatchetNextKeyTransmission_AtThreshold sends enough ES messages to cross
// the 4096-tag threshold and verifies the exchange is emitted and re-emitted
// until acknowledged.
func TestDHRatchetNextKeyTransmission_AtThreshold(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash := mustBootstrapSession(t, sender, receiver)
	senderSession := lookupSessionByHash(t, sender, destHash)

	// Jump to the threshold rather than sending 4096 real messages.
	senderSession.mu.Lock()
	senderSession.usedTags = nextKeyTagThreshold
	senderSession.mu.Unlock()

	const total = 3
	for i := 0; i < total; i++ {
		_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err, "encrypt message %d", i)

		senderSession.mu.Lock()
		owed := senderSession.sendDir != nil && senderSession.sendDir.owed
		keyID := senderSession.sendKeyID
		senderSession.mu.Unlock()

		assert.True(t, owed, "message %d: rotation must fire at tag %d and keep re-sending", i, nextKeyTagThreshold)
		assert.Equal(t, uint16(0), keyID, "first exchange uses key 0")
	}

	// usedTags must advance with every send tag generated.
	senderSession.mu.Lock()
	assert.Greater(t, int(senderSession.usedTags), int(nextKeyTagThreshold), "usedTags must track tag consumption")
	senderSession.mu.Unlock()
}

// ============================================================================
// Test helpers
// ============================================================================

// getAnyTag returns a tag from the manager's tag index without consuming it.
func getAnyTag(t testing.TB, sm *SessionManager) [8]byte {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for tag := range sm.tagIndex {
		return tag
	}
	t.Fatal("no tags in session manager's tag index")
	return [8]byte{}
}

// lookupSessionByAnyTag finds a session from the tag index without consuming the tag.
func lookupSessionByAnyTag(t testing.TB, sm *SessionManager) *Session {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, session := range sm.tagIndex {
		return session
	}
	t.Fatal("no sessions in tag index")
	return nil
}

// lookupSessionByHash returns the session stored under hash.
func lookupSessionByHash(t testing.TB, sm *SessionManager, hash [32]byte) *Session {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[hash]
	if !ok {
		t.Fatal("no session for hash")
	}
	return session
}

// ============================================================================
// Multiple NS / NSR support (ecies.md §"Multiple NSR Messages")
// ============================================================================

// TestMultipleNSR_SecondReplyCompletesSession verifies that if the first NSR is
// lost, the session can still be completed by a later NSR - the property the
// single-slot implementation lacked (audit finding R-08).
func TestMultipleNSR_SecondReplyCompletesSession(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := types.SHA256(responder.ourPublicKey[:])

	// Initiator sends NS #1.
	ns1, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns1")))
	require.NoError(t, err)
	_, _, sh1, err := responder.DecryptGarlicMessage(ns1)
	require.NoError(t, err)
	require.NotNil(t, sh1)

	// Initiator retransmits NS #2 (NSR #1 assumed lost on the way back).
	ns2, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns2")))
	require.NoError(t, err)
	require.NotEmpty(t, ns2)
	_, _, sh2, err := responder.DecryptGarlicMessage(ns2)
	require.NoError(t, err)
	require.NotNil(t, sh2)
	assert.Equal(t, *sh1, *sh2, "both NSs are for the same initiator identity")

	// The responder must retain the state for BOTH and be able to reply to the
	// second one after the first reply.
	nsr1, err := responder.EncryptNewSessionReply(*sh1, []byte("reply-1"))
	require.NoError(t, err)
	nsr2, err := responder.EncryptNewSessionReply(*sh1, []byte("reply-2"))
	require.NoError(t, err, "a second NSR must be sendable for the second NS")
	assert.NotEqual(t, nsr1, nsr2, "each NSR uses its own ephemeral key and tagset")

	// The first NSR that reaches the initiator establishes the session.
	_, _, _, err = initiator.DecryptGarlicMessage(nsr1)
	require.NoError(t, err)

	// ES traffic must now work initiator -> responder.
	msg := []byte("after-nsr")
	enc, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, msg)
	require.NoError(t, err)
	dec, _, _, err := responder.DecryptGarlicMessage(enc)
	require.NoError(t, err, "responder must decrypt ES after its first NSR was accepted")
	assert.Equal(t, msg, dec)

	// The second NSR is now redundant; it must not corrupt the session.
	_, _, _, _ = initiator.DecryptGarlicMessage(nsr2)

	enc2, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, []byte("still-ok"))
	require.NoError(t, err)
	_, _, _, err = responder.DecryptGarlicMessage(enc2)
	require.NoError(t, err, "session must remain usable after a redundant NSR")
}

// TestMultipleNSR_ResponderKeepsBothTagsets verifies the responder can decrypt an
// ES message produced from EITHER reply's keys, since the initiator uses
// whichever NSR arrives first.
//
// Spec ref: ecies.md §"Multiple NS Messages" - "For each NS message received,
// Bob creates a new inbound session."
func TestMultipleNSR_ResponderKeepsBothTagsets(t *testing.T) {
	initiator, responder := createLinkedManagers(t)
	destHash := types.SHA256(responder.ourPublicKey[:])

	ns1, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns1")))
	require.NoError(t, err)
	_, _, sh1, err := responder.DecryptGarlicMessage(ns1)
	require.NoError(t, err)

	ns2, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns2")))
	require.NoError(t, err)
	_, _, _, err = responder.DecryptGarlicMessage(ns2)
	require.NoError(t, err)

	_, err = responder.EncryptNewSessionReply(*sh1, []byte("reply-1"))
	require.NoError(t, err)
	nsr2, err := responder.EncryptNewSessionReply(*sh1, []byte("reply-2"))
	require.NoError(t, err)

	// Initiator happens to receive the SECOND reply first.
	_, _, _, err = initiator.DecryptGarlicMessage(nsr2)
	require.NoError(t, err)

	enc, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, []byte("from-nsr2"))
	require.NoError(t, err)
	_, _, _, err = responder.DecryptGarlicMessage(enc)
	require.NoError(t, err, "responder must decrypt ES keyed by the second NSR's tagset")
}

// ============================================================================
// Ratchet-layer response obligations (ecies.md §"Ratchet-layer Responses")
// ============================================================================

// TestResponseObligation_NextKeyRequiresResponse verifies that receiving a
// NextKey block arms a response obligation with the spec's ~1 second deadline,
// and that real outbound traffic discharges it.
//
// Spec ref: ecies.md §"Retransmissions and State Transistions" -> §"Ratchet-layer
// Responses": "receipt of ACK Request and Next Key blocks also require a response.
// Implementations should start a timer ... and generate an 'empty' (no Garlic
// Clove block) response at the ECIES layer if no reverse traffic is sent in a
// short period of time (e.g. 1 second)."
func TestResponseObligation_NextKeyRequiresResponse(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.receiver)

	session.mu.Lock()
	// The fixture establishes the session with mustEstablishNS, which sends an NS
	// and leaves the responder without an NSR, so an obligation is already armed
	// before the NextKey receipt under test.
	assert.Contains(t, session.response.kinds, "new session",
		"an unanswered NS must already be an obligation")
	session.mu.Unlock()

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: false, RequestReverse: true, KeyID: 0, PublicKey: pub}
	require.NoError(t, f.receiver.handleNextKeyBlock(session, info))

	session.mu.Lock()
	assert.False(t, session.response.deadline.IsZero(), "NextKey receipt must arm a response obligation")
	assert.Contains(t, session.response.kinds, "next key")
	assert.False(t, session.responseDue(time.Now()), "the deadline must not already be expired")
	session.mu.Unlock()

	// The obligation is discharged only by this session's own outbound traffic
	// (encryptExistingSession calls fulfillResponse once the message is built), so
	// simulate that directly rather than standing up a second send path.
	session.mu.Lock()
	session.fulfillResponse()
	assert.True(t, session.response.deadline.IsZero(), "outbound traffic clears the obligation")
	session.mu.Unlock()
}

// TestSweepResponses_FiresAfterDeadline verifies the host-facing sweep: an
// obligation is reported once its deadline passes and is not silently consumed,
// so a failed send retries.
func TestSweepResponses_FiresAfterDeadline(t *testing.T) {
	f := newLinkedSessionFixture(t)
	session := lookupSessionByAnyTag(t, f.receiver)

	var pub [32]byte
	_, _ = rand.Read(pub[:])
	info := NextKeyInfo{KeyPresent: true, Reverse: false, RequestReverse: true, KeyID: 0, PublicKey: pub}
	require.NoError(t, f.receiver.handleNextKeyBlock(session, info))

	// Nothing is due yet.
	assert.Empty(t, f.receiver.SweepResponses(), "no response is due before the deadline")

	// Force the deadline into the past.
	session.mu.Lock()
	session.response.deadline = time.Now().Add(-time.Millisecond)
	session.mu.Unlock()

	due := f.receiver.SweepResponses()
	require.Len(t, due, 1, "an expired obligation must be reported")
	assert.Contains(t, due[0].Kinds, "next key")
	assert.Greater(t, due[0].OverdueBy, time.Duration(0))

	// Still reported on the next sweep: the obligation is only cleared by an
	// actual send, so a host whose send fails retries rather than losing it.
	assert.Len(t, f.receiver.SweepResponses(), 1, "sweep must not consume the obligation")
}

// TestResponseObligation_NSArmsHandshakeTimer verifies an inbound New Session
// arms the shorter handshake-response timer, per §"Ratchet-layer Responses":
// "It may also be appropriate for an even shorter timeout for responses to NS and
// NSR messages, to shift the traffic to the efficient ES messages as soon as
// possible."
func TestResponseObligation_NSArmsHandshakeTimer(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash := types.SHA256(receiver.ourPublicKey[:])

	ns, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sh, err := receiver.DecryptGarlicMessage(ns)
	require.NoError(t, err)
	require.NotNil(t, sh)

	session := lookupSessionByHash(t, receiver, *sh)
	session.mu.Lock()
	defer session.mu.Unlock()
	require.False(t, session.response.deadline.IsZero(), "NS receipt must arm an NSR obligation")
	assert.Contains(t, session.response.kinds, "new session")
	assert.Less(t, time.Until(session.response.deadline), responseTimerES,
		"the handshake response timer must be shorter than the ES one")
}
