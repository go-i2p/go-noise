package ratchet

import (
	"fmt"
	"testing"

	"github.com/go-i2p/crypto/rand"
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
// Session NextKey State
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

func TestSession_IncrementSendKeyID(t *testing.T) {
	session := createTestSession(t, true)

	err := session.IncrementSendKeyID()
	require.NoError(t, err)

	sendKeyID, _, _ := session.NextKeyState()
	assert.Equal(t, uint16(1), sendKeyID)
}

func TestSession_IncrementSendKeyID_MaxReached(t *testing.T) {
	session := createTestSession(t, true)
	session.sendKeyID = MaxKeyID

	err := session.IncrementSendKeyID()
	assert.Error(t, err, "Should error when key ID at maximum")
	assert.Contains(t, err.Error(), "maximum")
}

// ============================================================================
// DH Ratchet Step Queues NextKey Block
// ============================================================================

func TestPerformDHRatchetStep_QueuesNextKey(t *testing.T) {
	session := createTestSession(t, true)

	// Perform a DH ratchet step — this should queue a NextKey block.
	err := performDHRatchetStep(session)
	require.NoError(t, err)

	assert.True(t, session.HasPendingNextKeys(), "Should have pending NextKey after DH rotation")
	assert.NotNil(t, session.newEphemeralPub, "newEphemeralPub should be set")

	blocks := session.GetPendingNextKeys()
	require.Len(t, blocks, 1, "Should have exactly one pending NextKey block")

	// Verify the NextKey block contents.
	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent, "Forward NextKey should include the public key")
	assert.False(t, info.Reverse, "Should be a forward key")
	assert.True(t, info.RequestReverse, "First rotation should request reverse")
	assert.Equal(t, uint16(0), info.KeyID, "First key ID should be 0")
	assert.Equal(t, *session.newEphemeralPub, info.PublicKey, "Key should match newEphemeralPub")

	// After GetPendingNextKeys, the queue should be empty.
	assert.False(t, session.HasPendingNextKeys(), "Pending queue should be cleared after Get")
	assert.True(t, session.awaitingReverseKey, "Should be awaiting reverse key")
}

func TestPerformDHRatchetStep_ConsecutiveRotations(t *testing.T) {
	session := createTestSession(t, true)

	// Two consecutive DH ratchets should each queue a NextKey block.
	err := performDHRatchetStep(session)
	require.NoError(t, err)
	err = performDHRatchetStep(session)
	require.NoError(t, err)

	blocks := session.GetPendingNextKeys()
	assert.Len(t, blocks, 2, "Two rotations should queue two NextKey blocks")
}

// ============================================================================
// ProcessReceivedNextKey — Forward Key
// ============================================================================

func TestProcessReceivedNextKey_ForwardKey(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Simulate a forward NextKey from the sender.
	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: false,
		KeyID:          0,
		PublicKey:      newKey,
	}

	err := f.receiver.ProcessReceivedNextKey(f.tag, info)
	require.NoError(t, err, "Processing forward NextKey should succeed")
}

func TestProcessReceivedNextKey_ForwardKeyRequestsReverse(t *testing.T) {
	f := newLinkedSessionFixture(t)

	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0,
		PublicKey:      newKey,
	}

	err := f.receiver.ProcessReceivedNextKey(f.tag, info)
	require.NoError(t, err)

	// The receiver should now have a pending reverse NextKey to send back.
	session := lookupSessionByAnyTag(t, f.receiver)
	require.NotNil(t, session)

	session.mu.Lock()
	hasPending := session.HasPendingNextKeys()
	session.mu.Unlock()

	assert.True(t, hasPending, "Should have queued a reverse NextKey response")
}

// ============================================================================
// ProcessReceivedNextKey — Reverse Key
// ============================================================================

func TestProcessReceivedNextKey_ReverseKey(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Set awaitingReverseKey on the session to simulate having sent a forward key.
	session := lookupSessionByAnyTag(t, f.receiver)
	session.mu.Lock()
	session.awaitingReverseKey = true
	session.mu.Unlock()

	var reverseKey [32]byte
	_, _ = rand.Read(reverseKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        true,
		RequestReverse: false,
		KeyID:          0,
		PublicKey:      reverseKey,
	}

	err := f.receiver.ProcessReceivedNextKey(f.tag, info)
	require.NoError(t, err)

	session.mu.Lock()
	_, _, awaiting := session.NextKeyState()
	session.mu.Unlock()

	assert.False(t, awaiting, "awaitingReverseKey should be cleared after receiving reverse key")
}

// ============================================================================
// ProcessReceivedNextKey — Ack (No Key)
// ============================================================================

func TestProcessReceivedNextKey_AckNoKey(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Ack with no key: peer acknowledges with their existing key.
	info := NextKeyInfo{
		KeyPresent:     false,
		Reverse:        true,
		RequestReverse: false,
		KeyID:          0,
	}

	err := f.receiver.ProcessReceivedNextKey(f.tag, info)
	require.NoError(t, err, "Processing NextKey ack should succeed")
}

// ============================================================================
// ProcessReceivedNextKey — Error Cases
// ============================================================================

func TestProcessReceivedNextKey_UnknownTag(t *testing.T) {
	sm := createTestSessionManager(t)

	var unknownTag [8]byte
	unknownTag[0] = 0xFF

	info := NextKeyInfo{
		KeyPresent: true,
		KeyID:      0,
	}

	err := sm.ProcessReceivedNextKey(unknownTag, info)
	assert.Error(t, err, "Should error for unknown session tag")
	assert.Contains(t, err.Error(), "no session found")
}

// ============================================================================
// ProcessIncomingDHRatchet — Coverage Tests
// ============================================================================

func TestProcessIncomingDHRatchet_Success(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Generate a new DH key to simulate a peer ratchet.
	var newPubKey [32]byte
	_, _ = rand.Read(newPubKey[:])

	err := f.receiver.ProcessIncomingDHRatchet(f.tag, newPubKey)
	require.NoError(t, err, "ProcessIncomingDHRatchet should succeed with valid tag and key")
}

func TestProcessIncomingDHRatchet_UnknownTag(t *testing.T) {
	sm := createTestSessionManager(t)

	var unknownTag [8]byte
	unknownTag[0] = 0xDE

	var pubKey [32]byte
	_, _ = rand.Read(pubKey[:])

	err := sm.ProcessIncomingDHRatchet(unknownTag, pubKey)
	assert.Error(t, err, "Should error for unknown session tag")
	assert.Contains(t, err.Error(), "no session found")
}

func TestProcessIncomingDHRatchet_UpdatesReceivingChain(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Get the original receiving ratchets.
	session := lookupSessionByAnyTag(t, f.receiver)
	require.NotNil(t, session)

	session.mu.Lock()
	origRecvSym := session.RecvSymmetricRatchet
	origRecvTag := session.RecvTagRatchet
	session.mu.Unlock()

	// Process a DH ratchet.
	var newPubKey [32]byte
	_, _ = rand.Read(newPubKey[:])
	err := f.receiver.ProcessIncomingDHRatchet(f.tag, newPubKey)
	require.NoError(t, err)

	session.mu.Lock()
	newRecvSym := session.RecvSymmetricRatchet
	newRecvTag := session.RecvTagRatchet
	remotePub := session.RemotePublicKey
	session.mu.Unlock()

	assert.NotEqual(t, origRecvSym, newRecvSym, "RecvSymmetricRatchet should be replaced")
	assert.NotEqual(t, origRecvTag, newRecvTag, "RecvTagRatchet should be replaced")
	assert.Equal(t, newPubKey, remotePub, "RemotePublicKey should be updated")
}

func TestProcessIncomingDHRatchet_MultipleRotations(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Process multiple DH ratchets with different keys.
	for i := 0; i < 3; i++ {
		sessionTag := getAnyTag(t, f.receiver)

		var newPubKey [32]byte
		newPubKey[0] = byte(i + 1)
		_, _ = rand.Read(newPubKey[1:])

		err := f.receiver.ProcessIncomingDHRatchet(sessionTag, newPubKey)
		require.NoError(t, err, "DH ratchet %d should succeed", i)
	}
}

// ============================================================================
// Full NextKey Exchange Flow
// ============================================================================

func TestNextKeyExchange_FullFlow(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	destHash := mustBootstrapSession(t, sender, receiver)

	// Send a baseline ES message BEFORE DH ratchet to measure payload size.
	baselinePayload := []byte("baseline-msg")
	baselineEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, baselinePayload)
	require.NoError(t, err)

	// 2. Trigger DH ratchet on sender (artificially advance counter).
	sender.mu.RLock()
	senderSession := sender.sessions[destHash]
	sender.mu.RUnlock()
	require.NotNil(t, senderSession)

	senderSession.mu.Lock()
	senderSession.dhRatchetCounter = DHRatchetInterval - 1 // Will trigger on next encrypt
	senderSession.mu.Unlock()

	// 3. Encrypt a message — this triggers DH ratchet. The NextKey block is now
	// automatically serialized into the encrypted payload (consumed, not left pending).
	ratchetPayload := []byte("trigger-ratch") // same length as baseline for comparison
	ratchetEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, ratchetPayload)
	require.NoError(t, err)

	// 4. Verify the sender has NO pending NextKey blocks — they were consumed
	// and embedded in the ciphertext by encryptExistingSession.
	senderSession.mu.Lock()
	hasPending := senderSession.HasPendingNextKeys()
	senderSession.mu.Unlock()

	assert.False(t, hasPending, "Sender should NOT have pending NextKey after encryption (consumed into payload)")

	// 5. The ratchet-triggered message should be LARGER than the baseline because
	// it contains serialized NextKey block(s) in the payload (1-byte type +
	// 2-byte length + 3-byte flags/keyID + 32-byte pubkey = 38 bytes per block).
	assert.Greater(t, len(ratchetEnc), len(baselineEnc),
		"ES message with NextKey block should be larger than baseline")

	// 6. Verify the sender is now awaiting a reverse key.
	senderSession.mu.Lock()
	sendKeyID, _, awaiting := senderSession.NextKeyState()
	senderSession.mu.Unlock()
	assert.True(t, awaiting, "Sender should be awaiting reverse key after DH rotation")
	assert.Equal(t, uint16(1), sendKeyID, "sendKeyID should have been incremented")

	// 7. Simulate the receiver processing the forward NextKey manually (since
	// the DH ratchet changes the sender's tag set, the receiver cannot decrypt
	// the ES message until it processes the NextKey — that is a separate concern).
	// Build a forward NextKey info matching what the sender would have sent.
	senderSession.mu.Lock()
	pubKey := senderSession.newEphemeralPub
	senderSession.mu.Unlock()
	require.NotNil(t, pubKey, "sender should have a new ephemeral pub key")

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0, // the block carries the old ID (pre-increment)
		PublicKey:      *pubKey,
	}

	recvTag := getAnyTag(t, receiver)
	err = receiver.ProcessReceivedNextKey(recvTag, info)
	require.NoError(t, err)

	// 8. Receiver should have a reverse NextKey queued.
	recvSession := lookupSessionByAnyTag(t, receiver)
	require.NotNil(t, recvSession)

	recvSession.mu.Lock()
	reverseBlocks := recvSession.GetPendingNextKeys()
	recvSession.mu.Unlock()

	require.NotEmpty(t, reverseBlocks, "Receiver should have queued a reverse NextKey")

	reverseInfo, err := reverseBlocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, reverseInfo.KeyPresent)
	assert.True(t, reverseInfo.Reverse)
	assert.False(t, reverseInfo.RequestReverse)

	_ = baselineEnc // used only for size comparison
}

// ============================================================================
// MaxKeyID
// ============================================================================

func TestMaxKeyIDConstant(t *testing.T) {
	assert.Equal(t, uint16(32767), uint16(MaxKeyID),
		"MaxKeyID should be 32767 per the spec")
}

func TestGenerateReverseNextKey_MaxKeyID(t *testing.T) {
	f := newLinkedSessionFixture(t)

	// Set the session's sendKeyID to MaxKeyID so reverse key generation fails.
	session := lookupSessionByAnyTag(t, f.receiver)
	session.mu.Lock()
	session.sendKeyID = MaxKeyID
	session.mu.Unlock()

	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0,
		PublicKey:      newKey,
	}

	err := f.receiver.ProcessReceivedNextKey(f.tag, info)
	assert.Error(t, err, "Should error when send key ID is at maximum")
}

// ============================================================================
// GetPublicKey (was at 0% coverage)
// ============================================================================

func TestGetPublicKey(t *testing.T) {
	sm := createTestSessionManager(t)
	pubKey := sm.GetPublicKey()

	allZero := true
	for _, b := range pubKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Public key should not be all zeros")
}

func TestGetPublicKey_DifferentManagers(t *testing.T) {
	sm1 := createTestSessionManager(t)
	sm2 := createTestSessionManager(t)

	assert.NotEqual(t, sm1.GetPublicKey(), sm2.GetPublicKey(),
		"Different managers should have different public keys")
}

// ============================================================================
// sendKeyID increment in performDHRatchetStep
// ============================================================================

// TestPerformDHRatchetStep_IncrementsSendKeyID verifies that the session's
// sendKeyID is incremented after a successful DH ratchet step.
// Spec ref: ecies.rst §"Key and Tag Set IDs" — tag set ID advances when
// the sender issues a new forward key.
func TestPerformDHRatchetStep_IncrementsSendKeyID(t *testing.T) {
	session := createTestSession(t, true)

	assert.Equal(t, uint16(0), session.sendKeyID, "sendKeyID must start at 0")

	err := performDHRatchetStep(session)
	require.NoError(t, err)

	assert.Equal(t, uint16(1), session.sendKeyID,
		"sendKeyID must be 1 after first DH ratchet step")

	// The queued NextKey block must carry the old ID (0) so the peer
	// can associate the reverse key with the correct tag set.
	blocks := session.GetPendingNextKeys()
	require.Len(t, blocks, 1)
	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.Equal(t, uint16(0), info.KeyID,
		"NextKey block must carry the pre-increment key ID")
}

// TestPerformDHRatchetStep_ConsecutiveRotations_KeyIDsAdvance verifies that
// consecutive DH ratchet steps produce NextKey blocks with monotonically
// increasing key IDs (0, 1, 2, …) and that sendKeyID tracks correctly.
func TestPerformDHRatchetStep_ConsecutiveRotations_KeyIDsAdvance(t *testing.T) {
	session := createTestSession(t, true)

	for i := 0; i < 3; i++ {
		err := performDHRatchetStep(session)
		require.NoError(t, err, "step %d should succeed", i)
	}

	assert.Equal(t, uint16(3), session.sendKeyID, "sendKeyID must be 3 after three steps")

	blocks := session.GetPendingNextKeys()
	require.Len(t, blocks, 3)

	for i, block := range blocks {
		info, err := block.NextKey()
		require.NoError(t, err)
		assert.Equal(t, uint16(i), info.KeyID,
			"block %d must carry key ID %d", i, i)
	}
}

// TestPerformDHRatchetStep_MaxKeyID_ReturnsError verifies that a DH ratchet
// step is refused when sendKeyID has reached MaxKeyID, preventing key-set ID
// overflow. Spec ref: ecies.rst §"Key and Tag Set IDs".
func TestPerformDHRatchetStep_MaxKeyID_ReturnsError(t *testing.T) {
	session := createTestSession(t, true)
	session.sendKeyID = MaxKeyID

	err := performDHRatchetStep(session)
	assert.Error(t, err, "performDHRatchetStep must error when sendKeyID is at MaxKeyID")
	assert.Contains(t, err.Error(), "maximum")
	assert.Equal(t, uint16(MaxKeyID), session.sendKeyID,
		"sendKeyID must not change on error")
	assert.False(t, session.HasPendingNextKeys(),
		"no NextKey block should be queued on error")
}

// ============================================================================
// generateReverseNextKey — sendKeyID increment
// ============================================================================

// TestGenerateReverseNextKey_IncrementsSendKeyID verifies that generateReverseNextKey
// increments sendKeyID after queuing the reverse block. Without this increment, a
// subsequent forward rotation via performDHRatchetStep would produce a NextKey block
// with the same keyID as the reverse block, confusing the peer's keyID tracking.
func TestGenerateReverseNextKey_IncrementsSendKeyID(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	mustBootstrapSession(t, sender, receiver)

	// Look up the receiver's session and record the initial sendKeyID.
	session := lookupSessionByAnyTag(t, receiver)
	session.mu.Lock()
	initialKeyID := session.sendKeyID
	session.mu.Unlock()

	// Simulate a forward NextKey from the sender requesting a reverse.
	sessionTag := getAnyTag(t, receiver)
	var newKey [32]byte
	_, _ = rand.Read(newKey[:])
	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0,
		PublicKey:      newKey,
	}
	err := receiver.ProcessReceivedNextKey(sessionTag, info)
	require.NoError(t, err)

	// After generating the reverse key, sendKeyID must have been incremented.
	session.mu.Lock()
	afterReverseKeyID := session.sendKeyID
	pending := session.GetPendingNextKeys()
	session.mu.Unlock()

	assert.Equal(t, initialKeyID+1, afterReverseKeyID,
		"sendKeyID must be incremented after generating a reverse NextKey")
	require.Len(t, pending, 1, "exactly one reverse NextKey block should be queued")

	// The block should carry the OLD (pre-increment) keyID.
	blockInfo, err := pending[0].NextKey()
	require.NoError(t, err)
	assert.Equal(t, initialKeyID, blockInfo.KeyID,
		"reverse NextKey block must carry the pre-increment keyID")
	assert.True(t, blockInfo.Reverse, "block must be flagged as reverse")
}

// TestForwardAndReverse_NoKeyIDCollision verifies the double-rotation scenario:
//  1. Forward rotation (performDHRatchetStep) — creates forward block with keyID=N, sendKeyID→N+1
//  2. Reverse response (generateReverseNextKey) — creates reverse block with keyID=N+1, sendKeyID→N+2
//  3. Another forward rotation — creates forward block with keyID=N+2
//
// All three keyIDs must be distinct, preventing peer-side confusion.
func TestForwardAndReverse_NoKeyIDCollision(t *testing.T) {
	session := createTestSession(t, true)

	sm := createTestSessionManager(t)

	// Step 1: Forward rotation.
	err := performDHRatchetStep(session)
	require.NoError(t, err)
	forwardBlocks := session.GetPendingNextKeys()
	require.Len(t, forwardBlocks, 1)
	fwdInfo1, err := forwardBlocks[0].NextKey()
	require.NoError(t, err)

	// Step 2: Reverse response.
	err = sm.generateReverseNextKey(session)
	require.NoError(t, err)
	reverseBlocks := session.GetPendingNextKeys()
	require.Len(t, reverseBlocks, 1)
	revInfo, err := reverseBlocks[0].NextKey()
	require.NoError(t, err)

	// Step 3: Another forward rotation.
	err = performDHRatchetStep(session)
	require.NoError(t, err)
	forwardBlocks2 := session.GetPendingNextKeys()
	require.Len(t, forwardBlocks2, 1)
	fwdInfo2, err := forwardBlocks2[0].NextKey()
	require.NoError(t, err)

	// All three keyIDs must be distinct.
	allIDs := []uint16{fwdInfo1.KeyID, revInfo.KeyID, fwdInfo2.KeyID}
	seen := make(map[uint16]bool)
	for _, id := range allIDs {
		assert.False(t, seen[id],
			"keyID %d appears more than once in [forward=%d, reverse=%d, forward2=%d]",
			id, allIDs[0], allIDs[1], allIDs[2])
		seen[id] = true
	}

	// Verify the expected sequence: 0, 1, 2.
	assert.Equal(t, uint16(0), fwdInfo1.KeyID, "first forward block should carry keyID=0")
	assert.Equal(t, uint16(1), revInfo.KeyID, "reverse block should carry keyID=1")
	assert.Equal(t, uint16(2), fwdInfo2.KeyID, "second forward block should carry keyID=2")

	t.Logf("KeyID sequence: forward=%d, reverse=%d, forward=%d — no collision",
		fwdInfo1.KeyID, revInfo.KeyID, fwdInfo2.KeyID)
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// attemptDHRatchetRotation — failure branches
// ============================================================================

// TestAttemptDHRatchetRotation_FailOnce_ContinuesSymRatchet verifies the
// "fail but continue" branch: when performDHRatchetStep returns an error but
// consecutiveDHFailures has not yet hit MaxConsecutiveDHFailures,
// attemptDHRatchetRotation swallows the error and returns nil, allowing the
// session to keep sending via the symmetric ratchet.
//
// The sendKeyID=MaxKeyID trick forces performDHRatchetStep to error without
// needing to mock the DH ratchet or break heap state.
func TestAttemptDHRatchetRotation_FailOnce_ContinuesSymRatchet(t *testing.T) {
	session := createTestSession(t, true)

	// One increment will bring dhRatchetCounter to DHRatchetInterval, triggering
	// the ratchet‐step attempt.
	session.dhRatchetCounter = DHRatchetInterval - 1
	// Force performDHRatchetStep to return an error.
	session.sendKeyID = MaxKeyID

	rotErr := attemptDHRatchetRotation(session)
	assert.NoError(t, rotErr,
		"first failure (below threshold) must be swallowed and return nil")
	assert.Equal(t, uint32(1), session.consecutiveDHFailures,
		"consecutiveDHFailures must be incremented on first failure")
	assert.False(t, session.HasPendingNextKeys(),
		"no NextKey block should be queued on failed step")
}

// TestAttemptDHRatchetRotation_MaxConsecutiveFailures_ReturnsError verifies
// the "fatal failure" branch: when consecutiveDHFailures reaches
// MaxConsecutiveDHFailures, attemptDHRatchetRotation propagates the error so
// the caller can tear down the session rather than silently forfeiting forward
// secrecy indefinitely.
func TestAttemptDHRatchetRotation_MaxConsecutiveFailures_ReturnsError(t *testing.T) {
	session := createTestSession(t, true)

	// Pre-fill so one more failure crosses the threshold.
	session.dhRatchetCounter = DHRatchetInterval - 1
	session.sendKeyID = MaxKeyID
	session.consecutiveDHFailures = MaxConsecutiveDHFailures - 1

	rotErr := attemptDHRatchetRotation(session)
	require.Error(t, rotErr,
		"hitting MaxConsecutiveDHFailures must return an error")
	assert.Contains(t, rotErr.Error(), "consecutive",
		"error message must mention consecutive failure count")
	assert.Equal(t, uint32(MaxConsecutiveDHFailures), session.consecutiveDHFailures)
}

// TestAttemptDHRatchetRotation_BelowInterval_NoRatchetAttempted verifies the
// counter-gating path: when dhRatchetCounter is below DHRatchetInterval, no
// DH ratchet step is attempted and nil is returned immediately.
// This covers the fast path that runs for the vast majority of messages.
func TestAttemptDHRatchetRotation_BelowInterval_NoRatchetAttempted(t *testing.T) {
	session := createTestSession(t, true)

	// Counter starts at 0; first increment → 1, which is < DHRatchetInterval (50).
	initialKeyID := session.sendKeyID

	rotErr := attemptDHRatchetRotation(session)
	assert.NoError(t, rotErr, "below-interval call must return nil")
	assert.Equal(t, uint32(1), session.dhRatchetCounter,
		"dhRatchetCounter must be incremented")
	assert.Equal(t, initialKeyID, session.sendKeyID,
		"sendKeyID must not change when no ratchet step was attempted")
	assert.False(t, session.HasPendingNextKeys(),
		"no pending NextKey blocks when no ratchet step was attempted")
}

// getAnyTag extracts a tag from the session manager's tag index.
// It grabs a fresh tag by peeking at the index. The tag IS consumed by this lookup.
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

// TestPrependPendingNextKeys_WithBlocks verifies that pending NextKey blocks
// are serialized and prepended to the plaintext. The resulting payload should
// parse into the NextKey block(s) followed by the original data.
func TestPrependPendingNextKeys_WithBlocks(t *testing.T) {
	session := createTestSession(t, true)

	// Queue a forward NextKey block manually.
	var testPub [32]byte
	_, _ = rand.Read(testPub[:])
	block := NewNextKeyBlock(0, &testPub, false, true)
	session.pendingNextKeys = append(session.pendingNextKeys, block)

	// Build a GarlicClove payload as the original plaintext.
	originalPayload := []byte{byte(BlockGarlicClove), 0, 5, 'h', 'e', 'l', 'l', 'o'}

	result, err := prependPendingNextKeys(session, originalPayload)
	require.NoError(t, err)

	// result should be larger than original.
	assert.Greater(t, len(result), len(originalPayload))

	// The pending queue should now be empty.
	assert.False(t, session.HasPendingNextKeys())

	// Parse the combined result — should start with a NextKey block.
	blocks, err := ParsePayload(result)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(blocks), 2, "should have NextKey + original blocks")
	assert.Equal(t, BlockNextKey, blocks[0].Type)

	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.Equal(t, testPub, info.PublicKey)

	// The rest should be the original payload.
	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
	assert.Equal(t, []byte("hello"), blocks[1].Data)
}

// ============================================================================
// Integration test: >50 ES messages with DH ratchet
// ============================================================================

// TestDHRatchetNextKeyTransmission_Over50Messages sends more than
// DHRatchetInterval (50) consecutive ES messages through EncryptGarlicMessage
// and verifies that:
//   - The DH ratchet rotation fires at the expected interval.
//   - NextKey blocks are consumed (not left pending) during encryption.
//   - The encrypted payload grows when a NextKey block is included.
//   - The sender's sendKeyID advances after rotation.
//
// This test covers the critical integration gap identified in the audit:
// NextKey blocks must be transmitted inside ES messages for forward secrecy.
func TestDHRatchetNextKeyTransmission_Over50Messages(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Bootstrap the session: NS → NSR.
	destHash = mustBootstrapSession(t, sender, receiver)

	sender.mu.RLock()
	senderSession := sender.sessions[destHash]
	sender.mu.RUnlock()
	require.NotNil(t, senderSession)

	// Track metrics across the message burst.
	var (
		rotationCount   int
		lastRotationMsg int
	)

	// Send 60 messages (> DHRatchetInterval = 50).
	const totalMessages = 60
	for i := 0; i < totalMessages; i++ {
		payload := []byte(fmt.Sprintf("msg-%d", i))
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err, "encrypt message %d", i)
		require.NotEmpty(t, enc, "ciphertext should not be empty for message %d", i)

		// After encryption, NextKey blocks should never be left pending.
		senderSession.mu.Lock()
		hasPending := senderSession.HasPendingNextKeys()
		sendKeyID := senderSession.sendKeyID
		dhCounter := senderSession.dhRatchetCounter
		senderSession.mu.Unlock()

		assert.False(t, hasPending,
			"message %d: pending NextKey blocks should have been consumed by encryption", i)

		// Detect when a DH ratchet rotation occurred: sendKeyID advances
		// and dhRatchetCounter resets to 0.
		if sendKeyID > 0 && dhCounter == 0 {
			if rotationCount == 0 {
				rotationCount++
				lastRotationMsg = i
			}
		}
	}

	// Verify at least one DH ratchet rotation occurred.
	assert.GreaterOrEqual(t, rotationCount, 1,
		"should have at least 1 DH ratchet rotation in %d messages", totalMessages)

	// The first rotation should happen around message DHRatchetInterval (50).
	// Allow ±2 for off-by-one in counter initialization.
	assert.InDelta(t, DHRatchetInterval, lastRotationMsg, 2,
		"first DH ratchet should fire near message %d", DHRatchetInterval)

	// sendKeyID should have advanced from 0.
	senderSession.mu.Lock()
	finalKeyID := senderSession.sendKeyID
	senderSession.mu.Unlock()
	assert.Greater(t, finalKeyID, uint16(0),
		"sendKeyID should advance after DH ratchet rotation")

	t.Logf("Sent %d ES messages; DH ratchet fired at message ~%d; final sendKeyID=%d",
		totalMessages, lastRotationMsg, finalKeyID)
}
