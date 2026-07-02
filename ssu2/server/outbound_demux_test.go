package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestKey returns a reproducible 32-byte key filled with value v.
func makeTestKey(v byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = v
	}
	return k
}

// makeSessCreatedProtector builds a HeaderProtector suitable for
// HeaderTypeSessionCreated using remoteIntroKey as k1 and sessCreateKey as k2.
func makeSessCreatedProtector(remoteIntroKey, sessCreateKey []byte) (*HeaderProtector, error) {
	return wire.NewHeaderProtector(remoteIntroKey, sessCreateKey, wire.HeaderTypeSessionCreated)
}

// makeRetryProtector builds a HeaderProtector for HeaderTypeRetry using
// remoteIntroKey for both k1 and k2.
func makeRetryProtector(remoteIntroKey []byte) (*HeaderProtector, error) {
	return wire.NewHeaderProtector(remoteIntroKey, remoteIntroKey, wire.HeaderTypeRetry)
}

// buildMinimalPacketData builds the smallest byte slice that satisfies the
// header-protection validation (LongHeaderSize + 24 bytes for IV extraction)
// with the dest conn ID written big-endian into bytes 0–7.
func buildMinimalPacketData(destConnID uint64) []byte {
	buf := make([]byte, LongHeaderSize+24) // 56 bytes minimum
	binary.BigEndian.PutUint64(buf[0:8], destConnID)
	// Bytes 8–55 are zero; the ChaCha20 IV is extracted from the last 24 bytes.
	return buf
}

// ─── PendingOutboundRegistry.Register ─────────────────────────────────────────

// TestPendingOutboundRegistry_Register_NilConn verifies that Register rejects nil.
func TestPendingOutboundRegistry_Register_NilConn(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	err := reg.Register(0xDEAD, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// TestPendingOutboundRegistry_Register_Duplicate verifies that registering the
// same source conn ID twice is rejected.
func TestPendingOutboundRegistry_Register_Duplicate(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(0xABCD, conn, nil))
	err := reg.Register(0xABCD, conn, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

// TestPendingOutboundRegistry_Register_CapacityExceeded verifies the max-pending cap.
func TestPendingOutboundRegistry_Register_CapacityExceeded(t *testing.T) {
	reg := NewPendingOutboundRegistry(1, 0)
	conn1 := NewMockSSU2Conn(0)
	conn2 := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(1, conn1, nil))
	err := reg.Register(2, conn2, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capacity exceeded")
}

// ─── PendingOutboundRegistry.SetProtector ─────────────────────────────────────

// TestPendingOutboundRegistry_SetProtector_SessionNotFound verifies that
// SetProtector returns an error for an unknown session.
func TestPendingOutboundRegistry_SetProtector_SessionNotFound(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	p, err := makeSessCreatedProtector(makeTestKey(1), makeTestKey(2))
	require.NoError(t, err)
	err = reg.SetProtector(0xFFFF, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestPendingOutboundRegistry_SetProtector_NilRejected verifies that a nil
// protector is rejected (preventing accidental nil overwrites).
func TestPendingOutboundRegistry_SetProtector_NilRejected(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(1, conn, nil))
	err := reg.SetProtector(1, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// TestPendingOutboundRegistry_SetProtector_Idempotent verifies that calling
// SetProtector twice with a valid protector succeeds both times (idempotent update).
func TestPendingOutboundRegistry_SetProtector_Idempotent(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(1, conn, nil))
	p, err := makeSessCreatedProtector(makeTestKey(1), makeTestKey(2))
	require.NoError(t, err)
	require.NoError(t, reg.SetProtector(1, p))
	// Second call (e.g. after Retry re-derives the same key) must also succeed.
	require.NoError(t, reg.SetProtector(1, p))
}

// ─── LookupAndDeobfuscate nil-protector passthrough (Defect A regression) ────

// TestLookupAndDeobfuscate_NilProtectorFails is the regression test for
// Defect A: a nil headerProtector must now return an error rather than
// silently passing obfuscated bytes through as-if plaintext.
func TestLookupAndDeobfuscate_NilProtectorFails(t *testing.T) {
	const connID = uint64(0x1234567890ABCDEF)
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	// Register with nil retryProtector AND no SetProtector call → headerProtector is nil.
	require.NoError(t, reg.Register(connID, conn, nil))

	pkt := buildMinimalPacketData(connID)
	_, _, err := reg.LookupAndDeobfuscate(connID, pkt)
	require.Error(t, err, "nil headerProtector must not silently pass bytes through")
	assert.Contains(t, err.Error(), "not yet installed")
}

// TestLookupAndDeobfuscate_NotFound verifies (nil, nil, nil) when no session matches.
func TestLookupAndDeobfuscate_NotFound(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	pkt := buildMinimalPacketData(0xDEAD)
	conn, data, err := reg.LookupAndDeobfuscate(0xDEAD, pkt)
	assert.NoError(t, err)
	assert.Nil(t, conn)
	assert.Nil(t, data)
}

// ─── TrialDeobfuscate (Defect B fix) ──────────────────────────────────────────

// TestTrialDeobfuscate_SessionCreated is the primary regression test for Defect B.
// It simulates the listener receiving a header-protected SessionCreated reply,
// verifies TrialDeobfuscate correctly deobfuscates it, and confirms the returned
// conn and cleartext data are correct.
func TestTrialDeobfuscate_SessionCreated(t *testing.T) {
	const connID = uint64(0xFEEDFACECAFEBABE)

	remoteIntroKey := makeTestKey(0x11)
	sessCreateKey := makeTestKey(0x22)

	// Build the protector the responder uses to encrypt SessionCreated header.
	senderProtector, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)

	// Build the matching protector the initiator uses to decrypt.
	// (Same key material from the initiator's perspective.)
	receiverProtector, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)

	// Build a packet whose cleartext dest conn ID == connID.
	pkt := buildMinimalPacketData(connID)

	// Encrypt (as the responder would).
	require.NoError(t, senderProtector.EncryptHeader(pkt))

	// Verify the raw bytes no longer match connID (header protection is active).
	rawDestID := binary.BigEndian.Uint64(pkt[0:8])
	assert.NotEqual(t, connID, rawDestID, "header protection should mask bytes 0-7")

	// Register the pending session with the receiver-side protector.
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(connID, conn, nil))
	require.NoError(t, reg.SetProtector(connID, receiverProtector))

	// TrialDeobfuscate must find the session and return cleartext bytes.
	gotConn, gotData, err := reg.TrialDeobfuscate(pkt)
	require.NoError(t, err)
	require.NotNil(t, gotConn, "TrialDeobfuscate should return the matching conn")
	require.NotNil(t, gotData, "TrialDeobfuscate should return deobfuscated data")

	// The decrypted dest conn ID must match the expected connID.
	decryptedDestID := binary.BigEndian.Uint64(gotData[0:8])
	assert.Equal(t, connID, decryptedDestID, "decrypted dest conn ID must match sourceConnID")
}

// TestTrialDeobfuscate_RetryPacket verifies that a Retry packet (protected with
// remoteIntroKey for both k1 and k2) is deobfuscated via the retryProtector
// registered at creation time — before SessCreateHeaderKey is available.
func TestTrialDeobfuscate_RetryPacket(t *testing.T) {
	const connID = uint64(0xAABBCCDDEEFF0011)

	remoteIntroKey := makeTestKey(0x33)

	// Build sender-side Retry protector (responder uses this to encrypt Retry).
	senderProtector, err := makeRetryProtector(remoteIntroKey)
	require.NoError(t, err)

	// Build receiver-side Retry protector (initiator uses this to decrypt).
	receiverProtector, err := makeRetryProtector(remoteIntroKey)
	require.NoError(t, err)

	// Build a packet with the cleartext dest conn ID.
	pkt := buildMinimalPacketData(connID)
	require.NoError(t, senderProtector.EncryptHeader(pkt))

	rawDestID := binary.BigEndian.Uint64(pkt[0:8])
	assert.NotEqual(t, connID, rawDestID, "Retry header protection should mask bytes 0-7")

	// Register with retryProtector but NO headerProtector (SessCreate key not yet derived).
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(connID, conn, receiverProtector))
	// headerProtector intentionally not set (nil) — this is the pre-key state.

	gotConn, gotData, err := reg.TrialDeobfuscate(pkt)
	require.NoError(t, err)
	require.NotNil(t, gotConn, "TrialDeobfuscate should route via retryProtector")
	require.NotNil(t, gotData)

	decryptedDestID := binary.BigEndian.Uint64(gotData[0:8])
	assert.Equal(t, connID, decryptedDestID)
}

// TestTrialDeobfuscate_WrongKey verifies that TrialDeobfuscate returns (nil, nil, nil)
// when no pending session's protector decrypts to a matching conn ID.
func TestTrialDeobfuscate_WrongKey(t *testing.T) {
	const connID = uint64(0x1111111111111111)
	const differentConnID = uint64(0x2222222222222222)

	sessCreateKey := makeTestKey(0x44)
	remoteIntroKey := makeTestKey(0x55)

	// Encrypt with one connID but register a session expecting a different connID.
	senderProtector, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)

	pkt := buildMinimalPacketData(connID)
	require.NoError(t, senderProtector.EncryptHeader(pkt))

	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	receiverProtector, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)
	require.NoError(t, reg.Register(differentConnID, conn, nil))
	require.NoError(t, reg.SetProtector(differentConnID, receiverProtector))

	// Must not match because the decrypted dest ID ≠ differentConnID.
	gotConn, gotData, err := reg.TrialDeobfuscate(pkt)
	assert.NoError(t, err)
	assert.Nil(t, gotConn, "no match expected for wrong conn ID")
	assert.Nil(t, gotData)
}

// TestTrialDeobfuscate_NoSessions verifies that TrialDeobfuscate with an empty
// registry returns (nil, nil, nil) without error.
func TestTrialDeobfuscate_NoSessions(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	pkt := buildMinimalPacketData(0xABCD)
	gotConn, gotData, err := reg.TrialDeobfuscate(pkt)
	assert.NoError(t, err)
	assert.Nil(t, gotConn)
	assert.Nil(t, gotData)
}

// TestTrialDeobfuscate_TooShort verifies that a packet shorter than 8 bytes is
// handled gracefully (no panic, returns nil).
func TestTrialDeobfuscate_TooShort(t *testing.T) {
	reg := NewPendingOutboundRegistry(0, 0)
	gotConn, gotData, err := reg.TrialDeobfuscate([]byte{0x01, 0x02})
	assert.NoError(t, err)
	assert.Nil(t, gotConn)
	assert.Nil(t, gotData)
}

// TestTrialDeobfuscate_PostRetrySetProtectorUpdate verifies the Retry flow:
// after a Retry round-trip, SetProtector is called again (idempotent) and
// subsequent SessionCreated packets are deobfuscated correctly.
func TestTrialDeobfuscate_PostRetrySetProtectorUpdate(t *testing.T) {
	const connID = uint64(0xDEADBEEF12345678)

	remoteIntroKey := makeTestKey(0x66)
	sessCreateKey := makeTestKey(0x77)

	retryReceiver, err := makeRetryProtector(remoteIntroKey)
	require.NoError(t, err)

	// Step 1: Register with retryProtector only.
	reg := NewPendingOutboundRegistry(0, 0)
	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(connID, conn, retryReceiver))

	// Step 2: Simulate Retry arrives before SessCreate key is installed.
	retrySender, err := makeRetryProtector(remoteIntroKey)
	require.NoError(t, err)
	retryPkt := buildMinimalPacketData(connID)
	require.NoError(t, retrySender.EncryptHeader(retryPkt))

	gotConn, _, err := reg.TrialDeobfuscate(retryPkt)
	require.NoError(t, err)
	require.NotNil(t, gotConn, "Retry must be demuxed before SessCreate key is available")

	// Step 3: After re-sending SessionRequest with token, SessCreate key arrives.
	sessCreatedProtector, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)
	require.NoError(t, reg.SetProtector(connID, sessCreatedProtector))

	// Step 4: SessionCreated arrives — must be demuxed via the new headerProtector.
	scSender, err := makeSessCreatedProtector(remoteIntroKey, sessCreateKey)
	require.NoError(t, err)
	scPkt := buildMinimalPacketData(connID)
	require.NoError(t, scSender.EncryptHeader(scPkt))

	gotConn, gotData, err := reg.TrialDeobfuscate(scPkt)
	require.NoError(t, err)
	require.NotNil(t, gotConn, "SessionCreated must be demuxed after SetProtector")
	require.NotNil(t, gotData)
	assert.Equal(t, connID, binary.BigEndian.Uint64(gotData[0:8]))
}

// TestTrialDeobfuscate_MultiplePendingSessions verifies correct isolation when
// multiple outbound sessions are registered simultaneously.
func TestTrialDeobfuscate_MultiplePendingSessions(t *testing.T) {
	const connA = uint64(0xAAAAAAAAAAAAAAAA)
	const connB = uint64(0xBBBBBBBBBBBBBBBB)

	remoteIntroKeyA := makeTestKey(0x0A)
	sessCreateKeyA := makeTestKey(0x1A)
	remoteIntroKeyB := makeTestKey(0x0B)
	sessCreateKeyB := makeTestKey(0x1B)

	senderA, err := makeSessCreatedProtector(remoteIntroKeyA, sessCreateKeyA)
	require.NoError(t, err)
	senderB, err := makeSessCreatedProtector(remoteIntroKeyB, sessCreateKeyB)
	require.NoError(t, err)
	receiverA, err := makeSessCreatedProtector(remoteIntroKeyA, sessCreateKeyA)
	require.NoError(t, err)
	receiverB, err := makeSessCreatedProtector(remoteIntroKeyB, sessCreateKeyB)
	require.NoError(t, err)

	connObjA := NewMockSSU2Conn(0)
	connObjB := NewMockSSU2Conn(0)

	reg := NewPendingOutboundRegistry(0, 0)
	require.NoError(t, reg.Register(connA, connObjA, nil))
	require.NoError(t, reg.Register(connB, connObjB, nil))
	require.NoError(t, reg.SetProtector(connA, receiverA))
	require.NoError(t, reg.SetProtector(connB, receiverB))

	// Build SessionCreated for session A.
	pktA := buildMinimalPacketData(connA)
	require.NoError(t, senderA.EncryptHeader(pktA))

	// Build SessionCreated for session B.
	pktB := buildMinimalPacketData(connB)
	require.NoError(t, senderB.EncryptHeader(pktB))

	// A's packet must map to connObjA.
	gotConn, gotData, err := reg.TrialDeobfuscate(pktA)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	assert.Equal(t, connObjA, gotConn, "pktA must route to connObjA")
	assert.Equal(t, connA, binary.BigEndian.Uint64(gotData[0:8]))

	// B's packet must map to connObjB.
	gotConn, gotData, err = reg.TrialDeobfuscate(pktB)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	assert.Equal(t, connObjB, gotConn, "pktB must route to connObjB")
	assert.Equal(t, connB, binary.BigEndian.Uint64(gotData[0:8]))
}

// ─── Cleanup ──────────────────────────────────────────────────────────────────

// TestPendingOutboundRegistry_Cleanup tests the stale-entry cleanup goroutine.
func TestPendingOutboundRegistry_Cleanup(t *testing.T) {
	timeout := 50 * time.Millisecond
	reg := NewPendingOutboundRegistry(0, timeout)
	reg.StartCleanup()
	defer reg.StopCleanup()

	conn := NewMockSSU2Conn(0)
	require.NoError(t, reg.Register(1, conn, nil))
	assert.Equal(t, 1, reg.Count())

	// Wait for cleanup to run (2× timeout for margin).
	time.Sleep(timeout * 3)
	assert.Equal(t, 0, reg.Count(), "stale entry should be removed by cleanup goroutine")
}
