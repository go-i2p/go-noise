package ratchet

import (
	"crypto/sha256"
	"testing"

	"github.com/go-i2p/crypto/hmac"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Noise IK Handshake State
// ============================================================================

// noiseIKHandshakePair holds both sides of a Noise IK handshake after message 1
// has been written and read, ready for message 2 (NSR).
type noiseIKHandshakePair struct {
	initiator *SessionManager
	responder *SessionManager
	iHS       *noiseHandshakeState
	rHS       *noiseHandshakeState
}

// ikMessage1Result holds all values returned by a writeNoiseIKMessage1 /
// readNoiseIKMessage1 round-trip.
type ikMessage1Result struct {
	initiator    *SessionManager
	responder    *SessionManager
	iHS          *noiseHandshakeState
	rHS          *noiseHandshakeState
	initiatorPub [32]byte
	isUnbound    bool
}

// mustWriteAndReadIKMessage1 creates an initiator and responder, writes an IK
// message 1 with the given payload, reads it back, and returns all results.
func mustWriteAndReadIKMessage1(t testing.TB, payload []byte) ikMessage1Result {
	t.Helper()
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg1, _, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)

	return ikMessage1Result{
		initiator:    initiator,
		responder:    responder,
		iHS:          iHS,
		initiatorPub: result.initiatorStaticPub,
		isUnbound:    result.isUnbound,
		rHS:          result.hs,
	}
}

// setupNoiseIKHandshake creates an initiator and responder, writes and reads
// Noise IK message 1 ("ns"), and returns the handshake states for message 2.
func setupNoiseIKHandshake(t testing.TB) noiseIKHandshakePair {
	t.Helper()
	r := mustWriteAndReadIKMessage1(t, []byte("ns"))
	return noiseIKHandshakePair{
		initiator: r.initiator,
		responder: r.responder,
		iHS:       r.iHS,
		rHS:       r.rHS,
	}
}

// hashPubKey computes SHA-256(pubKey) to create a session hash, matching
// how session_manager.go uses types.SHA256 for session lookup keys.
func hashPubKey(pub [32]byte) [32]byte {
	return sha256.Sum256(pub[:])
}

// initNoiseIKWithMixedKey creates a Noise IK symmetric state with a random
// responder public key and a random cipher key already mixed in.
func initNoiseIKWithMixedKey(t *testing.T) *noise.SymmetricState {
	t.Helper()
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)
	ns := initNoiseIK(respPub)
	ikm := make([]byte, 32)
	_, err = rand.Read(ikm)
	require.NoError(t, err)
	ns.MixKey(ikm)
	return ns
}

func TestNoiseIKState_MixHash(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns1 := initNoiseIK(respPub)
	ns2 := initNoiseIK(respPub)

	assert.Equal(t, ns1.HandshakeHash(), ns2.HandshakeHash(), "Same inputs should produce same initial state")

	ns1.MixHash([]byte("test data"))
	assert.NotEqual(t, ns1.HandshakeHash(), ns2.HandshakeHash(), "MixHash should change the state")

	ns2.MixHash([]byte("test data"))
	assert.Equal(t, ns1.HandshakeHash(), ns2.HandshakeHash(), "Same MixHash inputs should produce same state")
}

// initFreshNoiseIK creates a Noise IK symmetric state with a random responder
// public key, asserts it has no cipher key, and returns the state.
func initFreshNoiseIK(t *testing.T) *noise.SymmetricState {
	t.Helper()
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)
	ns := initNoiseIK(respPub)
	assert.False(t, ns.HasKey(), "Initial state should not have a cipher key")
	return ns
}

func TestNoiseIKState_MixKey(t *testing.T) {
	ns := initFreshNoiseIK(t)

	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	require.NoError(t, err)

	oldCK := ns.ChainingKey()
	ns.MixKey(ikm)

	assert.True(t, ns.HasKey(), "MixKey should set hasKey")
	assert.NotEqual(t, oldCK, ns.ChainingKey(), "MixKey should update chaining key")
	assert.Equal(t, uint64(0), ns.Nonce(), "MixKey should reset nonce to 0")
}

// TestNoiseHKDF1_MatchesFirstOutputOfHKDF2 verifies that noise.HKDF1SHA256 produces
// the same value as the first output of noise.HKDF2SHA256. This ensures the "ee"
// single-output HKDF and the standard 2-output HKDF agree on the chaining key.
func TestNoiseHKDF1_MatchesFirstOutputOfHKDF2(t *testing.T) {
	ck := randomBytes32(t)
	ikm := randomBytes32(t)

	output1 := noise.HKDF1SHA256(ck, ikm)
	first, _ := noise.HKDF2SHA256(ck, ikm)
	assert.Equal(t, first, output1, "HKDF1SHA256 should produce the same output as the first output of HKDF2SHA256")
}

// TestNoiseIKState_MixKeyCKOnly verifies that mixKeyCKOnly updates only the
// chaining key (ck) and does NOT update the cipher key (k), nonce (n), or
// hasKey flag. Per I2P ratchet.md §1g, the "ee" handshake token uses a
// single-output HKDF that only advances the chaining key.
func TestNoiseIKState_MixKeyCKOnly(t *testing.T) {
	ns := initNoiseIKWithMixedKey(t)

	// Record state before mixKeyCKOnly
	oldCK := ns.ChainingKey()
	oldKey := ns.UnsafeKey()
	oldN := ns.Nonce()
	oldHasKey := ns.HasKey()

	// Apply mixKeyCKOnly with new input
	eeIKM := make([]byte, 32)
	_, err := rand.Read(eeIKM)
	require.NoError(t, err)
	mixKeyCKOnly(ns, eeIKM)

	// ck MUST change
	assert.NotEqual(t, oldCK, ns.ChainingKey(), "mixKeyCKOnly should update chaining key")
	// k, n, hasKey MUST NOT change
	assert.Equal(t, oldKey, ns.UnsafeKey(), "mixKeyCKOnly must NOT update cipher key")
	assert.Equal(t, oldN, ns.Nonce(), "mixKeyCKOnly must NOT reset nonce")
	assert.Equal(t, oldHasKey, ns.HasKey(), "mixKeyCKOnly must NOT change hasKey flag")

	// Verify ck matches noise.HKDF1SHA256 directly
	expected := noise.HKDF1SHA256(oldCK, eeIKM)
	assert.Equal(t, expected[:], ns.ChainingKey(), "ck should equal noise.HKDF1SHA256(oldCK, ikm)")
}

// TestNSR_EE_DoesNotSetCipherKey verifies that the "ee" step in the NSR
// handshake does not set a cipher key, matching the I2P ratchet.md §1g spec.
// The cipher key should only be set by the subsequent "se" step.
func TestNSR_EE_DoesNotSetCipherKey(t *testing.T) {
	ns := initFreshNoiseIK(t)

	// Simulate the "ee" step using mixKeyCKOnly
	eeIKM := make([]byte, 32)
	_, err := rand.Read(eeIKM)
	require.NoError(t, err)
	mixKeyCKOnly(ns, eeIKM)

	// After "ee", there should be no cipher key set (hasKey remains false
	// if it was false before — the "es" step from message 1 would have set
	// hasKey=true, but mixKeyCKOnly must not change it)
	assert.False(t, ns.HasKey(),
		"mixKeyCKOnly (ee step) must not set hasKey; cipher key is set by the subsequent 'se' step")
}

func TestNoiseIKState_EncryptDecryptAndHash(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	// Create two identical states
	encState := initNoiseIK(respPub)
	decState := initNoiseIK(respPub)

	// Set same key
	ikm := make([]byte, 32)
	_, err = rand.Read(ikm)
	require.NoError(t, err)
	encState.MixKey(ikm)
	decState.MixKey(ikm)

	// Encrypt
	plaintext := []byte("hello noise protocol")
	ciphertext, err := encState.EncryptAndHash(nil, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext[:len(plaintext)], "Ciphertext should differ from plaintext")
	assert.Equal(t, len(plaintext)+16, len(ciphertext), "Ciphertext should include 16-byte AEAD tag")

	// Decrypt
	decrypted, err := decState.DecryptAndHash(nil, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// States should match after symmetric operations
	assert.Equal(t, encState.HandshakeHash(), decState.HandshakeHash(), "Handshake hash should match after encrypt/decrypt")
	assert.Equal(t, encState.Nonce(), decState.Nonce(), "Nonce counters should match")
}

func TestNoiseIKState_EncryptAndHash_NoKey(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)
	assert.False(t, ns.HasKey())

	data := []byte("plaintext pass-through")
	result, err := ns.EncryptAndHash(nil, data)
	require.NoError(t, err)
	assert.Equal(t, data, result, "Without key, EncryptAndHash should pass through")
}

func TestNoiseIKState_DecryptAndHash_TooShort(t *testing.T) {
	ns := initNoiseIKWithMixedKey(t)

	_, err := ns.DecryptAndHash(nil, make([]byte, 10))
	assert.Error(t, err, "Should reject ciphertext shorter than 16 bytes")
}

func TestNoiseIKState_ProtocolName(t *testing.T) {
	// Protocol name should be longer than 32 bytes, so it gets hashed
	assert.Greater(t, len(noiseProtocolName), 32,
		"Protocol name should exceed HASHLEN to trigger hashing")

	var respPub [32]byte
	ns := initNoiseIK(respPub)

	expectedH := sha256.Sum256([]byte(noiseProtocolName))
	// After MixHash(null prologue) + MixHash(Hash(respPub)), h should differ from initial
	assert.NotEqual(t, expectedH[:], ns.HandshakeHash(),
		"After pre-message processing, h should differ from initial hash")
}

// TestInitNoiseIK_NullPrologue verifies the exact handshake transcript for
// initNoiseIK, pinning the spec-required null-prologue step.
//
// The I2P ECIES-X25519-AEAD-Ratchet spec mandates this three-step sequence:
//
//	h0 = SHA-256(protocolName)           InitializeSymmetric
//	h1 = SHA-256(h0 || "")               MixHash(null prologue)
//	h2 = SHA-256(h1 || SHA-256(respPub)) MixHash(Hash(rs)) — hs2
//
// If any step is reordered or omitted, the test will fail with a mismatch,
// signaling an interoperability break with conformant I2P routers.
func TestInitNoiseIK_NullPrologue(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)

	// Step 1: InitializeSymmetric — h0 = SHA-256(protocolName)
	h0 := sha256.Sum256([]byte(noiseProtocolName))

	// Step 2: MixHash(null prologue) — h1 = SHA-256(h0 || "")
	h1 := sha256.Sum256(h0[:])

	// Step 3: MixHash(Hash(rs)) per hs2 — h2 = SHA-256(h1 || SHA-256(respPub))
	rsHash := sha256.Sum256(respPub[:])
	hasher := sha256.New()
	hasher.Write(h1[:])
	hasher.Write(rsHash[:])
	var expectedH [32]byte
	copy(expectedH[:], hasher.Sum(nil))

	assert.Equal(t, expectedH[:], ns.HandshakeHash(),
		"initNoiseIK transcript must include MixHash(null prologue) before hs2 pre-message; "+
			"omitting this breaks interoperability with conformant I2P routers")
	assert.Equal(t, h0[:], ns.ChainingKey(),
		"chaining key must equal SHA-256(protocolName) and must not change during pre-message phase")
}

func TestNoiseIKState_Hs2Modification(t *testing.T) {
	var respPub1, respPub2 [32]byte
	_, err := rand.Read(respPub1[:])
	require.NoError(t, err)
	_, err = rand.Read(respPub2[:])
	require.NoError(t, err)

	ns1 := initNoiseIK(respPub1)
	ns2 := initNoiseIK(respPub2)

	assert.NotEqual(t, ns1.HandshakeHash(), ns2.HandshakeHash(),
		"Different responder keys should produce different initial states")
}

// ============================================================================
// Noise IK Message Round-trip
// ============================================================================

func TestWriteReadNoiseIKMessage1_Roundtrip(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	plaintext := []byte("hello through Noise IK!")

	msg, iKeys, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)
	require.NotNil(t, iKeys)
	require.NotNil(t, iHS, "Initiator handshake state should be retained")

	// Verify wire format size: 32 (e) + 48 (s) + len(plaintext) + 16 (payload tag)
	expectedSize := 32 + 48 + len(plaintext) + 16
	assert.Equal(t, expectedSize, len(msg), "Wire message size should match Noise IK format")

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NotNil(t, result.hs, "Responder handshake state should be retained")
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.plaintext)
	assert.Equal(t, initiator.ourPublicKey, result.initiatorStaticPub,
		"Responder should recover initiator's static public key")

	// Both sides should derive the same session keys
	assert.Equal(t, iKeys.rootKey, result.keys.rootKey, "Root keys should match")
	assert.Equal(t, iKeys.symKey, result.keys.symKey, "Symmetric keys should match")
	assert.Equal(t, iKeys.tagKey, result.keys.tagKey, "Tag keys should match")
}

func TestWriteReadNoiseIKMessage1_EmptyPayload(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte{},
	)
	require.NoError(t, err)

	// Minimum size: 32 + 48 + 16 = 96 bytes
	assert.Equal(t, noiseIKMinMessageSize, len(msg))

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.Empty(t, result.plaintext)
}

func TestWriteReadNoiseIKMessage1_LargePayload(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	plaintext := make([]byte, 64*1024) // 64KB
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, result.plaintext)
}

func TestReadNoiseIKMessage1_TooShort(t *testing.T) {
	var priv, pub [32]byte
	_, err := rand.Read(priv[:])
	require.NoError(t, err)
	_, err = rand.Read(pub[:])
	require.NoError(t, err)

	_, err = readNoiseIKMessage1(priv, pub, make([]byte, 50))
	assert.Error(t, err, "Should reject messages shorter than minimum size")
}

func TestReadNoiseIKMessage1_WrongKey(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)
	wrongRecipient := createTestSessionManager(t)

	plaintext := []byte("not for you")
	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	// Wrong recipient should fail to decrypt
	_, err = readNoiseIKMessage1(
		wrongRecipient.ourPrivateKey, wrongRecipient.ourPublicKey, msg,
	)
	assert.Error(t, err, "Wrong recipient should fail to decrypt")
}

func TestReadNoiseIKMessage1_TamperedMessage(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("secret"),
	)
	require.NoError(t, err)

	// Tamper with the encrypted static section
	msg[40] ^= 0xFF

	_, err = readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	assert.Error(t, err, "Tampered message should fail authentication")
}

func TestWriteNoiseIKMessage1_NonDeterministic(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	payload := []byte("same payload")

	msg1, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	msg2, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	assert.NotEqual(t, msg1, msg2,
		"Each message should use a fresh Elligator2 ephemeral key, producing unique ciphertext")
}

// ============================================================================
// Unbound (N-pattern) New Session — writeNoiseIKMessage1Unbound
// ============================================================================

// TestWriteReadNoiseIKMessage1Unbound_Roundtrip verifies that an unbound NS
// message written by the sender can be decrypted by the receiver, that the
// receiver correctly identifies the message as unbound (isUnbound=true), and
// that the decrypted payload matches the original.
func TestWriteReadNoiseIKMessage1Unbound_Roundtrip(t *testing.T) {
	responder := createTestSessionManager(t)

	plaintext := []byte("unbound one-way message")

	msg, wKeys, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, plaintext)
	require.NoError(t, err)
	require.NotNil(t, wKeys, "Session keys should be derived even for unbound messages")

	// Minimum wire size: 32 (ephemeral) + 48 (flags section) + 16 (empty payload tag) = 96
	// With non-empty payload: 32 + 48 + len(plaintext) + 16
	expectedSize := 32 + 48 + len(plaintext) + 16
	assert.Equal(t, expectedSize, len(msg), "Unbound NS wire format should match §1c spec")

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.True(t, result.isUnbound, "Receiver should detect unbound (N-pattern) message")
	assert.Equal(t, plaintext, result.plaintext, "Decrypted payload should match original")
	assert.Equal(t, [32]byte{}, result.initiatorStaticPub, "No initiator static key for unbound messages")
	assert.Nil(t, result.hs, "No handshake state retained for unbound (non-repliable) sessions")
	assert.NotNil(t, result.keys, "Receiver should derive session keys from unbound handshake")

	// Both sides derive session keys from the same chaining key; verify they match.
	assert.Equal(t, wKeys.rootKey, result.keys.rootKey, "Root keys should match across unbound session")
	assert.Equal(t, wKeys.symKey, result.keys.symKey, "Symmetric keys should match")
	assert.Equal(t, wKeys.tagKey, result.keys.tagKey, "Tag keys should match")
}

// TestWriteReadNoiseIKMessage1Unbound_EmptyPayload verifies behaviour with an
// empty payload: minimum wire size (96 bytes) and successful decryption.
func TestWriteReadNoiseIKMessage1Unbound_EmptyPayload(t *testing.T) {
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte{})
	require.NoError(t, err)
	// Minimum: 32 + 48 + 16 = 96 bytes (same as bound minimum).
	assert.Equal(t, noiseIKMinMessageSize, len(msg))

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.True(t, result.isUnbound)
	assert.Empty(t, result.plaintext)
}

// TestReadNoiseIKMessage1_Bound_IsNotUnbound verifies that a normal (bound, IK)
// New Session message returns isUnbound=false.
func TestReadNoiseIKMessage1_Bound_IsNotUnbound(t *testing.T) {
	r := mustWriteAndReadIKMessage1(t, []byte("bound message"))
	assert.False(t, r.isUnbound, "Bound IK message should not be flagged as unbound")
	assert.Equal(t, r.initiator.ourPublicKey, r.initiatorPub, "Bound: initiator static key recovered")
	assert.NotNil(t, r.rHS, "Bound: handshake state retained for NSR")
}

// TestWriteNoiseIKMessage1Unbound_NonDeterministic verifies that each unbound
// message uses a fresh Elligator2 ephemeral key, producing unique ciphertexts
// even for the same payload.
func TestWriteNoiseIKMessage1Unbound_NonDeterministic(t *testing.T) {
	responder := createTestSessionManager(t)

	payload := []byte("same unbound payload")

	msg1, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, payload)
	require.NoError(t, err)
	msg2, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, payload)
	require.NoError(t, err)

	assert.NotEqual(t, msg1, msg2,
		"Each unbound message should use a fresh ephemeral key (non-deterministic)")
}

// TestWriteNoiseIKMessage1Unbound_WrongRecipient verifies that an unbound message
// encrypted for one recipient cannot be decrypted by another.
func TestWriteNoiseIKMessage1Unbound_WrongRecipient(t *testing.T) {
	responder := createTestSessionManager(t)
	wrongRecipient := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte("secret"))
	require.NoError(t, err)

	_, err = readNoiseIKMessage1(
		wrongRecipient.ourPrivateKey, wrongRecipient.ourPublicKey, msg,
	)
	assert.Error(t, err, "Wrong recipient should fail to decrypt unbound message")
}

// TestWriteNoiseIKMessage1Unbound_TamperedFlagsSection verifies that tampering
// with the encrypted flags section causes authentication failure.
func TestWriteNoiseIKMessage1Unbound_TamperedFlagsSection(t *testing.T) {
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte("payload"))
	require.NoError(t, err)

	// Tamper with the encrypted flags section (bytes 32..79).
	msg[40] ^= 0xFF

	_, err = readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	assert.Error(t, err, "Tampered flags section should fail authentication")
}

// TestIsAllZeros verifies the isAllZeros helper.
func TestIsAllZeros(t *testing.T) {
	assert.True(t, isAllZeros(make([]byte, 32)), "All-zero slice should return true")
	assert.True(t, isAllZeros(nil), "Nil slice (empty) should return true")
	assert.True(t, isAllZeros([]byte{}), "Empty slice should return true")

	nonzero := make([]byte, 32)
	nonzero[16] = 1
	assert.False(t, isAllZeros(nonzero), "Slice with non-zero byte should return false")

	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	assert.False(t, isAllZeros(allFF), "All-0xFF slice should return false")
}

func TestNoiseHKDF2_Deterministic(t *testing.T) {
	ck := randomBytes32(t)
	ikm := randomBytes32(t)

	o1a, o2a := noise.HKDF2SHA256(ck, ikm)
	o1b, o2b := noise.HKDF2SHA256(ck, ikm)

	assert.Equal(t, o1a, o1b)
	assert.Equal(t, o2a, o2b)
	assert.NotEqual(t, o1a, o2a, "HKDF outputs should differ")
}

func TestNoiseNonce(t *testing.T) {
	nonce := noise.BuildNonce(0)
	assert.Equal(t, 12, len(nonce))
	assert.Equal(t, [12]byte{}, nonce, "Nonce 0 should be all zeros")

	nonce = noise.BuildNonce(1)
	assert.Equal(t, byte(1), nonce[4], "Counter should be at offset 4 (LE)")
	assert.Equal(t, byte(0), nonce[0], "First 4 bytes should be zero padding")
}

func TestHmacSHA256_KnownOutput(t *testing.T) {
	key := []byte("test key")
	data := []byte("test data")

	result1 := hmac.HMACSHA256(key, data)
	result2 := hmac.HMACSHA256(key, data)
	assert.Equal(t, result1, result2, "HMAC-SHA256 should be deterministic")

	result3 := hmac.HMACSHA256(key, []byte("different data"))
	assert.NotEqual(t, result1, result3, "Different data should produce different HMAC")
}

// ============================================================================
// kdf.StandardHKDF
// ============================================================================

func TestStandardHKDF_DeterministicAndDifferentInputs(t *testing.T) {
	salt := randomBytes32(t)
	ikm := randomBytes32(t)

	tests := []struct {
		name      string
		info1     string
		info2     string
		ikm1      []byte
		ikm2      []byte
		length    int
		wantEqual bool
		msg       string
	}{
		{"same inputs", "test_info", "test_info", ikm, ikm, 64, true, "Same inputs should produce identical HKDF output"},
		{"different info", "info_a", "info_b", ikm, ikm, 32, false, "Different info strings should produce different output"},
		{"different IKM", "info_a", "info_a", ikm, nil, 32, false, "Different IKM should produce different output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out1, err := kdf.StandardHKDF(salt, tt.ikm1, []byte(tt.info1), tt.length)
			require.NoError(t, err)
			out2, err := kdf.StandardHKDF(salt, tt.ikm2, []byte(tt.info2), tt.length)
			require.NoError(t, err)
			if tt.wantEqual {
				assert.Equal(t, out1, out2, tt.msg)
				assert.Equal(t, tt.length, len(out1))
			} else {
				assert.NotEqual(t, out1, out2, tt.msg)
			}
		})
	}
}

func TestStandardHKDF_VariableLengths(t *testing.T) {
	salt := randomBytes32(t)

	out32, err := kdf.StandardHKDF(salt, nil, []byte("test"), 32)
	require.NoError(t, err)
	out64, err := kdf.StandardHKDF(salt, nil, []byte("test"), 64)
	require.NoError(t, err)
	assert.Equal(t, 32, len(out32))
	assert.Equal(t, 64, len(out64))
	// First 32 bytes of 64-byte output should match the 32-byte output
	assert.Equal(t, out32, out64[:32], "HKDF expand should produce consistent prefix")
}

// ============================================================================
// NSR Tag Ratchet Derivation
// ============================================================================

// mustDeriveAndTag derives an NSR tag ratchet from the given chain key and
// generates its first tag. Fails the test on any error.
func mustDeriveAndTag(t *testing.T, chainKey []byte) [8]byte {
	t.Helper()
	tr, err := deriveNSRTagRatchet(chainKey)
	require.NoError(t, err)
	require.NotNil(t, tr)
	tag, err := tr.GenerateNextTag()
	require.NoError(t, err)
	return tag
}

func TestDeriveNSRTagRatchet_BothSidesMatch(t *testing.T) {
	// Both initiator and responder should derive the same NSR tag ratchet
	// from the same chain key.
	var chainKey [32]byte
	_, err := rand.Read(chainKey[:])
	require.NoError(t, err)

	tag1 := mustDeriveAndTag(t, chainKey[:])
	tag2 := mustDeriveAndTag(t, chainKey[:])
	assert.Equal(t, tag1, tag2, "Same chain key should produce same NSR tags")
}

func TestDeriveNSRTagRatchet_DifferentChainKeys(t *testing.T) {
	var ck1, ck2 [32]byte
	_, err := rand.Read(ck1[:])
	require.NoError(t, err)
	_, err = rand.Read(ck2[:])
	require.NoError(t, err)

	tag1 := mustDeriveAndTag(t, ck1[:])
	tag2 := mustDeriveAndTag(t, ck2[:])
	assert.NotEqual(t, tag1, tag2, "Different chain keys should produce different tags")
}

// ============================================================================
// NSR Message Round-trip (writeNoiseIKMessage2 / readNoiseIKMessage2)
// ============================================================================

func TestWriteReadNoiseIKMessage2_Roundtrip(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Step 1: Initiator sends New Session (message 1)
	nsPayload := []byte("hello from Alice")
	msg1, _, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, nsPayload,
	)
	require.NoError(t, err)
	require.NotNil(t, iHS, "Initiator handshake state should be retained")

	// Step 2: Responder reads New Session and retains handshake state

	result, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)
	require.NotNil(t, result.hs, "Responder handshake state should be retained")

	// Step 3: Responder writes New Session Reply (message 2)
	nsrPayload := []byte("hello from Bob")
	nsrTag, nsrWire, respKeys, err := writeNoiseIKMessage2(result.hs, nsrPayload)
	require.NoError(t, err)
	require.NotNil(t, respKeys)
	assert.NotEqual(t, [8]byte{}, nsrTag, "NSR tag should not be zero")

	// Verify wire format: [tag(8)] + [eph(32)] + [mac(16)] + [payload+mac(N+16)]
	expectedSize := 8 + 32 + 16 + len(nsrPayload) + 16
	assert.Equal(t, expectedSize, len(nsrWire), "NSR wire message size should match format")

	// Step 4: Initiator reads New Session Reply
	decrypted, initKeys, err := readNoiseIKMessage2(iHS, initiator.ourPrivateKey, nsrWire)
	require.NoError(t, err)
	assert.Equal(t, nsrPayload, decrypted, "Initiator should recover NSR payload")

	// Both sides should derive matching directional keys
	assert.Equal(t, respKeys.keyAB, initKeys.keyAB, "keyAB should match")
	assert.Equal(t, respKeys.keyBA, initKeys.keyBA, "keyBA should match")
	assert.Equal(t, respKeys.chainKey, initKeys.chainKey, "chainKey should match")
}

func TestWriteReadNoiseIKMessage2_EmptyPayload(t *testing.T) {
	hp := setupNoiseIKHandshake(t)

	_, nsrWire, _, err := writeNoiseIKMessage2(hp.rHS, []byte{})
	require.NoError(t, err)

	// Minimum NSR size: 8 + 32 + 16 + 16 = 72
	assert.Equal(t, nsrMinMessageSize, len(nsrWire))

	decrypted, _, err := readNoiseIKMessage2(hp.iHS, hp.initiator.ourPrivateKey, nsrWire)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestReadNoiseIKMessage2_TooShort(t *testing.T) {
	var priv [32]byte
	_, err := rand.Read(priv[:])
	require.NoError(t, err)

	hs := &noiseHandshakeState{}
	_, _, err = readNoiseIKMessage2(hs, priv, make([]byte, 50))
	assert.Error(t, err, "Should reject NSR messages shorter than minimum size")
}

func TestReadNoiseIKMessage2_TamperedMessage(t *testing.T) {
	hp := setupNoiseIKHandshake(t)

	_, nsrWire, _, err := writeNoiseIKMessage2(hp.rHS, []byte("nsr payload"))
	require.NoError(t, err)

	// Tamper with the key section MAC
	nsrWire[42] ^= 0xFF

	_, _, err = readNoiseIKMessage2(hp.iHS, hp.initiator.ourPrivateKey, nsrWire)
	assert.Error(t, err, "Tampered NSR should fail authentication")
}

func TestWriteNoiseIKMessage2_NonDeterministic(t *testing.T) {
	hp := setupNoiseIKHandshake(t)
	rHS := hp.rHS

	// Write two NSR messages from same state — different ephemeral keys each time
	_, wire1, _, err := writeNoiseIKMessage2(rHS, []byte("nsr"))
	require.NoError(t, err)
	_, wire2, _, err := writeNoiseIKMessage2(rHS, []byte("nsr"))
	require.NoError(t, err)

	assert.NotEqual(t, wire1, wire2,
		"Each NSR should use a fresh ephemeral key, producing unique ciphertext")
}

// ============================================================================
// NSR Payload Encryption/Decryption
// ============================================================================

func TestEncryptDecryptNSRPayload_Roundtrip(t *testing.T) {
	// Create matched states (same h, ck)
	var h, ck [32]byte
	_, err := rand.Read(h[:])
	require.NoError(t, err)
	_, err = rand.Read(ck[:])
	require.NoError(t, err)

	// Encryption state
	encNS := &noise.SymmetricState{}
	encNS.SetCipherSuite(noise.ChaChaPoly_SHA256())
	encNS.SetHandshakeHash(h[:])
	encNS.SetChainingKey(ck[:])
	payload := []byte("garlic clove response data")
	encrypted, eKeys, err := encryptNSRPayload(encNS, payload)
	require.NoError(t, err)
	require.NotNil(t, eKeys)
	assert.Equal(t, len(payload)+16, len(encrypted), "Encrypted output includes 16-byte tag")

	// Decryption state (same h, ck)
	decNS := &noise.SymmetricState{}
	decNS.SetCipherSuite(noise.ChaChaPoly_SHA256())
	decNS.SetHandshakeHash(h[:])
	decNS.SetChainingKey(ck[:])
	decrypted, dKeys, err := decryptNSRPayload(decNS, encrypted)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)

	assert.Equal(t, eKeys.keyAB, dKeys.keyAB, "AB keys should match")
	assert.Equal(t, eKeys.keyBA, dKeys.keyBA, "BA keys should match")
}

// ============================================================================
// SessionManager NSR Integration
// ============================================================================

func TestSessionManager_EncryptNewSessionReply(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Send NS from initiator → responder — must be a valid NS payload.
	nsPayload := mustBuildNSPayload(t, []byte("initial garlic clove"))
	encrypted, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey, nsPayload,
	)
	require.NoError(t, err)

	// Responder decrypts NS
	decrypted, _, _, err := responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, nsPayload, decrypted)

	// Responder sends NSR
	sessionHash := hashPubKey(initiator.ourPublicKey)
	nsrPayload := []byte("reply garlic clove")
	nsrMsg, err := responder.EncryptNewSessionReply(sessionHash, nsrPayload)
	require.NoError(t, err)
	require.NotNil(t, nsrMsg)
	assert.GreaterOrEqual(t, len(nsrMsg), nsrMinMessageSize)
}

func TestSessionManager_EncryptNewSessionReply_NoSession(t *testing.T) {
	sm := createTestSessionManager(t)
	var fakeHash [32]byte
	_, err := rand.Read(fakeHash[:])
	require.NoError(t, err)

	_, err = sm.EncryptNewSessionReply(fakeHash, []byte("payload"))
	assert.Error(t, err, "Should fail when no session exists")
}

func TestSessionManager_EncryptNewSessionReply_InitiatorCantSendNSR(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Create a session as initiator — must be a valid NS payload.
	_, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey,
		mustBuildNSPayload(t, []byte("hello")),
	)
	require.NoError(t, err)

	// Initiator should NOT be able to send NSR
	_, err = initiator.EncryptNewSessionReply(hashPubKey(responder.ourPublicKey), []byte("nsr"))
	assert.Error(t, err, "Initiator should not be able to send NSR")
}

func TestSessionManager_EncryptNewSessionReply_ClearsHandshakeState(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Send NS from initiator → responder — must be a valid NS payload.
	encrypted, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey,
		mustBuildNSPayload(t, []byte("ns")),
	)
	require.NoError(t, err)

	_, _, _, err = responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)

	sessionHash := hashPubKey(initiator.ourPublicKey)

	// First NSR should succeed
	_, err = responder.EncryptNewSessionReply(sessionHash, []byte("nsr1"))
	require.NoError(t, err)

	// Second NSR should fail (handshake state cleared)
	_, err = responder.EncryptNewSessionReply(sessionHash, []byte("nsr2"))
	assert.Error(t, err, "Second NSR should fail after handshake state is cleared")
}
