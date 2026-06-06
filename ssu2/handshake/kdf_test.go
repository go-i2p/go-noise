package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hmacSHA256Test is a test helper that computes HMAC-SHA256(key, data).
func hmacSHA256Test(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data) //nolint:errcheck
	return mac.Sum(nil)
}

// TestAudit_SSU2_KDF_IntermediateHeaderKey verifies that deriveIntermediateHeaderKey
// follows the SSU2 spec's HKDF pattern for intermediate header protection keys:
//
//	temp_key = HMAC-SHA256(salt=chainKey, ikm=ZEROLEN)
//	key      = HMAC-SHA256(temp_key, info || 0x01)
//
// Used during handshake for SessionRequest and SessionCreated header protection.
//
// NOTE (M-3): This is an algorithm-conformance test based on the SSU2 spec
// description. It should be supplemented with official I2P SSU2 test vectors
// when they become publicly available. Self-consistency tests passed for NTCP2
// but failed interop (msg2 option layout, msg3 RI flag byte); spec-vector tests
// would catch wire-format drift that Go↔Go tests cannot.
func TestAudit_SSU2_KDF_IntermediateHeaderKey(t *testing.T) {
	// Test with deterministic chain key
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 100)
	}

	info := "SSU2TestInfo"

	// Derive key using the implementation
	derivedKey := deriveIntermediateHeaderKey(chainKey, info)
	require.Len(t, derivedKey, 32, "derived key must be 32 bytes")

	// Manually reconstruct per spec

	// Step 1: temp_key = HMAC-SHA256(chainKey, ZEROLEN)
	tempKey := hmacSHA256Test(chainKey, []byte{})

	// Step 2: key = HMAC-SHA256(temp_key, info || 0x01)
	step2Data := make([]byte, len(info)+1)
	copy(step2Data, []byte(info))
	step2Data[len(info)] = 0x01
	expectedKey := hmacSHA256Test(tempKey, step2Data)

	// Assert implementation matches spec
	assert.Equal(t, expectedKey, derivedKey, "intermediate header key derivation must match SSU2 spec algorithm")
}

// TestAudit_SSU2_KDF_IntermediateHeaderKey_Deterministic verifies that
// deriveIntermediateHeaderKey produces deterministic output.
func TestAudit_SSU2_KDF_IntermediateHeaderKey_Deterministic(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i * 3)
	}

	info := "SSU2SessionRequest"

	// Derive twice
	key1 := deriveIntermediateHeaderKey(chainKey, info)
	key2 := deriveIntermediateHeaderKey(chainKey, info)

	// Assert outputs are identical
	assert.Equal(t, key1, key2, "deriveIntermediateHeaderKey must be deterministic")
}

// TestAudit_SSU2_KDF_IntermediateHeaderKey_DistinctKeys verifies that
// different chain keys or info strings produce different derived keys.
func TestAudit_SSU2_KDF_IntermediateHeaderKey_DistinctKeys(t *testing.T) {
	chainKey1 := make([]byte, 32)
	chainKey2 := make([]byte, 32)
	for i := range chainKey1 {
		chainKey1[i] = byte(i)
		chainKey2[i] = byte(i + 1)
	}

	info1 := "SSU2SessionRequest"
	info2 := "SSU2SessionCreated"

	// Different chain keys, same info
	key1 := deriveIntermediateHeaderKey(chainKey1, info1)
	key2 := deriveIntermediateHeaderKey(chainKey2, info1)
	assert.NotEqual(t, key1, key2, "different chain keys must produce different keys")

	// Same chain key, different info
	key3 := deriveIntermediateHeaderKey(chainKey1, info1)
	key4 := deriveIntermediateHeaderKey(chainKey1, info2)
	assert.NotEqual(t, key3, key4, "different info strings must produce different keys")
}

// TestAudit_SSU2_KDF_DeriveHeaderKeys_NilCipherStates verifies error
// handling when cipher states are not yet available (handshake incomplete).
//
// NOTE (M-3): Full handshake spec-vector testing requires published I2P SSU2
// test vectors, which may not yet exist. This test validates error handling;
// algorithm-conformance is tested via TestAudit_SSU2_KDF_IntermediateHeaderKey.
func TestAudit_SSU2_KDF_DeriveHeaderKeys_NilCipherStates(t *testing.T) {
	_, _, err := DeriveHeaderKeys(nil, nil)
	assert.Error(t, err, "nil cipher states must fail")
	assert.Contains(t, err.Error(), "handshake not complete", "error must indicate incomplete handshake")
}
