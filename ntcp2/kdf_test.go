package ntcp2

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/crypto/hmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hmacSHA256Test is a test helper that computes HMAC-SHA256(key, data).
func hmacSHA256Test(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	// hash.Hash.Write never fails for in-memory test data, so this is
	// intentionally ignored.
	mac.Write(data) //nolint:errcheck
	return mac.Sum(nil)
}

// TestAudit_KDF_UsesHMACNotHKDF verifies that DeriveSipHashKeys uses the
// 5-step HMAC-SHA256 chain from the NTCP2 spec, not golang.org/x/crypto/hkdf.
func TestAudit_KDF_UsesHMACNotHKDF(t *testing.T) {
	askMaster := deterministicBytes(32, 0)
	handshakeHash := deterministicBytes(32, 64)

	sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, err := DeriveSipHashKeys(askMaster, handshakeHash)
	require.NoError(t, err)

	// Step 1: temp_key = HMAC-SHA256(ask_master, h || "siphash")
	step1Data := make([]byte, 32+len("siphash"))
	copy(step1Data, handshakeHash)
	copy(step1Data[32:], "siphash")
	tempKey := hmacSHA256Test(askMaster, step1Data)

	// Step 2: sip_master = HMAC-SHA256(temp_key, 0x01)
	sipMaster := hmacSHA256Test(tempKey, []byte{0x01})

	// Step 3: temp_key = HMAC-SHA256(sip_master, zerolen)
	tempKey = hmacSHA256Test(sipMaster, []byte{})

	// Step 4: sipkeys_ab = HMAC-SHA256(temp_key, 0x01)
	fullAB := hmacSHA256Test(tempKey, []byte{0x01})
	expectedK1AB := binary.LittleEndian.Uint64(fullAB[0:8])
	expectedK2AB := binary.LittleEndian.Uint64(fullAB[8:16])
	expectedIVAB := binary.LittleEndian.Uint64(fullAB[16:24])

	// Step 5: sipkeys_ba = HMAC-SHA256(temp_key, sipkeys_ab[0:32] || 0x02)
	// Uses the full 32-byte HMAC output from step 4, not just 24 bytes.
	step5Data := make([]byte, len(fullAB)+1)
	copy(step5Data, fullAB)
	step5Data[len(fullAB)] = 0x02
	fullBA := hmacSHA256Test(tempKey, step5Data)
	expectedK1BA := binary.LittleEndian.Uint64(fullBA[0:8])
	expectedK2BA := binary.LittleEndian.Uint64(fullBA[8:16])
	expectedIVBA := binary.LittleEndian.Uint64(fullBA[16:24])

	assert.Equal(t, expectedK1AB, sipKeysAB[0], "sipk1_AB mismatch")
	assert.Equal(t, expectedK2AB, sipKeysAB[1], "sipk2_AB mismatch")
	assert.Equal(t, expectedIVAB, sipIVAB, "sipIV_AB mismatch")

	assert.Equal(t, expectedK1BA, sipKeysBA[0], "sipk1_BA mismatch")
	assert.Equal(t, expectedK2BA, sipKeysBA[1], "sipk2_BA mismatch")
	assert.Equal(t, expectedIVBA, sipIVBA, "sipIV_BA mismatch")
}

// TestAudit_KDF_PerDirectionKeysAreDifferent verifies that the AB and BA
// key material from DeriveSipHashKeys is distinct.
func TestAudit_KDF_PerDirectionKeysAreDifferent(t *testing.T) {
	askMaster := make([]byte, 32)
	handshakeHash := make([]byte, 32)
	for i := range handshakeHash {
		handshakeHash[i] = byte(i + 1)
	}

	sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, err := DeriveSipHashKeys(askMaster, handshakeHash)
	require.NoError(t, err)

	assert.NotEqual(t, sipKeysAB, sipKeysBA, "AB and BA SipHash keys must differ")
	assert.NotEqual(t, sipIVAB, sipIVBA, "AB and BA SipHash IVs must differ")
}

// TestAudit_KDF_InvalidInput validates error handling for bad input lengths.
func TestAudit_KDF_InvalidInput(t *testing.T) {
	validKey := make([]byte, 32)
	validHash := make([]byte, 32)

	_, _, _, _, err := DeriveSipHashKeys(make([]byte, 16), validHash)
	assert.Error(t, err, "short ask_master must fail")
	assert.Contains(t, err.Error(), "ask_master must be exactly")

	_, _, _, _, err = DeriveSipHashKeys(validKey, make([]byte, 16))
	assert.Error(t, err, "short handshake hash must fail")
	assert.Contains(t, err.Error(), "handshake hash must be exactly")
}

// TestDeriveSipHashKeys_Deterministic verifies that DeriveSipHashKeys
// produces deterministic output for the same inputs.
func TestDeriveSipHashKeys_Deterministic(t *testing.T) {
	askMaster := make([]byte, 32)
	for i := range askMaster {
		askMaster[i] = byte(i + 10)
	}
	handshakeHash := make([]byte, 32)
	for i := range handshakeHash {
		handshakeHash[i] = byte(i + 50)
	}

	keysAB1, ivAB1, keysBA1, ivBA1, err1 := DeriveSipHashKeys(askMaster, handshakeHash)
	keysAB2, ivAB2, keysBA2, ivBA2, err2 := DeriveSipHashKeys(askMaster, handshakeHash)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, keysAB1, keysAB2)
	assert.Equal(t, ivAB1, ivAB2)
	assert.Equal(t, keysBA1, keysBA2)
	assert.Equal(t, ivBA1, ivBA2)
}
