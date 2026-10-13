package handshake

import (
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// deriveIntermediateHeaderKey derives a header protection key from the
// handshake's current chaining key using the SSU2 spec's HKDF pattern:
//
//	temp_key = HMAC-SHA256(salt=chainKey, ikm=ZEROLEN)
//	key      = HMAC-SHA256(temp_key, info || 0x01)
//
// This is standard HKDF (RFC 5869) with an empty IKM, so it delegates to the
// canonical go-i2p/crypto/kdf.StandardHKDF one-shot wrapper (salt=chainKey,
// ikm=ZEROLEN).
func deriveIntermediateHeaderKey(chainKey []byte, info string) []byte {
	key, err := kdf.StandardHKDF(chainKey, nil, []byte(info), 32)
	if err != nil {
		// Unreachable: chainKey is a 32-byte chaining key and info is a short
		// constant, so the HKDF parameter validation can never fail here.
		panic("ssu2/handshake: deriveIntermediateHeaderKey: " + err.Error())
	}
	return key
}

// deriveDataPhaseKeys derives both k_data and k_header_2 for the data phase
// from a split cipher key using the SSU2 spec's two-step HKDF:
//
//	temp_key = HMAC-SHA256(key, ZEROLEN)
//	k_data   = HMAC-SHA256(temp_key, "HKDFSSU2DataKeys" || 0x01)  // first 32 bytes
//	k_header_2 = HMAC-SHA256(temp_key, k_data || "HKDFSSU2DataKeys" || 0x02)
//
// This is standard HKDF (RFC 5869) with an empty IKM expanded to 64 bytes, so
// it delegates to the canonical go-i2p/crypto/kdf.StandardHKDF one-shot wrapper
// (salt=chainingKey, ikm=ZEROLEN).
//
// Per spec, k_data replaces the raw split key for AEAD encryption,
// and k_header_2 is used for data-phase header protection.
func deriveDataPhaseKeys(cs *noise.CipherState) (kData, kHeader2 []byte, err error) {
	key := cs.UnsafeKey()

	out, err := kdf.StandardHKDF(key[:], nil, []byte("HKDFSSU2DataKeys"), 64)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive data-phase keys")
	}

	return out[:32], out[32:64], nil
}

// DeriveHeaderKeys derives data-phase header protection keys (k_header_2) for both
// send and receive directions. This function also installs the derived k_data keys
// into the cipher states (replacing the handshake's raw split key) so that data-phase
// AEAD uses the spec-mandated derived key.
// Returns the send-direction k_header_2 and recv-direction k_header_2.
func DeriveHeaderKeys(sendCipher, recvCipher *noise.CipherState) (sendKHeader2, recvKHeader2 []byte, err error) {
	flog("DeriveHeaderKeys").Debug("Deriving data-phase header keys")
	if sendCipher == nil || recvCipher == nil {
		return nil, nil, oops.Errorf("handshake not complete: cipher states not available")
	}

	sendKData, sendKHeader2, err := deriveDataPhaseKeys(sendCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive send data-phase keys")
	}

	recvKData, recvKHeader2, err := deriveDataPhaseKeys(recvCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive recv data-phase keys")
	}

	// Install k_data as the AEAD encryption key per SSU2 spec §KDF for
	// data phase. The raw split keys (k_ab/k_ba) must NOT be used directly.
	var sendKey, recvKey [32]byte
	copy(sendKey[:], sendKData)
	copy(recvKey[:], recvKData)
	sendCipher.UnsafeSetKey(sendKey)
	recvCipher.UnsafeSetKey(recvKey)

	return sendKHeader2, recvKHeader2, nil
}
