package ratchet

import (
	"crypto/subtle"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface check.
var _ BuildRecordEncryptor = (*BuildRequestCrypto)(nil)

// BuildRequestCrypto handles asymmetric encryption and decryption of tunnel
// build request records using ECIES-X25519-AEAD.
//
// A tunnel build request is the first message in an I2P tunnel: it asks a
// peer to join a tunnel and carries the keys needed to encrypt the reply.
// "Asymmetric" means the sender encrypts with the recipient's public key and
// only the recipient's private key can decrypt.
//
// This type handles only the request half of the tunnel-build crypto:
// EncryptBuildRequest, DecryptBuildRequest, and VerifyIdentityHash. Callers
// that need only request record operations should use this type directly via
// the [BuildRecordEncryptor] interface, so the expected key material (X25519
// public/private key) is clear at every call site.
//
// For the symmetric ChaCha20-Poly1305 reply half see [BuildReplyCrypto].
// For backward compatibility a combined type is available as
// [BuildRecordCrypto].
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
type BuildRequestCrypto struct{}

// NewBuildRequestCrypto creates a new [BuildRequestCrypto] handler.
func NewBuildRequestCrypto() *BuildRequestCrypto {
	return &BuildRequestCrypto{}
}

// EncryptBuildRequest encrypts a serialized build request record (222 bytes)
// using ECIES-X25519-AEAD encryption.
//
// This implements the I2P specification for encrypted tunnel build records.
// The caller (go-i2p) is responsible for extracting the recipient's public
// key and identity hash from RouterInfo before calling this function.
//
// Format of the 528-byte output:
//
//   - Bytes 0-15: First 16 bytes of recipientIdentityHash (lets the recipient
//     quickly check whether the record is for them).
//   - Bytes 16-297: ECIES-X25519 encrypted data (ephemeral public key +
//     nonce + AEAD ciphertext).
//   - Bytes 298-527: Zero padding.
//
// Parameters:
//   - cleartext: 222-byte serialized BuildRequestRecord.
//   - recipientPubKey: recipient's 32-byte X25519 public key (extracted from
//     RouterInfo by caller).
//   - recipientIdentityHash: recipient's 32-byte identity hash (extracted
//     from RouterInfo by caller).
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
func (c *BuildRequestCrypto) EncryptBuildRequest(
	cleartext []byte,
	recipientPubKey, recipientIdentityHash [32]byte,
) ([528]byte, error) {
	var encrypted [528]byte

	if err := validateSize("cleartext", len(cleartext), 222); err != nil {
		return encrypted, err
	}

	// Copy first 16 bytes of identity hash (toPeer field)
	writePrefix16FromArray32(encrypted[0:16], recipientIdentityHash)

	// Encrypt using ECIES-X25519
	// Output: ephemeral_pubkey(32) + nonce(12) + aead_ciphertext(222+16=238) = 282 bytes
	ciphertext, err := ecies.EncryptECIESX25519(recipientPubKey[:], cleartext)
	if err != nil {
		return encrypted, oops.Wrapf(err, "ECIES encryption failed")
	}

	if len(ciphertext) > 512 {
		return encrypted, oops.Errorf("ciphertext too large: %d bytes (max 512)", len(ciphertext))
	}

	// Copy ciphertext to bytes 16-527 (remaining bytes are zero-padded)
	copy(encrypted[16:], ciphertext)

	flog("EncryptBuildRequest", logger.Fields{"record_size": 528, "cleartext_size": 222, "ciphertext_size": len(ciphertext)}).
		Debug("BuildRequest encrypted successfully")

	return encrypted, nil
}

// DecryptBuildRequest decrypts a 528-byte encrypted build request record
// using ECIES-X25519-AEAD.
//
// The caller (go-i2p) converts the returned cleartext to a
// BuildRequestRecord.
//
// Parameters:
//   - encrypted: 528-byte encrypted build request record.
//   - privateKey: our 32-byte X25519 private key.
//
// Returns the 222-byte cleartext.
func (c *BuildRequestCrypto) DecryptBuildRequest(encrypted [528]byte, privateKey []byte) ([]byte, error) {
	if err := validateSize("private key", len(privateKey), 32); err != nil {
		return nil, err
	}

	// Extract ECIES ciphertext portion (bytes 16-297)
	// ephemeral_pubkey(32) + nonce(12) + aead_ciphertext(222+16=238) = 282 bytes
	const eciesCiphertextLen = 32 + 12 + 222 + 16 // = 282
	ciphertext := encrypted[16 : 16+eciesCiphertextLen]

	cleartext, err := ecies.DecryptECIESX25519(privateKey, ciphertext)
	if err != nil {
		return nil, oops.Wrapf(err, "ECIES decryption failed")
	}

	if err := validateSize("decrypted data", len(cleartext), 222); err != nil {
		return nil, err
	}

	flog("DecryptBuildRequest", logger.Fields{"record_size": 528, "cleartext_size": len(cleartext)}).
		Debug("BuildRequest decrypted successfully")

	return cleartext, nil
}

// VerifyIdentityHash checks whether an encrypted build request record is
// intended for us by comparing the first 16 bytes of the record with our
// identity hash.
//
// This provides a fast pre-check before attempting full ECIES decryption.
// The comparison runs in constant time so an attacker cannot learn anything
// about our identity by measuring how long the check takes.
//
// Parameters:
//   - encrypted: 528-byte encrypted build request record.
//   - ourIdentityHash: our 32-byte identity hash.
func (c *BuildRequestCrypto) VerifyIdentityHash(encrypted [528]byte, ourIdentityHash [32]byte) bool {
	flog("VerifyIdentityHash").Debug("Verifying identity hash prefix match")
	return subtle.ConstantTimeCompare(encrypted[:16], ourIdentityHash[:16]) == 1
}

// ExtractIdentityHashPrefixRaw returns the first 16 bytes of an encrypted
// build request record as a [32]byte (remaining bytes zero).
//
// These 16 bytes are the first half of the recipient's identity hash,
// which is stored in cleartext so routers can route the record to the
// right destination. Useful for debugging and logging to identify the
// intended recipient.
func ExtractIdentityHashPrefixRaw(encrypted [528]byte) [32]byte {
	var hash [32]byte
	readPrefix16ToArray32(&hash, encrypted[0:16])
	return hash
}

// ComputeIdentityHash computes the SHA-256 hash of raw identity bytes.
// The caller (go-i2p) serializes RouterIdentity.KeysAndCert to bytes
// before calling.
//
// The resulting 32-byte hash identifies a router's identity; the first 16
// bytes of it are embedded in cleartext in every build request record so
// the recipient can verify the record was addressed to it.
func ComputeIdentityHash(identityBytes []byte) [32]byte {
	return types.SHA256(identityBytes)
}
