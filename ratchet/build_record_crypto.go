// Package ratchet provides ECIES-X25519-AEAD-Ratchet cryptographic primitives.
//
// This file implements tunnel build record encryption/decryption using
// ChaCha20-Poly1305 (I2P 0.9.44+). All function signatures use primitive
// types ([32]byte, [16]byte, []byte) rather than I2P-specific types.
// The go-i2p consumer converts session_key.SessionKey and
// BuildResponseRecord/BuildRequestRecord before calling these APIs.
package ratchet

import (
	"crypto/subtle"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface checks for the focused types.
var (
	_ BuildReplyEncryptor = (*BuildReplyCrypto)(nil)
)

const (
	buildRecordPlaintextSize  = 528
	buildRecordCiphertextSize = 544 // 528 bytes ciphertext + 16-byte Poly1305 tag
)

// BuildReplyCrypto handles symmetric encryption and decryption of tunnel build
// reply records using ChaCha20-Poly1305 (I2P 0.9.44+).
//
// This type handles only the symmetric half of the tunnel-build crypto:
// EncryptReplyRecord and DecryptReplyRecord.  Callers that need only reply
// record operations should use this type directly via the BuildReplyEncryptor
// interface, so the expected key material (32-byte session key + 16-byte IV)
// is clear at every call site.
//
// For the asymmetric ECIES-X25519 request half see BuildRequestCrypto.
// For backward compatibility a combined type is available as BuildRecordCrypto.
type BuildReplyCrypto struct{}

// NewBuildReplyCrypto creates a new BuildReplyCrypto handler.
func NewBuildReplyCrypto() *BuildReplyCrypto {
	return &BuildReplyCrypto{}
}

// BuildRecordCrypto is a backward-compatible wrapper that implements both
// BuildReplyEncryptor (ChaCha20-Poly1305) and BuildRecordEncryptor
// (ECIES-X25519) by embedding the two focused types.
//
// New code should prefer BuildReplyCrypto or BuildRequestCrypto directly so
// that required key material is explicit at every call site.
//
// Deprecated: Use BuildReplyCrypto or BuildRequestCrypto instead.
// This type will be removed in the next major version.
type BuildRecordCrypto struct {
	BuildReplyCrypto
	BuildRequestCrypto
}

// Compile-time backward-compat checks: the combined wrapper still satisfies
// both interfaces.
var (
	_ BuildReplyEncryptor  = (*BuildRecordCrypto)(nil)
	_ BuildRecordEncryptor = (*BuildRecordCrypto)(nil)
)

// NewBuildRecordCrypto creates a new BuildRecordCrypto handler.
// Deprecated: prefer NewBuildReplyCrypto() or NewBuildRequestCrypto() for
// call sites that use only one of the two crypto operations.
func NewBuildRecordCrypto() *BuildRecordCrypto {
	return &BuildRecordCrypto{}
}

// EncryptReplyRecord encrypts a serialized 528-byte response record using the
// reply key and IV.
//
// Uses ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+):
//
// Output: 528 bytes encrypted data + 16 bytes authentication tag = 544 bytes
//
// The caller (go-i2p) serializes BuildResponseRecord to cleartext before calling.
func (c *BuildReplyCrypto) EncryptReplyRecord(
	cleartext []byte,
	replyKey [32]byte,
	replyIV [16]byte,
) ([]byte, error) {
	if len(cleartext) != buildRecordPlaintextSize {
		return nil, oops.Errorf("invalid cleartext size: expected %d bytes, got %d", buildRecordPlaintextSize, len(cleartext))
	}

	encrypted, err := c.encryptChaCha20Poly1305(cleartext, replyKey, replyIV)
	if err != nil {
		return nil, oops.Wrapf(err, "ChaCha20-Poly1305 encryption failed")
	}

	log.WithFields(logger.Fields{
		"pkg":        "ratchet",
		"func":       "EncryptReplyRecord",
		"encryption": "ChaCha20-Poly1305",
		"size":       len(encrypted),
	}).Debug("Encrypted build response record")

	return encrypted, nil
}

// DecryptReplyRecord decrypts an encrypted reply record.
//
// Uses ChaCha20-Poly1305 AEAD decryption (I2P 0.9.44+).
// Expects 544 bytes input (528 ciphertext + 16 auth tag).
// Returns 528 bytes plaintext; the caller (go-i2p) parses and verifies the hash.
func (c *BuildReplyCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey [32]byte,
	replyIV [16]byte,
) ([]byte, error) {
	if len(encryptedData) != buildRecordCiphertextSize {
		return nil, oops.Errorf("invalid encrypted data size: expected %d bytes, got %d", buildRecordCiphertextSize, len(encryptedData))
	}

	cleartext, err := c.decryptChaCha20Poly1305(encryptedData, replyKey, replyIV)
	if err != nil {
		return nil, oops.Wrapf(err, "ChaCha20-Poly1305 decryption failed")
	}

	if len(cleartext) != buildRecordPlaintextSize {
		return nil, oops.Errorf("invalid decrypted data size: expected %d bytes, got %d", buildRecordPlaintextSize, len(cleartext))
	}

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "DecryptReplyRecord"}).Debug("Decrypted build response record")
	return cleartext, nil
}

// SerializeResponseRecord converts response record fields to wire format (528 bytes).
//
// Format:
//
// bytes 0-31:   SHA-256 hash of bytes 32-527
// bytes 32-526: Random data (495 bytes)
// byte 527:     Reply status code
func SerializeResponseRecord(hash [32]byte, randomData [495]byte, reply byte) []byte {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "SerializeResponseRecord", "reply_code": reply}).Debug("Serializing response record")
	buf := make([]byte, 528)
	copy(buf[0:32], hash[:])
	copy(buf[32:527], randomData[:])
	buf[527] = reply
	return buf
}

// buildResponseRecordHashInput constructs the 496-byte buffer that is hashed
// to produce (or verify) the SHA-256 field of a build response record.
// Layout: randomData[0:495] || reply byte.
func buildResponseRecordHashInput(randomData [495]byte, reply byte) []byte {
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = reply
	return data
}

// VerifyResponseRecordHash verifies the SHA-256 hash in a serialized response record.
// The hash covers bytes 32-527 (randomData + reply byte).
func VerifyResponseRecordHash(hash [32]byte, randomData [495]byte, reply byte) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "VerifyResponseRecordHash", "reply_code": reply}).Debug("Verifying response record hash")
	data := buildResponseRecordHashInput(randomData, reply)

	expectedHash := types.SHA256(data)

	if subtle.ConstantTimeCompare(hash[:], expectedHash[:]) != 1 {
		return oops.Errorf("hash verification failed")
	}

	return nil
}

// CreateBuildResponseRecordRaw creates a valid response record with proper hash.
//
// Parameters:
//   - reply: Status code (0=accept, non-zero=reject reason)
//   - randomData: 495 bytes of random data (should be cryptographically random)
//
// Returns the SHA-256 hash that should be placed in the first 32 bytes of the record.
func CreateBuildResponseRecordRaw(reply byte, randomData [495]byte) [32]byte {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "CreateBuildResponseRecordRaw", "reply_code": reply}).Debug("Creating build response record hash")
	return types.SHA256(buildResponseRecordHashInput(randomData, reply))
}

// newChaCha20Poly1305 creates a ChaCha20-Poly1305 AEAD cipher and derives the
// 12-byte nonce from the first 12 bytes of the 16-byte IV per the I2P ECIES
// build-record spec (Proposal 152, §"ChaCha20/Poly1305").
func newChaCha20Poly1305(key [32]byte, iv [16]byte) (*chacha20poly1305.AEAD, []byte, error) {
	aead, err := chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to create ChaCha20-Poly1305 cipher")
	}
	return aead, iv[:12], nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305 AEAD.
func (c *BuildReplyCrypto) encryptChaCha20Poly1305(
	plaintext []byte,
	key [32]byte,
	iv [16]byte,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "encryptChaCha20Poly1305", "plaintext_len": len(plaintext)}).Debug("Encrypting with ChaCha20-Poly1305")
	aead, nonce, err := prepareChaCha20Poly1305Input(plaintext, buildRecordPlaintextSize, "plaintext", key, iv)
	if err != nil {
		return nil, err
	}

	ct, tag, err := aead.Encrypt(plaintext, nil, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt")
	}

	// Concatenate ciphertext + tag (528 + 16 = 544 bytes)
	result := make([]byte, len(ct)+len(tag))
	copy(result, ct)
	copy(result[len(ct):], tag[:])

	if len(result) != buildRecordCiphertextSize {
		return nil, oops.Errorf("unexpected ciphertext length: %d", len(result))
	}

	return result, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305 AEAD.
func (c *BuildReplyCrypto) decryptChaCha20Poly1305(
	ciphertext []byte,
	key [32]byte,
	iv [16]byte,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "decryptChaCha20Poly1305", "ciphertext_len": len(ciphertext)}).Debug("Decrypting with ChaCha20-Poly1305")
	aead, nonce, err := prepareChaCha20Poly1305Input(ciphertext, buildRecordCiphertextSize, "ciphertext", key, iv)
	if err != nil {
		return nil, err
	}

	// Split into ciphertext (first 528 bytes) and tag (last 16 bytes)
	ct := ciphertext[:buildRecordPlaintextSize]
	tag := ciphertext[buildRecordPlaintextSize:]

	plaintext, err := aead.Decrypt(ct, tag, nil, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	if len(plaintext) != buildRecordPlaintextSize {
		return nil, oops.Errorf("unexpected plaintext length: %d", len(plaintext))
	}

	return plaintext, nil
}

func prepareChaCha20Poly1305Input(input []byte, expectedLen int, inputName string, key [32]byte, iv [16]byte) (*chacha20poly1305.AEAD, []byte, error) {
	if len(input) != expectedLen {
		return nil, nil, oops.Errorf("%s must be %d bytes, got %d", inputName, expectedLen, len(input))
	}

	aead, nonce, err := newChaCha20Poly1305(key, iv)
	if err != nil {
		return nil, nil, err
	}

	return aead, nonce, nil
}
