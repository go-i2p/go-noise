package wire

import (
	gocrypto_chacha20poly1305 "github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// Retry (type 9) payload AEAD, per ssu2.rst §"KDF for Retry":
//
//	// bik = Bob's intro key
//	k  = bik
//	n  = 4 byte packet number from header
//	ad = 32 byte header, before header encryption
//	ciphertext = ENCRYPT(k, n, payload, ad)
//
//	// Header encryption keys for this message
//	k_header_1 = bik
//	k_header_2 = bik
//
// The 4-byte packet-number nonce is expanded to the 12-byte ChaChaPoly nonce
// with four leading zero bytes, matching the Noise ChaChaPoly convention used
// by the rest of the stack (see github.com/go-i2p/noise.BuildNonce).
//
// Retry is a pre-session message, so it is protected with the symmetric intro
// key only — no DH and no Noise handshake state. This is what keeps it cheap
// for Bob to generate without decrypting Alice's Session Request.

// retryAEADNonce builds the 12-byte ChaCha20-Poly1305 nonce for an intro-key
// protected message from the 4-byte header packet number.
//
// The spec fixes only the width ("n = 4 byte packet number from header"); the
// expansion into the 12-byte AEAD nonce follows the same convention the
// data-phase AEAD uses (github.com/go-i2p/noise.BuildNonce: four leading zero
// bytes then the counter little-endian), so a single nonce construction covers
// every SSU2 ChaChaPoly AEAD in the stack.
func retryAEADNonce(packetNumber uint32) []byte {
	nonce := noise.BuildNonce(uint64(packetNumber))
	return nonce[:]
}

// EncryptIntroKeyAEAD seals a pre-session payload with the intro key as the
// AEAD key, the cleartext header as associated data, and the header packet
// number as the nonce. Used for Retry per ssu2.rst §"KDF for Retry".
//
// Returns the ciphertext and the 16-byte Poly1305 tag separately so the caller
// can place the tag in the packet's trailing MAC field.
func EncryptIntroKeyAEAD(introKey, header, payload []byte, packetNumber uint32) (ciphertext, mac []byte, err error) {
	if len(introKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("key_len", len(introKey)).
			Errorf("intro key must be exactly %d bytes", HeaderKeySize)
	}
	if len(header) != LongHeaderSize {
		return nil, nil, oops.
			Code("INVALID_HEADER").
			In("ssu2").
			With("header_len", len(header)).
			Errorf("Retry associated data must be the %d-byte cleartext long header", LongHeaderSize)
	}

	var key [32]byte
	copy(key[:], introKey)

	aead, err := gocrypto_chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to create ChaCha20-Poly1305 AEAD")
	}

	ct, tag, err := aead.Encrypt(payload, header, retryAEADNonce(packetNumber))
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to AEAD-encrypt intro-key payload")
	}

	macCopy := make([]byte, len(tag))
	copy(macCopy, tag[:])
	return ct, macCopy, nil
}

// DecryptIntroKeyAEAD opens an intro-key protected payload produced by
// EncryptIntroKeyAEAD. The header supplied here must be the cleartext
// (already de-obfuscated) header, since it is the AEAD associated data.
func DecryptIntroKeyAEAD(introKey, header, ciphertext, mac []byte, packetNumber uint32) ([]byte, error) {
	if len(introKey) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("key_len", len(introKey)).
			Errorf("intro key must be exactly %d bytes", HeaderKeySize)
	}
	if len(header) != LongHeaderSize {
		return nil, oops.
			Code("INVALID_HEADER").
			In("ssu2").
			With("header_len", len(header)).
			Errorf("Retry associated data must be the %d-byte cleartext long header", LongHeaderSize)
	}
	if len(mac) != MACSize {
		return nil, oops.
			Code("INVALID_MAC").
			In("ssu2").
			With("mac_len", len(mac)).
			Errorf("Retry MAC must be exactly %d bytes", MACSize)
	}

	var key [32]byte
	copy(key[:], introKey)

	aead, err := gocrypto_chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create ChaCha20-Poly1305 AEAD")
	}

	tag := make([]byte, MACSize)
	copy(tag, mac)

	plaintext, err := aead.Decrypt(ciphertext, tag, header, retryAEADNonce(packetNumber))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to AEAD-decrypt intro-key payload")
	}
	return plaintext, nil
}
