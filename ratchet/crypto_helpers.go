package ratchet

import (
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

func zero32(k *[32]byte) {
	for i := range k {
		k[i] = 0
	}
}

// deriveDirectionalKeys derives distinct send and receive keys from a base key
// using HKDF with the spec-compliant "KDFDHRatchetStep" info string.
// Produces 64 bytes split into two 32-byte directional keys (a→b and b→a).
// The initiator sends on keys[0] and receives on keys[1]; the responder
// reverses this to maintain symmetric key agreement.
// Returns an error if key derivation fails.
// Spec ref: ratchet.md §"DH INITIALIZATION KDF".
func deriveDirectionalKeys(baseKey [32]byte, isInitiator bool) (sendKey, recvKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "deriveDirectionalKeys", "is_initiator": isInitiator}).Debug("deriving send/recv keys")
	kd := kdf.NewKeyDerivation(baseKey)

	keys, err := kd.DeriveKeys([]byte(hkdfInfoDHRatchetStep), 2)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive directional keys via KDFDHRatchetStep")
	}

	if isInitiator {
		return keys[0], keys[1], nil
	}
	return keys[1], keys[0], nil
}

// deriveSessionKeysFromSecret derives root, symmetric, and tag keys from a shared secret.
func deriveSessionKeysFromSecret(sharedSecret []byte) (*sessionKeys, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "deriveSessionKeysFromSecret", "secret_len": len(sharedSecret)}).Debug("deriving root/sym/tag keys from shared secret")
	var arr [32]byte
	copy(arr[:], sharedSecret)
	kd := kdf.NewKeyDerivation(arr)
	rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive session keys")
	}
	return &sessionKeys{rootKey: rootKey, symKey: symKey, tagKey: tagKey}, nil
}

// parseExistingSessionMessage parses an Existing Session message (without session tag prefix).
// Format: [ciphertext(N)] + [tag(16)]
// The nonce is derived from the message counter, not transmitted on the wire.
func parseExistingSessionMessage(msg []byte) (ciphertext []byte, tag [16]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "parseExistingSessionMessage", "msg_len": len(msg)}).Debug("parsing existing session message")
	if len(msg) < 16 {
		return nil, [16]byte{}, oops.Errorf("existing session message too short: %d bytes", len(msg))
	}

	ciphertext = msg[:len(msg)-16]
	copy(tag[:], msg[len(msg)-16:])

	return ciphertext, tag, nil
}

// encryptWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is counter-based: [0,0,0,0 || LE64(messageNumber)] per the spec.
func encryptWithSessionKey(messageKey [32]byte, plaintext []byte, sessionTag [8]byte, messageNumber uint32) (ciphertext []byte, tag [16]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "encryptWithSessionKey", "plaintext_len": len(plaintext), "message_number": messageNumber}).Debug("encrypting with session key")
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce := noise.BuildNonce(uint64(messageNumber))

	ciphertext, tag, err = aead.Encrypt(plaintext, sessionTag[:], nonce[:])
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	return ciphertext, tag, nil
}

// decryptWithSessionTag decrypts ciphertext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is derived from the message number: [0,0,0,0 || LE64(messageNumber)].
func decryptWithSessionTag(messageKey [32]byte, ciphertext []byte, tag [16]byte, sessionTag [8]byte, messageNumber uint32) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "decryptWithSessionTag", "ciphertext_len": len(ciphertext), "message_number": messageNumber}).Debug("decrypting with session tag")
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce := noise.BuildNonce(uint64(messageNumber))

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce[:])
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

// buildExistingSessionMessage constructs the wire format for an Existing Session message.
// Format: [sessionTag(8)] + [ciphertext(N)] + [authTag(16)]
// The nonce is not transmitted; both sides derive it from the message counter.
func buildExistingSessionMessage(sessionTag [8]byte, ciphertext []byte, tag [16]byte) []byte {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "buildExistingSessionMessage", "ciphertext_len": len(ciphertext)}).Debug("building wire format message")
	msg := make([]byte, 8+len(ciphertext)+16)
	copy(msg[0:8], sessionTag[:])
	copy(msg[8:8+len(ciphertext)], ciphertext)
	copy(msg[8+len(ciphertext):], tag[:])
	return msg
}

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// deriveMessageKey advances the symmetric ratchet to produce the next message key.
func deriveMessageKey(session *Session) ([32]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "deriveMessageKey", "message_counter": session.MessageCounter}).Debug("advancing symmetric ratchet for next message key")
	messageKey, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}
	return messageKey, nil
}

// generateAndTrackSessionTag generates the next session tag from the send-direction
// tag ratchet. The generated tag is NOT added to session.pendingTags: pendingTags
// tracks only incoming recv-direction tags used for the receive-window lookup.
// Tracking outbound send tags there would pollute the recv window, cause the
// replenishment threshold to never fire, and silently drain the actual recv window.
func generateAndTrackSessionTag(session *Session) ([8]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "generateAndTrackSessionTag"}).Debug("generating next session tag from send-direction ratchet")
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Wrapf(err, "failed to generate session tag")
	}
	return sessionTag, nil
}

// deriveTagAndSymKeysFromChainKey derives session tag and symmetric key chain keys
// from a chain key using HKDF with the spec-compliant "TagAndKeyGenKeys" info string.
// Returns (sessTag_ck, symmKey_ck) per the DH INITIALIZATION KDF:
//
//	keydata = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:31], symmKey_ck = keydata[32:63]
//
// Note: the byte ranges above use the I2P spec's inclusive notation, so each
// key is a full 32 bytes: sessTag_ck = keydata bytes 0..31, symmKey_ck =
// keydata bytes 32..63. The implementation derives the two 32-byte keys via the
// KDF library (DeriveKeys(..., 2)).
//
// Spec ref: ratchet.md §"DH INITIALIZATION KDF".
func deriveTagAndSymKeysFromChainKey(chainKey [32]byte) (tagKey, symKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "deriveTagAndSymKeysFromChainKey"}).Debug("deriving tag and symmetric keys via TagAndKeyGenKeys")
	kd := kdf.NewKeyDerivation(chainKey)
	keys, err := kd.DeriveKeys([]byte(hkdfInfoTagAndKeyGenKeys), 2)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive tag and symmetric keys via TagAndKeyGenKeys")
	}
	return keys[0], keys[1], nil
}

// performDHRatchetStep performs a Diffie-Hellman ratchet step for forward secrecy.
// After obtaining the new chain key from the DH ratchet, it derives the session tag
// and symmetric key chain keys using HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
// per the spec's DH INITIALIZATION KDF.
// On success, a NextKey block is queued for inclusion in the next outgoing message
// and session.sendKeyID is incremented to the new tag-set ID.
// Spec ref: ratchet.md §"Key and Tag Set IDs" — tag set ID is incremented when a
// new forward key is issued; maximum is MaxKeyID (32767).
func applyRatchetKeys(session *Session, send bool) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "applyRatchetKeys", "direction": map[bool]string{true: "send", false: "recv"}[send]}).Debug("performing DH ratchet step and applying derived keys")
	sendingChainKey, receivingChainKey, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		if send {
			return oops.Wrapf(err, "failed to perform DH ratchet")
		}
		return oops.Wrapf(err, "failed to perform receiving DH ratchet")
	}

	chainKey := receivingChainKey
	if send {
		chainKey = sendingChainKey
	}

	tagKey, symKey, err := deriveTagAndSymKeysFromChainKey(chainKey)
	if err != nil {
		if send {
			return oops.Wrapf(err, "failed to derive keys after DH ratchet step")
		}
		return oops.Wrapf(err, "failed to derive receiving tag and symmetric keys after DH ratchet")
	}

	if send {
		session.SymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
		session.TagRatchet = ratchet.NewTagRatchet(tagKey)
	} else {
		session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
		session.RecvTagRatchet = ratchet.NewTagRatchet(tagKey)
	}

	return nil
}

// applyRecvRatchetKeys performs a DH ratchet step and applies the derived keys
// to the session's receiving ratchet state.
func applyRecvRatchetKeys(session *Session) error {
	return applyRatchetKeys(session, false)
}

// applySendRatchetKeys performs a DH ratchet step and applies the derived keys
// to the session's sending ratchet state.
func applySendRatchetKeys(session *Session) error {
	return applyRatchetKeys(session, true)
}
