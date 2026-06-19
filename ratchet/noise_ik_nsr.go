package ratchet

// This file implements the Noise IK message 2 (New Session Reply) for I2P
// ECIES-X25519-AEAD-Ratchet. The NSR completes the IK handshake initiated by
// the New Session message (message 1, implemented in noise_ik.go).
//
// NSR wire format:
//   [SessionTag(8)] + [Elligator2(bepk)(32)] + [KeySectionMAC(16)] + [EncPayload(N)] + [PayloadMAC(16)]
//
// The responder (Bob) writes message 2. The initiator (Alice) reads message 2.
// Both sides retain handshake state (h, ck) from message 1 to continue the handshake.
//
// Spec ref: ratchet.md §"1g) New Session Reply format"

import (
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/elligator2"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

const (
	// nsrMinMessageSize is the minimum NSR message size:
	// 8 (tag) + 32 (ephemeral) + 16 (key section MAC) + 16 (empty payload MAC).
	nsrMinMessageSize = 8 + 32 + 16 + 16

	// nsrHeaderSize is the fixed header before the encrypted payload:
	// 8 (tag) + 32 (ephemeral) + 16 (key section MAC).
	nsrHeaderSize = 8 + 32 + 16

	// hkdfInfoSessionReplyTags is the info string for deriving the NSR reply tagset key.
	// Spec ref: ratchet.md §"KDF for Reply TagSet".
	hkdfInfoSessionReplyTags = "SessionReplyTags"

	// hkdfInfoAttachPayloadKDF is the info string for deriving the NSR payload encryption key.
	// Spec ref: ratchet.md §"KDF for Payload Section Encrypted Contents".
	hkdfInfoAttachPayloadKDF = "AttachPayloadKDF"
)

// noiseHandshakeState captures intermediate Noise IK state after message 1
// (New Session) for constructing message 2 (New Session Reply).
// Both the initiator and responder retain this state after the NS exchange.
type noiseHandshakeState struct {
	h  []byte // handshake hash after NS message 1
	ck []byte // chaining key after NS message 1

	// localEphPriv is the initiator's ephemeral private key, retained for the
	// "ee" DH pattern in message 2. Only set on the initiator side.
	localEphPriv []byte

	// remoteEphPub is the remote peer's ephemeral public key (decoded from
	// Elligator2). Set on the responder side for the "ee" DH pattern.
	remoteEphPub [32]byte

	// remoteStaticPub is the remote peer's static public key (recovered from
	// the encrypted static key section). Set on the responder side for "se".
	remoteStaticPub [32]byte
}

// nsrSessionKeys holds the directional keys derived from the NSR split() operation.
// These keys initialize the Existing Session ratchets after the handshake completes.
type nsrSessionKeys struct {
	chainKey [32]byte // chain key for DH ratchet initialization
	keyAB    [32]byte // initiator → responder direction key
	keyBA    [32]byte // responder → initiator direction key
}

// deriveNSRTagRatchet creates a TagRatchet for NSR session tags.
// Both initiator and responder call this with the same chainKey from the NS exchange
// to generate/recognize NSR tags.
//
// Spec: tagsetKey = HKDF(chainKey, ZEROLEN, "SessionReplyTags", 32)
//
//	tagset_nsr = DH_INITIALIZE(chainKey, tagsetKey)
func deriveNSRTagRatchet(chainKey []byte) (*ratchet.TagRatchet, error) {
	flog("deriveNSRTagRatchet", logger.Fields{"chain_key_len": len(chainKey)}).Debug("Deriving NSR tag ratchet")
	// Step 1: Derive tagsetKey
	tagsetKey, err := kdf.StandardHKDF(chainKey, nil, []byte(hkdfInfoSessionReplyTags), 32)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive NSR tagset key")
	}

	// Step 2: DH_INITIALIZE(chainKey, tagsetKey)
	// keydata = HKDF(chainKey, tagsetKey, "KDFDHRatchetStep", 64)
	keydata, err := kdf.StandardHKDF(chainKey, tagsetKey, []byte(hkdfInfoDHRatchetStep), 64)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive NSR DH ratchet step")
	}
	var ck [32]byte
	copy(ck[:], keydata[32:64])

	// keydata2 = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
	keydata2, err := kdf.StandardHKDF(ck[:], nil, []byte(hkdfInfoTagAndKeyGenKeys), 64)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive NSR tag and key gen keys")
	}
	var nsrTagKey [32]byte
	copy(nsrTagKey[:], keydata2[0:32])

	return ratchet.NewTagRatchet(nsrTagKey), nil
}

// writeNoiseIKMessage2 constructs a New Session Reply (NSR) message.
// The responder (Bob) calls this after receiving Alice's New Session.
//
// Parameters:
//   - hs: handshake state retained from readNoiseIKMessage1
//   - payload: plaintext payload for the reply
//
// Returns the NSR session tag, wire-format message including the 8-byte tag
// prefix at bytes [0:8], and directional session keys for initializing ES ratchets.
func writeNoiseIKMessage2(
	hs *noiseHandshakeState,
	payload []byte,
) (nsrTag [8]byte, wireMsg []byte, keys *nsrSessionKeys, err error) {
	flog("writeNoiseIKMessage2", logger.Fields{"payload_len": len(payload)}).Debug("Constructing New Session Reply (NSR) message")
	// Derive NSR tag
	nsrTagRatchet, err := deriveNSRTagRatchet(hs.ck)
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to derive NSR tag ratchet")
	}
	tag, err := nsrTagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to generate NSR tag")
	}

	// Continue Noise handshake from retained state
	ns := &noise.SymmetricState{}
	resumeNoiseHandshakeState(ns, hs)

	// MixHash(tag) — bind the tag into the handshake transcript
	ns.MixHash(tag[:])

	// "e" pattern: Generate Bob's Elligator2-representable ephemeral key pair
	ephPub, ephPrivBytes, err := elligator2.GenerateKeyPair()
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to generate NSR ephemeral key pair")
	}
	ephEncoded, err := elligator2.Encode(ephPub)
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to Elligator2-encode NSR ephemeral key")
	}
	ns.MixHash(ephEncoded) // MixHash the wire representation

	// "ee" pattern: DH(besk, aepk)
	// Per I2P ratchet.md §1g, "ee" uses single-output HKDF: only ck is updated.
	// The cipher key (k) is not modified until the subsequent "se" step.
	sharedEE, err := curve25519.SharedKey(ephPrivBytes, hs.remoteEphPub[:])
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to compute NSR DH(e, re)")
	}
	mixKeyCKOnly(ns, sharedEE)

	// "se" pattern: DH(besk, apk)
	sharedSE, err := curve25519.SharedKey(ephPrivBytes, hs.remoteStaticPub[:])
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to compute NSR DH(e, rs)")
	}
	ns.MixKey(sharedSE)

	// Encrypt ZEROLEN to produce the key section MAC (16 bytes)
	keySectionMAC, err := ns.EncryptAndHash(nil, []byte{})
	if err != nil {
		return [8]byte{}, nil, nil, oops.Wrapf(err, "failed to encrypt NSR key section")
	}

	// Payload section: split() and encrypt
	encryptedPayload, nsrKeys, err := encryptNSRPayload(ns, payload)
	if err != nil {
		return [8]byte{}, nil, nil, err
	}

	// Wire format: [tag(8)] + [ephEncoded(32)] + [keySectionMAC(16)] + [encPayload(N+16)]
	msg := make([]byte, 0, 8+32+len(keySectionMAC)+len(encryptedPayload))
	msg = append(msg, tag[:]...)
	msg = append(msg, ephEncoded...)
	msg = append(msg, keySectionMAC...)
	msg = append(msg, encryptedPayload...)

	return tag, msg, nsrKeys, nil
}

// readNoiseIKMessage2 processes a received New Session Reply from the responder.
// The initiator (Alice) calls this after receiving Bob's NSR.
//
// Parameters:
//   - hs: handshake state retained from writeNoiseIKMessage1
//   - ourStaticPriv: Alice's static private key (for the "se" DH)
//   - message: the full NSR wire message including the tag prefix
//
// Returns the decrypted payload and directional session keys.
func readNoiseIKMessage2(
	hs *noiseHandshakeState,
	ourStaticPriv [32]byte,
	message []byte,
) ([]byte, *nsrSessionKeys, error) {
	flog("readNoiseIKMessage2").Debug("Processing received New Session Reply")
	if len(message) < nsrMinMessageSize {
		return nil, nil, oops.Errorf(
			"NSR message too short: %d bytes (minimum %d)", len(message), nsrMinMessageSize,
		)
	}

	// Parse tag
	var nsrTag [8]byte
	copy(nsrTag[:], message[0:8])

	// Continue Noise handshake from retained state
	ns := &noise.SymmetricState{}
	resumeNoiseHandshakeState(ns, hs)

	// MixHash(tag)
	ns.MixHash(nsrTag[:])

	// "e" pattern: Read Bob's Elligator2-encoded ephemeral key
	ephEncoded := message[8:40]
	ns.MixHash(ephEncoded)

	ephPubBytes, err := elligator2.Decode(ephEncoded)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to decode NSR Elligator2 ephemeral key")
	}

	// "ee" pattern: DH(aesk, bepk)
	// Per I2P ratchet.md §1g, "ee" uses single-output HKDF: only ck is updated.
	// The cipher key (k) is not modified until the subsequent "se" step.
	sharedEE, err := curve25519.SharedKey(hs.localEphPriv, ephPubBytes)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to compute NSR DH(e, re)")
	}
	mixKeyCKOnly(ns, sharedEE)

	// "se" pattern: DH(ask, bepk)
	sharedSE, err := curve25519.SharedKey(ourStaticPriv[:], ephPubBytes)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to compute NSR DH(s, re)")
	}
	ns.MixKey(sharedSE)

	// Decrypt key section MAC (verify ZEROLEN encryption)
	keySectionMAC := message[40:56]
	_, err = ns.DecryptAndHash(nil, keySectionMAC)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "NSR key section authentication failed")
	}

	// Payload section: split() and decrypt
	encryptedPayload := message[56:]
	plaintext, nsrKeys, err := decryptNSRPayload(ns, encryptedPayload)
	if err != nil {
		return nil, nil, err
	}

	return plaintext, nsrKeys, nil
}

// deriveNSRPayloadCipher derives the AEAD cipher and session keys for NSR payload
// encryption or decryption by performing the split() operation and payload key
// derivation. This consolidates the common key derivation logic shared by
// encryptNSRPayload and decryptNSRPayload.
func deriveNSRPayloadCipher(ns *noise.SymmetricState) (*chacha20poly1305.AEAD, [32]byte, [32]byte, error) {
	flog("deriveNSRPayloadCipher").Debug("Deriving NSR payload cipher via split() and HKDF")
	// split(): keydata = HKDF(chainKey, ZEROLEN, "", 64)
	kAB, kBA := noise.HKDF2SHA256(ns.ChainingKey(), nil)

	// Derive payload key: k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)
	payloadKeyBytes, err := kdf.StandardHKDF(kBA[:], nil, []byte(hkdfInfoAttachPayloadKDF), 32)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive NSR payload key")
	}
	var payloadKey [32]byte
	copy(payloadKey[:], payloadKeyBytes)

	aead, err := chacha20poly1305.NewAEAD(payloadKey)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to create AEAD for NSR payload")
	}

	return aead, kAB, kBA, nil
}

// encryptNSRPayload performs the split() and payload encryption for NSR.
// Spec ref: ratchet.md §"KDF for Payload Section Encrypted Contents".
func encryptNSRPayload(ns *noise.SymmetricState, payload []byte) ([]byte, *nsrSessionKeys, error) {
	flog("encryptNSRPayload", logger.Fields{"payload_len": len(payload)}).Debug("Encrypting NSR payload")
	aead, kAB, kBA, err := deriveNSRPayloadCipher(ns)
	if err != nil {
		return nil, nil, err
	}

	nonce := noise.BuildNonce(0)
	ct, tag, err := aead.Encrypt(payload, ns.HandshakeHash(), nonce[:])
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to encrypt NSR payload")
	}

	var encrypted []byte
	encrypted = append(encrypted, ct...)
	encrypted = append(encrypted, tag[:]...)

	var chainKey [32]byte
	copy(chainKey[:], ns.ChainingKey())
	return encrypted, &nsrSessionKeys{
		chainKey: chainKey,
		keyAB:    kAB,
		keyBA:    kBA,
	}, nil
}

// decryptNSRPayload performs the split() and payload decryption for NSR.
func decryptNSRPayload(ns *noise.SymmetricState, encrypted []byte) ([]byte, *nsrSessionKeys, error) {
	flog("decryptNSRPayload", logger.Fields{"encrypted_len": len(encrypted)}).Debug("Decrypting NSR payload")
	if len(encrypted) < 16 {
		return nil, nil, oops.Errorf("NSR payload too short for auth tag: %d bytes", len(encrypted))
	}

	aead, kAB, kBA, err := deriveNSRPayloadCipher(ns)
	if err != nil {
		return nil, nil, err
	}

	ct := encrypted[:len(encrypted)-16]
	var tag [16]byte
	copy(tag[:], encrypted[len(encrypted)-16:])

	nonce := noise.BuildNonce(0)
	plaintext, err := aead.Decrypt(ct, tag[:], ns.HandshakeHash(), nonce[:])
	if err != nil {
		return nil, nil, oops.Wrapf(err, "NSR payload decryption failed (authentication error)")
	}

	var chainKey [32]byte
	copy(chainKey[:], ns.ChainingKey())
	return plaintext, &nsrSessionKeys{
		chainKey: chainKey,
		keyAB:    kAB,
		keyBA:    kBA,
	}, nil
}
