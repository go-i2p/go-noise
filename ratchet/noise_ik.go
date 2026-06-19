package ratchet

// This file implements the Noise IKelg2+hs2 handshake for I2P
// ECIES-X25519-AEAD-Ratchet New Session messages. The implementation follows
// the Noise Protocol Framework (revision 34) with two I2P-specific
// modifications:
//
//   - elg2: Ephemeral public keys are Elligator2-encoded to be
//     indistinguishable from random bytes on the wire.
//   - hs2: The responder's static public key pre-message uses Hash(s)
//     instead of the raw key, allowing initiators to start a handshake
//     knowing only the responder's identity hash.
//
// Wire format for New Session (IK message 1):
//
//	[Elligator2(ephemeral_pub)(32)] + [EncryptAndHash(static_pub)(48)] + [EncryptAndHash(payload)(N+16)]

import (
	"crypto/sha256"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/elligator2"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

const (
	// noiseProtocolName is the Noise protocol identifier for I2P ECIES-X25519-AEAD-Ratchet.
	noiseProtocolName = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"

	// noiseIKOverhead is the fixed overhead added by the Noise IK handshake:
	// 32 (Elligator2 ephemeral key) + 16 (static key AEAD tag) + 16 (payload AEAD tag).
	noiseIKOverhead = 32 + 16 + 16

	// noiseIKMinMessageSize is the minimum New Session message size:
	// 32 (ephemeral) + 48 (encrypted static) + 16 (minimum payload AEAD = empty plaintext + tag).
	noiseIKMinMessageSize = 32 + 48 + 16

	// noiseEncryptedStaticSize is the size of the encrypted static key section:
	// 32 bytes key + 16 bytes AEAD tag.
	noiseEncryptedStaticSize = 48
)

// initNoiseIK initializes the Noise symmetric state for the IKelg2+hs2 handshake.
// The protocol name is hashed (since it exceeds 32 bytes), then the null prologue
// is mixed in (as required by the Noise spec §5.6 and the I2P ECIES-X25519-AEAD-Ratchet
// spec KDF section), and finally the responder's static key hash is mixed in per hs2.
//
// Initialization transcript:
//
//	h = SHA-256(protocol_name)           InitializeSymmetric
//	ck = h
//	h = SHA-256(h || "")                 MixHash(null prologue)  — required by spec
//	h = SHA-256(h || SHA-256(rs))        MixHash(Hash(rs))       — hs2 pre-message
func initNoiseIK(responderStaticPub [32]byte) *noise.SymmetricState {
	flog("initNoiseIK").Debug("Initializing Noise IKelg2+hs2 symmetric state")
	ns := &noise.SymmetricState{}
	ns.SetCipherSuite(noise.ChaChaPoly_SHA256())
	ns.InitializeSymmetric([]byte(noiseProtocolName))

	// MixHash(null prologue): h = SHA-256(h || "")
	// The I2P ECIES-X25519-AEAD-Ratchet spec requires an explicit MixHash of the
	// empty prologue before any pre-message processing. Omitting this step diverges
	// from the spec transcript and breaks interoperability with conformant routers
	// (Java I2P, i2pd) which apply this step correctly.
	ns.MixHash([]byte{})

	// Pre-message (← s) with hs2: MixHash(Hash(rs)) instead of MixHash(rs)
	rsHash := sha256.Sum256(responderStaticPub[:])
	ns.MixHash(rsHash[:])

	return ns
}

func resumeNoiseHandshakeState(ns *noise.SymmetricState, hs *noiseHandshakeState) {
	ns.SetCipherSuite(noise.ChaChaPoly_SHA256())
	ns.SetHandshakeHash(hs.h)
	ns.SetChainingKey(hs.ck)
}

// mixKeyCKOnly updates only the chaining key via a single-output HKDF.
// Per I2P ratchet.md §1g, the "ee" handshake token in the NSR uses:
//
//	ck = HKDF(chainKey, DH(e, re), "", 32)
//
// Unlike MixKey, this does NOT update the cipher key (k) or reset the nonce.
// The spec mandates single-output HKDF for "ee" to prevent accidental use
// of an intermediate cipher key between the "ee" and "se" steps.
func mixKeyCKOnly(ns *noise.SymmetricState, ikm []byte) {
	flog("mixKeyCKOnly", logger.Fields{"ikm_len": len(ikm)}).Debug("mixKeyCKOnly: updating chaining key via single-output HKDF")
	ck1 := noise.HKDF1SHA256(ns.ChainingKey(), ikm)
	ns.SetChainingKey(ck1[:])
}

// writeNoiseIKMessage1 constructs a New Session message using the Noise IK pattern
// with Elligator2-encoded ephemeral keys (elg2) and hashed static pre-message (hs2).
//
// The initiator calls this to encrypt a payload for a known responder. Returns
// the wire-format message, session keys derived from the handshake chaining key,
// and the handshake state retained for processing the New Session Reply (message 2).
func writeNoiseIKMessage1(
	ourStaticPriv, ourStaticPub, responderStaticPub [32]byte,
	payload []byte,
) ([]byte, *sessionKeys, *noiseHandshakeState, error) {
	flog("writeNoiseIKMessage1").Debug("Constructing Noise IK New Session message")
	ns := initNoiseIK(responderStaticPub)

	// Token e: Generate Elligator2-representable ephemeral key pair
	ephPub, ephPrivBytes, err := elligator2.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to generate Elligator2 ephemeral key pair")
	}

	// Elligator2-encode the ephemeral public key for the wire
	ephEncoded, err := elligator2.Encode(ephPub)
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to Elligator2-encode ephemeral public key")
	}

	// MixHash the encoded (wire) representation, not the raw key
	ns.MixHash(ephEncoded)

	// Token es: DH(ephemeral_private, responder_static)
	sharedES, err := curve25519.SharedKey(ephPrivBytes, responderStaticPub[:])
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to compute DH(e, rs)")
	}
	ns.MixKey(sharedES)

	// Token s: Encrypt our static public key under the current key
	encryptedStatic, err := ns.EncryptAndHash(nil, ourStaticPub[:])
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to encrypt static public key")
	}

	// Token ss: DH(our_static_private, responder_static)
	sharedSS, err := curve25519.SharedKey(ourStaticPriv[:], responderStaticPub[:])
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to compute DH(s, rs)")
	}
	ns.MixKey(sharedSS)

	// Encrypt the garlic payload
	encryptedPayload, err := ns.EncryptAndHash(nil, payload)
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to encrypt payload")
	}

	// Construct wire message: [elligator2(e)(32)] + [encrypted_s(48)] + [encrypted_payload(N+16)]
	msg := make([]byte, 0, 32+len(encryptedStatic)+len(encryptedPayload))
	msg = append(msg, ephEncoded...)
	msg = append(msg, encryptedStatic...)
	msg = append(msg, encryptedPayload...)

	// Retain handshake state for New Session Reply (message 2)
	hs := &noiseHandshakeState{
		h:            ns.HandshakeHash(),
		ck:           ns.ChainingKey(),
		localEphPriv: ephPrivBytes,
	}

	// Derive session keys from the final chaining key
	keys, err := deriveSessionKeysFromSecret(ns.ChainingKey())
	if err != nil {
		return nil, nil, nil, oops.Wrapf(err, "failed to derive session keys from handshake")
	}

	return msg, keys, hs, nil
}

// writeNoiseIKMessage1Unbound constructs an unbound New Session message using
// the Noise N pattern (§1c of the I2P ECIES-X25519-AEAD-Ratchet spec). The
// initiator's static key is NOT included; instead a 32-byte zero flags section
// is encrypted in its place. The receiver detects the unbound variant by
// decrypting the flags section and testing whether all 32 bytes are zero.
//
// Use cases: raw-datagram and one-time-send traffic where sender anonymity
// requires not advertising the static key. Unbound sessions are non-repliable.
//
// Wire format: [Elligator2(e)(32)] + [EncryptAndHash(zeros32)(48)] + [EncryptAndHash(payload)(N+16)]
//
// KDF differences from the bound (IK) variant:
//   - No Token s: flags section (zeros) is encrypted with n=0 (same k as es token)
//   - No Token ss: no second DH, no new MixKey — the nonce counter is NOT reset
//   - Payload is encrypted with n=1 (one above the flags section)
//
// Spec ref: ratchet.md §1c, §1f "KDF for Payload Section (without Alice static key)"
func writeNoiseIKMessage1Unbound(
	responderStaticPub [32]byte,
	payload []byte,
) ([]byte, *sessionKeys, error) {
	flog("writeNoiseIKMessage1Unbound", logger.Fields{"payload_len": len(payload)}).Debug("Constructing unbound Noise N New Session message")
	// Same IK initializer as the bound variant: identical protocol name, null
	// prologue MixHash, and Hash(rs) pre-message. Spec §1f: "we use the same
	// initializer for both the IK pattern (bound sessions) and for N pattern
	// (unbound sessions)."
	ns := initNoiseIK(responderStaticPub)

	// Token e: Generate Elligator2-representable ephemeral key pair.
	ephPub, ephPrivBytes, err := elligator2.GenerateKeyPair()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to generate Elligator2 ephemeral key pair")
	}

	ephEncoded, err := elligator2.Encode(ephPub)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to Elligator2-encode ephemeral public key")
	}

	// MixHash the wire (Elligator2-encoded) representation.
	ns.MixHash(ephEncoded)

	// Token es: DH(ephemeral_private, responder_static). Sets k, resets n=0.
	sharedES, err := curve25519.SharedKey(ephPrivBytes, responderStaticPub[:])
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to compute DH(e, rs)")
	}
	ns.MixKey(sharedES) // n=0 after this

	// Flags section (unbound marker): EncryptAndHash(zeros32) using n=0.
	// Plaintext is 32 zero bytes — the receiver tests the decrypted plaintext
	// for all-zeros to identify the unbound variant. Spec §1c.
	// After encryption ns.n advances to 1.
	encryptedFlags, err := ns.EncryptAndHash(nil, make([]byte, 32))
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to encrypt unbound flags section")
	}

	// Encrypt payload with n=1 (no ss token, no MixKey reset).
	// Spec §1f "KDF for Payload Section (without Alice static key)": n=1.
	encryptedPayload, err := ns.EncryptAndHash(nil, payload)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to encrypt payload")
	}

	// Wire: [Elligator2(e)(32)] + [encryptedFlags(48)] + [encryptedPayload(N+16)]
	msg := make([]byte, 0, 32+len(encryptedFlags)+len(encryptedPayload))
	msg = append(msg, ephEncoded...)
	msg = append(msg, encryptedFlags...)
	msg = append(msg, encryptedPayload...)

	// Derive session keys from the final chaining key.
	keys, err := deriveSessionKeysFromSecret(ns.ChainingKey())
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive session keys from unbound handshake")
	}

	return msg, keys, nil
}

// isAllZeros reports whether all bytes in b are 0x00.
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// readNoiseIKMessage1 processes a received New Session message using the Noise
// IK pattern. The responder calls this to decrypt the initiator's payload.
// It handles both the bound (IK, with initiator static key) and unbound (N,
// flags section all-zeros) variants; isUnbound signals which was detected.
//
// For bound messages: returns initiator's static public key and handshake state.
// For unbound messages: initiatorStaticPub is [32]byte{} (zero), hs is nil.
//
// Returns the decrypted payload, initiator's static public key, session keys,
// handshake state for the New Session Reply (nil for unbound), isUnbound, and error.
func readNoiseIKMessage1(
	ourStaticPriv, ourStaticPub [32]byte,
	message []byte,
) ([]byte, [32]byte, *sessionKeys, *noiseHandshakeState, bool, error) {
	flog("readNoiseIKMessage1").Debug("Processing received Noise IK New Session message")
	if len(message) < noiseIKMinMessageSize {
		return nil, [32]byte{}, nil, nil, false, oops.Errorf(
			"new session message too short: %d bytes (minimum %d)", len(message), noiseIKMinMessageSize,
		)
	}

	ns := initNoiseIK(ourStaticPub)

	initiatorEphPub, err := readEphemeralKey(ns, message[0:32])
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, err
	}

	// Token es: DH(our_static_private, ephemeral). Sets k, resets n=0.
	sharedES, err := curve25519.SharedKey(ourStaticPriv[:], initiatorEphPub[:])
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to compute DH(s, re)")
	}
	ns.MixKey(sharedES)

	// Decrypt the static key / flags section (n=0; after decryption ns.n=1).
	encryptedStatic := message[32 : 32+noiseEncryptedStaticSize]
	initiatorStaticBytes, err := ns.DecryptAndHash(nil, encryptedStatic)
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to decrypt initiator static key / flags section")
	}

	encryptedPayload := message[32+noiseEncryptedStaticSize:]

	if isAllZeros(initiatorStaticBytes) {
		return readUnboundPayload(ns, encryptedPayload)
	}
	return readBoundPayload(ns, ourStaticPriv, initiatorEphPub, initiatorStaticBytes, encryptedPayload)
}

// readEphemeralKey reads and decodes the Elligator2-encoded ephemeral key.
func readEphemeralKey(ns *noise.SymmetricState, ephEncoded []byte) ([32]byte, error) {
	flog("readEphemeralKey", logger.Fields{"encoded_len": len(ephEncoded)}).Debug("Decoding Elligator2 ephemeral key")
	ns.MixHash(ephEncoded)
	ephPubBytes, err := elligator2.Decode(ephEncoded)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to decode Elligator2 ephemeral key")
	}
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	return ephPub, nil
}

// readUnboundPayload handles the unbound (N-pattern) variant of the IK message.
func readUnboundPayload(ns *noise.SymmetricState, encryptedPayload []byte) ([]byte, [32]byte, *sessionKeys, *noiseHandshakeState, bool, error) {
	flog("readUnboundPayload", logger.Fields{"encrypted_len": len(encryptedPayload)}).Debug("Processing unbound (N-pattern) payload")
	payload, err := ns.DecryptAndHash(nil, encryptedPayload)
	if err != nil {
		return nil, [32]byte{}, nil, nil, true, oops.Wrapf(err, "failed to decrypt unbound payload")
	}
	keys, err := deriveSessionKeysFromSecret(ns.ChainingKey())
	if err != nil {
		return nil, [32]byte{}, nil, nil, true, oops.Wrapf(err, "failed to derive session keys from unbound handshake")
	}
	return payload, [32]byte{}, keys, nil, true, nil
}

// readBoundPayload handles the bound (IK) variant of the message.
func readBoundPayload(
	ns *noise.SymmetricState, ourStaticPriv [32]byte,
	initiatorEphPub [32]byte, initiatorStaticBytes []byte,
	encryptedPayload []byte,
) ([]byte, [32]byte, *sessionKeys, *noiseHandshakeState, bool, error) {
	flog("readBoundPayload", logger.Fields{"encrypted_len": len(encryptedPayload)}).Debug("Processing bound (IK-pattern) payload")
	var initiatorStaticPub [32]byte
	copy(initiatorStaticPub[:], initiatorStaticBytes)

	// Token ss: DH(our_static_private, initiator_static). Resets n=0.
	sharedSS, err := curve25519.SharedKey(ourStaticPriv[:], initiatorStaticPub[:])
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to compute DH(s, rs)")
	}
	ns.MixKey(sharedSS)

	payload, err := ns.DecryptAndHash(nil, encryptedPayload)
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to decrypt payload")
	}

	hs := &noiseHandshakeState{
		h:               ns.HandshakeHash(),
		ck:              ns.ChainingKey(),
		remoteEphPub:    initiatorEphPub,
		remoteStaticPub: initiatorStaticPub,
	}
	keys, err := deriveSessionKeysFromSecret(ns.ChainingKey())
	if err != nil {
		return nil, [32]byte{}, nil, nil, false, oops.Wrapf(err, "failed to derive session keys from handshake")
	}
	return payload, initiatorStaticPub, keys, hs, false, nil
}
