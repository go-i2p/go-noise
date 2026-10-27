package ratchet

import (
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// deriveDirectionalTagSet performs the full per-direction DH_INITIALIZE
// followed by TagAndKeyGenKeys, producing the root key, session tag chain key,
// and symmetric key chain key for one direction.
//
// Spec ref: ecies.rst §"DH Ratchet KDF" + §"Tag and Key Generation" —
//
//	// DH_INITIALIZE(rootKey, k):
//	keydata = HKDF(rootKey, k, "KDFDHRatchetStep", 64)
//	nextRootKey = keydata[0:32]
//	ck = keydata[32:64]
//
//	// TagAndKeyGenKeys(ck):
//	keydata2 = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata2[0:32]
//	symmKey_ck = keydata2[32:64]
func deriveDirectionalTagSet(rootKey, k [32]byte) (nextRootKey, sessTagCK, symmKeyCK [32]byte, err error) {
	// Step 1: DH_INITIALIZE(rootKey, k)
	nextRootKey, ck, err := ratchet.DH_INITIALIZEFull(rootKey, k)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, oops.Wrapf(err, "DH_INITIALIZE failed")
	}

	// Step 2: TagAndKeyGenKeys(ck)
	sessTagCK, symmKeyCK, err = deriveTagAndSymKeysFromChainKey(ck)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, oops.Wrapf(err, "TagAndKeyGenKeys failed")
	}

	return nextRootKey, sessTagCK, symmKeyCK, nil
}

// deriveSessionKeysFromSecret performs the spec's split() operation on the
// final Noise handshake chain key, producing the directional keys k_ab and k_ba.
//
// Spec ref: ecies.rst §"Data Phase" —
//
//	keydata = HKDF(chainKey, ZEROLEN, "", 64)
//	k_ab = keydata[0:32]  (initiator → responder)
//	k_ba = keydata[32:64] (responder → initiator)
//
// The intermediate arr copy is zeroed before returning to prevent key material
// lingering on the stack.
func deriveSessionKeysFromSecret(chainKey []byte) (*sessionKeys, error) {
	flog("deriveSessionKeysFromSecret", logger.Fields{"secret_len": len(chainKey)}).Debug("deriving directional keys via split()")
	var arr [32]byte
	defer securemem.SecureZero(arr[:]) // Zero intermediate key material
	copy(arr[:], chainKey)

	keydata, err := kdf.StandardHKDF(arr[:], nil, []byte(""), 64)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive session keys via split()")
	}

	var kAB, kBA [32]byte
	copy(kAB[:], keydata[0:32])
	copy(kBA[:], keydata[32:64])

	return &sessionKeys{chainKey: arr, kAB: kAB, kBA: kBA}, nil
}

// parseExistingSessionMessage parses an Existing Session message (without session tag prefix).
// Format: [ciphertext(N)] + [tag(16)]
// The nonce is derived from the message counter, not transmitted on the wire.
func parseExistingSessionMessage(msg []byte) (ciphertext []byte, tag [16]byte, err error) {
	flog("parseExistingSessionMessage", logger.Fields{"msg_len": len(msg)}).Debug("parsing existing session message")
	if len(msg) < 16 {
		return nil, [16]byte{}, oops.Errorf("existing session message too short: %d bytes", len(msg))
	}

	ciphertext = msg[:len(msg)-16]
	copy(tag[:], msg[len(msg)-16:])

	return ciphertext, tag, nil
}

// encryptWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is counter-based: [0,0,0,0 || LE64(messageNumber)] per the spec.
// The messageKey is zeroed before returning to prevent key material lingering in memory.
func encryptWithSessionKey(messageKey [32]byte, plaintext []byte, sessionTag [8]byte, messageNumber uint32) (ciphertext []byte, tag [16]byte, err error) {
	defer securemem.SecureZero(messageKey[:]) // Zero message key after use

	flog("encryptWithSessionKey", logger.Fields{"plaintext_len": len(plaintext), "message_number": messageNumber}).Debug("encrypting with session key")
	aead, nonce, err := setupAEADWithNonce(messageKey, messageNumber)
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to create AEAD")
	}

	ciphertext, tag, err = aead.Encrypt(plaintext, sessionTag[:], nonce[:])
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	return ciphertext, tag, nil
}

// decryptWithSessionTag decrypts ciphertext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is derived from the message number: [0,0,0,0 || LE64(messageNumber)].
// The messageKey is zeroed before returning to prevent key material lingering in memory.
func decryptWithSessionTag(messageKey [32]byte, ciphertext []byte, tag [16]byte, sessionTag [8]byte, messageNumber uint32) ([]byte, error) {
	defer securemem.SecureZero(messageKey[:]) // Zero message key after use

	flog("decryptWithSessionTag", logger.Fields{"ciphertext_len": len(ciphertext), "message_number": messageNumber}).Debug("decrypting with session tag")
	aead, nonce, err := setupAEADWithNonce(messageKey, messageNumber)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce[:])
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

func setupAEADWithNonce(messageKey [32]byte, messageNumber uint32) (*chacha20poly1305.AEAD, [12]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [12]byte{}, err
	}

	nonce := noise.BuildNonce(uint64(messageNumber))
	return aead, nonce, nil
}

// buildExistingSessionMessage constructs the wire format for an Existing Session message.
// Format: [sessionTag(8)] + [ciphertext(N)] + [authTag(16)]
// The nonce is not transmitted; both sides derive it from the message counter.
func buildExistingSessionMessage(sessionTag [8]byte, ciphertext []byte, tag [16]byte) []byte {
	flog("buildExistingSessionMessage", logger.Fields{"ciphertext_len": len(ciphertext)}).Debug("building wire format message")
	msg := make([]byte, 8+len(ciphertext)+16)
	copy(msg[0:8], sessionTag[:])
	copy(msg[8:8+len(ciphertext)], ciphertext)
	copy(msg[8+len(ciphertext):], tag[:])
	return msg
}

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// deriveMessageKey advances the symmetric ratchet to produce the next message key.
func deriveMessageKey(session *Session) ([32]byte, error) {
	flog("deriveMessageKey", logger.Fields{"message_counter": session.MessageCounter}).Debug("advancing symmetric ratchet for next message key")
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
	flog("generateAndTrackSessionTag").Debug("generating next session tag from send-direction ratchet")
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Wrapf(err, "failed to generate session tag")
	}
	// Track consumption so the dynamic look-ahead and the "send next key at tag
	// 4096" threshold operate on real values.
	// Spec ref: ecies.md §"Parameters" - "Tagset look ahead of tag N",
	// "Send next key at tag: 4096".
	session.usedTags++
	return sessionTag, nil
}

// deriveTagAndSymKeysFromChainKey derives session tag and symmetric key chain keys
// from a chain key using RFC 5869 HKDF with the "TagAndKeyGenKeys" info string.
//
//	keydata = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
//
// Spec ref: ecies.rst §"DH INITIALIZATION KDF".
func deriveTagAndSymKeysFromChainKey(chainKey [32]byte) (tagKey, symKey [32]byte, err error) {
	flog("deriveTagAndSymKeysFromChainKey").Debug("deriving tag and symmetric keys via TagAndKeyGenKeys")
	keydata, err := kdf.StandardHKDF(chainKey[:], nil, []byte(hkdfInfoTagAndKeyGenKeys), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive tag and symmetric keys via TagAndKeyGenKeys")
	}
	copy(tagKey[:], keydata[0:32])
	copy(symKey[:], keydata[32:64])
	return tagKey, symKey, nil
}

// installSendTagset performs the send direction's DH and installs the resulting
// chains. It is called only when the peer's reverse NextKey arrives, which is
// when the spec says the tag sender does its single DH.
//
// Spec ref: ecies.md §"4a) DH Ratchet" -> §"DH RATCHET MESSAGE FLOW":
// "(do DH, create OB Tagset #N)".
//
// Per the same section, "After the DH ratchet is complete for an outbound
// tagset ... it should be used immediately, and the old outbound tagset may be
// deleted" - so, unlike the inbound direction, nothing is archived here.
//
// Must be called with session.mu held.
func (s *Session) installSendTagset(tagSetID uint16) error {
	flog("installSendTagset", logger.Fields{"tag_set_id": tagSetID}).Debug("Performing send-direction DH ratchet")
	tagKey, symKey, err := s.sendDir.ratchet(&s.sendRootKey)
	if err != nil {
		return err
	}
	s.TagRatchet = ratchet.NewTagRatchet(tagKey)
	s.SymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
	s.sendTagSetID = tagSetID
	// The outbound tagset restarts its message-number chain at 0: §"4b) Session
	// Tag Ratchet" defines N as "the message number of the message in the
	// current chain", and both references reset the counter with each new
	// tagset (i2pd RatchetTagSet::m_NextIndex, Java RatchetTagSet._lastKey).
	s.MessageCounter = 0
	s.usedTags = 0
	return nil
}

// installRecvTagset performs the receive direction's DH, archives the tagset it
// replaces, and installs the new inbound chains with a fresh tagset-local
// receive window.
//
// Spec ref: ecies.md §"4a) DH Ratchet" -> §"DH RATCHET MESSAGE FLOW":
// "(generate new key #N, do DH, create IB Tagset #N)".
func (s *Session) installRecvTagset(tagSetID uint16) error {
	flog("installRecvTagset", logger.Fields{"tag_set_id": tagSetID}).Debug("Performing receive-direction DH ratchet")
	tagKey, symKey, err := s.recvDir.ratchet(&s.recvRootKey)
	if err != nil {
		return err
	}
	// Keep listening on the superseded tagset for ~3 minutes.
	s.archiveRecvTagset()

	s.RecvTagRatchet = ratchet.NewTagRatchet(tagKey)
	s.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
	s.recvTagSetID = tagSetID
	// The new inbound tagset has its own tagset-local message-number chain
	// starting at 0, so the receive window and tag->counter map restart. The
	// old tags moved to prevRecv and stay in the manager's index, so the peer
	// can keep sending on the old tag set; the session's own pending list must
	// be emptied to let the caller generate the new tag set's window.
	s.recvTagCounter = make(map[[8]byte]uint32)
	s.pendingTags = nil
	// A new inbound tagset restarts the tagset-local message-number chain, so the
	// inbound index N restarts at 0 and the tagset counter advances. The counter
	// is what selects the sizing rule — "ES tagset 0 size: tsmin 24, tsmax 160"
	// versus "ES tagset (1+) size: 160 tsmin and tsmax" (ecies.md §"Parameters").
	s.usedRecvTags = 0
	s.recvTagsetIndex++
	resetRecvWindow(s)
	return nil
}
