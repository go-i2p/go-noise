package ratchet

import (
	"context"
)

// GarlicEncryptor provides ECIES-X25519-AEAD-Ratchet encryption for garlic
// messages.
//
// A garlic message is the I2P term for an encrypted message that may carry
// several "cloves" (sub-messages) for different destinations. Implementations
// handle session creation, key exchange, and ratchet advancement.
//
// All parameters use primitive types ([32]byte, []byte) rather than I2P-specific
// types. Callers in go-i2p are responsible for converting common.Hash, SessionKey,
// and other I2P types to raw bytes before calling these methods.
type GarlicEncryptor interface {
	// EncryptGarlicMessage encrypts a garlic message for a destination.
	//
	// Parameters:
	//   - destinationHash: 32-byte hash identifying the destination.
	//   - destinationPubKey: X25519 public key of the recipient.
	//   - plaintext: serialized garlic message bytes.
	//
	// Returns the complete encrypted message (New Session or Existing Session
	// format).
	EncryptGarlicMessage(destinationHash, destinationPubKey [32]byte, plaintext []byte) ([]byte, error)

	// EncryptUnboundGarlicMessage encrypts a garlic message as a one-shot
	// "unbound" New Session message that does not advertise the sender's
	// static key.
	//
	// "Unbound" means no session state is created on the sender side, so the
	// recipient cannot reply. Use this for fire-and-forget messages.
	//
	// Parameters:
	//   - destinationPubKey: X25519 public key of the recipient.
	//   - plaintext: serialized garlic message bytes.
	//
	// Returns the encrypted bytes in the unbound New Session format.
	EncryptUnboundGarlicMessage(destinationPubKey [32]byte, plaintext []byte) ([]byte, error)
}

// GarlicDecryptor provides ECIES-X25519-AEAD-Ratchet decryption for garlic
// messages. Implementations handle session tag lookup, key derivation, and
// AEAD decryption.
type GarlicDecryptor interface {
	// DecryptGarlicMessage decrypts an encrypted garlic message.
	//
	// Returns:
	//   - plaintext: the decrypted garlic payload.
	//   - sessionTag: the 8-byte tag that identifies the session; zero for
	//     New Session and New Session Reply messages.
	//   - sessionHash: SHA-256 of the initiator's static public key, for New
	//     Session messages; nil for Existing Session and New Session Reply.
	//     Responders must pass the dereferenced value to
	//     [GarlicSessionManager.EncryptNewSessionReply].
	//   - err: non-nil on decryption failure.
	DecryptGarlicMessage(encrypted []byte) (plaintext []byte, sessionTag [8]byte, sessionHash *[32]byte, err error)
}

// GarlicSessionManager combines encryption, decryption, and lifecycle
// management for ECIES-X25519-AEAD-Ratchet garlic sessions. This is the
// primary interface consumed by go-i2p's message processor and I2CP message
// router.
type GarlicSessionManager interface {
	GarlicEncryptor
	GarlicDecryptor

	// EncryptNewSessionReply constructs and returns a New Session Reply (NSR)
	// for a session established by a received New Session message. The
	// responder calls this to complete the Noise IK handshake and transition
	// to Existing Session encryption.
	//
	// sessionHash is the [32]byte value returned by DecryptGarlicMessage
	// (dereference the *[32]byte: `*sessionHash`). payload is the reply
	// plaintext.
	EncryptNewSessionReply(sessionHash [32]byte, payload []byte) ([]byte, error)

	// ProcessIncomingDHRatchet updates a session's receiving ratchet state
	// when a DH ratchet key is received from a peer.
	//
	// Parameters:
	//   - sessionTag: the tag that identified the session.
	//   - newRemotePubKey: the peer's new ephemeral public key.
	ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error

	// GetSessionCount returns the number of active sessions.
	GetSessionCount() int

	// CleanupExpiredSessions removes sessions past the timeout. Returns the
	// number of sessions removed.
	CleanupExpiredSessions() int

	// StartCleanupLoop starts periodic cleanup. The loop stops when EITHER
	// ctx is cancelled OR Close() is called on the SessionManager — whichever
	// comes first. Callers should not assume their ctx is the sole stop signal;
	// a concurrent Close() will also terminate the loop.
	StartCleanupLoop(ctx context.Context)

	// Close stops the cleanup loop, removes all sessions, and zeroes key
	// material.
	Close() error
}

// BuildRecordEncryptor encrypts tunnel build request records using
// ECIES-X25519.
//
// A tunnel build request is the first message in an I2P tunnel: it asks a
// peer to join a tunnel and carries the keys needed to encrypt the reply.
// This interface accepts pre-extracted raw key material; go-i2p is
// responsible for extracting keys from RouterInfo before calling these
// methods.
type BuildRecordEncryptor interface {
	// EncryptBuildRequest encrypts a serialized build request record
	// (222 bytes).
	//
	// Parameters:
	//   - cleartext: 222-byte serialized BuildRequestRecord.
	//   - recipientPubKey: recipient's 32-byte X25519 public key (extracted
	//     from RouterInfo by caller).
	//   - recipientIdentityHash: recipient's 32-byte identity hash (extracted
	//     from RouterInfo by caller).
	//
	// Returns the 528-byte encrypted record.
	EncryptBuildRequest(cleartext []byte, recipientPubKey, recipientIdentityHash [32]byte) ([528]byte, error)

	// DecryptBuildRequest decrypts a 528-byte encrypted build request record.
	//
	// Parameters:
	//   - encrypted: the 528-byte encrypted record.
	//   - privateKey: our 32-byte X25519 private key.
	//
	// Returns the 222-byte cleartext.
	DecryptBuildRequest(encrypted [528]byte, privateKey []byte) ([]byte, error)

	// VerifyIdentityHash checks whether an encrypted build request record is
	// intended for us, by comparing the embedded identity hash against ours.
	//
	// Parameters:
	//   - encrypted: the 528-byte record.
	//   - ourIdentityHash: our 32-byte identity hash.
	VerifyIdentityHash(encrypted [528]byte, ourIdentityHash [32]byte) bool
}

// BuildReplyEncryptor encrypts and decrypts tunnel build reply records.
//
// A tunnel build reply is the peer's answer to a build request: it either
// accepts the tunnel (and returns the session keys) or rejects it.
// Implementations use ChaCha20-Poly1305 or AES-256-CBC depending on record
// type.
type BuildReplyEncryptor interface {
	// EncryptReplyRecord encrypts a reply record.
	//
	// Parameters:
	//   - cleartext: serialized response record bytes.
	//   - replyKey: 32-byte session key.
	//   - replyIV: 16-byte initialization vector.
	//
	// Returns the encrypted bytes (544 bytes for ChaCha20-Poly1305).
	EncryptReplyRecord(cleartext []byte, replyKey [32]byte, replyIV [16]byte) ([]byte, error)

	// DecryptReplyRecord decrypts an encrypted reply record.
	//
	// Parameters:
	//   - encrypted: ciphertext bytes.
	//   - replyKey: 32-byte session key.
	//   - replyIV: 16-byte initialization vector.
	//
	// Returns the plaintext bytes.
	DecryptReplyRecord(encrypted []byte, replyKey [32]byte, replyIV [16]byte) ([]byte, error)
}

// TagResolver provides O(1) session tag lookup for incoming messages.
//
// This capability is embedded in [GarlicSessionManager] but can be used
// independently for tag-only resolution without full session management.
type TagResolver interface {
	// FindSessionByTag checks if a session tag matches a known session.
	// Returns true if the tag was found (and consumed), false otherwise.
	FindSessionByTag(tag [8]byte) bool
}
