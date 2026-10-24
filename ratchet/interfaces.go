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

// Tunnel build-request and build-reply record crypto is deliberately NOT
// implemented here.
//
// The ECIES build-record formats live in tunnel-ecies.rst ("Tunnel ECIES-X25519
// Build Request Records"), not in ecies.rst, and they are Noise-pattern based
// ("Noise_N_25519_ChaChaPoly_SHA256", with the request's transcript hash `h`
// used as the reply record's associated data). Building them requires the
// HKDF-based layer/reply key derivation and, for Short records, raw ChaCha20
// (not ChaCha20/Poly1305) for the iteratively encrypted records.
//
// This package implements the ECIES *garlic* session only. Record crypto is a
// tunnel-layer concern and belongs in github.com/go-i2p/crypto, alongside the
// ECIES primitives it is built from; see the upstream gap report. The previous
// BuildRecordEncryptor / BuildReplyEncryptor interfaces and their
// implementations were removed because they encoded ElGamal-era record sizes
// (222-byte request cleartext, 528-byte reply cleartext with a caller-supplied
// reply key and IV) that no ECIES record format in the spec uses.

// TagResolver provides O(1) session tag lookup for incoming messages.
//
// This capability is embedded in [GarlicSessionManager] but can be used
// independently for tag-only resolution without full session management.
type TagResolver interface {
	// FindSessionByTag checks if a session tag matches a known session.
	// Returns true if the tag was found (and consumed), false otherwise.
	FindSessionByTag(tag [8]byte) bool
}
