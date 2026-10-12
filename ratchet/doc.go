// Package ratchet implements the ECIES-X25519-AEAD-Ratchet encryption scheme
// used by the I2P network to protect messages in transit.
//
// # How it works
//
// The scheme combines two ideas:
//
//  1. A ratchet for forward secrecy. A ratchet is a chain of keys where each
//     key is derived from the previous one, and each key is destroyed after
//     use. If an attacker steals a key today, they cannot decrypt messages
//     from yesterday — only messages from today onward are at risk.
//
//  2. X25519 key agreement. X25519 is a fast way for two parties to agree on
//     a shared secret over an open channel without ever sending the secret
//     itself. The ratchet uses X25519 to refresh its keys periodically.
//
// Together, these give the I2P network a way to encrypt messages so that old
// messages stay safe even if a key is later compromised.
//
// # The protocol
//
// A session between two I2P destinations starts with a New Session message,
// which uses the Noise IK handshake to establish the first shared keys.
// After that, every message is an Existing Session message: the sender
// advances the ratchet to derive a fresh key for that one message, encrypts
// the payload, and prefixes the message with an 8-byte tag that identifies
// the session. The receiver looks up the tag, finds the matching session,
// and decrypts.
//
// See [I2P Spec: ECIES](https://geti2p.net/spec/ecies) for details.
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// # What this package provides
//
// The package exposes a small set of interfaces so that the I2P routing layer
// (go-i2p) can use the crypto without depending on I2P-specific types. All
// parameters are primitive Go types: [32]byte for keys and hashes, [8]byte
// for session tags, and []byte for message bodies.
//
//   - [GarlicSessionManager]: the full interface — encrypt, decrypt, and
//     manage the lifecycle of sessions.
//   - [GarlicEncryptor]: encrypt-only subset, for components that only send.
//   - [GarlicDecryptor]: decrypt-only subset, for components that only receive.
//   - [BuildRecordEncryptor]: encrypts tunnel build request records (ECIES-X25519).
//   - [BuildReplyEncryptor]: encrypts tunnel build reply records (ChaCha20-Poly1305).
//   - [TagResolver]: fast lookup of a session by its 8-byte tag.
//
// Callers in go-i2p convert I2P types to raw bytes before calling these
// interfaces:
//
//   - common.Hash → [32]byte
//   - session_key.SessionKey → [32]byte
//   - session_tag.ECIESSessionTag → [8]byte
//   - router_info.RouterInfo → extracted [32]byte keys via adapter functions
//
// Reference: https://geti2p.net/spec/ecies
package ratchet
