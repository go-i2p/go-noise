// Package handshake implements the SSU2 handshake: the three-message
// exchange that establishes an encrypted, authenticated connection between
// two I2P routers over UDP.
//
// # How it works
//
// SSU2 is built on the Noise Protocol Framework, using the XK pattern with
// X25519, ChaCha20-Poly1305, and SHA-256. The handshake has three messages:
//
//  1. SessionRequest  (initiator → responder): carries the initiator's
//     ephemeral key and an encrypted static key.
//  2. SessionCreated  (responder → initiator): carries the responder's
//     ephemeral key.
//  3. SessionConfirmed (initiator → responder): carries the initiator's
//     RouterInfo and completes the key agreement.
//
// After all three messages, both sides hold the same transport keys and can
// exchange encrypted Data packets.
//
// I2P extends the base Noise pattern in a few ways: each handshake message
// carries a 16- or 32-byte header, that header is mixed into the handshake
// hash before encryption (binding it to the message), and the cleartext
// ephemeral keys are obfuscated with ChaCha20.
//
// The +hs1+hs2+hs3 in the protocol name names those three MixHash() calls by
// handshake message index — "an extra MixHash() before message N" — and each
// one mixes in that message's header. It does not mean "hash the key"; the
// responder's static key is mixed in raw, as MixHash(bpk), by the pre-message
// step.
//
// # What this package provides
//
//   - HandshakeHandler: drives the three-message exchange for both the
//     initiator and the responder.
//   - KeyRotationManager: tracks static and introduction keys and enforces
//     the minimum age before they may be rotated.
//   - Key and block helpers: key generation, key derivation, and the wire
//     block/packet types shared with the ssu2/wire package.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
package handshake
