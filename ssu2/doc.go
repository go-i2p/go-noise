// Package ssu2 implements the I2P SSU2 transport protocol.
//
// # What is SSU2?
//
// SSU2 (Secure Semi-reliable UDP version 2) is the transport protocol that
// I2P routers use to talk to each other over UDP. It carries I2NP messages
// (the messages routers exchange to build and use anonymous paths) between
// two routers, one UDP packet at a time.
//
// SSU2 is built on the Noise Protocol Framework, a well-studied way to
// securely agree on encryption keys between two parties. The exact Noise
// pattern SSU2 uses is:
//
//	Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256
//
// In plain terms:
//
//   - XK: the initiator already knows the responder's long-term public key,
//     so the first message can be small and the handshake is fast.
//   - chaobfse: the cleartext parts of the handshake (the one-time public
//     keys) are hidden with ChaCha20 stream encryption, so an observer
//     cannot tell which packets are handshake packets.
//   - hs1+hs2+hs3: three handshake messages, each carrying a 16 or 32 byte
//     header that is bound into the encryption (see below).
//   - 25519: X25519 key exchange (RFC 7748).
//   - ChaChaPoly: ChaCha20-Poly1305 encryption (RFC 7539) with a 12-byte
//     nonce whose first 4 bytes are zero.
//   - SHA256: SHA-256 for hashing.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
// details.
//
// # How SSU2 extends Noise
//
// I2P adds five extensions to the base Noise_XK pattern:
//
//  1. Each handshake message includes a 16 or 32 byte header.
//  2. The header is mixed into the Noise mixHash before encryption, which
//     binds the header to the message so it cannot be tampered with.
//  3. The header is encrypted and authenticated along with the message.
//  4. The cleartext ephemeral (one-time) keys are obfuscated with ChaCha20
//     (unlike NTCP2, which uses AES).
//  5. A payload format is defined for handshake messages 1, 2, and 3 and
//     for the data phase.
//
// Because all three handshake messages use the header as associated data,
// the SSU2 protocol identifier differs from NTCP2's.
//
// See [I2P Spec: SSU2](https://i2p.net/en/docs/specs/ssu2/) for details.
//
// # What SSU2 does and does not do
//
// SSU2 is an authenticated key agreement protocol for point-to-point
// router-to-router transport of I2NP messages over UDP. It is not a
// general-purpose data pipe.
//
// SSU2 does NOT provide in-order delivery or guaranteed delivery of I2NP
// messages, and it does NOT completely prevent duplicate delivery. Routers
// must be prepared to receive messages out of order or more than once.
//
// In addition to carrying I2NP messages, SSU2 provides:
//
//   - Relaying (NAT traversal): a third router can relay messages between
//     two peers that cannot reach each other directly.
//   - Peer Testing: a peer can test whether it is reachable from outside
//     its network (inbound reachability).
//   - Connection Migration: a session can survive the peer's IP address or
//     port changing (for example, when a NAT mapping changes).
//
// # Packet format
//
// SSU2 packet headers are adapted from WireGuard and QUIC. Header
// obfuscation uses ChaCha20 (from ECIES) instead of AES. Packet numbering
// is adapted from WireGuard and QUIC, and ACKs/nacks are adapted from QUIC.
//
// # Package layout
//
//   - ssu2 (this package): top-level API — dialing, listening, the
//     Coordinator for peer tests and relaying, and re-exports of the
//     subpackages' types for backward compatibility.
//   - ssu2/config: configuration types (SSU2Config, SSU2Addr) and
//     validation.
//   - ssu2/handshake: the XK handshake state machine, key generation, and
//     key rotation.
//   - ssu2/reliability: ACK handling, RTT estimation, congestion control,
//     receive window, and keepalive.
//   - ssu2/server: the listener (inbound sessions), token admission, and
//     transport wiring.
//   - ssu2/session: an established SSU2 connection (SSU2Conn), packet
//     routing, and I2NP message handling.
//   - ssu2/wire: the on-the-wire packet and block formats, header
//     protection, and obfuscation.
package ssu2
