// Package handshake provides a generic, protocol-agnostic framework for
// transforming the data that flows through a Noise connection.
//
// # What is a handshake modifier?
//
// A handshake modifier is a single, composable step that transforms handshake
// messages. Each modifier does one job — for example, adding padding or
// scrambling bytes with XOR — and hands the result on. Modifiers can be
// chained together to build more complex transformations while keeping the
// underlying Noise protocol secure.
//
// Every modifier works in two directions:
//
//   - Outbound: data being sent. The modifier transforms it before it leaves.
//   - Inbound: data being received. The modifier undoes the transformation.
//
// Modifiers are also phase-aware. A Noise connection moves through distinct
// phases — the handshake messages, then the data phase — and a modifier can
// behave differently in each one.
//
// # How the I2P protocols use this
//
// This package is protocol-agnostic: it does not know about NTCP2 or SSU2.
// Those transports build on top of it.
//
//   - NTCP2 (Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256) uses AES
//     obfuscation, SipHash-2-4 length obfuscation, and padding.
//   - SSU2 (Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256) uses
//     ChaCha20 header obfuscation and padding.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// # The building blocks
//
//   - [HandshakeModifier]: the interface every modifier implements.
//   - [HandshakePhase]: the phase of the connection a message is in.
//   - [ModifierChain]: applies several modifiers in order (and in reverse on
//     the way back in).
//   - [GenericPaddingModifier]: adds random padding with a length prefix.
//   - [XORModifier]: scrambles bytes with a repeating key.
//   - [PaddingEngine]: shared padding math and I2P block wire format used by
//     the NTCP2 and SSU2 padding modifiers.
//
// The [siphash] subpackage provides the SipHash-2-4 length obfuscation
// modifier shared by NTCP2 and SSU2.
//
// # Example
//
//	xor, _ := handshake.NewXORModifier("xor", key)
//	pad, _ := handshake.NewGenericPaddingModifier("pad", 16, 64)
//	chain := handshake.NewModifierChain("my-chain", xor, pad)
//
//	outbound, _ := chain.ModifyOutbound(handshake.PhaseInitial, plaintext)
//	recovered, _ := chain.ModifyInbound(handshake.PhaseInitial, outbound)
package handshake
