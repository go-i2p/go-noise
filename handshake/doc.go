// Package handshake provides a generic modifier framework for transforming
// handshake data during Noise protocol exchanges. Modifiers can add padding,
// XOR obfuscation, or protocol-specific transformations (e.g., NTCP2 AES
// obfuscation) to handshake messages while preserving Noise protocol security.
//
// The central abstraction is [HandshakeModifier], an interface that transforms
// data on both the outbound (encrypt) and inbound (decrypt) paths. Modifiers
// are phase-aware via [HandshakePhase], allowing different behavior during
// initial, exchange, and final handshake stages.
//
// Multiple modifiers can be composed into a [ModifierChain], which applies
// them in order for outbound data and in reverse order for inbound data
// (ensuring correct undo semantics). ModifierChain itself implements
// HandshakeModifier, so chains can be nested.
//
// Built-in modifiers:
//
//   - [PaddingModifier]: Adds cryptographically random padding with a 4-byte
//     length prefix. Padding size is uniformly random within [min, max].
//     WARNING: PaddingModifier uses a custom wire format that is NOT part of
//     any I2P specification. It must not be used as a replacement for
//     ntcp2.NTCP2PaddingModifier in NTCP2 transport chains. PaddingModifier
//     is phase-aware and only applies padding during handshake phases
//     (PhaseInitial, PhaseExchange, PhaseFinal); PhaseData passes through
//     unmodified.
//   - [XORModifier]: Applies repeating-key XOR to data. Self-inverting, so
//     the same modifier works for both outbound and inbound. Like
//     PaddingModifier, it is phase-aware and only applies during handshake
//     phases (PhaseInitial, PhaseExchange, PhaseFinal); PhaseData passes
//     through unmodified, because reusing the same static keystream at the
//     same byte offsets across every post-handshake message would let an
//     adversary who recovers plaintext at one offset in one message
//     de-obfuscate that same offset in every other message.
//
// Protocol-specific modifiers (in the ntcp2 package) implement the same
// interface for I2P NTCP2 transport obfuscation:
//
//   - ntcp2.AESObfuscationModifier: AES-256-CBC obfuscation of handshake bytes.
//   - ntcp2.SipHashLengthModifier: SipHash-based length obfuscation.
//   - ntcp2.NTCP2PaddingModifier: I2P-spec-compliant AEAD padding.
//
// Usage:
//
//	xor := handshake.NewXORModifier("xor", key)
//	pad, _ := handshake.NewGenericPaddingModifier("pad", 16, 64)
//	chain := handshake.NewModifierChain("my-chain", xor, pad)
//
//	outbound, _ := chain.ModifyOutbound(handshake.PhaseInitial, plaintext)
//	recovered, _ := chain.ModifyInbound(handshake.PhaseInitial, outbound)
package handshake
