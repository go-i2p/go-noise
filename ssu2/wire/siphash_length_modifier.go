package wire

import pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"

// SipHashIVSize is the byte size of a SipHash IV (uint64 = 8 bytes).
const SipHashIVSize = pkgsiphash.IVSize

// DataLengthFieldSize is the 2-byte length field obfuscated with SipHash-2-4
// in NTCP2 (ntcp2.rst "Data Phase" > "SipHash obfuscated length").
//
// NOTE: SSU2 has no data-phase length field. Each UDP datagram contains exactly
// one message and ssu2.rst states "the length of the datagram ... is the length
// of the message"; the only SipHash use in SSU2 is token generation and header
// protection. This constant is re-exported here only for API symmetry with the
// NTCP2 transport and must not be applied to SSU2 frames.
const DataLengthFieldSize = pkgsiphash.LengthFieldSize

// SipHashLengthModifier is the NTCP2 SipHash-2-4 length obfuscation modifier,
// re-exported here for API symmetry only. SSU2 has no data-phase length field to
// obfuscate (see DataLengthFieldSize above), so this type must not be wired into
// an SSU2 framing path. The canonical implementation lives in handshake/siphash.
type SipHashLengthModifier = pkgsiphash.LengthModifier

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions. The canonical implementation lives in handshake/siphash;
// this re-exports it for convenience.
var NewSipHashLengthModifier = pkgsiphash.NewLengthModifier

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the SSU2 specification. The canonical
// implementation lives in handshake/siphash; this re-exports it for convenience.
var NewSipHashLengthModifierDirectional = pkgsiphash.NewLengthModifierDirectional
