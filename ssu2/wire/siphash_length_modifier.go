package wire

import pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"

// SipHashIVSize is the byte size of a SipHash IV (uint64 = 8 bytes).
const SipHashIVSize = pkgsiphash.IVSize

// DataLengthFieldSize is the 2-byte data-phase length field that is
// obfuscated with SipHash-2-4 per SSU2 §Data Phase Length Obfuscation.
const DataLengthFieldSize = pkgsiphash.LengthFieldSize

// SipHashLengthModifier implements SSU2's SipHash-2-4 length obfuscation
// for data-phase packet lengths. The canonical implementation lives in
// handshake/siphash; this alias makes the type directly accessible from
// the wire package without an extra import.
type SipHashLengthModifier = pkgsiphash.LengthModifier

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifier(name, sipKeys, initialIV)
}

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the SSU2 specification.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifierDirectional(name, outKeys, inKeys, outIV, inIV)
}
