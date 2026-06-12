package ntcp2

import (
	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation
// for data phase frame lengths. The canonical implementation lives in
// handshake/siphash; this alias makes the type directly accessible from
// the ntcp2 package without an extra import.
type SipHashLengthModifier = pkgsiphash.LengthModifier

// NewSipHashLengthModifier creates a new SipHash length obfuscation modifier
// with shared keys for both directions. The canonical implementation lives
// in handshake/siphash; this re-exports it for convenience.
var NewSipHashLengthModifier = pkgsiphash.NewLengthModifier

// NewSipHashLengthModifierDirectional creates a SipHash length obfuscation
// modifier with per-direction keys as required by the NTCP2 spec.
// The canonical implementation lives in handshake/siphash; this re-exports
// it for convenience.
var NewSipHashLengthModifierDirectional = pkgsiphash.NewLengthModifierDirectional
