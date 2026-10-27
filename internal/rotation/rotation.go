// Package rotation enforces the I2P transports' key and IV rotation rules.
//
// Both ntcp2.md and ssu2.md carry a section titled "Public Key and IV Rotation"
// with the same mandatory rule:
//
//	"Due to caching of RouterInfos, routers must not rotate the static public key
//	or IV while the router is up, whether in a published address or not. Routers
//	must persistently store this key and IV for reuse after an immediate restart,
//	so incoming connections will continue to work, and restart times are not
//	exposed."
//
// A transport listener is the component that enforces this in practice: it is the
// object an operator calls when handing it a new identity. This package holds the
// comparison so the NTCP2 and SSU2 listeners apply identical rules rather than
// drifting apart.
//
// The rule has one documented exception. Both specs continue:
//
//	"If the router \"rekeys\" to a different Router Hash, it should generate a new
//	noise key and IV as well."
//
// A router hash change is therefore allowed to carry new key material. What is not
// allowed is rotating a key or IV underneath an unchanged identity, which breaks
// every peer that cached the old RouterInfo while leaving the hash — and so the
// published address — looking identical.
//
// Persistence and startup rotation are the caller's responsibility, not the
// listener's: the spec requires the router to store the key and IV, and to record
// its last-shutdown time so the previous downtime can be calculated at startup.
// A listener only sees configs, so it cannot know whether a key handed to it at
// startup is a rotation after a month of downtime or an unrotated value loaded
// from disk. The thresholds ("several days", "one month" published, "one day"
// SSU-only, "two hours" unpublished) are therefore enforced by the router layer,
// which owns the downtime record; see the transport docs for each listener.
package rotation

import "bytes"

// Inputs is the identity material [Compare] inspects.
type Inputs struct {
	// StaticKey is the long-term Noise static private key.
	StaticKey []byte
	// IV is the published obfuscation IV.
	IV []byte
	// IntroKey is the SSU2 header-protection intro key. Leave it nil for a
	// transport that has no intro key.
	IntroKey []byte
	// IdentityHash is the router identity hash. It is an array, so a missing hash
	// compares as the zero hash rather than as nil.
	IdentityHash [32]byte
}

// Change describes which identity material differs between the config a listener
// is running with and the one it is being asked to adopt.
type Change struct {
	// StaticKeyChanged is true when the long-term Noise static private key differs.
	StaticKeyChanged bool
	// IVChanged is true when the obfuscation IV differs. NTCP2 publishes a 16-byte
	// AES IV; SSU2 publishes an 8-byte ChaCha20 IV.
	IVChanged bool
	// IntroKeyChanged is true when the SSU2 intro key differs. ssu2.md: "Intro key
	// rotation is subject to identical rules as key rotation."
	IntroKeyChanged bool
	// IdentityChanged is true when the router identity (hash) differs, which the
	// specs treat as a rekey: new noise key material is expected to follow.
	IdentityChanged bool
}

// Compare reports the differences between the identity material in current and
// next.
//
// Filling in a field that was empty is not reported as a change. A listener is
// commonly constructed before its identity material exists — go-i2p's transports
// build the config, start the listener, then load the static key, IV and intro key
// from the keystore and publish them through UpdateIdentity — and reporting that
// first population as a rotation would reject the normal startup path. Only
// material that was already set and is then replaced (or dropped) counts as a
// rotation.
func Compare(current, next Inputs) Change {
	return Change{
		StaticKeyChanged: keyChanged(current.StaticKey, next.StaticKey),
		IVChanged:        keyChanged(current.IV, next.IV),
		IntroKeyChanged:  keyChanged(current.IntroKey, next.IntroKey),
		IdentityChanged:  !bytes.Equal(current.IdentityHash[:], next.IdentityHash[:]),
	}
}

// Forbidden returns the names of the rotations to reject while the listener is up,
// in a stable order for error messages.
//
// A rotation is forbidden only when the identity is unchanged: on a rekey the new
// key material is the correct behaviour, not a violation.
func (c Change) Forbidden() []string {
	if c.IdentityChanged {
		return nil
	}
	var names []string
	if c.StaticKeyChanged {
		names = append(names, "static key")
	}
	if c.IVChanged {
		names = append(names, "IV")
	}
	if c.IntroKeyChanged {
		names = append(names, "intro key")
	}
	return names
}

// Empty reports whether nothing changed at all.
func (c Change) Empty() bool {
	return !c.StaticKeyChanged && !c.IVChanged && !c.IntroKeyChanged && !c.IdentityChanged
}

// keyChanged reports whether previously-set material was replaced. Material that
// was absent is a first population, not a rotation.
func keyChanged(current, next []byte) bool {
	if len(current) == 0 {
		return false
	}
	return !bytes.Equal(current, next)
}
