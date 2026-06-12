package ntcp2

import (
	"time"

	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// NTCP2 protocol constants per the I2P NTCP2 specification.
// Reference: https://i2p.net/en/docs/specs/ntcp2

const (
	// RouterHashSize is the size of the I2P router identity hash in bytes.
	RouterHashSize = 32

	// StaticKeySize is the size of a Curve25519 static key in bytes.
	StaticKeySize = 32

	// IVSize is the size of the AES-CBC initialization vector in bytes.
	IVSize = 16

	// PaddingBlockType is the I2P NTCP2 padding block type identifier.
	PaddingBlockType = 254

	// MaxBlockDataSize is the maximum data size for a single I2P NTCP2 block (bytes).
	MaxBlockDataSize = 65516

	// MaxFrameSize is the maximum size of an NTCP2 data frame (bytes).
	MaxFrameSize = 65535

	// SpecMaxFrameSize is the absolute maximum frame size allowed by the I2P spec (uint16 max).
	// validateFrameConfiguration uses this to reject user-provided values that exceed the wire limit.
	SpecMaxFrameSize = 65535

	// MinDataPhaseFrameSize is the minimum valid data-phase frame size per the I2P spec.
	// The spec states the deobfuscated size range is 16–65535. The minimum corresponds
	// to a ChaChaPoly ciphertext containing only the 16-byte Poly1305 MAC tag (empty payload).
	MinDataPhaseFrameSize = 16

	// BlockHeaderSize is the size of an I2P block header: [type:1][size:2].
	BlockHeaderSize = 3

	// SipHashIVSize is the size of the SipHash IV in bytes (uint64 = 8 bytes).
	SipHashIVSize = pkgsiphash.IVSize

	// NTCP2ProtocolName is the full Noise protocol name for NTCP2 as defined by the I2P spec.
	// This is passed to InitializeSymmetric() via the ProtocolName field on noise.Config,
	// producing the correct KDF output for interoperability with other I2P implementations.
	NTCP2ProtocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

	// NTCP2Pattern is the base Noise pattern used by NTCP2.
	NTCP2Pattern = "XK"

	// DefaultMaxFrameSize is the default maximum frame size (16KB).
	DefaultMaxFrameSize = 16384

	// DefaultMaxPaddingSize is the default maximum padding size in bytes.
	DefaultMaxPaddingSize = 64

	// MaxNTCP2HandshakePadding is the maximum allowed cleartext padding size
	// during the NTCP2 handshake (bytes). Per spec §4.3, padding is "0..223 bytes"
	// in practice. We set a conservative limit of 1024 to allow for future spec
	// changes while preventing DoS via unbounded allocation on malicious padLen.
	MaxNTCP2HandshakePadding = 1024

	// MaxNTCP2Message3Part2Len is the maximum allowed size for message 3 part 2
	// (Alice's RouterInfo block plus optional padding/options). Per spec, RouterInfo
	// is typically < 2 KB; we allow up to 8192 bytes (8 KB) for legitimate RouterInfo
	// plus generous padding headroom, while preventing DoS via unbounded allocation
	// on malicious m3p2Len. This limit applies to the AEAD ciphertext size.
	MaxNTCP2Message3Part2Len = 8192

	// MaxPaddingRatio is the maximum padding ratio per I2P NTCP2 spec (4.4 fixed-point).
	MaxPaddingRatio = 15.9375

	// Poly1305Overhead is the ChaChaPoly AEAD authentication tag size in bytes.
	Poly1305Overhead = 16

	// MaxNonce is the nonce limit per the Noise Protocol spec and I2P NTCP2 spec.
	// Connections MUST be terminated before the nonce reaches 2^64 - 2.
	// Using 2^64 - 2 = 18446744073709551614.
	MaxNonce uint64 = 18446744073709551614

	// AEADErrorMaxJunkBytes is the maximum number of random bytes to read
	// on an AEAD authentication failure for probing resistance. Per the spec:
	// "random number of bytes (range TBD)" — we use 1024 as a reasonable upper bound.
	//
	// INVARIANT: AEADErrorMaxJunkBytes MUST be a power of two.
	// The bitmask in handleAEADError (val & (AEADErrorMaxJunkBytes - 1)) only
	// produces a uniform distribution when this constant is a power of two.
	// Changing it to a non-power-of-two value will introduce modulo bias.
	AEADErrorMaxJunkBytes = 1024

	// AEADErrorTimeoutMin is the minimum duration to wait while reading random
	// bytes on an AEAD authentication failure. Per the spec: "random timeout
	// (range TBD)" — randomized over [1s, 3s] to avoid timing fingerprints.
	AEADErrorTimeoutMin = 1 * time.Second

	// AEADErrorTimeoutMax is the maximum duration to wait while reading random
	// bytes on an AEAD authentication failure.
	AEADErrorTimeoutMax = 3 * time.Second

	// NonceRekeyThreshold is the nonce value at which the connection should
	// be considered approaching exhaustion. Since Noise Rekey() does not reset
	// the nonce counter, the correct response is to establish a new connection.
	// Set to MaxNonce - 1000 to provide advance warning.
	NonceRekeyThreshold = MaxNonce - 1000
)

// Compile-time enforcement that AEADErrorMaxJunkBytes is a power of two.
// If the constant is changed to a non-power-of-two value (e.g., 1000),
// the expression (AEADErrorMaxJunkBytes & (AEADErrorMaxJunkBytes - 1))
// will be non-zero, causing a negative array size and a compile error.
var _ = [1]struct{}{}[AEADErrorMaxJunkBytes&(AEADErrorMaxJunkBytes-1)]
