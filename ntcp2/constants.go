package ntcp2

import (
	"time"

	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// NTCP2 protocol constants, as defined by the I2P NTCP2 specification.
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.

const (
	// RouterHashSize is the size of an I2P router identity hash, in bytes.
	// A router identity hash is a 32-byte fingerprint that identifies a
	// router on the I2P network.
	RouterHashSize = 32

	// StaticKeySize is the size of a Curve25519 static key, in bytes.
	// A static key is a long-term public key that identifies a router.
	StaticKeySize = 32

	// IVSize is the size of the AES initialization vector, in bytes.
	// An initialization vector (IV) is a random starting value that makes
	// each encryption run different.
	IVSize = 16

	// PaddingBlockType is the block type number used for padding blocks in
	// the I2P block format. A padding block is filler data added to hide
	// the real size of a message.
	PaddingBlockType = 254

	// MaxBlockDataSize is the largest amount of data a single I2P block can
	// carry, in bytes.
	MaxBlockDataSize = 65516

	// MaxFrameSize is the maximum size of an NTCP2 data frame, in bytes.
	// A data frame is one encrypted unit of data sent after the handshake.
	MaxFrameSize = 65535

	// SpecMaxFrameSize is the absolute maximum frame size the wire format
	// allows (the largest value a two-byte field can hold). Configuration
	// values above this are rejected.
	SpecMaxFrameSize = 65535

	// MinDataPhaseFrameSize is the smallest valid data-phase frame, in
	// bytes. The minimum is a ChaCha20-Poly1305 ciphertext that contains
	// only the 16-byte authentication tag and no payload.
	MinDataPhaseFrameSize = 16

	// BlockHeaderSize is the size of an I2P block header, in bytes:
	// one byte of block type plus two bytes of block size.
	BlockHeaderSize = 3

	// SipHashIVSize is the size of the SipHash counter, in bytes.
	SipHashIVSize = pkgsiphash.IVSize

	// NTCP2ProtocolName is the full Noise protocol name for NTCP2. It is
	// fed into the Noise key derivation function, so using the exact name
	// is what makes this implementation interoperate with other I2P
	// routers.
	NTCP2ProtocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

	// NTCP2Pattern is the base Noise pattern used by NTCP2.
	NTCP2Pattern = "XK"

	// DefaultMaxFrameSize is the default maximum frame size (16 KB).
	DefaultMaxFrameSize = 16384

	// DefaultMaxPaddingSize is the default maximum padding size, in bytes.
	DefaultMaxPaddingSize = 64

	// MaxNTCP2HandshakePadding is the maximum cleartext padding accepted
	// during the handshake, in bytes. The spec allows far less in
	// practice; this generous cap keeps a malicious peer from forcing a
	// huge memory allocation.
	MaxNTCP2HandshakePadding = 1024

	// MaxNTCP2Message3Part2Len is the maximum size of message 3, part 2
	// (the sender's RouterInfo block plus any padding), in bytes. A
	// RouterInfo is typically under 2 KB; this cap allows headroom while
	// still bounding memory use. The limit applies to the encrypted size.
	MaxNTCP2Message3Part2Len = 8192

	// MaxPaddingRatio is the maximum padding ratio allowed by the I2P
	// NTCP2 spec. The ratio is padding bytes per data byte.
	MaxPaddingRatio = 15.9375

	// Poly1305Overhead is the size of the ChaCha20-Poly1305
	// authentication tag, in bytes. Every encrypted message carries this
	// tag so the receiver can detect tampering.
	Poly1305Overhead = 16

	// MaxNonce is the highest nonce value a connection may use. A nonce is
	// a number that must never repeat for a given key; the spec requires
	// connections to end before the nonce reaches 2^64 - 2.
	MaxNonce uint64 = 18446744073709551614

	// AEADErrorMaxJunkBytes is the maximum number of random bytes read
	// after an authentication failure, before the connection is closed.
	// Reading a random amount of junk makes it harder for an attacker to
	// probe the connection.
	AEADErrorMaxJunkBytes = 1024

	// AEADErrorTimeoutMin is the minimum wait before closing a connection
	// after an authentication failure. The wait is randomized between this
	// value and AEADErrorTimeoutMax so the timing does not leak
	// information.
	AEADErrorTimeoutMin = 1 * time.Second

	// AEADErrorTimeoutMax is the maximum wait before closing a connection
	// after an authentication failure.
	AEADErrorTimeoutMax = 3 * time.Second

	// NonceRekeyThreshold is the nonce value at which a connection is
	// considered close to running out of nonces. Because the nonce counter
	// cannot be reset on an existing connection, the right response is to
	// open a new one. This threshold is MaxNonce minus 1000, giving
	// advance warning.
	NonceRekeyThreshold = MaxNonce - 1000
)

// Compile-time enforcement that AEADErrorMaxJunkBytes is a power of two.
// If the constant is changed to a non-power-of-two value (e.g., 1000),
// the expression (AEADErrorMaxJunkBytes & (AEADErrorMaxJunkBytes - 1))
// will be non-zero, causing a negative array size and a compile error.
var _ = [1]struct{}{}[AEADErrorMaxJunkBytes&(AEADErrorMaxJunkBytes-1)]
