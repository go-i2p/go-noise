# ntcp2
--
    import "github.com/go-i2p/go-noise/ntcp2"

![ntcp2.svg](ntcp2.svg)

Package ntcp2 implements NTCP2, the transport protocol I2P routers use to talk
to each other over TCP.

# How it works

NTCP2 is built on the Noise Protocol Framework, a set of rules for securely
exchanging messages. Before any real data flows, the two routers run a short
handshake. The handshake lets each side prove who it is and agree on shared
secrets. After that, every message is encrypted and authenticated, so each
router can trust both the sender and the content.

NTCP2 uses the Noise pattern Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256.
The parts mean:

    - XK: the base pattern. The side that starts the connection already
      knows the other side's long-term public key, which keeps the
      handshake short.
    - 25519: key exchange on the X25519 curve (RFC 7748).
    - ChaChaPoly: encryption with ChaCha20-Poly1305 (RFC 7539), which also
      checks that messages were not tampered with.
    - SHA256: the hash function used to turn shared secrets into keys.

# NTCP2 extensions

NTCP2 adds a few I2P-specific twists on top of plain Noise_XK:

    - The short-lived public keys in the first two handshake messages are
      hidden with AES encryption, using a key based on the router's
      identity.
    - Random padding is added to messages 1 and 2 (outside the encryption)
      and to message 3 and every data frame (inside the encryption), so
      message sizes do not give away how much data is really being sent.
    - Data frames start with a two-byte length field, and that field is
      scrambled with SipHash-2-4, the same trick obfs4 uses.

The handshake follows a fixed order: SessionRequest, SessionCreated,
SessionConfirmed. Only after those three messages do the routers exchange data
frames. Every NTCP2 message is at most 65537 bytes.

# Using this package

DialNTCP2 connects to a remote router; ListenNTCP2 accepts incoming connections.
Both hand back a Conn, which works like a net.Conn: use Read and Write to send
and receive I2P messages. A Config controls the handshake timeout, padding, and
other options. Protocol constants (sizes, limits, block types) live in
constants.go.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details. See [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
for details.

## Usage

```go
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

	// MaxPaddingRatio is the largest padding ratio this implementation
	// accepts. The ratio is padding bytes per data byte. The NTCP2 spec
	// leaves the padding min/max "TBD" (it notes Java implementations cap
	// padding at 256 bytes), so this is an implementation limit, not a
	// value taken from the spec.
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
```

```go
const ClockSkewTolerance = 60 * time.Second
```
ClockSkewTolerance is the maximum allowed difference between local and remote
clocks for NTCP2 handshake timestamp validation.

Per the I2P spec, connections with clock skew exceeding this value should be
rejected.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

```go
const DefaultHandshakeRetries = 3
```
DefaultHandshakeRetries is the default number of times a failed handshake is
retried before giving up.

```go
const DefaultHandshakeTimeoutSeconds = 30
```
DefaultHandshakeTimeoutSeconds is the default handshake timeout, in seconds. A
handshake that takes longer than this is aborted.

```go
const FrameLengthFieldSize = 2
```
FrameLengthFieldSize is the size, in bytes, of the frame length field that
prefixes every NTCP2 data frame. The length is hidden by XORing it with a
SipHash mask, so an observer cannot tell how big each frame is.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

```go
var NewSipHashLengthModifier = pkgsiphash.NewLengthModifier
```
NewSipHashLengthModifier creates a new SipHash length obfuscation modifier with
shared keys for both directions.

The canonical implementation lives in handshake/siphash; this re-exports it for
convenience.

```go
var NewSipHashLengthModifierDirectional = pkgsiphash.NewLengthModifierDirectional
```
NewSipHashLengthModifierDirectional creates a SipHash length obfuscation
modifier with per-direction keys, as required by the NTCP2 spec.

The canonical implementation lives in handshake/siphash; this re-exports it for
convenience.

#### func  DeriveSipHashKeys

```go
func DeriveSipHashKeys(askMaster, handshakeHash []byte) (
	sipKeysAB [2]uint64, sipIVAB uint64,
	sipKeysBA [2]uint64, sipIVBA uint64,
	err error,
)
```
DeriveSipHashKeys derives the per-direction SipHash-2-4 keys and initial IVs
used to obfuscate NTCP2 frame lengths, from the Noise handshake hash and the
ask_master secret, as defined by the I2P NTCP2 specification.

The derivation follows the spec's 5-step HMAC-SHA256 chain:

    Step 1: temp_key   = HMAC-SHA256(key=ask_master, data=h || "siphash")
    Step 2: sip_master = HMAC-SHA256(key=temp_key,   data=byte(0x01))
    Step 3: temp_key   = HMAC-SHA256(key=sip_master, data=zerolen)
    Step 4: sipkeys_ab = HMAC-SHA256(key=temp_key,   data=byte(0x01))[0:24]
    Step 5: sipkeys_ba = HMAC-SHA256(key=temp_key,   data=sipkeys_ab[0:32] || byte(0x02))[0:24]

NOTE: Step 5 uses the full 32-byte HMAC output from step 4 as its input prefix,
not just the 24 bytes extracted for sipkeys_ab. This matches the i2pd reference
implementation (m_Sipkeysab is 32 bytes; m_Sipkeysab[32]=2 before the HMAC
call).

Each 24-byte output is split into (sipk1, sipk2, sipiv) as little-endian
uint64s.

Parameters:

    - askMaster: the ask_master secret from the Noise handshake (32 bytes).
      DeriveSipHashKeys copies this into an internal buffer, which is zeroed
      before the function returns (per spec: "overwrite ask_master in memory,
      no longer needed"); the caller's own askMaster slice is left untouched
      and remains the caller's responsibility to zero once no longer needed.
    - handshakeHash: the handshake hash (h) from the completed Noise session
      (32 bytes).

Returns:

    - sipKeysAB: [2]uint64{sipk1, sipk2} for direction A→B (initiator→responder)
    - sipIVAB: initial IV for the A→B SipHash length obfuscation chain
    - sipKeysBA: [2]uint64{sipk1, sipk2} for direction B→A (responder→initiator)
    - sipIVBA: initial IV for the B→A SipHash length obfuscation chain
    - err: non-nil if derivation fails

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### type AESObfuscationModifier

```go
type AESObfuscationModifier struct {
}
```

AESObfuscationModifier implements NTCP2's AES-based ephemeral key obfuscation.

In NTCP2, the ephemeral keys in handshake messages 1 and 2 are sent in
cleartext, but they are hidden from network observers by encrypting them with
AES-256-CBC. The key is the peer's router hash, and the initial IV
(initialization vector, the starting value for the cipher) is published in the
network database.

Per the NTCP2 spec, the AES state (the last ciphertext block) from message 1
encryption is carried forward as the IV for message 2 encryption.

After AES decryption, received keys are validated per the NTCP2 spec: X[31]&0x80
must be 0 (a Curve25519 requirement). Invalid keys cause the message to be
rejected.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func  NewAESObfuscationModifier

```go
func NewAESObfuscationModifier(name string, routerHash, iv []byte) (*AESObfuscationModifier, error)
```
NewAESObfuscationModifier creates a new AES obfuscation modifier for NTCP2.

routerHash must be 32 bytes (RH_B, the peer's router hash), and iv must be the
16-byte IV published in the network database.

#### func (*AESObfuscationModifier) Clone

```go
func (aom *AESObfuscationModifier) Clone() handshake.HandshakeModifier
```
Clone creates a deep copy of the AESObfuscationModifier with independent state.

This implements handshake.ModifierCloner to support safe Config.Clone()
operations. The cloned modifier starts with a fresh state (no aesState carried
over).

#### func (*AESObfuscationModifier) Close

```go
func (aom *AESObfuscationModifier) Close() error
```
Close zeroes the AES key material and IV stored in the modifier, so sensitive
data does not linger in memory after the connection is closed. This method is
safe for concurrent use.

#### func (*AESObfuscationModifier) ModifyInbound

```go
func (aom *AESObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes AES obfuscation from the ephemeral key in an inbound
handshake message.

The modifier chain receives the full Noise message (e.g. 64 bytes for msg1/msg2:
32-byte ephemeral key + AEAD payload). Only the first 32 bytes (the ephemeral
key) are AES-CBC decrypted; the remainder is passed through unchanged.

#### func (*AESObfuscationModifier) ModifyOutbound

```go
func (aom *AESObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound applies AES obfuscation to the ephemeral key in an outbound
handshake message.

    - Message 1: encrypts the X key with RH_B and the published IV.
    - Message 2: encrypts the Y key with RH_B and the AES state left over
      from message 1.

The modifier chain receives the full Noise message (e.g. 64 bytes for msg1/msg2:
32-byte ephemeral key + AEAD payload). Only the first 32 bytes (the ephemeral
key) are AES-CBC encrypted; the remainder is passed through unchanged.

#### func (*AESObfuscationModifier) Name

```go
func (aom *AESObfuscationModifier) Name() string
```
Name returns the modifier name, used for logging and debugging.

#### type Acceptor

```go
type Acceptor interface {
	net.Listener
	// AcceptWithHandshake accepts the next inbound connection and performs
	// the NTCP2 handshake before returning. The context governs handshake
	// cancellation for each accepted connection.
	AcceptWithHandshake(ctx context.Context) (ConnIface, error)
}
```

Acceptor accepts inbound NTCP2 connections on a listener.

It extends net.Listener with AcceptWithHandshake, which performs the NTCP2
handshake as part of the accept loop. *Listener satisfies this interface.

#### type Addr

```go
type Addr struct {
}
```

Addr is the address of an NTCP2 connection. It wraps the plain TCP address and
adds I2P-specific information: which router is on the other end (its router
hash) and whether this side started the connection ("initiator") or accepted it
("responder").

#### func  NewNTCP2Addr

```go
func NewNTCP2Addr(underlying net.Addr, routerHash data.Hash, role string) (*Addr, error)
```
NewNTCP2Addr creates an Addr from a TCP address, a router hash, and a role. The
router hash identifies the I2P router on the other end of the connection. The
role must be "initiator" (this side dialed out) or "responder" (this side
accepted the connection).

#### func (*Addr) IdentHash

```go
func (na *Addr) IdentHash() [32]byte
```
IdentHash returns the router identity hash as a fixed-size [32]byte array, which
is easier to use in Go code than a slice.

#### func (*Addr) Network

```go
func (na *Addr) Network() string
```
Network returns "ntcp2", identifying this as an NTCP2 address.

#### func (*Addr) Role

```go
func (na *Addr) Role() string
```
Role returns "initiator" if this side started the connection, or "responder" if
this side accepted it.

#### func (*Addr) RouterHash

```go
func (na *Addr) RouterHash() data.Hash
```
RouterHash returns the identity hash of the router on the other end of the
connection.

#### func (*Addr) SetRouterHash

```go
func (na *Addr) SetRouterHash(routerHash data.Hash)
```
SetRouterHash updates the router identity hash. The handshake reveals the remote
router's real identity, so this is used to replace the placeholder zero hash
that was set before the handshake finished.

#### func (*Addr) String

```go
func (na *Addr) String() string
```
String returns the address as a readable string in the form
"ntcp2://[router_hash]/[role]/[tcp_address]". The router hash is base64-encoded
so it is safe to print.

#### func (*Addr) UnderlyingAddr

```go
func (na *Addr) UnderlyingAddr() net.Addr
```
UnderlyingAddr returns the plain TCP address that this NTCP2 address wraps.

#### type Config

```go
type Config struct {
	// BaseHandshakeConfig holds the shared timeout, retry, and modifier
	// settings used by all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern to use.
	// NTCP2 always uses "XK".
	Pattern string

	// Initiator is true when this side starts the handshake.
	// Listeners are always the responder, so this is false for them.
	Initiator bool

	// BobRouterHash is the responder's router hash (RH_B in the spec).
	// Both sides use this hash as the AES key that hides the ephemeral
	// (one-time) keys sent in the clear during the handshake.
	// A responder sets its own router hash here; an initiator sets the
	// remote peer's router hash.
	BobRouterHash data.Hash

	// StaticKey is this peer's long-term Curve25519 private key (32 bytes).
	// It is used in the Noise XK handshake's Diffie-Hellman steps to derive
	// the session keys and to authenticate this side to the peer.
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity hash.
	// Required for outbound connections, optional for listeners.
	RemoteRouterHash *data.Hash

	// RemoteStaticKey is the remote peer's Curve25519 static public key
	// (32 bytes). The XK pattern requires the initiator to already know
	// the responder's static key, so this is required for outbound
	// connections.
	//
	// This is different from RemoteRouterHash: the router hash is the
	// SHA-256 of the peer's RouterIdentity, while the static key is a
	// Curve25519 public key.
	RemoteStaticKey []byte

	// EnableAESObfuscation turns on AES obfuscation of the cleartext
	// ephemeral keys in handshake messages 1 and 2.
	// Enabled by default.
	EnableAESObfuscation bool

	// ObfuscationIV is the 16-byte initialization vector (IV) for the AES
	// obfuscation. Per the NTCP2 spec it must be Bob's IV "as published in
	// Bob's network database entry" (the "i=" option); there is no valid
	// fallback. If it is nil when AES obfuscation is enabled, ToConnConfig
	// fails with MISSING_OBFUSCATION_IV.
	ObfuscationIV []byte

	// EnableSipHashLength turns on SipHash obfuscation of the two-byte
	// frame length field in the data phase.
	// Enabled by default.
	EnableSipHashLength bool

	// SipHashKeys are the two SipHash keys (k1 and k2) used to obfuscate
	// frame lengths. If left empty, they are derived from the session
	// keys during the handshake.
	SipHashKeys [2]uint64

	// MaxFrameSize is the largest NTCP2 data frame this side will send,
	// in bytes. Default: 16384 (16 KB).
	MaxFrameSize int

	// FramePaddingEnabled adds random padding to data frames. Padding
	// makes frame sizes less predictable, which helps against traffic
	// analysis. Enabled by default.
	FramePaddingEnabled bool

	// MinPaddingSize is the smallest amount of padding added to a frame,
	// in bytes. Default: 0.
	MinPaddingSize int

	// MaxPaddingSize is the largest amount of padding added to a frame,
	// in bytes. Default: 64.
	MaxPaddingSize int

	// LocalRouterInfo is this peer's serialized RouterInfo bytes.
	// Required for outbound connections: its length is written into the
	// m3p2Len field of message 1, and the bytes themselves are sent as
	// the encrypted payload of message 3 part 2.
	LocalRouterInfo []byte

	// StrictRouterInfoVerification is kept only for backward
	// compatibility.
	//
	// Deprecated: the local RouterInfo / static-key match is now ALWAYS
	// enforced as a hard error during the initiator handshake, regardless
	// of this field's value. It no longer has any effect. The check is a
	// no-op when no static key or no LocalRouterInfo is configured, so it
	// never fires on partially-configured connections.
	StrictRouterInfoVerification bool

	// ReplayDetector checks for replayed ephemeral keys during handshakes.
	// If nil, replay detection is disabled (not recommended for
	// production).
	// Shared across all responder connections using this config (typically
	// instantiated once per listener). Initiator connections ignore this
	// field.
	ReplayDetector ReplayDetector

	// AllowReuseAddress, when true, enables the SO_REUSEADDR socket
	// option for ListenNTCP2. This reduces restart-race delay by allowing
	// quick rebinding to the same address after shutdown. Use with caution
	// in production as it can allow stale packets from previous
	// incarnations to be delivered.
	// Default: false (conservative, matches net.Listen behavior).
	AllowReuseAddress bool
}
```

Config holds all the settings for creating NTCP2 connections and listeners.

Use NewNTCP2Config to create a Config with sensible defaults, then adjust the
fields you care about with the With* methods. Call Validate before using the
config to catch mistakes early.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func  NewNTCP2Config

```go
func NewNTCP2Config(bobRouterHash data.Hash, initiator bool) (*Config, error)
```
NewNTCP2Config creates a new Config with sensible defaults.

bobRouterHash is the responder's router hash (RH_B in the spec). Both sides use
it as the AES key for ephemeral key obfuscation, so a responder passes its own
router hash and an initiator passes the remote peer's router hash.

initiator is true when this connection will start the handshake.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Config) Clone

```go
func (nc *Config) Clone() *Config
```
Clone creates a deep copy of this Config that is safe to use independently, for
example for per-connection configs on the listener path.

The SipHash modifier field is not copied: the clone starts with a fresh zero
value, which is correct because the post-handshake hook fills it in after the
handshake.

Important: the Modifiers slice is shallow-copied, so the individual modifiers
(AES obfuscation, SipHash, etc.) are shared between the original and the clone.
Modifiers carry mutable state (AES cipher state, SipHash IVs), so the clone must
not be used concurrently with the original for handshakes. Call ToConnConfig()
on the clone before use; it creates fresh modifier instances with independent
state. The listener path does this correctly. Using Clone() without
ToConnConfig() while both configs are active concurrently causes data races and
corrupts handshake state.

#### func (*Config) SipHashModifier

```go
func (nc *Config) SipHashModifier() *SipHashLengthModifier
```
SipHashModifier returns the SipHash length modifier created during
ToConnConfig().

It returns nil until the post-handshake hook has run during Handshake(), because
the modifier's keys are derived from the handshake state. Do not call this
method before the handshake completes; calling PropagateSipHash() early returns
an error instead of silently doing nothing.

It also returns nil if SipHash length obfuscation is disabled or ToConnConfig()
has not been called. Each call to ToConnConfig() creates a fresh modifier
instance, so a config can be reused for multiple connections without sharing IV
state.

#### func (*Config) ToConnConfig

```go
func (nc *Config) ToConnConfig() (*noise.ConnConfig, error)
```
ToConnConfig converts this NTCP2 Config into the standard Noise ConnConfig used
by the underlying Noise connection.

It first calls Validate, then sets up the NTCP2-specific modifiers (AES
obfuscation, padding, SipHash length obfuscation) based on the configuration.

When SipHash length obfuscation is enabled, a post-handshake hook is registered
automatically. After the handshake finishes, the hook derives the per-direction
SipHash keys from the session keys and stores them for the data phase.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Config) Validate

```go
func (nc *Config) Validate() error
```
Validate checks that the configuration is valid for NTCP2. Call it before
creating connections or listeners to catch mistakes early.

#### func (*Config) WithAESObfuscation

```go
func (nc *Config) WithAESObfuscation(enabled bool, customIV []byte) *Config
```
WithAESObfuscation enables or disables the AES obfuscation of the cleartext
ephemeral keys in handshake messages 1 and 2.

When enabled with a custom IV, the IV must be exactly 16 bytes; other lengths
are silently ignored, so call Validate() to check all fields before use.

Note: options negotiation (padding limits, dummy traffic, delay parameters) is
handled by the higher-level router transport, not here.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Config) WithFrameSettings

```go
func (nc *Config) WithFrameSettings(maxSize int, paddingEnabled bool, minPadding, maxPadding int) *Config
```
WithFrameSettings configures NTCP2 data frame handling in one call.

    - maxSize: the largest frame this side will send (default: 16384
      bytes).
    - paddingEnabled: whether to add random padding to frames (default:
      true).
    - minPadding, maxPadding: the padding size range in bytes (default:
      0-64).

#### func (*Config) WithHandshakeRetries

```go
func (nc *Config) WithHandshakeRetries(retries int) *Config
```
WithHandshakeRetries sets how many times a failed handshake is retried. Use 0
for no retries, or -1 to retry forever.

#### func (*Config) WithHandshakeTimeout

```go
func (nc *Config) WithHandshakeTimeout(timeout time.Duration) *Config
```
WithHandshakeTimeout sets how long a handshake may take before it is aborted.

#### func (*Config) WithLocalRouterInfo

```go
func (nc *Config) WithLocalRouterInfo(ri []byte) *Config
```
WithLocalRouterInfo sets this peer's serialized RouterInfo bytes for outbound
connections. The length is written into the m3p2Len field of message 1, and the
bytes are encrypted and sent as message 3 part 2.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Config) WithModifiers

```go
func (nc *Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *Config
```
WithModifiers sets extra handshake modifiers for custom obfuscation, replacing
any previously set via this method (it does not accumulate across calls). At
ToConnConfig time these custom modifiers are appended after NTCP2's standard
modifiers (AES obfuscation, SipHash length, padding), so on the outbound path
they run last, and on the inbound path (which applies the chain in reverse) they
run first.

#### func (*Config) WithPattern

```go
func (nc *Config) WithPattern(pattern string) *Config
```
WithPattern sets the Noise protocol pattern. NTCP2 always uses "XK", so this
should normally be left alone.

#### func (*Config) WithReadTimeout

```go
func (nc *Config) WithReadTimeout(timeout time.Duration) *Config
```
WithReadTimeout sets how long a read may take after the handshake is done. A
zero value means no timeout.

#### func (*Config) WithRemoteRouterHash

```go
func (nc *Config) WithRemoteRouterHash(hash data.Hash) *Config
```
WithRemoteRouterHash sets the remote peer's router identity hash. Required for
outbound connections.

#### func (*Config) WithRemoteStaticKey

```go
func (nc *Config) WithRemoteStaticKey(key []byte) *Config
```
WithRemoteStaticKey sets the remote peer's Curve25519 static public key. key
must be exactly 32 bytes; other lengths are silently ignored, so call Validate()
to check all fields before use.

The XK pattern requires the initiator to already know the responder's static
key, so this is required for outbound connections. It is a different value from
RemoteRouterHash, which is the SHA-256 of the peer's RouterIdentity.

#### func (*Config) WithReplayDetector

```go
func (nc *Config) WithReplayDetector(detector ReplayDetector) *Config
```
WithReplayDetector sets the replay detector used by responder handshakes. A
replay detector remembers the ephemeral keys it has seen and rejects handshakes
that reuse one, which stops an attacker from replaying a captured handshake.

If nil, replay detection is disabled (not recommended for production). The
detector is shared across all responder connections that use this config, so
create one per listener. Initiator connections ignore this field.

#### func (*Config) WithRetryBackoff

```go
func (nc *Config) WithRetryBackoff(backoff time.Duration) *Config
```
WithRetryBackoff sets the base delay between handshake retry attempts. The delay
grows with each attempt.

#### func (*Config) WithReuseAddress

```go
func (nc *Config) WithReuseAddress(allow bool) *Config
```
WithReuseAddress enables the SO_REUSEADDR socket option for ListenNTCP2 listener
binding.

When enabled, the listener can quickly rebind to the same port after shutdown,
which shortens the delay before a restarted router can accept connections again.
Default is false (conservative).

Use with caution: stale packets from a previous socket instance may still
arrive.

#### func (*Config) WithSipHashLength

```go
func (nc *Config) WithSipHashLength(enabled bool, k1, k2 uint64) *Config
```
WithSipHashLength enables or disables SipHash obfuscation of the two-byte frame
length field in the data phase.

When enabled, a custom key pair is stored only if at least one of k1 or k2 is
non-zero (the other is then stored as given, including 0). If both are zero, the
keys are derived from the session keys during the handshake.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Config) WithStaticKey

```go
func (nc *Config) WithStaticKey(key []byte) *Config
```
WithStaticKey sets this peer's long-term Curve25519 key. key must be 32 bytes.
Keys of any other length are silently ignored, so call Validate() to check all
fields before use.

#### func (*Config) WithStrictRouterInfoVerification

```go
func (nc *Config) WithStrictRouterInfoVerification(strict bool) *Config
```
WithStrictRouterInfoVerification is kept only for backward compatibility.

Deprecated: the local RouterInfo / static-key match is now always enforced as a
hard error during the initiator handshake, so this builder does nothing. It
still sets the (now-unused) field to avoid breaking callers that still invoke
it.

#### func (*Config) WithWriteTimeout

```go
func (nc *Config) WithWriteTimeout(timeout time.Duration) *Config
```
WithWriteTimeout sets how long a write may take after the handshake is done. A
zero value means no timeout.

#### type Conn

```go
type Conn struct {

	// OnAEADError is an optional callback invoked during AEAD failure handling,
	// after the probing-resistance junk-read phase but before the TCP RST.
	// The router transport layer can use this to send a termination block
	// (type 4, reason 4 = "AEAD failure") before the connection is killed.
	// The callback receives the underlying net.Conn for direct writing;
	// the NTCP2Conn's broken flag is already set, so normal Write() is blocked.
	// If nil, no termination block is sent (current behaviour).
	OnAEADError func(conn net.Conn)
}
```

Conn is an NTCP2 connection. It works like a net.Conn: after the handshake
completes, use Read and Write to send and receive I2P messages.

Under the hood, a Conn wraps a Noise connection and adds the NTCP2 extensions:
AES obfuscation of the handshake keys, random padding, and SipHash-obfuscated
frame lengths. In the data phase, every frame is sent as a two-byte scrambled
length followed by an encrypted payload.

This type only handles the transport. Higher-level I2P concerns — parsing I2NP
messages, termination blocks, options negotiation, and replay protection — live
in the router transport layer (github.com/go-i2p/go-i2p/lib/transport/ntcp).

#### func  DialNTCP2

```go
func DialNTCP2(network, addr string, config *Config) (*Conn, error)
```
DialNTCP2 opens a TCP connection to addr and wraps it as an NTCP2 connection. It
combines dialing, Noise setup, and NTCP2 wrapping in one call. The returned
connection has not performed the handshake yet; call Handshake (or use
DialNTCP2WithHandshake) before sending data.

For more control over the underlying connection, dial with net.Dial and wrap it
with WrapNTCP2Conn instead.

#### func  DialNTCP2Context

```go
func DialNTCP2Context(ctx context.Context, network, addr string, config *Config) (*Conn, error)
```
DialNTCP2Context is like DialNTCP2 but takes a context that can cancel or
time-bound the dial.

#### func  DialNTCP2WithHandshake

```go
func DialNTCP2WithHandshake(network, addr string, config *Config) (*Conn, error)
```
DialNTCP2WithHandshake opens a connection to addr and performs the NTCP2
handshake automatically. The returned connection is ready for data-phase I/O.

#### func  DialNTCP2WithHandshakeContext

```go
func DialNTCP2WithHandshakeContext(ctx context.Context, network, addr string, config *Config) (*Conn, error)
```
DialNTCP2WithHandshakeContext is like DialNTCP2WithHandshake but takes a context
that can cancel or time-bound the dial and handshake.

#### func  NewNTCP2Conn

```go
func NewNTCP2Conn(noiseConn *noise.NoiseConn, localAddr, remoteAddr *Addr) (*Conn, error)
```
NewNTCP2Conn creates a Conn around an existing Noise connection. The Noise
connection must already be configured with the NTCP2 modifiers (AES obfuscation,
padding, SipHash length). localAddr and remoteAddr describe the two ends of the
connection.

#### func  WrapNTCP2Conn

```go
func WrapNTCP2Conn(conn net.Conn, config *Config) (*Conn, error)
```
WrapNTCP2Conn wraps an existing connection as an NTCP2 connection. It creates
the Noise wrapper and NTCP2 addresses. The returned connection has not performed
the handshake yet.

#### func (*Conn) Close

```go
func (nc *Conn) Close() error
```
Close closes the connection: it zeroes the key material and closes the
underlying Noise connection. Close is idempotent — calling it more than once is
safe.

#### func (*Conn) Handshake

```go
func (c *Conn) Handshake(ctx context.Context) (retErr error)
```
Handshake performs the NTCP2 three-way handshake (SessionRequest,
SessionCreated, SessionConfirmed) over the TCP connection.

Unlike standard Noise, NTCP2 handshake messages have no length prefix. This
method writes and reads raw Noise bytes directly over the socket to produce the
correct wire format:

    - Message 1 (64 bytes): [AES-obfuscated ephemeral key (32B)] [encrypted options (16B)] [tag (16B)]
    - Message 2 (64 bytes): [AES-obfuscated ephemeral key (32B)] [encrypted options (16B)] [tag (16B)]
    - Message 3 (48 + m3p2Len bytes): [encrypted static key (48B)] [encrypted RouterInfo block (m3p2Len B)]

After the handshake succeeds, the connection is ready for data-phase I/O
(Read/Write). Call PropagateSipHash and PropagatePeerStaticKey as needed by the
router transport layer.

Handshake must not be called concurrently on the same connection. See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details. See [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
for details.

#### func (*Conn) HandshakeHash

```go
func (nc *Conn) HandshakeHash() []byte
```
HandshakeHash returns the Noise handshake hash from the completed session. The
router transport layer uses it to derive the SipHash keys that scramble
data-phase frame lengths (see DeriveSipHashKeys). It returns nil if the
handshake has not started.

#### func (*Conn) LocalAddr

```go
func (nc *Conn) LocalAddr() net.Addr
```
LocalAddr returns the NTCP2 address of this end of the connection.

#### func (*Conn) NonceExhaustionImminent

```go
func (nc *Conn) NonceExhaustionImminent() bool
```
NonceExhaustionImminent reports whether the connection is close to running out
of nonces. A nonce is a number that must never repeat for a given key, and the
Noise Protocol's Rekey() does not reset the counter. When this returns true, the
right response is to open a new connection rather than keep using this one.

#### func (*Conn) PeerMessage3Payload

```go
func (nc *Conn) PeerMessage3Payload() []byte
```
PeerMessage3Payload returns the decrypted content of message 3, part 2, as sent
by the remote router. It is only meaningful on the responder side of a completed
handshake; it returns nil for initiator connections and before the handshake
succeeds.

The payload is an I2P block frame. Per the NTCP2 spec it contains a RouterInfo
block (type 2) and may also contain padding (type 254) and options (type 1)
blocks. The router transport layer parses it and stores the RouterInfo so
replies can be routed back to the peer.

The returned slice is a copy; you may modify it freely. See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Conn) PeerRouterInfoBytes

```go
func (nc *Conn) PeerRouterInfoBytes() []byte
```
PeerRouterInfoBytes finds the RouterInfo block inside the message-3 part-2
payload and returns just the RouterInfo bytes, with the leading flag byte
removed. It returns nil if no payload was captured, the payload is malformed, or
no RouterInfo block is present.

Each block in the frame has this layout:

    byte 0    : block type
    bytes 1-2 : block size (two bytes, big-endian) — number of bytes that follow
    bytes 3+  : block data (size bytes)

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Conn) PeerStaticKey

```go
func (nc *Conn) PeerStaticKey() []byte
```
PeerStaticKey returns the remote router's long-term public key (32 bytes). It is
available after the handshake completes. The router transport layer uses it to
compute the full router hash.

#### func (*Conn) PropagatePeerStaticKey

```go
func (nc *Conn) PropagatePeerStaticKey() error
```
PropagatePeerStaticKey records the remote router's identity on the connection's
remote address. Call it after a successful Handshake().

Before the handshake, the remote address holds a placeholder zero hash. This
method replaces it with the SHA-256 hash of the peer's static key, so the router
transport layer can identify the peer. It is a no-op if the address already has
a real hash. It returns an error if the peer's key is not available yet (the
handshake has not completed).

#### func (*Conn) PropagateSipHash

```go
func (nc *Conn) PropagateSipHash() error
```
PropagateSipHash copies the SipHash modifier derived during the handshake onto
this connection, enabling framed I/O. Call it right after a successful
Handshake().

It returns an error if no config was stored (SetNTCP2Config was not called) or
if the SipHash modifier is not available yet (the handshake has not finished, or
SipHash is disabled).

#### func (*Conn) Read

```go
func (nc *Conn) Read(b []byte) (int, error)
```
Read reads data from the NTCP2 connection, implementing the net.Conn interface.

When SipHash length obfuscation is active, reads use NTCP2 framed I/O:

    1. Return any plaintext left over from a previous frame, if there is
       some.
    2. Read exactly 2 bytes from the underlying TCP connection.
    3. XOR them with the SipHash inbound mask to recover the real frame
       length.
    4. Read exactly that many bytes of ciphertext from TCP.
    5. Decrypt the ciphertext with the Noise cipher state.
    6. Copy the plaintext into the caller's buffer; any remainder is
       buffered for the next Read call.

When no length obfuscator is set, Read delegates directly to the underlying
Noise connection.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func (*Conn) Rekey

```go
func (nc *Conn) Rekey() error
```
Rekey rotates the encryption keys of the underlying Noise connection, per the
Noise Protocol Framework. Note that rekeying does not reset the nonce counters,
so a connection near its nonce limit should be replaced with a new one instead.

See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
details.

#### func (*Conn) RemoteAddr

```go
func (nc *Conn) RemoteAddr() net.Addr
```
RemoteAddr returns the NTCP2 address of the other end of the connection.

#### func (*Conn) Role

```go
func (nc *Conn) Role() string
```
Role returns "initiator" if this side started the connection, or "responder" if
this side accepted it.

#### func (*Conn) RouterHash

```go
func (nc *Conn) RouterHash() data.Hash
```
RouterHash returns the identity hash of the router on the other end of the
connection.

#### func (*Conn) SetDeadline

```go
func (nc *Conn) SetDeadline(t time.Time) error
```
SetDeadline sets a single deadline that applies to both future Read and Write
calls. A Read or Write that takes longer than the deadline returns an error.

#### func (*Conn) SetLengthObfuscator

```go
func (nc *Conn) SetLengthObfuscator(slm *SipHashLengthModifier)
```
SetLengthObfuscator installs the SipHash length obfuscator used for data-phase
framing. Once set, Read and Write send and receive framed data: a two-byte
scrambled length followed by the encrypted payload. It is safe to call while
Read or Write is running.

#### func (*Conn) SetNTCP2Config

```go
func (nc *Conn) SetNTCP2Config(cfg *Config)
```
SetNTCP2Config remembers the Config used to create this connection. The
handshake derives the SipHash keys from that config, and PropagateSipHash copies
them onto the connection afterwards. It is safe to call while PropagateSipHash
is running.

#### func (*Conn) SetReadDeadline

```go
func (nc *Conn) SetReadDeadline(t time.Time) error
```
SetReadDeadline sets a deadline for future Read calls. A Read that takes longer
than the deadline returns an error.

#### func (*Conn) SetWriteDeadline

```go
func (nc *Conn) SetWriteDeadline(t time.Time) error
```
SetWriteDeadline sets a deadline for future Write calls. A Write that takes
longer than the deadline returns an error.

#### func (*Conn) UnderlyingConn

```go
func (nc *Conn) UnderlyingConn() *noise.NoiseConn
```
UnderlyingConn returns the Noise connection wrapped by this Conn. Use it only
when you need Noise-specific features that Conn does not expose.

#### func (*Conn) Write

```go
func (nc *Conn) Write(b []byte) (int, error)
```
Write writes data to the NTCP2 connection, implementing the net.Conn interface.

When SipHash length obfuscation is active, writes use NTCP2 framed I/O:

    1. Encrypt the plaintext with the Noise cipher state.
    2. Compute the ciphertext length as a 16-bit number.
    3. XOR it with the SipHash outbound mask to hide the length.
    4. Write the 2-byte obfuscated length followed by the ciphertext to
       the underlying TCP connection.

When no length obfuscator is set, Write delegates directly to the underlying
Noise connection.

Large writes are transparently split into multiple frames of at most
MaxFrameSize minus Poly1305Overhead bytes of plaintext each.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### type ConnIface

```go
type ConnIface interface {
	net.Conn
	// Handshake performs the NTCP2 handshake. It must be called before
	// Read or Write.
	Handshake(ctx context.Context) error
}
```

ConnIface is the minimal interface satisfied by *Conn.

Dialer.DialContext and Acceptor.AcceptWithHandshake return ConnIface instead of
the concrete *Conn type, so tests can substitute a fake connection without
importing the real one.

Where NTCP2-specific methods (e.g. PropagateSipHash, RouterHash) are needed, use
a type assertion: conn.(*Conn).PropagateSipHash().

#### type Dialer

```go
type Dialer interface {
	// DialContext opens an outbound NTCP2 connection to network/addr using
	// config, performs the NTCP2 handshake, and returns the established
	// connection. The context governs handshake cancellation.
	DialContext(ctx context.Context, network, addr string, config *Config) (ConnIface, error)
}
```

Dialer establishes outbound NTCP2 connections, including the handshake.

The package-level DialNTCP2WithHandshakeContext function provides this behavior;
NewDialer wraps it in a Dialer value, which is convenient for dependency
injection and test substitution.

#### func  NewDialer

```go
func NewDialer() Dialer
```
NewDialer returns a Dialer backed by DialNTCP2WithHandshakeContext.

The returned value may be stored in a Dialer field and replaced by a test double
without changing call sites.

#### type Listener

```go
type Listener struct {
}
```

Listener accepts incoming NTCP2 connections. It works like a net.Listener: call
Accept to wait for the next connection.

Each accepted TCP connection is wrapped in a Noise connection configured with
the NTCP2 cipher suite and modifiers, and then in a Conn. Accepted connections
act as the responder side of the handshake.

#### func  ListenNTCP2

```go
func ListenNTCP2(network, addr string, config *Config) (*Listener, error)
```
ListenNTCP2 starts listening on addr and returns a Listener that accepts NTCP2
connections. It combines net.Listen and NewNTCP2Listener in one call. For more
control over the underlying listener, use net.Listen followed by
NewNTCP2Listener.

Restart behavior: by default, after shutdown the port stays in TIME_WAIT state
for about 30-60 seconds (system-dependent), during which rebinding fails with
"address already in use". Enable config.AllowReuseAddress via
WithReuseAddress(true) to reduce this delay by setting SO_REUSEADDR, allowing
quick rebinding after shutdown. Use with caution in production: stale packets
from the previous listener instance may be delivered to the new listener during
the overlap window.

#### func  ListenNTCP2WithContext

```go
func ListenNTCP2WithContext(ctx context.Context, network, addr string, config *Config) (*Listener, error)
```
ListenNTCP2WithContext is like ListenNTCP2 but accepts a context that can cancel
or time-bound the socket creation step.

#### func  NewNTCP2Listener

```go
func NewNTCP2Listener(underlying net.Listener, config *Config) (*Listener, error)
```
NewNTCP2Listener wraps an existing TCP listener so that accepted connections are
NTCP2 connections. Each accepted connection is configured as a responder with
the NTCP2 cipher suite and modifiers from config.

#### func  WrapNTCP2Listener

```go
func WrapNTCP2Listener(listener net.Listener, config *Config) (*Listener, error)
```
WrapNTCP2Listener wraps an existing listener so that accepted connections are
NTCP2 connections. It is an alias for NewNTCP2Listener.

#### func (*Listener) Accept

```go
func (nl *Listener) Accept() (net.Conn, error)
```
Accept waits for and returns the next connection. The returned connection is a
Conn configured as a responder with the full NTCP2 cipher suite and modifiers.

The returned connection has NOT yet performed the handshake. Its
RemoteAddr().(*Addr).RouterHash is a zero value until Handshake(ctx) and
PropagatePeerStaticKey() complete. Most callers should use AcceptWithHandshake,
or call Handshake explicitly after Accept.

#### func (*Listener) AcceptWithHandshake

```go
func (nl *Listener) AcceptWithHandshake(ctx context.Context) (ConnIface, error)
```
AcceptWithHandshake waits for the next connection and performs the NTCP2
handshake on it automatically. It is the responder-side equivalent of
DialNTCP2WithHandshakeContext.

If the handshake fails, or the peer's static key cannot be recorded on the
remote address, the connection is closed and an error is returned.

#### func (*Listener) Addr

```go
func (nl *Listener) Addr() net.Addr
```
Addr returns the listener's NTCP2 address, which wraps the underlying TCP
listener's address.

#### func (*Listener) Close

```go
func (nl *Listener) Close() error
```
Close closes the listener and prevents new connections from being accepted. Any
blocked Accept calls are unblocked and return errors.

#### func (*Listener) Config

```go
func (nl *Listener) Config() *Config
```
Config returns the configuration used for new inbound handshakes.

#### func (*Listener) Underlying

```go
func (nl *Listener) Underlying() net.Listener
```
Underlying returns the raw TCP listener this NTCP2 listener wraps. Exposed so
callers can assert that an identity update did not replace the socket.

#### func (*Listener) UpdateIdentity

```go
func (nl *Listener) UpdateIdentity(cfg *Config) error
```
UpdateIdentity replaces the configuration used for new inbound handshakes
without touching the socket or any established session.

An NTCP2 responder's identity is consumed per connection, not per socket:
createResponderConnConfig clones the current config on every Accept, and
attachLocalRouterInfo reads the transport's RouterInfo when building message 3.
Updating the config in place is therefore enough for subsequent handshakes to
use a new RouterInfo, and it preserves the live listener that recreating it
would destroy. Rebinding the socket instead can never succeed: the old listener
must stay open for the swap to be atomic, and a second bind to the same port
fails with EADDRINUSE.

The listener stores the caller's pointer, mirroring NewNTCP2Listener, so a
caller that keeps mutating cfg continues to be observed. Use this method rather
than mutating after the listener has started if you need the update published
atomically together with the address hash.

#### type NTCP2PaddingModifier

```go
type NTCP2PaddingModifier struct {
}
```

NTCP2PaddingModifier implements NTCP2's padding strategies, as required by the
I2P NTCP2 specification.

Padding is random extra data added to messages so that an observer on the
network cannot tell how much real data each message carries. This makes traffic
analysis harder. NTCP2 uses two kinds of padding:

    - Cleartext padding for messages 1 and 2, added outside the AEAD
      frames (it is included in the MixHash, so it is still authenticated).
    - AEAD padding for message 3 and the data phase, added inside the
      AEAD frames as a block of type 254.

Padding sizes are chosen with a cryptographically secure random number
generator, and the padding ratio (how much padding relative to the data) is
configurable.

Padding computation and I2P block wire format operations are provided by the
shared handshake.PaddingEngine. NTCP2-specific concerns (AEAD removal with
trailing-block scan, frame validation) remain in this type.

All exported methods are safe for concurrent use.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func  NewNTCP2PaddingModifier

```go
func NewNTCP2PaddingModifier(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error)
```
NewNTCP2PaddingModifier creates a new NTCP2 padding modifier.

Parameters:

    - name: identifier for logging and debugging
    - minPadding: minimum padding bytes (0-65516)
    - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
    - useAEADPadding: false for messages 1-2 (cleartext padding), true
      for message 3 and the data phase (AEAD padding)

The modifier uses cryptographically secure random padding by default. Padding
sizes follow I2P NTCP2 specification guidelines.

#### func  NewNTCP2PaddingModifierWithRatio

```go
func NewNTCP2PaddingModifierWithRatio(name string, minPadding, maxPadding int, useAEADPadding bool, paddingRatio float64) (*NTCP2PaddingModifier, error)
```
NewNTCP2PaddingModifierWithRatio creates a new NTCP2 padding modifier with a
specific padding ratio.

Parameters:

    - name: identifier for logging and debugging
    - minPadding: minimum padding bytes (0-65516)
    - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
    - useAEADPadding: false for messages 1-2 (cleartext padding), true
      for message 3 and the data phase (AEAD padding)
    - paddingRatio: ratio of padding to data (0.0 to 15.9375; the spec
      leaves padding limits "TBD", so 15.9375 is an implementation cap)

A paddingRatio of 0.0 means no ratio-based padding (uses min/max only). A
paddingRatio of 1.0 means 100% padding (double the message size).

#### func (*NTCP2PaddingModifier) Clone

```go
func (npm *NTCP2PaddingModifier) Clone() handshake.HandshakeModifier
```
Clone creates a deep copy of the NTCP2PaddingModifier with independent state.

This implements handshake.ModifierCloner to support safe Config.Clone()
operations.

#### func (*NTCP2PaddingModifier) Close

```go
func (npm *NTCP2PaddingModifier) Close() error
```
Close is a no-op for NTCP2PaddingModifier, because it holds no sensitive key
material. It satisfies the HandshakeModifier lifecycle contract.

#### func (*NTCP2PaddingModifier) EstimatePaddingSize

```go
func (npm *NTCP2PaddingModifier) EstimatePaddingSize(dataLen int) int
```
EstimatePaddingSize estimates the padding size, in bytes, for a given data
length.

Useful for pre-allocating buffers and bandwidth calculations.

#### func (*NTCP2PaddingModifier) GetPaddingLimits

```go
func (npm *NTCP2PaddingModifier) GetPaddingLimits() (int, int)
```
GetPaddingLimits returns the current minimum and maximum padding limits, in
bytes.

#### func (*NTCP2PaddingModifier) GetPaddingRatio

```go
func (npm *NTCP2PaddingModifier) GetPaddingRatio() float64
```
GetPaddingRatio returns the current padding ratio.

The padding ratio is the amount of padding relative to the data size.

#### func (*NTCP2PaddingModifier) IsAEADMode

```go
func (npm *NTCP2PaddingModifier) IsAEADMode() bool
```
IsAEADMode returns true if this modifier is configured for AEAD padding (message
3 and the data phase), as opposed to cleartext padding (messages 1 and 2).

#### func (*NTCP2PaddingModifier) ModifyInbound

```go
func (npm *NTCP2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes NTCP2-specific padding from an inbound message.

PhaseFinal (message 3) is skipped — padding in message 3 is inside the encrypted
payload and parsed by the block-format layer, not the modifier.

#### func (*NTCP2PaddingModifier) ModifyOutbound

```go
func (npm *NTCP2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound adds NTCP2-specific padding to an outbound message, based on the
handshake phase.

PhaseFinal (message 3) is explicitly skipped because the handshake code manages
message 3 padding at the plaintext level — it must be included in m3p2Len, which
is committed in message 1 before the modifier runs. AEAD padding is only applied
during PhaseData (post-handshake frames).

#### func (*NTCP2PaddingModifier) Name

```go
func (npm *NTCP2PaddingModifier) Name() string
```
Name returns the modifier name, used for logging and debugging.

#### func (*NTCP2PaddingModifier) SetPaddingLimits

```go
func (npm *NTCP2PaddingModifier) SetPaddingLimits(minPadding, maxPadding int) error
```
SetPaddingLimits updates the minimum and maximum padding limits, allowing
dynamic adjustment.

Supports I2P NTCP2 options negotiation during the data phase.

#### func (*NTCP2PaddingModifier) SetPaddingRatio

```go
func (npm *NTCP2PaddingModifier) SetPaddingRatio(ratio float64) error
```
SetPaddingRatio updates the padding ratio, allowing dynamic adjustment during a
connection.

This supports I2P NTCP2 options negotiation, where padding parameters can be
updated.

#### func (*NTCP2PaddingModifier) ValidateAEADFrame

```go
func (npm *NTCP2PaddingModifier) ValidateAEADFrame(data []byte) bool
```
ValidateAEADFrame validates that a frame contains properly formatted AEAD
blocks.

Returns true if the frame structure is valid according to the I2P NTCP2 spec.

#### func (*NTCP2PaddingModifier) WithTestMode

```go
func (npm *NTCP2PaddingModifier) WithTestMode() *NTCP2PaddingModifier
```
WithTestMode enables deterministic (non-random) padding for this modifier.

WARNING: For testing only — deterministic padding compromises security. Returns
the receiver for method chaining.

#### type ReplayCache

```go
type ReplayCache struct {
}
```

ReplayCache is a thread-safe, bounded, TTL-based cache for detecting replayed
NTCP2 handshake ephemeral keys.

A replay attack is when an attacker re-sends a previously captured handshake
message, hoping the receiver will treat it as new. To defend against this, the
cache remembers the ephemeral keys it has already seen and rejects duplicates.

The cache stores the first 32 bytes of each message 1 (the ephemeral key X) and
rejects duplicates within the TTL (time-to-live) window. It is shared across all
listener goroutines within a single router instance.

ReplayCache implements the ReplayDetector interface.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### func  NewReplayCache

```go
func NewReplayCache() *ReplayCache
```
NewReplayCache creates a new replay cache and starts a background cleanup
goroutine that periodically removes expired entries.

Call Close() when the cache is no longer needed.

#### func (*ReplayCache) CheckAndAdd

```go
func (rc *ReplayCache) CheckAndAdd(ephemeralKey [32]byte) bool
```
CheckAndAdd checks whether an ephemeral key has been seen before.

If the key is new, it is added to the cache and false is returned (not a
replay). If the key has been seen within the TTL window, true is returned
(replay detected).

This is the primary method called by the listener before processing message 1.

#### func (*ReplayCache) Close

```go
func (rc *ReplayCache) Close()
```
Close stops the background cleanup goroutine and releases resources.

Close is idempotent — calling it more than once is safe and will not panic.

#### func (*ReplayCache) Size

```go
func (rc *ReplayCache) Size() int
```
Size returns the current number of entries in the cache.

#### type ReplayDetector

```go
type ReplayDetector interface {
	// CheckAndAdd returns true if the ephemeral key has been seen before
	// (a replay). If the key is new, it is added to the cache and false is
	// returned.
	CheckAndAdd(ephemeralKey [32]byte) bool

	// Size returns the current number of entries in the replay cache.
	Size() int

	// Close releases resources (stops the cleanup goroutine, if any).
	Close()
}
```

ReplayDetector checks for replayed ephemeral keys during NTCP2 handshakes.

A replay attack is when an attacker re-sends a previously captured handshake
message, hoping the receiver will treat it as new. To defend against this,
implementations maintain a TTL-based (time-to-live) cache of recently seen
ephemeral keys and reject duplicates.

The cache should automatically evict entries older than the configured TTL
(typically derived from ClockSkewTolerance). Implementations must be safe for
concurrent use.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.

#### type SipHashLengthModifier

```go
type SipHashLengthModifier = pkgsiphash.LengthModifier
```

SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation for data
phase frame lengths.

The canonical implementation lives in handshake/siphash; this alias makes the
type directly accessible from the ntcp2 package without an extra import.

See [I2P Spec:
NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for
details.



ntcp2 

github.com/go-i2p/go-noise/ntcp2

[go-i2p template file](/template.md)
