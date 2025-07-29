# ntcp2
--
    import "github.com/go-i2p/go-noise/ntcp2"

![ntcp2.svg](ntcp2.svg)

Package ntcp2 provides NTCP2-specific implementations for the Noise Protocol
Framework supporting I2P's NTCP2 transport protocol with router identity and
session management.

## Usage

#### type AESObfuscationModifier

```go
type AESObfuscationModifier struct {
}
```

AESObfuscationModifier implements NTCP2's AES-based ephemeral key obfuscation.
This modifier encrypts/decrypts the X and Y ephemeral keys in messages 1 and 2
using AES-256-CBC with the router hash as key and published IV. Moved from:
ntcp2/modifier.go

#### func  NewAESObfuscationModifier

```go
func NewAESObfuscationModifier(name string, routerHash, iv []byte) (*AESObfuscationModifier, error)
```
NewAESObfuscationModifier creates a new AES obfuscation modifier for NTCP2.
routerHash must be 32 bytes (RH_B), iv must be 16 bytes from network database.

#### func (*AESObfuscationModifier) ModifyInbound

```go
func (aom *AESObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes AES obfuscation from ephemeral keys in handshake messages.

#### func (*AESObfuscationModifier) ModifyOutbound

```go
func (aom *AESObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound applies AES obfuscation to ephemeral keys in handshake messages.
For message 1: encrypts X key with RH_B and published IV For message 2: encrypts
Y key with RH_B and AES state from message 1

#### func (*AESObfuscationModifier) Name

```go
func (aom *AESObfuscationModifier) Name() string
```
Name returns the modifier name for logging and debugging.

#### type NTCP2Addr

```go
type NTCP2Addr struct {
}
```

NTCP2Addr implements net.Addr for NTCP2 transport connections. It provides
I2P-specific addressing information including router identity, destination hash,
and session parameters for the NTCP2 protocol. Moved from: ntcp2/addr.go

#### func  NewNTCP2Addr

```go
func NewNTCP2Addr(underlying net.Addr, routerHash []byte, role string) (*NTCP2Addr, error)
```
NewNTCP2Addr creates a new NTCP2Addr with the specified TCP address and router
hash. routerHash must be exactly 32 bytes representing the I2P router identity.
role should be either "initiator" or "responder".

#### func (*NTCP2Addr) DestinationHash

```go
func (na *NTCP2Addr) DestinationHash() []byte
```
DestinationHash returns a copy of the destination hash, or nil for
router-to-router connections. The returned slice is a defensive copy to prevent
external modification.

#### func (*NTCP2Addr) IsRouterToRouter

```go
func (na *NTCP2Addr) IsRouterToRouter() bool
```
IsRouterToRouter returns true if this is a router-to-router connection (no
destination hash).

#### func (*NTCP2Addr) IsTunnelConnection

```go
func (na *NTCP2Addr) IsTunnelConnection() bool
```
IsTunnelConnection returns true if this is a tunnel connection (has destination
hash).

#### func (*NTCP2Addr) Network

```go
func (na *NTCP2Addr) Network() string
```
Network returns "ntcp2" to identify this as an NTCP2 transport address. This
implements the net.Addr interface requirement.

#### func (*NTCP2Addr) Role

```go
func (na *NTCP2Addr) Role() string
```
Role returns the connection role ("initiator" or "responder").

#### func (*NTCP2Addr) RouterHash

```go
func (na *NTCP2Addr) RouterHash() []byte
```
RouterHash returns a copy of the router identity hash. The returned slice is a
defensive copy to prevent external modification.

#### func (*NTCP2Addr) SessionTag

```go
func (na *NTCP2Addr) SessionTag() []byte
```
SessionTag returns a copy of the session tag, or nil if not set. The returned
slice is a defensive copy to prevent external modification.

#### func (*NTCP2Addr) String

```go
func (na *NTCP2Addr) String() string
```
String returns a string representation of the NTCP2 address. Format:
"ntcp2://[router_hash]/[role]/[tcp_address][?dest=dest_hash][&session=session_tag]"
Router hash and optional parameters are base64 encoded for readability.

#### func (*NTCP2Addr) UnderlyingAddr

```go
func (na *NTCP2Addr) UnderlyingAddr() net.Addr
```
UnderlyingAddr returns the underlying TCP network address.

#### func (*NTCP2Addr) WithDestinationHash

```go
func (na *NTCP2Addr) WithDestinationHash(destHash []byte) (*NTCP2Addr, error)
```
WithDestinationHash sets the destination hash for tunnel connections. destHash
must be exactly 32 bytes or nil for router-to-router connections.

#### func (*NTCP2Addr) WithSessionTag

```go
func (na *NTCP2Addr) WithSessionTag(sessionTag []byte) (*NTCP2Addr, error)
```
WithSessionTag sets the session tag for this connection. sessionTag must be
exactly 8 bytes or nil.

#### type NTCP2Config

```go
type NTCP2Config struct {
	// Pattern is the Noise protocol pattern for NTCP2
	// Default: "XK" (standard NTCP2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// RouterHash is the local router identity (32 bytes)
	// Required for NTCP2 addressing and session establishment
	RouterHash []byte

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity (32 bytes)
	// Required for outbound connections, optional for listeners
	RemoteRouterHash []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration

	// HandshakeRetries is the number of handshake retry attempts
	// Default: 3 attempts (0 = no retries, -1 = infinite retries)
	HandshakeRetries int

	// RetryBackoff is the base delay between retry attempts
	// Actual delay uses exponential backoff: delay = RetryBackoff * (2^attempt)
	// Default: 1 second
	RetryBackoff time.Duration

	// EnableAESObfuscation enables AES-based ephemeral key obfuscation
	// Default: true (recommended for production)
	EnableAESObfuscation bool

	// ObfuscationIV is the 16-byte IV for AES obfuscation
	// If nil, will be derived from router hash (recommended)
	ObfuscationIV []byte

	// EnableSipHashLength enables SipHash-based frame length obfuscation
	// Default: true (recommended for production)
	EnableSipHashLength bool

	// SipHashKeys are the k1, k2 keys for SipHash length obfuscation
	// If empty, will be derived during handshake
	SipHashKeys [2]uint64

	// Modifiers is a list of additional handshake modifiers for custom obfuscation
	// These are applied in addition to NTCP2's standard modifiers
	// Default: empty (no additional modifiers)
	Modifiers []handshake.HandshakeModifier

	// MaxFrameSize is the maximum size of NTCP2 data frames
	// Default: 16384 bytes (16KB)
	MaxFrameSize int

	// FramePaddingEnabled enables random padding in NTCP2 frames
	// Default: true (recommended for traffic analysis resistance)
	FramePaddingEnabled bool

	// MinPaddingSize is the minimum padding size for frames
	// Default: 0 bytes
	MinPaddingSize int

	// MaxPaddingSize is the maximum padding size for frames
	// Default: 64 bytes
	MaxPaddingSize int
}
```

NTCP2Config contains configuration for creating NTCP2 connections and listeners.
It follows the builder pattern for optional configuration and validation,
similar to the main ConnConfig but with NTCP2-specific parameters. Moved from:
ntcp2/config.go

#### func  NewNTCP2Config

```go
func NewNTCP2Config(routerHash []byte, initiator bool) (*NTCP2Config, error)
```
NewNTCP2Config creates a new NTCP2Config with sensible defaults. routerHash must
be exactly 32 bytes representing the local router identity. initiator indicates
whether this connection will initiate the handshake.

#### func (*NTCP2Config) ToConnConfig

```go
func (nc *NTCP2Config) ToConnConfig() (*noise.ConnConfig, error)
```
ToConnConfig converts NTCP2Config to a standard ConnConfig for use with
NoiseConn. This includes setting up NTCP2-specific modifiers based on the
configuration.

#### func (*NTCP2Config) Validate

```go
func (nc *NTCP2Config) Validate() error
```
Validate checks if the configuration is valid for NTCP2.

#### func (*NTCP2Config) WithAESObfuscation

```go
func (nc *NTCP2Config) WithAESObfuscation(enabled bool, customIV []byte) *NTCP2Config
```
WithAESObfuscation enables or disables AES-based ephemeral key obfuscation. When
enabled with a custom IV, the IV must be exactly 16 bytes.

#### func (*NTCP2Config) WithFrameSettings

```go
func (nc *NTCP2Config) WithFrameSettings(maxSize int, paddingEnabled bool, minPadding, maxPadding int) *NTCP2Config
```
WithFrameSettings configures NTCP2 frame handling parameters. maxSize sets the
maximum frame size (default: 16384 bytes). paddingEnabled enables random padding
(default: true). minPadding and maxPadding set the padding size range (default:
0-64 bytes).

#### func (*NTCP2Config) WithHandshakeRetries

```go
func (nc *NTCP2Config) WithHandshakeRetries(retries int) *NTCP2Config
```
WithHandshakeRetries sets the number of handshake retry attempts. Use 0 for no
retries, -1 for infinite retries.

#### func (*NTCP2Config) WithHandshakeTimeout

```go
func (nc *NTCP2Config) WithHandshakeTimeout(timeout time.Duration) *NTCP2Config
```
WithHandshakeTimeout sets the handshake timeout.

#### func (*NTCP2Config) WithModifiers

```go
func (nc *NTCP2Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *NTCP2Config
```
WithModifiers sets additional handshake modifiers for custom obfuscation. These
are applied in addition to NTCP2's standard modifiers.

#### func (*NTCP2Config) WithPattern

```go
func (nc *NTCP2Config) WithPattern(pattern string) *NTCP2Config
```
WithPattern sets the Noise protocol pattern. For NTCP2, this should typically
remain "XK".

#### func (*NTCP2Config) WithReadTimeout

```go
func (nc *NTCP2Config) WithReadTimeout(timeout time.Duration) *NTCP2Config
```
WithReadTimeout sets the read timeout for post-handshake operations.

#### func (*NTCP2Config) WithRemoteRouterHash

```go
func (nc *NTCP2Config) WithRemoteRouterHash(hash []byte) *NTCP2Config
```
WithRemoteRouterHash sets the remote peer's router identity. hash must be 32
bytes. Required for outbound connections.

#### func (*NTCP2Config) WithRetryBackoff

```go
func (nc *NTCP2Config) WithRetryBackoff(backoff time.Duration) *NTCP2Config
```
WithRetryBackoff sets the base delay between retry attempts.

#### func (*NTCP2Config) WithSipHashLength

```go
func (nc *NTCP2Config) WithSipHashLength(enabled bool, k1, k2 uint64) *NTCP2Config
```
WithSipHashLength enables or disables SipHash-based frame length obfuscation.
When enabled with custom keys, both k1 and k2 must be provided.

#### func (*NTCP2Config) WithStaticKey

```go
func (nc *NTCP2Config) WithStaticKey(key []byte) *NTCP2Config
```
WithStaticKey sets the static key for this connection. key must be 32 bytes for
Curve25519.

#### func (*NTCP2Config) WithWriteTimeout

```go
func (nc *NTCP2Config) WithWriteTimeout(timeout time.Duration) *NTCP2Config
```
WithWriteTimeout sets the write timeout for post-handshake operations.

#### type NTCP2Conn

```go
type NTCP2Conn struct {
}
```

NTCP2Conn implements net.Conn for NTCP2 transport connections. It wraps a
NoiseConn with NTCP2-specific addressing and protocol handling. Moved from:
ntcp2/conn.go

#### func  DialNTCP2

```go
func DialNTCP2(network, addr string, config *NTCP2Config) (*NTCP2Conn, error)
```
DialNTCP2 creates a connection to the given address and wraps it with NTCP2Conn.
This is a convenience function that combines net.Dial, NoiseConn creation, and
NTCP2 wrapping. For more control over the underlying connection, use net.Dial
followed by NewNoiseConn and NewNTCP2Conn.

#### func  DialNTCP2WithHandshake

```go
func DialNTCP2WithHandshake(network, addr string, config *NTCP2Config) (*NTCP2Conn, error)
```
DialNTCP2WithHandshake creates a connection and performs the NTCP2 handshake
automatically. This is a convenience function that combines DialNTCP2 and
handshake execution.

#### func  DialNTCP2WithHandshakeContext

```go
func DialNTCP2WithHandshakeContext(ctx context.Context, network, addr string, config *NTCP2Config) (*NTCP2Conn, error)
```
DialNTCP2WithHandshakeContext creates a connection and performs the NTCP2
handshake with context. The context can be used to cancel the dial or handshake
operations.

#### func  NewNTCP2Conn

```go
func NewNTCP2Conn(noiseConn *noise.NoiseConn, localAddr, remoteAddr *NTCP2Addr) (*NTCP2Conn, error)
```
NewNTCP2Conn creates a new NTCP2Conn wrapping the provided NoiseConn. The
NoiseConn must already be configured with appropriate NTCP2 modifiers.

#### func  WrapNTCP2Conn

```go
func WrapNTCP2Conn(conn net.Conn, config *NTCP2Config) (*NTCP2Conn, error)
```
WrapNTCP2Conn wraps an existing net.Conn with NTCP2Conn. This function creates
the necessary Noise wrapper and NTCP2 addressing.

#### func (*NTCP2Conn) Close

```go
func (nc *NTCP2Conn) Close() error
```
Close implements net.Conn.Close. Closes the underlying Noise connection and
cleans up resources.

#### func (*NTCP2Conn) DestinationHash

```go
func (nc *NTCP2Conn) DestinationHash() []byte
```
DestinationHash returns the destination hash from the remote address. Returns
nil for router-to-router connections.

#### func (*NTCP2Conn) LocalAddr

```go
func (nc *NTCP2Conn) LocalAddr() net.Addr
```
LocalAddr implements net.Conn.LocalAddr. Returns the NTCP2-specific local
address.

#### func (*NTCP2Conn) Read

```go
func (nc *NTCP2Conn) Read(b []byte) (int, error)
```
Read implements net.Conn.Read. Reads data from the underlying encrypted Noise
connection.

#### func (*NTCP2Conn) RemoteAddr

```go
func (nc *NTCP2Conn) RemoteAddr() net.Addr
```
RemoteAddr implements net.Conn.RemoteAddr. Returns the NTCP2-specific remote
address.

#### func (*NTCP2Conn) Role

```go
func (nc *NTCP2Conn) Role() string
```
Role returns the connection role (initiator or responder).

#### func (*NTCP2Conn) RouterHash

```go
func (nc *NTCP2Conn) RouterHash() []byte
```
RouterHash returns the router hash from the remote address. This is I2P-specific
functionality for NTCP2 connections.

#### func (*NTCP2Conn) SessionTag

```go
func (nc *NTCP2Conn) SessionTag() []byte
```
SessionTag returns the session tag from the remote address. Returns nil if no
session tag is set.

#### func (*NTCP2Conn) SetDeadline

```go
func (nc *NTCP2Conn) SetDeadline(t time.Time) error
```
SetDeadline implements net.Conn.SetDeadline. Sets read and write deadlines on
the underlying connection.

#### func (*NTCP2Conn) SetReadDeadline

```go
func (nc *NTCP2Conn) SetReadDeadline(t time.Time) error
```
SetReadDeadline implements net.Conn.SetReadDeadline. Sets the read deadline on
the underlying connection.

#### func (*NTCP2Conn) SetWriteDeadline

```go
func (nc *NTCP2Conn) SetWriteDeadline(t time.Time) error
```
SetWriteDeadline implements net.Conn.SetWriteDeadline. Sets the write deadline
on the underlying connection.

#### func (*NTCP2Conn) UnderlyingConn

```go
func (nc *NTCP2Conn) UnderlyingConn() *noise.NoiseConn
```
UnderlyingConn returns the underlying NoiseConn for advanced operations. This
allows access to Noise-specific functionality when needed.

#### func (*NTCP2Conn) Write

```go
func (nc *NTCP2Conn) Write(b []byte) (int, error)
```
Write implements net.Conn.Write. Writes data to the underlying encrypted Noise
connection.

#### type NTCP2Listener

```go
type NTCP2Listener struct {
}
```

NTCP2Listener implements net.Listener for accepting NTCP2 transport connections.
It wraps a NoiseListener and provides NTCP2-specific addressing and connection
handling with I2P router identity management and session establishment. Moved
from: ntcp2/listener.go

#### func  ListenNTCP2

```go
func ListenNTCP2(network, addr string, config *NTCP2Config) (*NTCP2Listener, error)
```
ListenNTCP2 creates a listener on the given address and wraps it with
NTCP2Listener. This is a convenience function that combines net.Listen and
NewNTCP2Listener. For more control over the underlying listener, use net.Listen
followed by NewNTCP2Listener.

#### func  NewNTCP2Listener

```go
func NewNTCP2Listener(underlying net.Listener, config *NTCP2Config) (*NTCP2Listener, error)
```
NewNTCP2Listener creates a new NTCP2Listener that wraps the underlying TCP
listener. The listener will accept connections and wrap them in NTCP2Conn
instances configured as responders with NTCP2-specific addressing and protocol
handling.

#### func  WrapNTCP2Listener

```go
func WrapNTCP2Listener(listener net.Listener, config *NTCP2Config) (*NTCP2Listener, error)
```
WrapNTCP2Listener wraps an existing net.Listener with NTCP2Listener. This is an
alias for NewNTCP2Listener for consistency with the transport API.

#### func (*NTCP2Listener) Accept

```go
func (nl *NTCP2Listener) Accept() (net.Conn, error)
```
Accept waits for and returns the next connection to the listener. The returned
connection is wrapped in an NTCP2Conn configured as a responder.

#### func (*NTCP2Listener) Addr

```go
func (nl *NTCP2Listener) Addr() net.Addr
```
Addr returns the listener's network address. This is an NTCP2Addr that wraps the
underlying listener's address.

#### func (*NTCP2Listener) Close

```go
func (nl *NTCP2Listener) Close() error
```
Close closes the listener and prevents new connections from being accepted. Any
blocked Accept operations will be unblocked and return errors.

#### type NTCP2PaddingModifier

```go
type NTCP2PaddingModifier struct {
}
```

NTCP2PaddingModifier implements NTCP2-specific padding strategies. Cleartext
padding for messages 1 and 2 (outside AEAD frames). AEAD padding for message 3
and data phase (inside AEAD frames). Moved from: ntcp2/modifier.go

#### func  NewNTCP2PaddingModifier

```go
func NewNTCP2PaddingModifier(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error)
```
NewNTCP2PaddingModifier creates a new NTCP2 padding modifier. useAEADPadding:
false for messages 1-2 (cleartext), true for message 3+ (AEAD).

#### func (*NTCP2PaddingModifier) ModifyInbound

```go
func (npm *NTCP2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes NTCP2-specific padding.

#### func (*NTCP2PaddingModifier) ModifyOutbound

```go
func (npm *NTCP2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound adds NTCP2-specific padding based on message phase.

#### func (*NTCP2PaddingModifier) Name

```go
func (npm *NTCP2PaddingModifier) Name() string
```
Name returns the modifier name for logging and debugging.

#### type SipHashLengthModifier

```go
type SipHashLengthModifier struct {
}
```

SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation for data
phase frame lengths. This prevents identification of frame lengths in the data
stream. Moved from: ntcp2/modifier.go

#### func  NewSipHashLengthModifier

```go
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier
```
NewSipHashLengthModifier creates a new SipHash length obfuscation modifier.
sipKeys must contain exactly 2 uint64 values (k1, k2). initialIV is the 8-byte
IV from the data phase KDF.

#### func (*SipHashLengthModifier) ModifyInbound

```go
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes SipHash obfuscation from frame lengths.

#### func (*SipHashLengthModifier) ModifyOutbound

```go
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound obfuscates 2-byte frame lengths using SipHash.

#### func (*SipHashLengthModifier) Name

```go
func (slm *SipHashLengthModifier) Name() string
```
Name returns the modifier name for logging and debugging.



ntcp2 

github.com/go-i2p/go-noise/ntcp2

[go-i2p template file](/template.md)
