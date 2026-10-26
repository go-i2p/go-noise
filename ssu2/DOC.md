# ssu2
--
    import "github.com/go-i2p/go-noise/ssu2"

![ssu2.svg](ssu2.svg)

Package ssu2 implements the I2P SSU2 transport protocol.

# What is SSU2?

SSU2 (Secure Semi-reliable UDP version 2) is the transport protocol that I2P
routers use to talk to each other over UDP. It carries I2NP messages (the
messages routers exchange to build and use anonymous paths) between two routers,
one UDP packet at a time.

SSU2 is built on the Noise Protocol Framework, a well-studied way to securely
agree on encryption keys between two parties. The exact Noise pattern SSU2 uses
is:

    Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256

In plain terms:

    - XK: the initiator already knows the responder's long-term public key,
      so the first message can be small and the handshake is fast.
    - chaobfse: the cleartext parts of the handshake (the one-time public
      keys) are hidden with ChaCha20 stream encryption, so an observer
      cannot tell which packets are handshake packets.
    - hs1+hs2+hs3: three handshake messages, each carrying a 16 or 32 byte
      header that is bound into the encryption (see below).
    - 25519: X25519 key exchange (RFC 7748).
    - ChaChaPoly: ChaCha20-Poly1305 encryption (RFC 7539) with a 12-byte
      nonce whose first 4 bytes are zero.
    - SHA256: SHA-256 for hashing.

See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
details.

# How SSU2 extends Noise

I2P adds five extensions to the base Noise_XK pattern:

    1. Each handshake message includes a 16 or 32 byte header.
    2. The header is mixed into the Noise mixHash before encryption, which
       binds the header to the message so it cannot be tampered with.
    3. The header is encrypted and authenticated along with the message.
    4. The cleartext ephemeral (one-time) keys are obfuscated with ChaCha20
       (unlike NTCP2, which uses AES).
    5. A payload format is defined for handshake messages 1, 2, and 3 and
       for the data phase.

Because all three handshake messages use the header as associated data, the SSU2
protocol identifier differs from NTCP2's.

See [I2P Spec:
SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for
details.

# What SSU2 does and does not do

SSU2 is an authenticated key agreement protocol for point-to-point
router-to-router transport of I2NP messages over UDP. It is not a
general-purpose data pipe.

SSU2 does NOT provide in-order delivery or guaranteed delivery of I2NP messages,
and it does NOT completely prevent duplicate delivery. Routers must be prepared
to receive messages out of order or more than once.

In addition to carrying I2NP messages, SSU2 provides:

    - Relaying (NAT traversal): a third router can relay messages between
      two peers that cannot reach each other directly.
    - Peer Testing: a peer can test whether it is reachable from outside
      its network (inbound reachability).
    - Connection Migration: a session can survive the peer's IP address or
      port changing (for example, when a NAT mapping changes).

# Packet format

SSU2 packet headers are adapted from WireGuard and QUIC. Header obfuscation uses
ChaCha20 (from ECIES) instead of AES. Packet numbering is adapted from WireGuard
and QUIC, and ACKs/nacks are adapted from QUIC.

# NAT detection and reachability state

All NAT detection, peer-test management, and reachability state management
(PeerTestManager, TestResult, NATStatus) is delegated to the external
github.com/go-i2p/path package. This means:

    1. Errors or panics in path validation code cannot be observed or
       instrumented from within go-noise.
    2. A bug in external path detection (for example, a false-positive
       FIREWALLED state) would be invisible at the go-noise layer.
    3. NAT state is the single source of truth from go-i2p/path; go-noise does
       not validate or override it.

If you need to observe NAT state transitions or integrate custom reachability
logic, you must hook directly into go-i2p/path, not go-noise. This is by design,
to keep the transport layer (go-noise) separate from the routing/path layer.

# Package layout

    - ssu2 (this package): top-level API — dialing, listening, the
      Coordinator for peer tests and relaying, and re-exports of the
      subpackages' types for backward compatibility.
    - ssu2/config: configuration types (SSU2Config, SSU2Addr) and
      validation.
    - ssu2/handshake: the XK handshake state machine, key generation, and
      key rotation.
    - ssu2/reliability: ACK handling, RTT estimation, congestion control,
      receive window, and keepalive.
    - ssu2/server: the listener (inbound sessions), token admission, and
      transport wiring.
    - ssu2/session: an established SSU2 connection (SSU2Conn), packet
      routing, and I2NP message handling.
    - ssu2/wire: the on-the-wire packet and block formats, header
      protection, and obfuscation.

## Usage

```go
const (
	PublishedKeyMinAge       = handshake.PublishedKeyMinAge
	UnpublishedKeyMinAge     = handshake.UnpublishedKeyMinAge
	KeyRotationCheckInterval = handshake.KeyRotationCheckInterval
	KeyGracePeriod           = handshake.KeyGracePeriod
	StaticKeySize            = handshake.StaticKeySize
	IntroKeySize             = handshake.IntroKeySize
	KeyStateActive           = handshake.KeyStateActive
	KeyStatePendingRotation  = handshake.KeyStatePendingRotation
	KeyStateRotating         = handshake.KeyStateRotating
	KeyStateRetired          = handshake.KeyStateRetired
)
```

```go
const (
	NATUnknown        = path.NATUnknown
	NATNone           = path.NATNone
	NATCone           = path.NATCone
	NATRestricted     = path.NATRestricted
	NATPortRestricted = path.NATPortRestricted
	NATSymmetric      = path.NATSymmetric
)
```

```go
const (
	HolePunchRequested = path.HolePunchRequested
	HolePunchSent      = path.HolePunchSent
	HolePunchWaiting   = path.HolePunchWaiting
	HolePunchSuccess   = path.HolePunchSuccess
	HolePunchFailed    = path.HolePunchFailed
)
```

```go
const (
	ChallengeSent      = path.ChallengeSent
	ChallengeReceived  = path.ChallengeReceived
	ChallengeValidated = path.ChallengeValidated
	ChallengeFailed    = path.ChallengeFailed
)
```

```go
const (
	PeerTestRequest      = path.PeerTestRequest
	PeerTestRelay        = path.PeerTestRelay
	PeerTestResponse     = path.PeerTestResponse
	PeerTestResult       = path.PeerTestResult
	PeerTestProbe        = path.PeerTestProbe
	PeerTestReply        = path.PeerTestReply
	PeerTestConfirmation = path.PeerTestConfirmation
)
```

```go
const (
	RoleInitiator = path.RoleInitiator
	RoleRelay     = path.RoleRelay
	RoleResponder = path.RoleResponder
)
```

```go
const (
	TestRequested = path.TestRequested
	TestRelayed   = path.TestRelayed
	TestProbed    = path.TestProbed
	TestComplete  = path.TestComplete
	TestFailed    = path.TestFailed
)
```

```go
const (
	PathValidationTimeout  = path.PathValidationTimeout
	MinMTU                 = path.MinMTU
	RelayRequestPrologue   = path.RelayRequestPrologue
	PeerTestPrologue       = path.PeerTestPrologue
	RelayAgreementPrologue = path.RelayAgreementPrologue
)
```

```go
const (
	CongestionFlagRequestACK = reliability.CongestionFlagRequestACK
	CongestionFlagECN        = reliability.CongestionFlagECN
)
```

```go
const (
	MinCongestionWindow     = reliability.MinCongestionWindow
	InitialCongestionWindow = reliability.InitialCongestionWindow
	MaxCongestionWindow     = reliability.MaxCongestionWindow
)
```

```go
const (
	SlowStart           = reliability.SlowStart
	CongestionAvoidance = reliability.CongestionAvoidance
	Recovery            = reliability.Recovery
)
```

```go
const (
	DefaultMaxWindowSize      = reliability.DefaultMaxWindowSize
	MaxPacketNumber           = reliability.MaxPacketNumber
	InitialSlowStartThreshold = reliability.InitialSlowStartThreshold
	RTTKMultiplier            = reliability.RTTKMultiplier
	ClockGranularity          = reliability.ClockGranularity
	InitialRTO                = reliability.InitialRTO
	MinRTO                    = reliability.MinRTO
	MaxRTO                    = reliability.MaxRTO
)
```

```go
const (
	StateInit        = session.StateInit
	StateHandshaking = session.StateHandshaking
	StateEstablished = session.StateEstablished
	StateClosing     = session.StateClosing
	StateClosed      = session.StateClosed
)
```

```go
const (
	BlockTypeDateTime          = wire.BlockTypeDateTime
	BlockTypeOptions           = wire.BlockTypeOptions
	BlockTypeRouterInfo        = wire.BlockTypeRouterInfo
	BlockTypeI2NPMessage       = wire.BlockTypeI2NPMessage
	BlockTypeFirstFragment     = wire.BlockTypeFirstFragment
	BlockTypeFollowOnFragment  = wire.BlockTypeFollowOnFragment
	BlockTypeTermination       = wire.BlockTypeTermination
	BlockTypeRelayRequest      = wire.BlockTypeRelayRequest
	BlockTypeRelayResponse     = wire.BlockTypeRelayResponse
	BlockTypeRelayIntro        = wire.BlockTypeRelayIntro
	BlockTypePeerTest          = wire.BlockTypePeerTest
	BlockTypeNextNonce         = wire.BlockTypeNextNonce
	BlockTypeACK               = wire.BlockTypeACK
	BlockTypeAddress           = wire.BlockTypeAddress
	BlockTypeReserved14        = wire.BlockTypeReserved14
	BlockTypeRelayTagRequest   = wire.BlockTypeRelayTagRequest
	BlockTypeRelayTag          = wire.BlockTypeRelayTag
	BlockTypeNewToken          = wire.BlockTypeNewToken
	BlockTypePathChallenge     = wire.BlockTypePathChallenge
	BlockTypePathResponse      = wire.BlockTypePathResponse
	BlockTypeFirstPacketNumber = wire.BlockTypeFirstPacketNumber
	BlockTypeCongestion        = wire.BlockTypeCongestion
	BlockTypePadding           = wire.BlockTypePadding
)
```

```go
const (
	TerminationNormalClose           = wire.TerminationNormalClose
	TerminationReceived              = wire.TerminationReceived
	TerminationIdleTimeout           = wire.TerminationIdleTimeout
	TerminationRouterShutdown        = wire.TerminationRouterShutdown
	TerminationDataPhaseAEADFailure  = wire.TerminationDataPhaseAEADFailure
	TerminationIncompatibleOptions   = wire.TerminationIncompatibleOptions
	TerminationIncompatibleSignature = wire.TerminationIncompatibleSignature
	TerminationClockSkew             = wire.TerminationClockSkew
	TerminationPaddingViolation      = wire.TerminationPaddingViolation
	TerminationAEADFramingError      = wire.TerminationAEADFramingError
	TerminationPayloadFormatError    = wire.TerminationPayloadFormatError
	TerminationSessionRequestError   = wire.TerminationSessionRequestError
	TerminationSessionCreatedError   = wire.TerminationSessionCreatedError
	TerminationSessionConfirmedError = wire.TerminationSessionConfirmedError
	TerminationTimeout               = wire.TerminationTimeout
	TerminationRISigVerifyFail       = wire.TerminationRISigVerifyFail
	TerminationSParamMissing         = wire.TerminationSParamMissing
	TerminationBanned                = wire.TerminationBanned
	TerminationBadToken              = wire.TerminationBadToken
	TerminationConnectionLimits      = wire.TerminationConnectionLimits
	TerminationIncompatibleVersion   = wire.TerminationIncompatibleVersion
	TerminationWrongNetID            = wire.TerminationWrongNetID
	TerminationReplacedByNewSession  = wire.TerminationReplacedByNewSession
)
```

```go
const (
	CategoryMessage  = wire.CategoryMessage
	CategoryRelay    = wire.CategoryRelay
	CategoryPeerTest = wire.CategoryPeerTest
	CategoryPath     = wire.CategoryPath
	CategorySession  = wire.CategorySession
	CategoryMetadata = wire.CategoryMetadata
	CategoryUnknown  = wire.CategoryUnknown
)
```

```go
const (
	HeaderTypeSessionRequest   = wire.HeaderTypeSessionRequest
	HeaderTypeSessionCreated   = wire.HeaderTypeSessionCreated
	HeaderTypeRetry            = wire.HeaderTypeRetry
	HeaderTypeTokenRequest     = wire.HeaderTypeTokenRequest
	HeaderTypeSessionConfirmed = wire.HeaderTypeSessionConfirmed
	HeaderTypeData             = wire.HeaderTypeData
	HeaderTypePeerTest         = wire.HeaderTypePeerTest
	HeaderTypeHolePunch        = wire.HeaderTypeHolePunch
)
```

```go
const (
	HeaderKeySize              = wire.HeaderKeySize
	MinPacketSizeForEncryption = wire.MinPacketSizeForEncryption
)
```

```go
const (
	MessageTypeSessionRequest   = wire.MessageTypeSessionRequest
	MessageTypeSessionCreated   = wire.MessageTypeSessionCreated
	MessageTypeSessionConfirmed = wire.MessageTypeSessionConfirmed
	MessageTypeData             = wire.MessageTypeData
	MessageTypePeerTest         = wire.MessageTypePeerTest
	MessageTypeRetry            = wire.MessageTypeRetry
	MessageTypeTokenRequest     = wire.MessageTypeTokenRequest
	MessageTypeHolePunch        = wire.MessageTypeHolePunch
)
```

```go
const (
	ShortHeaderSize  = wire.ShortHeaderSize
	LongHeaderSize   = wire.LongHeaderSize
	EphemeralKeySize = wire.EphemeralKeySize
	MACSize          = wire.MACSize
)
```

```go
const (
	MinPacketSize     = wire.MinPacketSize
	MaxPacketSizeIPv4 = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6 = wire.MaxPacketSizeIPv6
)
```

```go
const (
	SSU2ProtocolVersion = wire.SSU2ProtocolVersion
	SSU2NetworkID       = wire.SSU2NetworkID
)
```

```go
const (
	SipHashIVSize       = wire.SipHashIVSize
	DataLengthFieldSize = wire.DataLengthFieldSize
)
```

```go
const (
	TokenSize         = wire.TokenSize
	MaxTokenCacheSize = wire.MaxTokenCacheSize
)
```

```go
const DefaultHandshakeTimeout = config.DefaultHandshakeTimeout
```

```go
const SSU2ProtocolName = handshake.SSU2ProtocolName
```

```go
var (
	NewSSU2Config              = config.NewSSU2Config
	NewSSU2Addr                = config.NewSSU2Addr
	GenerateConnectionID       = config.GenerateConnectionID
	DefaultRouterInfoValidator = config.DefaultRouterInfoValidator
)
```

```go
var (
	NewHandshakeHandler         = handshake.NewHandshakeHandler
	NewHandshakeHandlerWithKeys = handshake.NewHandshakeHandlerWithKeys
	ParseOptionsBlock           = handshake.ParseOptionsBlock
)
```

```go
var (
	NewKeyRotationManager        = handshake.NewKeyRotationManager
	NewKeyRotationManagerWithAge = handshake.NewKeyRotationManagerWithAge
	GenerateNewStaticKey         = handshake.GenerateNewStaticKey
	GenerateNewIntroKey          = handshake.GenerateNewIntroKey
)
```

```go
var (
	NewHolePunchCoordinator      = path.NewHolePunchCoordinator
	NewIntroducerRegistry        = path.NewIntroducerRegistry
	NewPathValidator             = path.NewPathValidator
	NewPeerTestManager           = path.NewPeerTestManager
	NewPeerTestManagerWithFields = path.NewPeerTestManagerWithFields
	NewRelayManager              = path.NewRelayManager

	EncodePathChallenge            = path.EncodePathChallenge
	EncodePathChallengeWithPadding = path.EncodePathChallengeWithPadding
	EncodePathResponse             = path.EncodePathResponse
	DecodePathChallenge            = path.DecodePathChallenge
	DecodePathResponse             = path.DecodePathResponse

	DecodePeerTestBlock   = path.DecodePeerTestBlock
	EncodePeerTestBlock   = path.EncodePeerTestBlock
	DecodeRelayIntro      = path.DecodeRelayIntro
	EncodeRelayIntro      = path.EncodeRelayIntro
	DecodeRelayRequest    = path.DecodeRelayRequest
	EncodeRelayRequest    = path.EncodeRelayRequest
	DecodeRelayResponse   = path.DecodeRelayResponse
	EncodeRelayResponse   = path.EncodeRelayResponse
	DecodeRelayTag        = path.DecodeRelayTag
	EncodeRelayTag        = path.EncodeRelayTag
	DecodeRelayTagRequest = path.DecodeRelayTagRequest
	EncodeRelayTagRequest = path.EncodeRelayTagRequest

	BuildPeerTestSignedData      = path.BuildPeerTestSignedData
	BuildRelayRequestSignedData  = path.BuildRelayRequestSignedData
	BuildRelayResponseSignedData = path.BuildRelayResponseSignedData
	SignPeerTest                 = path.SignPeerTest
	SignRelayRequest             = path.SignRelayRequest
	SignRelayResponse            = path.SignRelayResponse
	VerifyPeerTestSignature      = path.VerifyPeerTestSignature
	VerifyRelayRequestSignature  = path.VerifyRelayRequestSignature
	VerifyRelayResponseSignature = path.VerifyRelayResponseSignature

	CompareNATTypes         = path.CompareNATTypes
	DetermineNATType        = path.DetermineNATType
	DescribeNATCapabilities = path.DescribeNATCapabilities
	HasPublicIP             = path.HasPublicIP
	IsSymmetricNAT          = path.IsSymmetricNAT
	RequiresRelay           = path.RequiresRelay
	SelectBestNATType       = path.SelectBestNATType
	SelectWorstNATType      = path.SelectWorstNATType

	AnalyzeProbeResults    = path.AnalyzeProbeResults
	ExtractExternalAddress = path.ExtractExternalAddress
	ExtractExternalPort    = path.ExtractExternalPort
	IsDirectlyReachable    = path.IsDirectlyReachable
	IsReachableViaRelay    = path.IsReachableViaRelay
	ValidateTestResult     = path.ValidateTestResult

	IsAddressConsistent = path.IsAddressConsistent
	IsIPConsistent      = path.IsIPConsistent
	IsPortConsistent    = path.IsPortConsistent
	IsValidSourcePort   = path.IsValidSourcePort
	NonceConnectionIDs  = path.NonceConnectionIDs
)
```

```go
var (
	NewACKHandler                  = reliability.NewACKHandler
	NewCongestionController        = reliability.NewCongestionController
	NewCongestionControllerWithMTU = reliability.NewCongestionControllerWithMTU
	NewRTTEstimator                = reliability.NewRTTEstimator
	NewReceiveWindow               = reliability.NewReceiveWindow
	DecodeCongestionBlock          = reliability.DecodeCongestionBlock
	EncodeCongestionBlock          = reliability.EncodeCongestionBlock
	SortDescDedupPackets           = reliability.SortDescDedupPackets
)
```

```go
var (
	NewSSU2Listener                     = server.NewSSU2Listener
	DialSSU2                            = server.DialSSU2
	DialSSU2WithConn                    = server.DialSSU2WithConn
	DialSSU2WithHandshake               = server.DialSSU2WithHandshake
	DialSSU2WithConnAndHandshake        = server.DialSSU2WithConnAndHandshake
	DialSSU2WithConnAndHandshakeContext = server.DialSSU2WithConnAndHandshakeContext
	DialSSU2WithHandshakeContext        = server.DialSSU2WithHandshakeContext
	ListenSSU2                          = server.ListenSSU2
	WrapSSU2Conn                        = server.WrapSSU2Conn
	WrapSSU2Listener                    = server.WrapSSU2Listener
)
```

```go
var (
	NewSSU2Conn     = session.NewSSU2Conn
	NewDataHandler  = session.NewDataHandler
	NewPacketRouter = session.NewPacketRouter
)
```

```go
var (
	NewSSU2Block      = wire.NewSSU2Block
	NewSSU2Packet     = wire.NewSSU2Packet
	NewBlockRouter    = wire.NewBlockRouter
	SerializeBlocks   = wire.SerializeBlocks
	DeserializeBlocks = wire.DeserializeBlocks
	FindBlockByType   = wire.FindBlockByType
	IsKnownBlockType  = wire.IsKnownBlockType
	GetBlockTypeName  = wire.GetBlockTypeName
	GetBlockCategory  = wire.GetBlockCategory
	AllBlockTypes     = wire.AllBlockTypes

	EncodeAddressBlock             = wire.EncodeAddressBlock
	DecodeAddressBlock             = wire.DecodeAddressBlock
	NewNewTokenBlock               = wire.NewNewTokenBlock
	ParseNewTokenBlock             = wire.ParseNewTokenBlock
	NewHeaderProtector             = wire.NewHeaderProtector
	NewHeaderProtectorFromIntroKey = wire.NewHeaderProtectorFromIntroKey
	NewHeaderProtectorManager      = wire.NewHeaderProtectorManager

	ExtractConnectionID = wire.ExtractConnectionID
	EncodeConnectionID  = wire.EncodeConnectionID
	ExtractPacketNumber = wire.ExtractPacketNumber
	EncodePacketNumber  = wire.EncodePacketNumber

	// SipHash length modifier constructors
	NewSipHashLengthModifier            = wire.NewSipHashLengthModifier
	NewSipHashLengthModifierDirectional = wire.NewSipHashLengthModifierDirectional

	// ChaCha obfuscation modifier constructor
	NewChaChaObfuscationModifier = wire.NewChaChaObfuscationModifier

	// SSU2 padding modifier constructors
	NewSSU2PaddingModifier          = wire.NewSSU2PaddingModifier
	NewSSU2PaddingModifierWithRatio = wire.NewSSU2PaddingModifierWithRatio
	NewSSU2PaddingModifierWithMTU   = wire.NewSSU2PaddingModifierWithMTU

	// IntroKey / StaticKey helpers
	IntroKeyFromRouterAddress  = wire.IntroKeyFromRouterAddress
	StaticKeyFromRouterAddress = wire.StaticKeyFromRouterAddress

	// TokenCache constructors
	NewTokenCache            = wire.NewTokenCache
	NewTokenCacheWithMaxSize = wire.NewTokenCacheWithMaxSize
)
```

```go
var NewKeepaliveManager = reliability.NewKeepaliveManager
```

#### type ACKHandler

```go
type ACKHandler = reliability.ACKHandler
```


#### type Acceptor

```go
type Acceptor = server.Acceptor
```

Acceptor is the consumer-facing interface for accepting SSU2 connections.
*SSU2Listener satisfies this interface.

#### type AddressBlock

```go
type AddressBlock = wire.AddressBlock
```


#### type BlockHandler

```go
type BlockHandler = wire.BlockHandler
```


#### type BlockHandlerFunc

```go
type BlockHandlerFunc = wire.BlockHandlerFunc
```


#### type BlockRouter

```go
type BlockRouter = wire.BlockRouter
```


#### type BlockRouterStats

```go
type BlockRouterStats = wire.BlockRouterStats
```


#### type BlockTypeCategory

```go
type BlockTypeCategory = wire.BlockTypeCategory
```


#### type ChaChaObfuscationModifier

```go
type ChaChaObfuscationModifier = wire.ChaChaObfuscationModifier
```

SipHash / ChaCha / padding modifier types

#### type CharlieSelector

```go
type CharlieSelector func() (hash data.Hash, addr *net.UDPAddr, ok bool)
```

CharlieSelector picks a responder ("Charlie") for a peer test that the local
router is relaying as "Bob". It returns ok=false when no suitable peer is
available, in which case the peer test is dropped. The router supplies this from
its peer database.

#### type CongestionController

```go
type CongestionController = reliability.CongestionController
```


#### type CongestionControllerAccessor

```go
type CongestionControllerAccessor = path.CongestionControllerAccessor
```


#### type CongestionState

```go
type CongestionState = reliability.CongestionState
```


#### type CongestionStats

```go
type CongestionStats = reliability.CongestionStats
```


#### type ConnIface

```go
type ConnIface interface {
	net.Conn
	// Handshake performs the SSU2 XK handshake. It must be called before
	// Read/Write.
	Handshake(ctx context.Context) error

	// WriteBlocksWithNumbers sends blocks as individual Data packets and
	// returns the packet number assigned to each block, in order. Callers can
	// use these numbers to match explicit ACK blocks from the peer to the
	// exact outbound packets, giving spec-correct delivery confirmation
	// without guessing which packet an ACK refers to.
	WriteBlocksWithNumbers(blocks []*session.SSU2Block) ([]uint32, error)
}
```

ConnIface is the minimal interface satisfied by *SSU2Conn. Dialer.DialContext
returns ConnIface so that callers can substitute test doubles without importing
the concrete *session.SSU2Conn type. Where SSU2-specific methods are needed, use
a type assertion:

    conn.(*session.SSU2Conn).CloseWithReason(...)

#### type ConnState

```go
type ConnState = session.ConnState
```


#### type Coordinator

```go
type Coordinator struct {
}
```

Coordinator wires the peer-test and relay state machines into session callbacks.
A single instance is shared across all of the local router's SSU2 sessions.

# What the Coordinator does

SSU2 has two extra features beyond carrying I2NP messages: peer testing
(checking whether a peer can be reached from outside its network) and relaying
(having a third router forward messages between two peers that cannot reach each
other directly). The state machines for these features live in the go-i2p/path
package (re-exported by this package). The Coordinator connects those state
machines to a live session: it turns inbound PeerTest and Relay blocks into
responses, and it verifies the signatures on those blocks.

# Layering

The Coordinator never resolves sessions or imports the router (go-i2p/go-i2p).
It only decides *what* to send and *to which peer*. Actual delivery is delegated
to an injected Dispatcher, which the router implements.

# Threading model

A single Coordinator is shared by the local router across all of its SSU2
sessions. BuildCallbacks is called once per established session with that peer's
router hash and Ed25519 signing key. It returns closures that read and write the
Coordinator's shared, mutex-guarded state. Peer-test and relay flows span three
peers and three distinct sessions (Alice<->Bob, Bob<->Charlie), so cross-session
state such as the per-nonce context lives on the shared Coordinator, not on a
per-connection object.

# Peer-test signature semantics

In a peer test, three routers take the roles of Alice (initiator), Bob (relay),
and Charlie (responder). Bob never signs; he forwards Alice's signature (message
1 -> message 2) and Charlie's signature (message 3 -> message 4), only changing
the message code and the included router hash. Only Alice (messages 1/2) and
Charlie (messages 3/4) produce signatures. The same is true of relaying: Bob
forwards Alice's request signature into the RelayIntro; only Alice and Charlie
sign.

See [I2P Spec:
SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for
details.

#### func  NewCoordinator

```go
func NewCoordinator(cfg CoordinatorConfig) (*Coordinator, error)
```
NewCoordinator creates a Coordinator. Dispatcher, PeerTest and Relay are
required; it returns an error if any of them is missing.

#### func (*Coordinator) BuildCallbacks

```go
func (c *Coordinator) BuildCallbacks(remoteHash data.Hash, remoteKey ed25519.Ed25519PublicKey) DataHandlerCallbacks
```
BuildCallbacks returns DataHandlerCallbacks bound to a single SSU2 session with
the given peer (identified by its router hash and authenticated Ed25519 signing
key). The returned closures read and mutate the shared Coordinator state, so
cross-session peer-test/relay flows resolve correctly.

remoteKey may be nil if the peer's signing key is not yet known; in that case
any verification whose signer is the directly-connected peer fails closed.

#### func (*Coordinator) IntroducerOptions

```go
func (c *Coordinator) IntroducerOptions() (map[string]string, error)
```
IntroducerOptions builds the SSU2 RouterAddress option map that advertises the
local router's current introducers, so that introduced peers can be contacted
through them. It bridges the shared relay manager's live introducer set to the
wire encoding (the itag/ih/iexp option keys). Expired or invalid entries are
skipped by the wire encoder.

#### func (*Coordinator) RegisterRelayClient

```go
func (c *Coordinator) RegisterRelayClient(relayTag uint32, routerHash data.Hash, addr *net.UDPAddr) error
```
RegisterRelayClient records that the local router (acting as Bob) has agreed to
act as an introducer for the peer identified by routerHash/addr, reachable via
the given relay tag. A relay tag is a small number that identifies an introducer
relationship. It both records the tag-to-hash mapping the Coordinator needs to
verify inbound RelayRequests and registers the peer with the shared relay
manager.

#### func (*Coordinator) StartPeerTest

```go
func (c *Coordinator) StartPeerTest(bobHash data.Hash, bobAddr, aliceExternal *net.UDPAddr) (uint32, error)
```
StartPeerTest initiates a peer test toward bobHash/bobAddr. aliceExternal is the
local router's believed external endpoint, embedded in the signed request. It
returns the test nonce.

#### func (*Coordinator) StartRelay

```go
func (c *Coordinator) StartRelay(bobHash data.Hash, bobAddr *net.UDPAddr, charlieHash data.Hash, relayTag uint32, aliceExternal *net.UDPAddr) (uint32, error)
```
StartRelay initiates a relay request asking bobHash to introduce the local
router to charlieHash via the given relay tag. aliceExternal is the local
router's believed external endpoint. It returns the relay nonce.

#### type CoordinatorConfig

```go
type CoordinatorConfig struct {
	// LocalRouterHash is the local router's identity hash. It is used as the
	// Bob hash when the local router acts as Bob, and as the Alice or Charlie
	// hash when it is the initiator or responder.
	LocalRouterHash data.Hash

	// SigningKey is the local router's Ed25519 signing private key. It is used
	// when the local router is Alice (signs peer-test and relay requests) or
	// Charlie (signs peer-test and relay responses). It is never used when
	// acting purely as Bob, because Bob never signs.
	SigningKey ed25519.Ed25519PrivateKey

	// KeyResolver resolves a remote router hash to its signing public key. It
	// is used to verify forwarded signatures whose signer is not the
	// directly-connected peer (for example, Charlie verifying Alice's
	// signature in a RelayIntro). If nil, such verifications fail closed.
	KeyResolver PeerKeyResolver

	// Dispatcher delivers outbound blocks. Required.
	Dispatcher Dispatcher

	// PeerTest is the shared peer-test state manager. Required.
	PeerTest *PeerTestManager

	// Relay is the shared relay/introducer state manager. Required.
	Relay *RelayManager

	// Introducers is the optional introducer registry used when the local
	// router is an introduced peer publishing its introducers.
	Introducers *IntroducerRegistry

	// SelectCharlie picks a responder when relaying a peer test as Bob. If nil,
	// inbound peer-test requests (message 1) are acknowledged-as-dropped.
	SelectCharlie CharlieSelector

	// LocalExternal is the local router's believed external endpoint, embedded
	// as Charlie's address in relay responses. May be nil if unknown.
	LocalExternal *net.UDPAddr

	// Now returns the current time; defaults to time.Now. Injectable for tests.
	Now func() time.Time
}
```

CoordinatorConfig configures a Coordinator. Dispatcher, PeerTest and Relay are
required; the remaining fields enable specific roles and default to safe no-ops
or fail-closed behavior when omitted.

#### type DataHandler

```go
type DataHandler = session.DataHandler
```


#### type DataHandlerCallbacks

```go
type DataHandlerCallbacks = session.DataHandlerCallbacks
```


#### type DataHandlerStats

```go
type DataHandlerStats = session.DataHandlerStats
```


#### type Dialer

```go
type Dialer interface {
	// DialContext establishes a new SSU2 session from localAddr to remoteAddr.
	// The context controls connection and handshake timeouts.
	DialContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (ConnIface, error)
}
```

Dialer establishes outbound SSU2 connections, including the handshake. Use
NewDialer to obtain the default implementation.

#### func  NewDialer

```go
func NewDialer() Dialer
```
NewDialer returns a Dialer backed by DialSSU2WithHandshakeContext.

#### type Dispatcher

```go
type Dispatcher interface {
	Dispatch(target SendTarget) error
}
```

Dispatcher delivers Coordinator-produced blocks to a peer. The router implements
this interface; it owns session resolution and the actual UDP write. Keeping
delivery behind an interface preserves the layering rule that go-noise must not
depend on the router.

#### type DispatcherFunc

```go
type DispatcherFunc func(SendTarget) error
```

DispatcherFunc adapts an ordinary function to the Dispatcher interface.

#### func (DispatcherFunc) Dispatch

```go
func (f DispatcherFunc) Dispatch(t SendTarget) error
```
Dispatch implements Dispatcher.

#### type FragmentSet

```go
type FragmentSet = session.FragmentSet
```


#### type HandshakeHandler

```go
type HandshakeHandler = handshake.HandshakeHandler
```


#### type HeaderProtector

```go
type HeaderProtector = wire.HeaderProtector
```


#### type HeaderProtectorManager

```go
type HeaderProtectorManager = wire.HeaderProtectorManager
```


#### type HeaderType

```go
type HeaderType = wire.HeaderType
```


#### type HolePunchAttempt

```go
type HolePunchAttempt = path.HolePunchAttempt
```


#### type HolePunchContextResolver

```go
type HolePunchContextResolver = path.HolePunchContextResolver
```


#### type HolePunchCoordinator

```go
type HolePunchCoordinator = path.HolePunchCoordinator
```


#### type HolePunchState

```go
type HolePunchState = path.HolePunchState
```


#### type HolePunchVerifyContext

```go
type HolePunchVerifyContext = path.HolePunchVerifyContext
```


#### type HolePunchVerifyInfo

```go
type HolePunchVerifyInfo = path.HolePunchVerifyInfo
```


#### type IntroducerInfo

```go
type IntroducerInfo = path.IntroducerInfo
```


#### type IntroducerRegistry

```go
type IntroducerRegistry = path.IntroducerRegistry
```


#### type KeepaliveManager

```go
type KeepaliveManager = reliability.KeepaliveManager
```


#### type KeyRotationCallback

```go
type KeyRotationCallback = handshake.KeyRotationCallback
```


#### type KeyRotationManager

```go
type KeyRotationManager = handshake.KeyRotationManager
```


#### type KeyRotationStatus

```go
type KeyRotationStatus = handshake.KeyRotationStatus
```


#### type KeyState

```go
type KeyState = handshake.KeyState
```


#### type ListenerRef

```go
type ListenerRef = path.ListenerRef
```


#### type ManagedKey

```go
type ManagedKey = handshake.ManagedKey
```


#### type NATType

```go
type NATType = path.NATType
```


#### type NewTokenBlock

```go
type NewTokenBlock = wire.NewTokenBlock
```


#### type OptionsParams

```go
type OptionsParams = handshake.OptionsParams
```


#### type PacketRouter

```go
type PacketRouter = session.PacketRouter
```


#### type PathChallenge

```go
type PathChallenge = path.PathChallenge
```


#### type PathChallengeState

```go
type PathChallengeState = path.PathChallengeState
```


#### type PathValidationConn

```go
type PathValidationConn = path.PathValidationConn
```


#### type PathValidator

```go
type PathValidator = path.PathValidator
```


#### type PeerKeyResolver

```go
type PeerKeyResolver func(routerHash data.Hash) (ed25519.Ed25519PublicKey, bool)
```

PeerKeyResolver looks up a peer's Ed25519 signing public key from its router
hash (the 32-byte identity that identifies a router on the I2P network). It is
used to verify signatures. It returns ok=false when the key is unknown; in that
case verification fails closed (the signature is rejected). The router backs
this with its network database; go-noise never resolves identities itself.

#### type PeerTest

```go
type PeerTest = path.PeerTest
```


#### type PeerTestBlock

```go
type PeerTestBlock = path.PeerTestBlock
```


#### type PeerTestManager

```go
type PeerTestManager = path.PeerTestManager
```


#### type PeerTestMessageCode

```go
type PeerTestMessageCode = path.PeerTestMessageCode
```


#### type PeerTestRole

```go
type PeerTestRole = path.PeerTestRole
```


#### type PeerTestState

```go
type PeerTestState = path.PeerTestState
```


#### type PendingACK

```go
type PendingACK = reliability.PendingACK
```


#### type PendingPacket

```go
type PendingPacket = session.PendingPacket
```


#### type PendingSession

```go
type PendingSession = path.PendingSession
```


#### type RTTEstimator

```go
type RTTEstimator = reliability.RTTEstimator
```


#### type ReceiveWindow

```go
type ReceiveWindow = reliability.ReceiveWindow
```


#### type RegisteredIntroducer

```go
type RegisteredIntroducer = path.RegisteredIntroducer
```


#### type RelayIntroBlock

```go
type RelayIntroBlock = path.RelayIntroBlock
```


#### type RelayManager

```go
type RelayManager = path.RelayManager
```


#### type RelayRequestBlock

```go
type RelayRequestBlock = path.RelayRequestBlock
```


#### type RelayResponseBlock

```go
type RelayResponseBlock = path.RelayResponseBlock
```


#### type RelayTag

```go
type RelayTag = path.RelayTag
```


#### type RelayTagBlock

```go
type RelayTagBlock = path.RelayTagBlock
```


#### type RelayTagRequestBlock

```go
type RelayTagRequestBlock = path.RelayTagRequestBlock
```


#### type Router

```go
type Router = session.Router
```

Router is the consumer-facing interface for routing SSU2 packets. *PacketRouter
satisfies this interface.

#### type SSU2Addr

```go
type SSU2Addr = config.SSU2Addr
```


#### type SSU2Block

```go
type SSU2Block = wire.SSU2Block
```


#### type SSU2Config

```go
type SSU2Config = config.SSU2Config
```


#### type SSU2Conn

```go
type SSU2Conn = session.SSU2Conn
```


#### type SSU2Listener

```go
type SSU2Listener = server.SSU2Listener
```


#### type SSU2Packet

```go
type SSU2Packet = wire.SSU2Packet
```


#### type SSU2PaddingModifier

```go
type SSU2PaddingModifier = wire.SSU2PaddingModifier
```

SipHash / ChaCha / padding modifier types

#### type SendReceiver

```go
type SendReceiver = reliability.SendReceiver
```


#### type SendTarget

```go
type SendTarget struct {
	// RouterHash is the destination peer's router identity hash. Zero when the
	// destination is identified only by Addr.
	RouterHash data.Hash

	// Addr is the destination UDP endpoint, used for out-of-session delivery.
	// nil when the destination is identified only by RouterHash.
	Addr *net.UDPAddr

	// Blocks are the SSU2 blocks to deliver to the destination.
	Blocks []*SSU2Block
}
```

SendTarget describes a set of outbound SSU2 blocks and where they must be
delivered. RouterHash identifies a known peer (the common case); Addr is set for
out-of-session delivery, such as a hole-punch probe sent to a raw endpoint that
has no session yet.

#### type SipHashLengthModifier

```go
type SipHashLengthModifier = wire.SipHashLengthModifier
```

SipHash / ChaCha / padding modifier types

#### type TerminationReason

```go
type TerminationReason = wire.TerminationReason
```


#### type TestResult

```go
type TestResult = path.TestResult
```


#### type Token

```go
type Token = wire.Token
```

TokenCache types

#### type TokenCache

```go
type TokenCache = wire.TokenCache
```

TokenCache types

#### type TokenCacheAccessor

```go
type TokenCacheAccessor = path.TokenCacheAccessor
```



ssu2 

github.com/go-i2p/go-noise/ssu2

[go-i2p template file](/template.md)
