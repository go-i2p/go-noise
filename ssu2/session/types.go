// Package session: type aliases for types from ssu2 sub-packages.
// This file re-exports all external ssu2 types used within this package so
// that the implementation files need only change their package declaration.
package session

import (
	ssu2config "github.com/go-i2p/go-noise/ssu2/config"
	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/reliability"
	"github.com/go-i2p/go-noise/ssu2/wire"
	path "github.com/go-i2p/path"
)

// ─── From ssu2/config ─────────────────────────────────────────────────────────

type (
	SSU2Config = ssu2config.SSU2Config
	SSU2Addr   = ssu2config.SSU2Addr
)

var (
	NewSSU2Config        = ssu2config.NewSSU2Config
	NewSSU2Addr          = ssu2config.NewSSU2Addr
	NewMockSSU2Addr      = ssu2config.NewMockSSU2Addr
	GenerateConnectionID = ssu2config.GenerateConnectionID
)

// ─── From ssu2/wire ───────────────────────────────────────────────────────────

type (
	SSU2Block              = wire.SSU2Block
	SSU2Packet             = wire.SSU2Packet
	TerminationReason      = wire.TerminationReason
	BlockRouter            = wire.BlockRouter
	HeaderType             = wire.HeaderType
	HeaderProtectorManager = wire.HeaderProtectorManager
	SSU2PaddingModifier    = wire.SSU2PaddingModifier
	Token                  = wire.Token
)

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
	BlockTypeRelayTagRequest   = wire.BlockTypeRelayTagRequest
	BlockTypeRelayTag          = wire.BlockTypeRelayTag
	BlockTypeNewToken          = wire.BlockTypeNewToken
	BlockTypePathChallenge     = wire.BlockTypePathChallenge
	BlockTypePathResponse      = wire.BlockTypePathResponse
	BlockTypeFirstPacketNumber = wire.BlockTypeFirstPacketNumber
	BlockTypeCongestion        = wire.BlockTypeCongestion
	BlockTypePadding           = wire.BlockTypePadding
)

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

const (
	ShortHeaderSize   = wire.ShortHeaderSize
	MACSize           = wire.MACSize
	MaxPacketSizeIPv4 = wire.MaxPacketSizeIPv4
	HeaderKeySize     = wire.HeaderKeySize
)

var (
	NewSSU2Block              = wire.NewSSU2Block
	NewBlockRouter            = wire.NewBlockRouter
	SerializeBlocks           = wire.SerializeBlocks
	DeserializeBlocks         = wire.DeserializeBlocks
	FindBlockByType           = wire.FindBlockByType
	ExtractConnectionID       = wire.ExtractConnectionID
	ParseNewTokenBlock        = wire.ParseNewTokenBlock
	NewHeaderProtectorManager = wire.NewHeaderProtectorManager
)

// ─── From ssu2/handshake ──────────────────────────────────────────────────────

type (
	HandshakeHandler    = ssu2hs.HandshakeHandler
	OptionsParams       = ssu2hs.OptionsParams
	KeyState            = ssu2hs.KeyState
	ManagedKey          = ssu2hs.ManagedKey
	KeyRotationCallback = ssu2hs.KeyRotationCallback
	KeyRotationManager  = ssu2hs.KeyRotationManager
	KeyRotationStatus   = ssu2hs.KeyRotationStatus
)

const (
	SSU2ProtocolName         = ssu2hs.SSU2ProtocolName
	PublishedKeyMinAge       = ssu2hs.PublishedKeyMinAge
	UnpublishedKeyMinAge     = ssu2hs.UnpublishedKeyMinAge
	KeyRotationCheckInterval = ssu2hs.KeyRotationCheckInterval
	KeyGracePeriod           = ssu2hs.KeyGracePeriod
	StaticKeySize            = ssu2hs.StaticKeySize
	IntroKeySize             = ssu2hs.IntroKeySize
	KeyStateActive           = ssu2hs.KeyStateActive
	KeyStatePendingRotation  = ssu2hs.KeyStatePendingRotation
	KeyStateRotating         = ssu2hs.KeyStateRotating
	KeyStateRetired          = ssu2hs.KeyStateRetired
)

var (
	NewHandshakeHandler         = ssu2hs.NewHandshakeHandler
	NewHandshakeHandlerWithKeys = ssu2hs.NewHandshakeHandlerWithKeys
	ParseOptionsBlock           = ssu2hs.ParseOptionsBlock
	NewKeyRotationManager       = ssu2hs.NewKeyRotationManager
	GenerateNewStaticKey        = ssu2hs.GenerateNewStaticKey
	GenerateNewIntroKey         = ssu2hs.GenerateNewIntroKey
)

// ─── From ssu2/reliability ────────────────────────────────────────────────────

type (
	ACKHandler           = reliability.ACKHandler
	CongestionController = reliability.CongestionController
	CongestionState      = reliability.CongestionState
	CongestionStats      = reliability.CongestionStats
	PendingACK           = reliability.PendingACK
	RTTEstimator         = reliability.RTTEstimator
	ReceiveWindow        = reliability.ReceiveWindow
	SendReceiver         = reliability.SendReceiver
	KeepaliveManager     = reliability.KeepaliveManager
)

const (
	CongestionFlagRequestACK  = reliability.CongestionFlagRequestACK
	CongestionFlagECN         = reliability.CongestionFlagECN
	MinCongestionWindow       = reliability.MinCongestionWindow
	InitialCongestionWindow   = reliability.InitialCongestionWindow
	MaxCongestionWindow       = reliability.MaxCongestionWindow
	SlowStart                 = reliability.SlowStart
	CongestionAvoidance       = reliability.CongestionAvoidance
	Recovery                  = reliability.Recovery
	DefaultMaxWindowSize      = reliability.DefaultMaxWindowSize
	MaxPacketNumber           = reliability.MaxPacketNumber
	InitialSlowStartThreshold = reliability.InitialSlowStartThreshold
	RTTKMultiplier            = reliability.RTTKMultiplier
	ClockGranularity          = reliability.ClockGranularity
	InitialRTO                = reliability.InitialRTO
	MinRTO                    = reliability.MinRTO
	MaxRTO                    = reliability.MaxRTO
)

var (
	NewACKHandler                  = reliability.NewACKHandler
	NewCongestionController        = reliability.NewCongestionController
	NewCongestionControllerWithMTU = reliability.NewCongestionControllerWithMTU
	NewRTTEstimator                = reliability.NewRTTEstimator
	NewReceiveWindow               = reliability.NewReceiveWindow
	NewKeepaliveManager            = reliability.NewKeepaliveManager
	DecodeCongestionBlock          = reliability.DecodeCongestionBlock
	EncodeCongestionBlock          = reliability.EncodeCongestionBlock
	SortDescDedupPackets           = reliability.SortDescDedupPackets
)

// ─── From ssu2/path ───────────────────────────────────────────────────────────

type (
	ListenerRef                  = path.ListenerRef
	PathValidationConn           = path.PathValidationConn
	TokenCacheAccessor           = path.TokenCacheAccessor
	CongestionControllerAccessor = path.CongestionControllerAccessor
	HolePunchAttempt             = path.HolePunchAttempt
	HolePunchCoordinator         = path.HolePunchCoordinator
	HolePunchState               = path.HolePunchState
	IntroducerInfo               = path.IntroducerInfo
	IntroducerRegistry           = path.IntroducerRegistry
	NATType                      = path.NATType
	PathChallenge                = path.PathChallenge
	PathChallengeState           = path.PathChallengeState
	PathValidator                = path.PathValidator
	PeerTest                     = path.PeerTest
	PeerTestBlock                = path.PeerTestBlock
	PeerTestManager              = path.PeerTestManager
	PeerTestMessageCode          = path.PeerTestMessageCode
	PeerTestRole                 = path.PeerTestRole
	PeerTestState                = path.PeerTestState
	PendingSession               = path.PendingSession
	RegisteredIntroducer         = path.RegisteredIntroducer
	RelayIntroBlock              = path.RelayIntroBlock
	RelayManager                 = path.RelayManager
	RelayRequestBlock            = path.RelayRequestBlock
	RelayResponseBlock           = path.RelayResponseBlock
	RelayTag                     = path.RelayTag
	RelayTagBlock                = path.RelayTagBlock
	RelayTagRequestBlock         = path.RelayTagRequestBlock
	TestResult                   = path.TestResult
)

const (
	NATUnknown        = path.NATUnknown
	NATNone           = path.NATNone
	NATCone           = path.NATCone
	NATRestricted     = path.NATRestricted
	NATPortRestricted = path.NATPortRestricted
	NATSymmetric      = path.NATSymmetric

	HolePunchRequested = path.HolePunchRequested
	HolePunchSent      = path.HolePunchSent
	HolePunchWaiting   = path.HolePunchWaiting
	HolePunchSuccess   = path.HolePunchSuccess
	HolePunchFailed    = path.HolePunchFailed

	ChallengeSent      = path.ChallengeSent
	ChallengeReceived  = path.ChallengeReceived
	ChallengeValidated = path.ChallengeValidated
	ChallengeFailed    = path.ChallengeFailed

	PeerTestRequest      = path.PeerTestRequest
	PeerTestRelay        = path.PeerTestRelay
	PeerTestResponse     = path.PeerTestResponse
	PeerTestResult       = path.PeerTestResult
	PeerTestProbe        = path.PeerTestProbe
	PeerTestReply        = path.PeerTestReply
	PeerTestConfirmation = path.PeerTestConfirmation

	RoleInitiator = path.RoleInitiator
	RoleRelay     = path.RoleRelay
	RoleResponder = path.RoleResponder

	TestRequested = path.TestRequested
	TestRelayed   = path.TestRelayed
	TestProbed    = path.TestProbed
	TestComplete  = path.TestComplete
	TestFailed    = path.TestFailed
)

var (
	NewPathValidator             = path.NewPathValidator
	DecodeRelayIntro             = path.DecodeRelayIntro
	DecodeRelayRequest           = path.DecodeRelayRequest
	DecodeRelayResponse          = path.DecodeRelayResponse
	DecodePeerTestBlock          = path.DecodePeerTestBlock
	EncodeRelayRequest           = path.EncodeRelayRequest
	EncodeRelayResponse          = path.EncodeRelayResponse
	EncodeRelayIntro             = path.EncodeRelayIntro
	EncodeRelayTagRequest        = path.EncodeRelayTagRequest
	EncodeRelayTag               = path.EncodeRelayTag
	EncodePeerTestBlock          = path.EncodePeerTestBlock
	VerifyRelayRequestSignature  = path.VerifyRelayRequestSignature
	VerifyRelayResponseSignature = path.VerifyRelayResponseSignature
	VerifyPeerTestSignature      = path.VerifyPeerTestSignature
)
