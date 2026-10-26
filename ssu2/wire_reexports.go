package ssu2

import "github.com/go-i2p/go-noise/ssu2/wire"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	SSU2Block              = wire.SSU2Block
	SSU2Packet             = wire.SSU2Packet
	TerminationReason      = wire.TerminationReason
	AddressBlock           = wire.AddressBlock
	NewTokenBlock          = wire.NewTokenBlock
	BlockHandler           = wire.BlockHandler
	BlockHandlerFunc       = wire.BlockHandlerFunc
	BlockRouter            = wire.BlockRouter
	BlockRouterStats       = wire.BlockRouterStats
	BlockTypeCategory      = wire.BlockTypeCategory
	HeaderType             = wire.HeaderType
	HeaderProtector        = wire.HeaderProtector
	HeaderProtectorManager = wire.HeaderProtectorManager
	// IntroKeyMessageSpec describes one intro-key protected out-of-session message.
	IntroKeyMessageSpec = wire.IntroKeyMessageSpec
)

// ChaCha / padding modifier types
type (
	ChaChaObfuscationModifier = wire.ChaChaObfuscationModifier
	SSU2PaddingModifier       = wire.SSU2PaddingModifier
)

// TokenCache types
type (
	TokenCache = wire.TokenCache
	// SessionTokenStore holds tokens received from peers in New Token blocks.
	SessionTokenStore = wire.SessionTokenStore
	Token             = wire.Token
)

// ─── Block type constants ─────────────────────────────────────────────────────

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

// ─── Termination reason constants ─────────────────────────────────────────────

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

// ─── Block category constants ──────────────────────────────────────────────────

const (
	CategoryMessage  = wire.CategoryMessage
	CategoryRelay    = wire.CategoryRelay
	CategoryPeerTest = wire.CategoryPeerTest
	CategoryPath     = wire.CategoryPath
	CategorySession  = wire.CategorySession
	CategoryMetadata = wire.CategoryMetadata
	CategoryUnknown  = wire.CategoryUnknown
)

// ─── Header type constants ─────────────────────────────────────────────────────

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

// ─── Header size constants ─────────────────────────────────────────────────────

const (
	HeaderKeySize              = wire.HeaderKeySize
	MinPacketSizeForEncryption = wire.MinPacketSizeForEncryption
)

// ─── Message type constants ────────────────────────────────────────────────────

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

// ─── Packet/frame size constants ──────────────────────────────────────────────

const (
	ShortHeaderSize  = wire.ShortHeaderSize
	LongHeaderSize   = wire.LongHeaderSize
	EphemeralKeySize = wire.EphemeralKeySize
	MACSize          = wire.MACSize
)

const (
	MinPacketSize     = wire.MinPacketSize
	MaxPacketSizeIPv4 = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6 = wire.MaxPacketSizeIPv6
)

// ─── Protocol constants ────────────────────────────────────────────────────────

const (
	SSU2ProtocolVersion = wire.SSU2ProtocolVersion
	MainNetworkID       = wire.MainNetworkID
)

// ─── TokenCache constants ──────────────────────────────────────────────────────

const (
	TokenSize         = wire.TokenSize
	MaxTokenCacheSize = wire.MaxTokenCacheSize

	// RetryTokenTTL is the lifetime of a token issued in a Retry message.
	// Spec ref: ssu2.md §"Tokens" - "expires in a few seconds"; i2pd
	// SSU2_TOKEN_EXPIRATION_TIMEOUT = 9.
	RetryTokenTTL = wire.RetryTokenTTL
)

// ─── Function re-exports ───────────────────────────────────────────────────────

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

	ExtractConnectionID    = wire.ExtractConnectionID
	BuildIntroKeyMessage   = wire.BuildIntroKeyMessage
	OpenIntroKeyMessage    = wire.OpenIntroKeyMessage
	NewDateTimeBlock       = wire.NewDateTimeBlock
	NewAddressBlockForAddr = wire.NewAddressBlockForAddr
	EncodeConnectionID     = wire.EncodeConnectionID
	ExtractPacketNumber    = wire.ExtractPacketNumber
	EncodePacketNumber     = wire.EncodePacketNumber

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
	NewSessionTokenStore     = wire.NewSessionTokenStore
	NewTokenCacheWithMaxSize = wire.NewTokenCacheWithMaxSize
)
