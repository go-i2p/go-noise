package handshake

import "github.com/go-i2p/go-noise/ssu2/wire"

// Type aliases from ssu2/wire so handshake code can reference these types
// without qualifying them with the wire package name.
type (
	SSU2Block         = wire.SSU2Block
	SSU2Packet        = wire.SSU2Packet
	TerminationReason = wire.TerminationReason
)

// Block type constant aliases
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

// Packet type constant aliases
const (
	MessageTypeSessionRequest   = wire.MessageTypeSessionRequest
	MessageTypeSessionCreated   = wire.MessageTypeSessionCreated
	MessageTypeSessionConfirmed = wire.MessageTypeSessionConfirmed
	MessageTypeData             = wire.MessageTypeData
	MessageTypePeerTest         = wire.MessageTypePeerTest
	MessageTypeRetry            = wire.MessageTypeRetry
	MessageTypeTokenRequest     = wire.MessageTypeTokenRequest
	MessageTypeHolePunch        = wire.MessageTypeHolePunch
	SSU2ProtocolVersion         = wire.SSU2ProtocolVersion
	MainNetworkID               = wire.MainNetworkID
	ShortHeaderSize             = wire.ShortHeaderSize
	MACSize                     = wire.MACSize
	MaxPacketNumber             = wire.MaxPacketNumber
	MinPayloadSize              = wire.MinPayloadSize
)

// Termination reason aliases
const (
	TerminationSParamMissing = wire.TerminationSParamMissing
)

// Constructor and function aliases
var (
	NewSSU2Block             = wire.NewSSU2Block
	SerializeBlocks          = wire.SerializeBlocks
	DeserializeBlocks        = wire.DeserializeBlocks
	EncodeRouterInfoBlock    = wire.EncodeRouterInfoBlock
	DecodeRouterInfoBlock    = wire.DecodeRouterInfoBlock
	EncodeAddressBlock       = wire.EncodeAddressBlock
	DecodeAddressBlock       = wire.DecodeAddressBlock
	PadPayloadToMin          = wire.PadPayloadToMin
	Gunzip                   = wire.Gunzip
	ReadRouterInfo           = wire.ReadRouterInfo
	ExtractSSU2AddressParams = wire.ExtractSSU2AddressParams
)
