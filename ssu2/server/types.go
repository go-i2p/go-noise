// Package server: type aliases for types from ssu2 sub-packages.
// This file re-exports all external ssu2 types used within this package so
// that the implementation files need only change their package declaration.
package server

import (
	ssu2config "github.com/go-i2p/go-noise/ssu2/config"
	"github.com/go-i2p/go-noise/ssu2/session"
	"github.com/go-i2p/go-noise/ssu2/wire"
)

// ─── From ssu2/config ─────────────────────────────────────────────────────────

type (
	SSU2Config = ssu2config.SSU2Config
	SSU2Addr   = ssu2config.SSU2Addr
)

var (
	NewSSU2Addr                = ssu2config.NewSSU2Addr
	NewMockSSU2Addr            = ssu2config.NewMockSSU2Addr
	NewSSU2Config              = ssu2config.NewSSU2Config
	GenerateConnectionID       = ssu2config.GenerateConnectionID
	DefaultRouterInfoValidator = ssu2config.DefaultRouterInfoValidator
)

// ─── From ssu2/session ────────────────────────────────────────────────────────

type (
	SSU2Conn     = session.SSU2Conn
	PacketRouter = session.PacketRouter
	DataHandler  = session.DataHandler
)

var (
	NewSSU2Conn     = session.NewSSU2Conn
	NewMockSSU2Conn = session.NewMockSSU2Conn
	NewPacketRouter = session.NewPacketRouter
)

// ─── From ssu2/wire ───────────────────────────────────────────────────────────

type (
	SSU2Block       = wire.SSU2Block
	SSU2Packet      = wire.SSU2Packet
	TokenCache      = wire.TokenCache
	Token           = wire.Token
	NewTokenBlock   = wire.NewTokenBlock
	HeaderProtector = wire.HeaderProtector
)

const (
	BlockTypeDateTime        = wire.BlockTypeDateTime
	BlockTypeOptions         = wire.BlockTypeOptions
	BlockTypeNewToken        = wire.BlockTypeNewToken
	BlockTypeTermination     = wire.BlockTypeTermination
	BlockTypeRelayRequest    = wire.BlockTypeRelayRequest
	BlockTypeRelayResponse   = wire.BlockTypeRelayResponse
	BlockTypeRelayIntro      = wire.BlockTypeRelayIntro
	BlockTypePeerTest        = wire.BlockTypePeerTest
	BlockTypeACK             = wire.BlockTypeACK
	BlockTypeAddress         = wire.BlockTypeAddress
	BlockTypeRelayTagRequest = wire.BlockTypeRelayTagRequest
	BlockTypeRelayTag        = wire.BlockTypeRelayTag
	BlockTypePathChallenge   = wire.BlockTypePathChallenge
	BlockTypePathResponse    = wire.BlockTypePathResponse
	BlockTypePadding         = wire.BlockTypePadding

	MessageTypeSessionRequest   = wire.MessageTypeSessionRequest
	MessageTypeSessionCreated   = wire.MessageTypeSessionCreated
	MessageTypeSessionConfirmed = wire.MessageTypeSessionConfirmed
	MessageTypeData             = wire.MessageTypeData
	MessageTypePeerTest         = wire.MessageTypePeerTest
	MessageTypeRetry            = wire.MessageTypeRetry
	MessageTypeTokenRequest     = wire.MessageTypeTokenRequest
	MessageTypeHolePunch        = wire.MessageTypeHolePunch

	HeaderTypeSessionRequest   = wire.HeaderTypeSessionRequest
	HeaderTypeSessionCreated   = wire.HeaderTypeSessionCreated
	HeaderTypeRetry            = wire.HeaderTypeRetry
	HeaderTypeTokenRequest     = wire.HeaderTypeTokenRequest
	HeaderTypeSessionConfirmed = wire.HeaderTypeSessionConfirmed
	HeaderTypeData             = wire.HeaderTypeData
	HeaderTypePeerTest         = wire.HeaderTypePeerTest
	HeaderTypeHolePunch        = wire.HeaderTypeHolePunch

	ShortHeaderSize     = wire.ShortHeaderSize
	LongHeaderSize      = wire.LongHeaderSize
	HeaderKeySize       = wire.HeaderKeySize
	EphemeralKeySize    = wire.EphemeralKeySize
	MACSize             = wire.MACSize
	MaxPacketNumber     = wire.MaxPacketNumber
	MinPacketSize       = wire.MinPacketSize
	MaxPacketSizeIPv4   = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6   = wire.MaxPacketSizeIPv6
	SSU2ProtocolVersion = wire.SSU2ProtocolVersion
	SSU2NetworkID       = wire.SSU2NetworkID
	TokenSize           = wire.TokenSize
	MaxTokenCacheSize   = wire.MaxTokenCacheSize
)

var (
	NewSSU2Block                   = wire.NewSSU2Block
	NewSSU2Packet                  = wire.NewSSU2Packet
	NewNewTokenBlock               = wire.NewNewTokenBlock
	ParseNewTokenBlock             = wire.ParseNewTokenBlock
	NewTokenCacheWithMaxSize       = wire.NewTokenCacheWithMaxSize
	SerializeBlocks                = wire.SerializeBlocks
	DeserializeBlocks              = wire.DeserializeBlocks
	FindBlockByType                = wire.FindBlockByType
	ExtractConnectionID            = wire.ExtractConnectionID
	NewHeaderProtectorFromIntroKey = wire.NewHeaderProtectorFromIntroKey
	EncodeAddressBlock             = wire.EncodeAddressBlock
	DecodeAddressBlock             = wire.DecodeAddressBlock
	EncryptIntroKeyAEAD            = wire.EncryptIntroKeyAEAD
	DecryptIntroKeyAEAD            = wire.DecryptIntroKeyAEAD
)
