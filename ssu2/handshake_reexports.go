package ssu2

import "github.com/go-i2p/go-noise/ssu2/handshake"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	HandshakeHandler = handshake.HandshakeHandler
	OptionsParams    = handshake.OptionsParams
)

// ─── Constants ────────────────────────────────────────────────────────────────

const SSU2ProtocolName = handshake.SSU2ProtocolName

// ─── Function re-exports ───────────────────────────────────────────────────────

var (
	NewHandshakeHandler         = handshake.NewHandshakeHandler
	NewHandshakeHandlerWithKeys = handshake.NewHandshakeHandlerWithKeys
	ParseOptionsBlock           = handshake.ParseOptionsBlock
)

// ─── Key rotation type aliases ────────────────────────────────────────────────

type (
	KeyState            = handshake.KeyState
	ManagedKey          = handshake.ManagedKey
	KeyRotationCallback = handshake.KeyRotationCallback
	KeyRotationManager  = handshake.KeyRotationManager
	KeyRotationStatus   = handshake.KeyRotationStatus
)

// ─── Key rotation constants ───────────────────────────────────────────────────

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

// ─── Key rotation constructors ────────────────────────────────────────────────

var (
	NewKeyRotationManager        = handshake.NewKeyRotationManager
	NewKeyRotationManagerWithAge = handshake.NewKeyRotationManagerWithAge
	GenerateNewStaticKey         = handshake.GenerateNewStaticKey
	GenerateNewIntroKey          = handshake.GenerateNewIntroKey
)
