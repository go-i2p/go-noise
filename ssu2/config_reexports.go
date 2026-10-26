package ssu2

import "github.com/go-i2p/go-noise/ssu2/config"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	SSU2Config = config.SSU2Config
	SSU2Addr   = config.SSU2Addr
)

// ─── Function re-exports ──────────────────────────────────────────────────────

var (
	NewSSU2Config              = config.NewSSU2Config
	NewSSU2Addr                = config.NewSSU2Addr
	GenerateConnectionID       = config.GenerateConnectionID
	DefaultRouterInfoValidator = config.DefaultRouterInfoValidator
)

// ─── Constants re-exports ─────────────────────────────────────────────────────

const (
	DefaultHandshakeTimeout      = config.DefaultHandshakeTimeout
	DefaultSessionCreatedTimeout = config.DefaultSessionCreatedTimeout
)
