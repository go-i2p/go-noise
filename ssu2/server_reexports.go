package ssu2

import "github.com/go-i2p/go-noise/ssu2/server"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	SSU2Listener = server.SSU2Listener
	// Acceptor is the consumer-facing interface for accepting SSU2 connections.
	// *SSU2Listener satisfies this interface.
	Acceptor = server.Acceptor
)

// ─── Function re-exports ──────────────────────────────────────────────────────

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
