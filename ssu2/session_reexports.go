package ssu2

import "github.com/go-i2p/go-noise/ssu2/session"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	SSU2Conn             = session.SSU2Conn
	PendingPacket        = session.PendingPacket
	ConnState            = session.ConnState
	DataHandler          = session.DataHandler
	DataHandlerCallbacks = session.DataHandlerCallbacks
	DataHandlerStats     = session.DataHandlerStats
	PacketRouter         = session.PacketRouter
	FragmentSet          = session.FragmentSet
	// Router is the consumer-facing interface for routing SSU2 packets.
	// *PacketRouter satisfies this interface.
	Router = session.Router
)

// ─── Function re-exports ──────────────────────────────────────────────────────

var (
	NewSSU2Conn     = session.NewSSU2Conn
	NewDataHandler  = session.NewDataHandler
	NewPacketRouter = session.NewPacketRouter
)

// ─── State constant re-exports ────────────────────────────────────────────────

const (
	StateInit        = session.StateInit
	StateHandshaking = session.StateHandshaking
	StateEstablished = session.StateEstablished
	StateClosing     = session.StateClosing
	StateClosed      = session.StateClosed
)
