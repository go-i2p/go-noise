package ssu2

import "github.com/go-i2p/go-noise/ssu2/reliability"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	ACKHandler           = reliability.ACKHandler
	CongestionController = reliability.CongestionController
	CongestionState      = reliability.CongestionState
	CongestionStats      = reliability.CongestionStats
	PendingACK           = reliability.PendingACK
	RTTEstimator         = reliability.RTTEstimator
	ReceiveWindow        = reliability.ReceiveWindow
)

// ─── Congestion flag constants ────────────────────────────────────────────────

const (
	CongestionFlagRequestACK = reliability.CongestionFlagRequestACK
	CongestionFlagECN        = reliability.CongestionFlagECN
)

// ─── Congestion window constants ──────────────────────────────────────────────

const (
	MinCongestionWindow     = reliability.MinCongestionWindow
	InitialCongestionWindow = reliability.InitialCongestionWindow
	MaxCongestionWindow     = reliability.MaxCongestionWindow
)

// ─── Congestion state constants ───────────────────────────────────────────────

const (
	SlowStart           = reliability.SlowStart
	CongestionAvoidance = reliability.CongestionAvoidance
	Recovery            = reliability.Recovery
)

// ─── Window / packet number constants ─────────────────────────────────────────

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

// ─── Function re-exports ───────────────────────────────────────────────────────

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

// ─── Keepalive type aliases ───────────────────────────────────────────────────

type (
	SendReceiver     = reliability.SendReceiver
	KeepaliveManager = reliability.KeepaliveManager
)

// ─── Keepalive constructor ────────────────────────────────────────────────────

var NewKeepaliveManager = reliability.NewKeepaliveManager
