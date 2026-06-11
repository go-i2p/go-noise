// Package ssu2: path/relay/peertest re-exports from ssu2/path.
// Implementations live in ssu2/path; this file provides
// backward-compatible access from the flat ssu2 package.
//
// AUDIT 6.3: NAT Detection and Reachability State
// ────────────────────────────────────────────────
// All NAT detection, PeerTest management, and reachability state management
// (PeerTestManager, TestResult, NATStatus) is delegated to the external
// github.com/go-i2p/path package (pinned to v0.1.59999). This means:
//
//  1. Errors or panics in path validation code cannot be observed or
//     instrumented from within go-noise.
//  2. A bug in external path detection (e.g., false-positive FIREWALLED state)
//     would be invisible at the go-noise layer.
//  3. NAT state is the single source of truth from go-i2p/path; go-noise does not
//     validate or override it.
//
// If you need to observe NAT state transitions or integrate custom reachability
// logic, you must hook directly into go-i2p/path, not go-noise. This is by design
// to keep the transport layer (go-noise) separate from the routing/path layer.
package ssu2

import path "github.com/go-i2p/path"

// ─── Interface re-exports ──────────────────────────────────────────────────────

type (
	ListenerRef                  = path.ListenerRef
	PathValidationConn           = path.PathValidationConn
	TokenCacheAccessor           = path.TokenCacheAccessor
	CongestionControllerAccessor = path.CongestionControllerAccessor
)

// ─── Type aliases ─────────────────────────────────────────────────────────────

type (
	HolePunchAttempt     = path.HolePunchAttempt
	HolePunchCoordinator = path.HolePunchCoordinator
	HolePunchState       = path.HolePunchState
	IntroducerInfo       = path.IntroducerInfo
	IntroducerRegistry   = path.IntroducerRegistry
	NATType              = path.NATType
	PathChallenge        = path.PathChallenge
	PathChallengeState   = path.PathChallengeState
	PathValidator        = path.PathValidator
	PeerTest             = path.PeerTest
	PeerTestBlock        = path.PeerTestBlock
	PeerTestManager      = path.PeerTestManager
	PeerTestMessageCode  = path.PeerTestMessageCode
	PeerTestRole         = path.PeerTestRole
	PeerTestState        = path.PeerTestState
	PendingSession       = path.PendingSession
	RegisteredIntroducer = path.RegisteredIntroducer
	RelayIntroBlock      = path.RelayIntroBlock
	RelayManager         = path.RelayManager
	RelayRequestBlock    = path.RelayRequestBlock
	RelayResponseBlock   = path.RelayResponseBlock
	RelayTag             = path.RelayTag
	RelayTagBlock        = path.RelayTagBlock
	RelayTagRequestBlock = path.RelayTagRequestBlock
	TestResult           = path.TestResult
)

// ─── NAT type constants ────────────────────────────────────────────────────────

const (
	NATUnknown        = path.NATUnknown
	NATNone           = path.NATNone
	NATCone           = path.NATCone
	NATRestricted     = path.NATRestricted
	NATPortRestricted = path.NATPortRestricted
	NATSymmetric      = path.NATSymmetric
)

// ─── HolePunch state constants ─────────────────────────────────────────────────

const (
	HolePunchRequested = path.HolePunchRequested
	HolePunchSent      = path.HolePunchSent
	HolePunchWaiting   = path.HolePunchWaiting
	HolePunchSuccess   = path.HolePunchSuccess
	HolePunchFailed    = path.HolePunchFailed
)

// ─── PathChallenge state constants ────────────────────────────────────────────

const (
	ChallengeSent      = path.ChallengeSent
	ChallengeReceived  = path.ChallengeReceived
	ChallengeValidated = path.ChallengeValidated
	ChallengeFailed    = path.ChallengeFailed
)

// ─── PeerTest message code constants ──────────────────────────────────────────

const (
	PeerTestRequest      = path.PeerTestRequest
	PeerTestRelay        = path.PeerTestRelay
	PeerTestResponse     = path.PeerTestResponse
	PeerTestResult       = path.PeerTestResult
	PeerTestProbe        = path.PeerTestProbe
	PeerTestReply        = path.PeerTestReply
	PeerTestConfirmation = path.PeerTestConfirmation
)

// ─── PeerTest role constants ───────────────────────────────────────────────────

const (
	RoleInitiator = path.RoleInitiator
	RoleRelay     = path.RoleRelay
	RoleResponder = path.RoleResponder
)

// ─── PeerTest state constants ──────────────────────────────────────────────────

const (
	TestRequested = path.TestRequested
	TestRelayed   = path.TestRelayed
	TestProbed    = path.TestProbed
	TestComplete  = path.TestComplete
	TestFailed    = path.TestFailed
)

// ─── Validation / MTU / relay constants ───────────────────────────────────────

const (
	PathValidationTimeout  = path.PathValidationTimeout
	MinMTU                 = path.MinMTU
	RelayRequestPrologue   = path.RelayRequestPrologue
	PeerTestPrologue       = path.PeerTestPrologue
	RelayAgreementPrologue = path.RelayAgreementPrologue
)

// ─── Function re-exports ───────────────────────────────────────────────────────

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
