package config

import (
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/internal/baseconfig"
)

// SSU2Config contains configuration for creating SSU2 connections and listeners.
// SSU2 (Secure Semi-reliable UDP version 2) is I2P's UDP-based transport protocol.
// It follows the builder pattern for optional configuration and validation.
type SSU2Config struct {
	// BaseHandshakeConfig embeds the shared timeout, retry, and modifier fields
	// common to all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern for SSU2
	// Default: "XK" (standard SSU2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// AllowLoopback, when true, permits loopback addresses (127.0.0.0/8, ::1)
	// for dial and listen operations. By default (true), loopback addresses
	// are permitted for testing and development. In production, explicitly
	// validate addresses before creating configs.
	// AUDIT 7.2 — Address validation.
	AllowLoopback bool

	// RouterHash is the local router identity hash
	// Required for SSU2 addressing and session establishment
	RouterHash data.Hash

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// LocalRouterInfo is the local router's RouterInfo to transmit during the SSU2
	// handshake (SessionConfirmed message for initiators). This RouterInfo MUST contain
	// an SSU2 RouterAddress with the "s" parameter set to the static public key derived
	// from StaticKey, otherwise the peer will reject the handshake.
	// Required for initiator connections (Initiator=true); optional for responders.
	// If nil or empty, the connection will transmit RouterHash instead (legacy behavior,
	// incompatible with strict static key verification).
	LocalRouterInfo []byte

	// RemoteRouterHash is the remote peer's router identity hash
	// Used for identity verification, optional for listeners
	RemoteRouterHash *data.Hash

	// RemoteStaticKey is the remote peer's X25519 static public key (32 bytes).
	// Required for initiator connections (XK pattern requires pre-knowledge of
	// the responder's static key). This is NOT the router hash — it is the "s"
	// parameter from the peer's RouterAddress options.
	RemoteStaticKey []byte

	// EnableChaChaObfuscation enables ChaCha20-based ephemeral key obfuscation
	// Default: true (recommended for production)
	EnableChaChaObfuscation bool

	// ObfuscationIV is the 8-byte IV for ChaCha20 obfuscation
	// If nil, will be derived from router hash (recommended)
	ObfuscationIV []byte

	// MTU is the Maximum Transmission Unit for UDP packets
	// Default: 1280 bytes (IPv6 minimum MTU)
	// Range: 1280-1500 bytes
	MTU int

	// MaxPacketSize is the maximum UDP packet size to send/receive
	// Default: 1500 bytes (typical Ethernet MTU)
	MaxPacketSize int

	// EnableFragmentation allows splitting large messages across multiple packets
	// Default: false (handle at SSU2 layer)
	EnableFragmentation bool

	// PaddingEnabled enables random padding in SSU2 frames
	// Default: true (recommended for traffic analysis resistance)
	PaddingEnabled bool

	// MinPaddingSize is the minimum padding size for frames
	// Default: 0 bytes
	MinPaddingSize int

	// MaxPaddingSize is the maximum padding size for frames
	// Default: 64 bytes
	MaxPaddingSize int

	// PaddingRatio is the padding amount as ratio of data size
	// Valid range: 0.0 to 15.9375 (I2P specification)
	// Default: 1.0 (100% of data size)
	PaddingRatio float64

	// ConnectionID is the 8-byte SSU2 connection identifier
	// If 0, will be generated randomly
	ConnectionID uint64

	// KeepaliveInterval is the time between keepalive packets
	// UDP requires active keepalive to maintain connection state
	// Default: 15 seconds
	KeepaliveInterval time.Duration

	// IntroKey is the local router's intro key for header protection (32 bytes).
	// If nil, header protection is disabled (headers sent in plaintext).
	IntroKey []byte

	// RemoteIntroKey is the remote peer's intro key for header protection (32 bytes).
	// Required for initiator when IntroKey is set; optional for responder.
	RemoteIntroKey []byte

	// InitiatorConnectionID is the initiator's source connection ID, used by
	// the responder to construct the Noise prologue for handshake binding.
	// Set by the listener when creating a responder connection.
	InitiatorConnectionID uint64

	// RequireRetry, when true, causes the listener to send a Retry message
	// in response to SessionRequest packets that do not carry a valid token.
	// This implements SSU2 source-address validation: the responder sends
	// Retry with a token, and the initiator must resend SessionRequest
	// including that token before the handshake proceeds.
	// Default: false (accept SessionRequest without token)
	RequireRetry bool

	// IdleTimeout is the maximum duration without activity before the
	// connection is closed. The spec does not mandate a specific value.
	// Default: 5 minutes.
	IdleTimeout time.Duration

	// FragmentTimeout is the duration after which incomplete fragment sets
	// are discarded by the DataHandler. The SSU2 spec does not prescribe
	// a specific value; 10 seconds matches the Java I2P default (M-4).
	// Default: 10 seconds.
	FragmentTimeout time.Duration

	// TokenCacheMaxSize is the maximum number of retry tokens the listener
	// will cache. Under high connection rates, a small cache can evict
	// legitimate tokens before use.
	// Default: 10000.
	TokenCacheMaxSize int

	// GlobalTokenIssuanceRate caps the total number of retry tokens the
	// listener will issue per second across ALL source addresses. This
	// backstops the per-IP rate limiter so that a UDP-spoofing attacker
	// who fans out across many source addresses still cannot amplify
	// issuance beyond the configured rate.
	// Default: 40 tokens/sec.
	// Set to 0 to disable token issuance entirely (listener will refuse
	// all Retry/TokenRequest flows). Set to a very large value to
	// effectively disable the cap.
	GlobalTokenIssuanceRate float64

	// GlobalTokenIssuanceBurst is the burst capacity of the global token
	// issuance bucket. Short spikes up to this many tokens can be issued
	// instantaneously before rate limiting applies.
	// Default: max(GlobalTokenIssuanceRate, 80). Ignored when
	// GlobalTokenIssuanceRate == 0.
	GlobalTokenIssuanceBurst float64

	// FirstSightRequired, when true, causes the listener to decline the
	// first TokenRequest from a previously-unseen source address and
	// record the sighting in a cheap, bounded tracker. A token is only
	// issued on the second (or subsequent) TokenRequest from the same
	// address within FirstSightWindow. SSU2 clients already retry
	// TokenRequests with backoff per spec, so legitimate peers recover
	// transparently on the next retry.
	// This defends against off-path spoofed-source token-cache
	// exhaustion: an attacker pays two packets per spoofed address
	// instead of one, and the first-sight tracker entries are smaller
	// than full Token cache entries and live in a separate bounded map.
	// Default: true.
	FirstSightRequired bool

	// FirstSightWindow is the time a first-sight record stays fresh. A
	// peer that re-contacts within this window will be granted a token
	// (subject to other limits). Older entries are treated as first evicted.
	// Default: 30 seconds.
	FirstSightWindow time.Duration

	// FirstSightMaxEntries bounds the memory held by the first-sight
	// tracker. When full, the oldest sighting is evicted.
	// Default: 50000.
	FirstSightMaxEntries int

	// MaxSessions bounds the number of concurrently-registered inbound
	// sessions a listener will hold. Once reached, new inbound handshakes
	// are refused until existing sessions close. This caps the listener's
	// session-map and per-session goroutine memory so a flood of handshake
	// packets cannot exhaust resources (AUDIT 8.2). 0 means unlimited.
	// Default: 65536.
	MaxSessions int

	// DestroyTimeout is the time to wait after sending a Termination block
	// before releasing session resources. Per spec §Termination, this gives
	// the remote peer time to receive and acknowledge the close.
	// Default: 11 seconds (max RTO per spec). Set to 0 to skip the wait (e.g. in tests).
	DestroyTimeout time.Duration

	// EnableNextNonce enables the NextNonce rekey mechanism (block type 11).
	// WARNING: The SSU2 spec has NOT finalized this block's format or
	// semantics (marked "TODO" with size "TBD"). Enabling this risks
	// breaking interoperability with peers that implement a different
	// (or no) rekey protocol.
	//
	// SECURITY TRADE-OFF: When disabled (default), long-lived sessions hold
	// the same send/receive cipher keys for their entire lifetime. Without
	// mid-session key rotation, forward secrecy is not refreshed — an attacker
	// who later compromises the static key can decrypt the entire session
	// retroactively. For a router holding sessions for weeks, this is a real
	// forward-secrecy gap. Nonce exhaustion guards (elsewhere) mitigate the
	// risk of nonce reuse, but forward secrecy is not recovered until the
	// session closes and a new one is established.
	//
	// Default: false (disabled until spec is finalized) (M-2).
	EnableNextNonce bool

	// ReplayCacheTTL is the time-to-live for entries in the handshake replay
	// cache. The spec does not mandate a specific value; 4 minutes is a
	// reasonable default for the handshake window.
	// Default: 4 minutes (M-2).
	ReplayCacheTTL time.Duration

	// MaxClockSkew is the maximum allowed difference between local and
	// remote clocks for handshake timestamp validation (G-1). Per the SSU2
	// spec, the receiver should verify that the DateTime block timestamp is
	// within a certain window of local time.
	// Default: 120 seconds. Set to 0 to disable skew validation.
	MaxClockSkew time.Duration

	// ReceiveWindowSize is the maximum number of out-of-order packets
	// buffered by the receive window. Larger values improve throughput
	// on lossy links at the cost of memory (M-3).
	// Default: 256. Use 0 for DefaultMaxWindowSize (512).
	ReceiveWindowSize uint

	// RouterInfoValidator is a callback invoked after the handshake
	// completes on the responder side. It receives the raw RouterInfo block
	// from SessionConfirmed and the Noise-authenticated static public key.
	// The validator MUST verify that the RouterInfo's identity key corresponds
	// to the static key authenticated by the Noise handshake (C-2).
	// Required for responder configs (Initiator=false); use
	// DefaultRouterInfoValidator or provide a custom implementation.
	RouterInfoValidator func(routerInfo, authenticatedStaticKey []byte) error
}
