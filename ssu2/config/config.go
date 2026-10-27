package config

import (
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/ssu2/wire"
)

// SSU2Config contains configuration for creating SSU2 connections and
// listeners. SSU2 (Secure Semi-reliable UDP version 2) is I2P's UDP-based
// transport protocol. It follows the builder pattern for optional
// configuration and validation.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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

	// AllowLoopback, when true, permits loopback addresses (127.0.0.0/8,
	// ::1) for dial and listen operations. By default (true), loopback
	// addresses are permitted for testing and development. In production,
	// explicitly validate addresses before creating configs.
	AllowLoopback bool

	// RouterHash is the local router identity hash
	// Required for SSU2 addressing and session establishment
	RouterHash data.Hash

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// LocalRouterInfo is the local router's serialized RouterInfo, sent in the
	// Session Confirmed message. ssu2.md §"Session Confirmed": "The Session
	// Confirmed message must contain the full signed Router Info".
	//
	// Required for initiator connections (Initiator=true); optional for
	// responders, which are authenticated by the RouterInfo the initiator sent.
	// It MUST contain an SSU2 RouterAddress whose "s" parameter is the static
	// public key derived from StaticKey, or the peer rejects the handshake.
	//
	// There is no fallback to sending a bare RouterHash: ssu2.md requires the
	// full signed RouterInfo, and a hash carries neither the "s" parameter nor a
	// signature, so i2pd and Java both reject it. CreateSessionConfirmed fails
	// with MISSING_LOCAL_ROUTER_INFO when this is empty.
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

	// ObfuscationIV is the 8-byte IV for ChaCha20 obfuscation.
	//
	// Note: this field is currently only length-validated; it is not consumed
	// when building the SSU2 ChaCha20 ephemeral-key obfuscation modifier. Per
	// the SSU2 spec, that obfuscation uses Bob's intro key as the ChaCha20 key
	// with counter position n=1 (no separate IV), so set IntroKey /
	// RemoteIntroKey instead. See createChaChaModifierIfEnabled.
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
	// are discarded by the DataHandler. The SSU2 spec does not prescribe a
	// specific value; 10 seconds matches the Java I2P default.
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
	// packets cannot exhaust resources. 0 means unlimited.
	// Default: 65536.
	MaxSessions int

	// DestroyTimeout is the time to wait after sending a Termination block
	// before releasing session resources. Per spec §Termination, this gives
	// the remote peer time to receive and acknowledge the close.
	// Default: 11 seconds (max RTO per spec). Set to 0 to skip the wait (e.g. in tests).
	DestroyTimeout time.Duration

	// EnableNextNonce enables the NextNonce rekey mechanism (block type
	// 11).
	//
	// WARNING: The SSU2 spec has NOT finalized this block's format or
	// semantics (it is marked "TODO" with size "TBD"). Enabling this risks
	// breaking interoperability with peers that implement a different (or
	// no) rekey protocol.
	//
	// Security trade-off: when disabled (the default), long-lived sessions
	// hold the same send/receive cipher keys for their entire lifetime.
	// Without mid-session key rotation, forward secrecy is not refreshed —
	// an attacker who later compromises the static key can decrypt the
	// entire session retroactively. For a router holding sessions for
	// weeks, this is a real forward-secrecy gap. Nonce exhaustion guards
	// (elsewhere) mitigate the risk of nonce reuse, but forward secrecy is
	// not recovered until the session closes and a new one is established.
	//
	// Default: false (disabled until the spec is finalized).
	EnableNextNonce bool

	// ReplayCacheTTL is the time-to-live for entries in the handshake
	// replay cache. The spec does not mandate a specific value; 4 minutes
	// is a reasonable default for the handshake window.
	// Default: 4 minutes.
	ReplayCacheTTL time.Duration

	// NetworkID is the I2P network ID written into header byte 14 of every
	// long-header SSU2 message (Session Request, Session Created, Retry, Token
	// Request, Peer Test, Hole Punch) and required of inbound ones.
	//
	// ssu2.md §"Header" fixes the value for the main network ("2: SSU 2"), and
	// proposal 147 ("I2P Network ID") defines the mechanism's purpose: a
	// non-matching ID means the peer is on a different network, so the
	// connection must fail fast rather than mix traffic. Test networks publish
	// different values, which is why this is configuration rather than a
	// hardcoded constant — the same reason NTCP2 exposes Config.NetworkID.
	//
	// Zero (the struct-literal default) is treated as the main network, so this
	// field only needs setting for test networks.
	// Default: 2.
	NetworkID uint8

	// MaxClockSkew is the maximum allowed difference between local and
	// remote clocks for handshake timestamp validation.
	//
	// ssu2.rst §"Replay Prevention": "Both Alice and Bob validate that the time
	// for these messages is within a valid skew (recommended +/- 2 minutes). For
	// 'probing resistance', Bob should not reply to Token Request or Session
	// Request messages if the skew is invalid, as these messages may be a replay
	// or probing attack."
	//
	// Default: 120 seconds, i.e. the spec's recommended ±2 minutes.
	// Set to 0 to disable skew validation.
	MaxClockSkew time.Duration

	// ReceiveWindowSize is how many packet numbers the inbound filter tracks
	// for duplicate detection. It is NOT a reordering buffer: ssu2.rst
	// §"Delivery Guarantees" states SSU2 "does NOT provide in-order delivery of
	// I2NP messages", so every non-duplicate packet is delivered on arrival.
	// A larger span detects duplicates further back at the cost of memory.
	// Default: 256. Use 0 for DefaultMaxWindowSize (512).
	ReceiveWindowSize uint

	// RouterInfoValidator is a callback invoked after the handshake
	// completes on the responder side. It receives the raw (already
	// gunzipped) RouterInfo block from SessionConfirmed and the
	// Noise-authenticated static public key.
	//
	// ssu2.md §"Session Confirmed" -> §"Notes" requires the responder to
	// validate the signature type, signature and timestamp of the RouterInfo
	// and to confirm that the static key (s) of an address advertising a
	// matching version (v) equals the key authenticated by the handshake.
	// DefaultRouterInfoValidator performs all of those checks and is the
	// configured default; a custom implementation must do the same.
	// Required for responder configs (Initiator=false).
	RouterInfoValidator func(routerInfo, authenticatedStaticKey []byte) error

	// AllowKeyRotation permits [SSU2Listener.UpdateIdentity] to swap the static key,
	// intro key or IV while the listener is up, which the spec otherwise forbids.
	//
	// ssu2.md §"Public Key and IV Rotation" allows rotation only at startup, after a
	// downtime long enough that peers holding a cached RouterInfo have dropped it
	// ("several days at least", "for example one month" with a published SSU2
	// address, "one day" SSU-only, "as short as two hours" unpublished). Only the
	// router stores the last-shutdown time needed to check that, so a listener that
	// cannot see it refuses the rotation and the caller sets this flag once it has
	// verified the downtime itself. A change of [SSU2Config.RouterHash] — a rekey —
	// is accepted without this flag, as the spec requires new key material on a
	// rekey.
	//
	// Default: false.
	AllowKeyRotation bool

	// SessionTokens stores the tokens this router has *received* from peers in
	// New Token blocks, so a later Session Request can present one instead of
	// doing a Token Request / Retry round trip.
	//
	// ssu2.md §"Session Request": "Token :: 0 if not previously received from
	// Bob", and §"Tokens": "A token sent in a New Token block in an established
	// session may be used in a subsequent connection". Without a store, an
	// initiator can never satisfy the §"Session Establishment" fast path ("when
	// Alice has a valid token previously received from Bob") and every
	// reconnection pays the Token Request/Retry cost.
	//
	// nil disables both saving and presenting. The listener shares one store
	// across the connections it creates.
	// Default: nil.
	SessionTokens *wire.SessionTokenStore

	// TokenIssuer is the cache this router issues tokens from, so a responder
	// can answer a peer's New Token request for a *subsequent* connection
	// (ssu2.md §"Tokens": "They would typically be sent at least once, during or
	// soon after session establishment"). It is the listener's own retry-token
	// cache; issuing a session-lifetime entry there is what makes the token
	// valid when the peer presents it in a later Session Request.
	//
	// nil means this config cannot issue New Token blocks (e.g. a dedicated
	// outbound-only connection). Set by the listener on every conn config.
	// Default: nil.
	TokenIssuer *wire.TokenCache

	// SessionTokenLifetime is how long a token issued in a New Token block
	// stays valid. ssu2.md §"Tokens": "recommended values are several minutes
	// minimum, one or more hours maximum". Zero selects
	// wire.DefaultSessionTokenLifetime.
	// Default: 0 (30 minutes).
	SessionTokenLifetime time.Duration

	// HandshakeTotalTimeout is the budget for the handshake as a whole, shared
	// across every phase (Token Request, Session Request, Session Created,
	// Session Confirmed).
	//
	// ssu2.md §"Handshake Retransmission" -> §"Total Timeout": "Recommended
	// total timeout for the handshake is 20 seconds." It is distinct from
	// HandshakeTimeout, which §"Session Request" sets at "15 seconds total" for
	// that single phase: the phases are sequential, so one 15 s value cannot
	// serve as both. Zero falls back to DefaultHandshakeTotalTimeout.
	// Default: 20 seconds.
	HandshakeTotalTimeout time.Duration

	// MessageQueueSize is the capacity of the inbound message queue for
	// complete reassembled I2NP messages. When the queue is full and a new
	// message is received, the oldest message is dropped with a counter
	// incremented.
	// Default: 100 messages.
	MessageQueueSize int
}
