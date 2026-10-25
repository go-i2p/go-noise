package ntcp2

import (
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/internal/securemem"
	internalvalidation "github.com/go-i2p/go-noise/internal/validation"
	"github.com/go-i2p/go-noise/mod/validation"
	"github.com/go-i2p/logger"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// DefaultHandshakeTimeoutSeconds is the default handshake timeout, in seconds.
// A handshake that takes longer than this is aborted.
const DefaultHandshakeTimeoutSeconds = 30

// DefaultHandshakeRetries is the default number of times a failed handshake
// is retried before giving up.
const DefaultHandshakeRetries = 3

// Config holds all the settings for creating NTCP2 connections and listeners.
//
// Use NewNTCP2Config to create a Config with sensible defaults, then adjust
// the fields you care about with the With* methods. Call Validate before
// using the config to catch mistakes early.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
type Config struct {
	// BaseHandshakeConfig holds the shared timeout, retry, and modifier
	// settings used by all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern to use.
	// NTCP2 always uses "XK".
	Pattern string

	// Initiator is true when this side starts the handshake.
	// Listeners are always the responder, so this is false for them.
	Initiator bool

	// BobRouterHash is the responder's router hash (RH_B in the spec).
	// Both sides use this hash as the AES key that hides the ephemeral
	// (one-time) keys sent in the clear during the handshake.
	// A responder sets its own router hash here; an initiator sets the
	// remote peer's router hash.
	BobRouterHash data.Hash

	// StaticKey is this peer's long-term Curve25519 private key (32 bytes).
	// It is used in the Noise XK handshake's Diffie-Hellman steps to derive
	// the session keys and to authenticate this side to the peer.
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity hash.
	// Required for outbound connections, optional for listeners.
	RemoteRouterHash *data.Hash

	// RemoteStaticKey is the remote peer's Curve25519 static public key
	// (32 bytes). The XK pattern requires the initiator to already know
	// the responder's static key, so this is required for outbound
	// connections.
	//
	// This is different from RemoteRouterHash: the router hash is the
	// SHA-256 of the peer's RouterIdentity, while the static key is a
	// Curve25519 public key.
	RemoteStaticKey []byte

	// EnableAESObfuscation turns on AES obfuscation of the cleartext
	// ephemeral keys in handshake messages 1 and 2.
	// Enabled by default.
	EnableAESObfuscation bool

	// ObfuscationIV is the 16-byte initialization vector (IV) for the AES
	// obfuscation. Per the NTCP2 spec it must be Bob's IV "as published in
	// Bob's network database entry" (the "i=" option); there is no valid
	// fallback. If it is nil when AES obfuscation is enabled, ToConnConfig
	// fails with MISSING_OBFUSCATION_IV.
	ObfuscationIV []byte

	// EnableSipHashLength turns on SipHash obfuscation of the two-byte
	// frame length field in the data phase.
	// Enabled by default.
	EnableSipHashLength bool

	// SipHashKeys are the two SipHash keys (k1 and k2) used to obfuscate
	// frame lengths. If left empty, they are derived from the session
	// keys during the handshake.
	SipHashKeys [2]uint64

	// MaxFrameSize is the largest NTCP2 data frame this side will send,
	// in bytes. Default: 16384 (16 KB).
	MaxFrameSize int

	// FramePaddingEnabled adds random padding to data frames. Padding
	// makes frame sizes less predictable, which helps against traffic
	// analysis. Enabled by default.
	FramePaddingEnabled bool

	// MinPaddingSize is the smallest amount of padding added to a frame,
	// in bytes. Default: 0.
	MinPaddingSize int

	// MaxPaddingSize is the largest amount of padding added to a frame,
	// in bytes. Default: 64.
	MaxPaddingSize int

	// LocalRouterInfo is this peer's serialized RouterInfo bytes.
	// Required for outbound connections: its length is written into the
	// m3p2Len field of message 1, and the bytes themselves are sent as
	// the encrypted payload of message 3 part 2.
	LocalRouterInfo []byte

	// StrictRouterInfoVerification is kept only for backward
	// compatibility.
	//
	// Deprecated: the local RouterInfo / static-key match is now ALWAYS
	// enforced as a hard error during the initiator handshake, regardless
	// of this field's value. It no longer has any effect. The check is a
	// no-op when no static key or no LocalRouterInfo is configured, so it
	// never fires on partially-configured connections.
	StrictRouterInfoVerification bool

	// sipHashModifier stores the SipHash modifier created during
	// ToConnConfig() so it can be passed to NTCP2Conn for data-phase
	// framing.
	// Access is via atomic.Pointer to avoid data races between the
	// PostHandshakeHook goroutine and SipHashModifier() callers.
	sipHashModifier atomic.Pointer[SipHashLengthModifier]

	// ReplayDetector checks for replayed ephemeral keys during handshakes.
	//
	// Leave it nil to use the shared process-wide default cache; replay
	// protection is never disabled, because ntcp2.rst §"Session Request" makes
	// the duplicate-handshake-value cache mandatory. Set it to a cache you own
	// (see NewReplayCacheWithTTL) to scope entries per listener and to control
	// its lifetime via Close().
	//
	// Shared across all responder connections using this config (typically
	// instantiated once per listener). Initiator connections ignore this field.
	ReplayDetector ReplayDetector

	// AllowReuseAddress, when true, enables the SO_REUSEADDR socket
	// option for ListenNTCP2. This reduces restart-race delay by allowing
	// quick rebinding to the same address after shutdown. Use with caution
	// in production as it can allow stale packets from previous
	// incarnations to be delivered.
	// Default: false (conservative, matches net.Listen behavior).
	AllowReuseAddress bool

	// NetworkID is the I2P network ID written into the "id" field of the
	// message 1 options block and required of inbound message 1s. The main
	// network value is 2; test networks use different values so that
	// cross-network connections fail fast, per proposal 147.
	//
	// Zero (the struct-literal default) is treated as the main network, so this
	// field only needs setting for test networks. See networkID.
	// Default: 2.
	NetworkID uint8

	// MaxClockSkew is the largest tolerated difference between the local clock
	// and the tsA/tsB timestamps in handshake messages 1 and 2. The spec's
	// Clock Skew Guidelines section says a skew beyond +/- 60 seconds "is
	// generally fatal".
	//
	// Zero (the struct-literal default) selects ClockSkewTolerance so timestamp
	// validation is enabled for every configuration; set a negative value to
	// disable it. See maxClockSkew.
	// Default: ClockSkewTolerance (60 seconds).
	MaxClockSkew time.Duration

	// peerTimestampSecs and msg1ReceivedAt are per-connection scratch state
	// captured by the responder during message 1, for the mandatory post-
	// SessionConfirmed clock-skew recheck.
	//
	// ntcp2.md §"Clock Skew Guidelines": "If Alice does reply with Session
	// Confirmed ... Bob should adjust the calculated clock skew by subtracting
	// half the RTT. If the adjusted clock skew exceeds the maximum, Bob should
	// then reply with a Disconnect message containing a clock skew reason code,
	// and close the connection." Reference: Java InboundEstablishState.verifyInbound()
	// (net/i2p/router/transport/ntcp/InboundEstablishState.java:218-246,
	// `_peerSkew -= ((rtt / 2) + 500) / 1000` then REASON_SKEW).
	//
	// Not exported and not copied by Clone(): each accepted connection gets a
	// fresh clone, so these fields are written and read only by that
	// connection's handshake goroutine.
	peerTimestampSecs uint64
	msg1ReceivedAt    time.Time
	msg3ReceivedAt    time.Time
}

// NewNTCP2Config creates a new Config with sensible defaults.
//
// bobRouterHash is the responder's router hash (RH_B in the spec). Both
// sides use it as the AES key for ephemeral key obfuscation, so a
// responder passes its own router hash and an initiator passes the remote
// peer's router hash.
//
// initiator is true when this connection will start the handshake.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func NewNTCP2Config(bobRouterHash data.Hash, initiator bool) (*Config, error) {
	flog("NewNTCP2Config", logger.Fields{"initiator": initiator}).Debug("Creating new NTCP2Config")
	return &Config{
		Pattern:       NTCP2Pattern,
		Initiator:     initiator,
		BobRouterHash: bobRouterHash,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: DefaultHandshakeTimeoutSeconds * time.Second,
			ReadTimeout:      0,
			WriteTimeout:     0,
			HandshakeRetries: DefaultHandshakeRetries,
			RetryBackoff:     1 * time.Second,
		},
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		MaxFrameSize:         DefaultMaxFrameSize,
		FramePaddingEnabled:  true,
		MinPaddingSize:       0,
		MaxPaddingSize:       DefaultMaxPaddingSize,
		NetworkID:            ntcp2NetID,
		MaxClockSkew:         ClockSkewTolerance,
	}, nil
}

// networkID returns the network ID for this configuration, falling back to the
// main-network value when the field is unset. Both the options-block writer and
// the inbound validator go through this accessor so they can never disagree
// about which value is expected, including for configs built as struct literals
// rather than with NewNTCP2Config.
func (nc *Config) networkID() uint8 {
	if nc == nil || nc.NetworkID == 0 {
		return ntcp2NetID
	}
	return nc.NetworkID
}

// maxClockSkew returns the clock-skew tolerance applied to the tsA/tsB
// handshake timestamps. An unset (zero) field selects the spec's 60-second
// guidance so that timestamp validation is on by default for every config,
// including struct literals. Set it to a negative value to disable validation.
func (nc *Config) maxClockSkew() time.Duration {
	if nc == nil || nc.MaxClockSkew == 0 {
		return ClockSkewTolerance
	}
	if nc.MaxClockSkew < 0 {
		return 0
	}
	return nc.MaxClockSkew
}

// WithNetworkID sets the I2P network ID written into, and required of, the
// message 1 options block. Use the main-network default of 2 unless operating a
// test network.
func (nc *Config) WithNetworkID(id uint8) *Config {
	nc.NetworkID = id
	return nc
}

// WithMaxClockSkew sets the tolerated difference between the local clock and the
// peer's handshake timestamps. Zero selects the 60-second default; a negative
// value disables timestamp validation.
func (nc *Config) WithMaxClockSkew(d time.Duration) *Config {
	nc.MaxClockSkew = d
	return nc
}

// WithPattern sets the Noise protocol pattern.
// NTCP2 always uses "XK", so this should normally be left alone.
func (nc *Config) WithPattern(pattern string) *Config {
	nc.Pattern = pattern
	return nc
}

// copyKeyBytes makes a copy of a key byte slice, or returns nil if key is nil/empty.
// This is the canonical way to defensively copy security-sensitive key material
// during configuration cloning and builder-pattern operations.
func copyKeyBytes(key []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	dst := make([]byte, len(key))
	copy(dst, key)
	return dst
}

// WithStaticKey sets this peer's long-term Curve25519 key.
// key must be 32 bytes. Keys of any other length are silently ignored,
// so call Validate() to check all fields before use.
func (nc *Config) WithStaticKey(key []byte) *Config {
	if len(key) == StaticKeySize {
		nc.StaticKey = copyKeyBytes(key)
	}
	return nc
}

// WithRemoteRouterHash sets the remote peer's router identity hash.
// Required for outbound connections.
func (nc *Config) WithRemoteRouterHash(hash data.Hash) *Config {
	nc.RemoteRouterHash = &hash
	return nc
}

// WithRemoteStaticKey sets the remote peer's Curve25519 static public key.
// key must be exactly 32 bytes; other lengths are silently ignored, so
// call Validate() to check all fields before use.
//
// The XK pattern requires the initiator to already know the responder's
// static key, so this is required for outbound connections. It is a
// different value from RemoteRouterHash, which is the SHA-256 of the
// peer's RouterIdentity.
func (nc *Config) WithRemoteStaticKey(key []byte) *Config {
	if len(key) == StaticKeySize {
		nc.RemoteStaticKey = copyKeyBytes(key)
	}
	return nc
}

// WithHandshakeTimeout sets how long a handshake may take before it is
// aborted.
func (nc *Config) WithHandshakeTimeout(timeout time.Duration) *Config {
	baseconfig.SetHandshakeTimeout(&nc.BaseHandshakeConfig, timeout)
	return nc
}

// WithReadTimeout sets how long a read may take after the handshake is
// done. A zero value means no timeout.
func (nc *Config) WithReadTimeout(timeout time.Duration) *Config {
	baseconfig.SetReadTimeout(&nc.BaseHandshakeConfig, timeout)
	return nc
}

// WithWriteTimeout sets how long a write may take after the handshake is
// done. A zero value means no timeout.
func (nc *Config) WithWriteTimeout(timeout time.Duration) *Config {
	baseconfig.SetWriteTimeout(&nc.BaseHandshakeConfig, timeout)
	return nc
}

// WithHandshakeRetries sets how many times a failed handshake is retried.
// Use 0 for no retries, or -1 to retry forever.
func (nc *Config) WithHandshakeRetries(retries int) *Config {
	baseconfig.SetHandshakeRetries(&nc.BaseHandshakeConfig, retries)
	return nc
}

// WithRetryBackoff sets the base delay between handshake retry attempts.
// The delay grows with each attempt.
func (nc *Config) WithRetryBackoff(backoff time.Duration) *Config {
	baseconfig.SetRetryBackoff(&nc.BaseHandshakeConfig, backoff)
	return nc
}

// WithAESObfuscation enables or disables the AES obfuscation of the
// cleartext ephemeral keys in handshake messages 1 and 2.
//
// When enabled with a custom IV, the IV must be exactly 16 bytes; other
// lengths are silently ignored, so call Validate() to check all fields
// before use.
//
// Note: options negotiation (padding limits, dummy traffic, delay
// parameters) is handled by the higher-level router transport, not here.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Config) WithAESObfuscation(enabled bool, customIV []byte) *Config {
	nc.EnableAESObfuscation = enabled
	if len(customIV) == IVSize {
		nc.ObfuscationIV = make([]byte, IVSize)
		copy(nc.ObfuscationIV, customIV)
	}
	return nc
}

// WithSipHashLength enables or disables SipHash obfuscation of the
// two-byte frame length field in the data phase.
//
// When enabled, a custom key pair is stored only if at least one of k1 or
// k2 is non-zero (the other is then stored as given, including 0). If both
// are zero, the keys are derived from the session keys during the handshake.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Config) WithSipHashLength(enabled bool, k1, k2 uint64) *Config {
	nc.EnableSipHashLength = enabled
	if enabled && (k1 != 0 || k2 != 0) {
		nc.SipHashKeys[0] = k1
		nc.SipHashKeys[1] = k2
	}
	return nc
}

// WithModifiers sets extra handshake modifiers for custom obfuscation,
// replacing any previously set via this method (it does not accumulate
// across calls). At ToConnConfig time these custom modifiers are appended
// after NTCP2's standard modifiers (AES obfuscation, SipHash length,
// padding), so on the outbound path they run last, and on the inbound path
// (which applies the chain in reverse) they run first.
func (nc *Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *Config {
	// Make defensive copy
	nc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(nc.Modifiers, modifiers)
	return nc
}

// WithLocalRouterInfo sets this peer's serialized RouterInfo bytes for
// outbound connections. The length is written into the m3p2Len field of
// message 1, and the bytes are encrypted and sent as message 3 part 2.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Config) WithLocalRouterInfo(ri []byte) *Config {
	if len(ri) > 0 {
		nc.LocalRouterInfo = make([]byte, len(ri))
		copy(nc.LocalRouterInfo, ri)
	}
	return nc
}

// WithStrictRouterInfoVerification is kept only for backward
// compatibility.
//
// Deprecated: the local RouterInfo / static-key match is now always
// enforced as a hard error during the initiator handshake, so this
// builder does nothing. It still sets the (now-unused) field to avoid
// breaking callers that still invoke it.
func (nc *Config) WithStrictRouterInfoVerification(strict bool) *Config {
	nc.StrictRouterInfoVerification = strict
	return nc
}

// WithReplayDetector sets the replay detector used by responder
// handshakes. A replay detector remembers the ephemeral keys it has seen
// and rejects handshakes that reuse one, which stops an attacker from
// replaying a captured handshake.
//
// If nil, replay detection is disabled (not recommended for production).
// The detector is shared across all responder connections that use this
// config, so create one per listener. Initiator connections ignore this
// field.
func (nc *Config) WithReplayDetector(detector ReplayDetector) *Config {
	nc.ReplayDetector = detector
	return nc
}

// WithReuseAddress enables the SO_REUSEADDR socket option for
// ListenNTCP2 listener binding.
//
// When enabled, the listener can quickly rebind to the same port after
// shutdown, which shortens the delay before a restarted router can accept
// connections again. Default is false (conservative).
//
// Use with caution: stale packets from a previous socket instance may
// still arrive.
func (nc *Config) WithReuseAddress(allow bool) *Config {
	nc.AllowReuseAddress = allow
	return nc
}

// WithFrameSettings configures NTCP2 data frame handling in one call.
//
//   - maxSize: the largest frame this side will send (default: 16384
//     bytes).
//   - paddingEnabled: whether to add random padding to frames (default:
//     true).
//   - minPadding, maxPadding: the padding size range in bytes (default:
//     0-64).
func (nc *Config) WithFrameSettings(maxSize int, paddingEnabled bool, minPadding, maxPadding int) *Config {
	if maxSize > 0 {
		nc.MaxFrameSize = maxSize
	}
	nc.FramePaddingEnabled = paddingEnabled
	if minPadding >= 0 {
		nc.MinPaddingSize = minPadding
	}
	if maxPadding >= minPadding {
		nc.MaxPaddingSize = maxPadding
	}
	return nc
}

// Validate checks that the configuration is valid for NTCP2.
// Call it before creating connections or listeners to catch mistakes
// early.
func (nc *Config) Validate() error {
	return validation.RunValidators(
		nc.validateCoreConfiguration,
		// Inline timeout configuration validation; see BaseHandshakeConfig documentation.
		func() error {
			return validation.ValidateTransportConfig(nc.HandshakeTimeout, nc.HandshakeRetries, nc.RetryBackoff, "ntcp2")
		},
		nc.validateFrameConfiguration,
		nc.validateModifiers,
	)
}

// validateCoreConfiguration checks pattern and cryptographic/session parameters.
func (nc *Config) validateCoreConfiguration() error {
	flog("NTCP2Config.validateCoreConfiguration").Debug("Validating NTCP2 core configuration")
	if err := validation.ValidatePattern(nc.Pattern, "ntcp2"); err != nil {
		return err
	}

	// BobRouterHash validation is implicit via data.Hash type (always 32 bytes).

	if err := validation.ValidateKeyLength(nc.StaticKey, "static key", "ntcp2"); err != nil {
		return err
	}

	// For initiator connections, remote router hash is required
	if nc.Initiator && nc.RemoteRouterHash == nil {
		return oops.
			Code("MISSING_REMOTE_ROUTER_HASH").
			In("ntcp2").
			Errorf("remote router hash is required for initiator connections")
	}

	if err := validation.ValidateKeyLength(nc.RemoteStaticKey, "remote static key", "ntcp2"); err != nil {
		return err
	}

	// For initiator XK connections, remote static key is required (pre-message: ← s)
	if nc.Initiator && nc.Pattern == NTCP2Pattern && len(nc.RemoteStaticKey) == 0 {
		return oops.
			Code("MISSING_REMOTE_STATIC_KEY").
			In("ntcp2").
			Errorf("remote static key is required for initiator XK connections (pre-message: ← s)")
	}

	// Validate LocalRouterInfo size to prevent uint16 overflow in m3p2Len
	// m3p2Len = BlockHeaderSize (3) + flag (1) + len(riBytes)
	//         + BlockHeaderSize (3) + msg3OptionsSize (12)
	//         + Poly1305Overhead (16)
	// Maximum safe size: 65535 - 35 = 65500 bytes.
	// ntcp2.md §"3) SessionConfirmed" Notes: the message 3 part 2 frame carries
	// the RouterInfo block and the (recommended) Options block; §"Options"
	// fixes the options data at "12 bytes minimum".
	// Reference: Java i2p.i2p OutboundNTCP2State.java:416-418 (prepareOutbound3)
	// adds BLOCK_HEADER_SIZE + OPTIONS3_SIZE for the Options block.
	const maxRouterInfoSize = 0xFFFF - (BlockHeaderSize + 1 + BlockHeaderSize + msg3OptionsSize + Poly1305Overhead)
	if len(nc.LocalRouterInfo) > maxRouterInfoSize {
		return oops.
			Code("ROUTER_INFO_TOO_LARGE").
			In("ntcp2").
			With("router_info_size", len(nc.LocalRouterInfo)).
			With("max_size", maxRouterInfoSize).
			Errorf("LocalRouterInfo too large for NTCP2 message 3 part 2 (max %d bytes)", maxRouterInfoSize)
	}

	// Validate AES obfuscation IV if provided
	if nc.ObfuscationIV != nil && len(nc.ObfuscationIV) != IVSize {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ntcp2").
			With("iv_length", len(nc.ObfuscationIV)).
			Errorf("obfuscation IV must be %d bytes", IVSize)
	}

	return nil
}

// validateFrameConfiguration checks frame size and padding settings.
func (nc *Config) validateFrameConfiguration() error {
	flog("NTCP2Config.validateFrameConfiguration").Debug("Validating NTCP2 frame configuration")
	// Validate frame settings
	if nc.MaxFrameSize <= 0 {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			Errorf("max frame size must be positive")
	}

	// Minimum frame size must accommodate at least one I2NP block header plus AEAD tag
	// to prevent arithmetic underflow in writeFramed: maxPlaintext = MaxFrameSize - Poly1305Overhead
	const minAllowedFrameSize = MinDataPhaseFrameSize + Poly1305Overhead
	comparison := internalvalidation.CompareIntRange(nc.MaxFrameSize, minAllowedFrameSize, SpecMaxFrameSize)
	if comparison == internalvalidation.BelowRange {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			With("min_allowed", minAllowedFrameSize).
			Errorf("max frame size %d is too small (minimum %d bytes required for I2NP block header + AEAD tag)", nc.MaxFrameSize, minAllowedFrameSize)
	}

	if comparison == internalvalidation.AboveRange {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			With("spec_max", SpecMaxFrameSize).
			Errorf("max frame size %d exceeds spec maximum %d", nc.MaxFrameSize, SpecMaxFrameSize)
	}

	// Delegate to the stricter ValidatePaddingParams (same gate used by
	// createPaddingModifierIfEnabled/ToConnConfig) so an invalid padding
	// config is rejected here rather than passing Validate() and only
	// failing later at ToConnConfig() with a different error code.
	if err := handshake.ValidatePaddingParams("ntcp2", nc.MinPaddingSize, nc.MaxPaddingSize, 0.0); err != nil {
		return err
	}

	return nil
}

// validateModifiers rejects modifiers that cannot be used with NTCP2.
//
// The two non-conformant generic modifiers this guard used to reject by type -
// handshake.XORModifier and handshake.GenericPaddingModifier - have been deleted
// from the codebase rather than merely refused here, because no I2P specification
// defines either of them:
//
//   - XORModifier XOR'd the entire handshake message with a repeating static key.
//     ntcp2.md §"Additions to the Framework" enumerates exactly five NTCP2
//     extensions (AES obfuscation of the ephemeral key, cleartext/AEAD padding,
//     the two-byte frame length, SipHash length obfuscation, payload format) and
//     none is a whole-message XOR; the only XOR the spec defines is the
//     SipHash-derived frame-length mask (§"SipHash obfuscated length").
//   - GenericPaddingModifier framed data as "[4-byte big-endian length][data]
//     [padding]". ntcp2.md §"Session Request" gives message 1 the layout
//     AES(X) ‖ AEAD ‖ padding with no length prefix, and §"Additions to the
//     Framework" states "Message 1 and 2 AEAD frames are fixed length", so a
//     length prefix is not part of the NTCP2 wire format.
//
// With those types gone, nothing here can silently produce non-interoperable
// frames, and the guard is back to what it can still detect: a nil modifier, and
// NTCP2's own modifiers being supplied out of the order the spec requires.
// Callers may still add custom modifiers for their own framing; that is the
// documented purpose of [Config.WithModifiers].
func (nc *Config) validateModifiers() error {
	flog("NTCP2Config.validateModifiers", logger.Fields{"modifier_count": len(nc.Modifiers)}).Debug("Validating NTCP2 modifiers")
	for i, mod := range nc.Modifiers {
		if mod == nil {
			return oops.
				Code("INVALID_MODIFIER").
				In("ntcp2").
				With("index", i).
				Errorf("nil modifier at index %d", i)
		}
		if mod.Name() == "" {
			return oops.
				Code("INVALID_MODIFIER").
				In("ntcp2").
				With("index", i).
				Errorf("modifier at index %d has an empty name", i)
		}
	}
	return nil
}

// ToConnConfig converts this NTCP2 Config into the standard Noise
// ConnConfig used by the underlying Noise connection.
//
// It first calls Validate, then sets up the NTCP2-specific modifiers
// (AES obfuscation, padding, SipHash length obfuscation) based on the
// configuration.
//
// When SipHash length obfuscation is enabled, a post-handshake hook is
// registered automatically. After the handshake finishes, the hook
// derives the per-direction SipHash keys from the session keys and
// stores them for the data phase.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Config) ToConnConfig() (*noise.ConnConfig, error) {
	flog("NTCP2Config.ToConnConfig").Debug("Converting NTCP2Config to ConnConfig")
	if err := nc.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Wrap(err)
	}

	config := nc.createBaseConnConfig()

	modifiers, err := nc.setupNTCP2Modifiers()
	if err != nil {
		return nil, err
	}

	config.Modifiers = modifiers

	// Wire PostHandshakeHook for SipHash key derivation.
	// Configure the ASK label so the upstream noise library derives
	// ask_master via SplitWithASK() during the handshake.
	if nc.EnableSipHashLength {
		config.AdditionalSymmetricKeyLabels = [][]byte{[]byte("ask")}
		config.PostHandshakeHook = nc.createPostHandshakeHook()
	}

	return config, nil
}

// createPostHandshakeHook returns a PostHandshakeHook that derives
// per-direction SipHash keys from the ASK master and handshake hash
// after the Noise XK handshake completes.
//
// The upstream go-i2p/noise library's SplitWithASK() derives the
// ask_master via Config.AdditionalSymmetricKeyLabels = {"ask"}.
// This hook retrieves it via AdditionalSymmetricKeys()[0], then calls
// DeriveSipHashKeys(askMaster, h) to produce directional SipHash keys
// and stores them in the NTCP2Config for later use by NTCP2Conn.
func (nc *Config) createPostHandshakeHook() func(*noise.NoiseConn) error {
	return func(conn *noise.NoiseConn) error {
		h := conn.ChannelBinding()
		if h == nil {
			return oops.
				Code("NO_HANDSHAKE_HASH").
				In("ntcp2").
				Errorf("handshake hash not available after handshake")
		}

		askKeys := conn.AdditionalSymmetricKeys()
		if len(askKeys) == 0 || len(askKeys[0]) == 0 {
			return oops.
				Code("NO_ASK_MASTER").
				In("ntcp2").
				Errorf("ask_master not available after handshake (no ASK labels configured?)")
		}
		askMaster := askKeys[0]

		sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, err := DeriveSipHashKeys(askMaster, h)
		// Per NTCP2 spec ("overwrite ask_master in memory, no longer needed"),
		// zero the ask_master secret now that key derivation is complete.
		// DeriveSipHashKeys only zeroes its own internal copy (see its doc
		// comment), so the original slice obtained from AdditionalSymmetricKeys
		// must be zeroed here by the caller.
		securemem.SecureZero(askMaster)
		if err != nil {
			return oops.
				Code("SIPHASH_DERIVATION_FAILED").
				In("ntcp2").
				Wrapf(err, "failed to derive SipHash keys from ask_master")
		}

		// Create a directional SipHash modifier with proper key assignment:
		//   Initiator: outbound = AB, inbound = BA
		//   Responder: outbound = BA, inbound = AB
		var modifier *SipHashLengthModifier
		if nc.Initiator {
			modifier = NewSipHashLengthModifierDirectional("ntcp2-siphash",
				sipKeysAB, sipKeysBA, sipIVAB, sipIVBA)
		} else {
			modifier = NewSipHashLengthModifierDirectional("ntcp2-siphash",
				sipKeysBA, sipKeysAB, sipIVBA, sipIVAB)
		}

		// Store the directional modifier for NTCP2Conn to use.
		nc.sipHashModifier.Store(modifier)

		role := "responder"
		if nc.Initiator {
			role = "initiator"
		}
		flog("NTCP2Config.createPostHandshakeHook", logger.Fields{"handshake_hash_len": len(h), "ask_master_len": len(askMaster), "role": role, "sipk1_ab": sipKeysAB[0], "sipk2_ab": sipKeysAB[1], "sipiv_ab": sipIVAB, "sipk1_ba": sipKeysBA[0], "sipk2_ba": sipKeysBA[1], "sipiv_ba": sipIVBA}).Debug("PostHandshakeHook: derived per-direction SipHash keys")

		return nil
	}
}

// createBaseConnConfig creates a base ConnConfig with core NTCP2 settings.
func (nc *Config) createBaseConnConfig() *noise.ConnConfig {
	// When no static key is provided, use nil (not a zero-length slice)
	// so the upstream library can distinguish "no key" from "empty key".
	staticKey := copyKeyBytes(nc.StaticKey)

	// When no remote static key is provided, use nil so the upstream
	// library can distinguish "no key" from "empty key".
	remoteKey := copyKeyBytes(nc.RemoteStaticKey)

	return &noise.ConnConfig{
		Pattern:   nc.Pattern,
		Initiator: nc.Initiator,
		StaticKey: staticKey,
		RemoteKey: remoteKey,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: nc.HandshakeTimeout,
			ReadTimeout:      nc.ReadTimeout,
			WriteTimeout:     nc.WriteTimeout,
			HandshakeRetries: nc.HandshakeRetries,
			RetryBackoff:     nc.RetryBackoff,
		},
		// NTCP2 mandates ChaChaPoly (ChaCha20-Poly1305 per RFC 7539)
		CipherSuite: upstreamnoise.NewCipherSuite(
			upstreamnoise.DH25519,
			upstreamnoise.CipherChaChaPoly,
			upstreamnoise.HashSHA256,
		),
		// NTCP2 uses a non-standard protocol name for InitializeSymmetric()
		ProtocolName: []byte(NTCP2ProtocolName),
	}
}

// setupNTCP2Modifiers creates and configures all NTCP2-specific handshake modifiers.
func (nc *Config) setupNTCP2Modifiers() ([]handshake.HandshakeModifier, error) {
	flog("NTCP2Config.setupNTCP2Modifiers").Debug("Setting up NTCP2-specific modifiers")
	var modifiers []handshake.HandshakeModifier

	factories := []func() (handshake.HandshakeModifier, error){
		nc.createAESModifierIfEnabled,
		func() (handshake.HandshakeModifier, error) {
			// Add placeholder to the handshake modifier list (no-op for non-PhaseFinal).
			// Do NOT store as nc.sipHashModifier — that is set by the post-handshake
			// hook with proper per-direction keys. Storing the zero-key placeholder
			// would expose a predictable modifier via SipHashModifier() before the
			// handshake completes.
			sip := nc.createSipHashModifierIfEnabled()
			if sip == nil {
				return nil, nil
			}
			return sip, nil
		},
		nc.createPaddingModifierIfEnabled,
	}

	for _, factory := range factories {
		mod, err := factory()
		if err != nil {
			return nil, err
		}
		if mod != nil {
			modifiers = append(modifiers, mod)
		}
	}

	modifiers = append(modifiers, nc.Modifiers...)
	return modifiers, nil
}

// createAESModifierIfEnabled creates an AES obfuscation modifier if enabled.
func (nc *Config) createAESModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !nc.EnableAESObfuscation {
		return nil, nil
	}

	iv := nc.ObfuscationIV
	if iv == nil {
		// The IV must be provided explicitly from the remote peer's published
		// network database entry ("i=" option). There is no valid fallback.
		return nil, oops.
			Code("MISSING_OBFUSCATION_IV").
			In("ntcp2").
			Errorf("AES obfuscation IV is required (published in peer's network database entry)")
	}

	aesModifier, err := NewAESObfuscationModifier("ntcp2-aes", nc.BobRouterHash[:], iv)
	if err != nil {
		return nil, oops.
			Code("AES_MODIFIER_FAILED").
			In("ntcp2").
			Wrap(err)
	}
	return aesModifier, nil
}

// createSipHashModifierIfEnabled creates a new SipHash length modifier if
// enabled.
// A fresh instance is created on every call to prevent shared state
// between connections.
//
// After the Noise XK handshake completes, the router transport layer must
// call DeriveSipHashKeys() to obtain per-direction keys and then create a
// directional modifier via NewSipHashLengthModifierDirectional(). The
// placeholder modifier returned here uses shared zero keys and is only
// suitable as a handshake-phase pass-through (SipHash is a no-op before
// PhaseFinal).
func (nc *Config) createSipHashModifierIfEnabled() *SipHashLengthModifier {
	if !nc.EnableSipHashLength {
		return nil
	}
	// SipHash keys (sipk1, sipk2) and initial IV should be derived from the
	// data-phase KDF after the Noise XK handshake completes. Use DeriveSipHashKeys()
	// with the ask_master secret and the handshake hash (from NTCP2Conn.HandshakeHash())
	// to obtain proper keys. The router transport layer should call DeriveSipHashKeys()
	// and then inject the result via SetLengthObfuscator() on the NTCP2Conn.
	return NewSipHashLengthModifier("ntcp2-siphash", nc.SipHashKeys, 0)
}

// createPaddingModifierIfEnabled creates an NTCP2 padding modifier if enabled.
// Uses AEAD padding (block format with type 254) for the data phase.
// Cleartext padding for handshake messages 1-2 is handled at the transport
// layer (appended after the fixed-size Noise message; receiver ignores it).
func (nc *Config) createPaddingModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !nc.FramePaddingEnabled {
		return nil, nil
	}
	mod, err := NewNTCP2PaddingModifier(
		"ntcp2-padding",
		nc.MinPaddingSize,
		nc.MaxPaddingSize,
		true, // AEAD padding for data phase (phase >= PhaseFinal)
	)
	if err != nil {
		return nil, oops.
			Code("PADDING_MODIFIER_FAILED").
			In("ntcp2").
			Wrap(err)
	}
	return mod, nil
}

// SipHashModifier returns the SipHash length modifier created during
// ToConnConfig().
//
// It returns nil until the post-handshake hook has run during
// Handshake(), because the modifier's keys are derived from the
// handshake state. Do not call this method before the handshake
// completes; calling PropagateSipHash() early returns an error instead
// of silently doing nothing.
//
// It also returns nil if SipHash length obfuscation is disabled or
// ToConnConfig() has not been called. Each call to ToConnConfig()
// creates a fresh modifier instance, so a config can be reused for
// multiple connections without sharing IV state.
func (nc *Config) SipHashModifier() *SipHashLengthModifier {
	return nc.sipHashModifier.Load()
}

// Clone creates a deep copy of this Config that is safe to use
// independently, for example for per-connection configs on the listener
// path.
//
// The SipHash modifier field is not copied: the clone starts with a
// fresh zero value, which is correct because the post-handshake hook
// fills it in after the handshake.
//
// Important: the Modifiers slice is shallow-copied, so the individual
// modifiers (AES obfuscation, SipHash, etc.) are shared between the
// original and the clone. Modifiers carry mutable state (AES cipher
// state, SipHash IVs), so the clone must not be used concurrently with
// the original for handshakes. Call ToConnConfig() on the clone before
// use; it creates fresh modifier instances with independent state. The
// listener path does this correctly. Using Clone() without
// ToConnConfig() while both configs are active concurrently causes data
// races and corrupts handshake state.
func (nc *Config) Clone() *Config {
	clone := &Config{
		Pattern:   nc.Pattern,
		Initiator: nc.Initiator,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: nc.HandshakeTimeout,
			ReadTimeout:      nc.ReadTimeout,
			WriteTimeout:     nc.WriteTimeout,
			HandshakeRetries: nc.HandshakeRetries,
			RetryBackoff:     nc.RetryBackoff,
		},
		EnableAESObfuscation: nc.EnableAESObfuscation,
		EnableSipHashLength:  nc.EnableSipHashLength,
		SipHashKeys:          nc.SipHashKeys,
		MaxFrameSize:         nc.MaxFrameSize,
		FramePaddingEnabled:  nc.FramePaddingEnabled,
		MinPaddingSize:       nc.MinPaddingSize,
		MaxPaddingSize:       nc.MaxPaddingSize,
		NetworkID:            nc.NetworkID,
		MaxClockSkew:         nc.MaxClockSkew,
		ReplayDetector:       nc.ReplayDetector, // Shared across clones for responder
	}
	clone.BobRouterHash = nc.BobRouterHash
	clone.StaticKey = copyKeyBytes(nc.StaticKey)
	if nc.RemoteRouterHash != nil {
		h := *nc.RemoteRouterHash
		clone.RemoteRouterHash = &h
	}
	clone.RemoteStaticKey = copyKeyBytes(nc.RemoteStaticKey)
	if nc.ObfuscationIV != nil {
		clone.ObfuscationIV = make([]byte, len(nc.ObfuscationIV))
		copy(clone.ObfuscationIV, nc.ObfuscationIV)
	}
	if nc.Modifiers != nil {
		clone.Modifiers = make([]handshake.HandshakeModifier, len(nc.Modifiers))
		for i, mod := range nc.Modifiers {
			// Deep-copy modifiers that implement ModifierCloner
			if cloner, ok := mod.(handshake.ModifierCloner); ok {
				clone.Modifiers[i] = cloner.Clone()
			} else {
				// Shallow copy for modifiers without Clone support
				// These modifiers MUST be either immutable or internally synchronized
				clone.Modifiers[i] = mod
			}
		}
	}
	return clone
}
