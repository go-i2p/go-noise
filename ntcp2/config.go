package ntcp2

import (
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/mod/validation"
	"github.com/go-i2p/logger"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// DefaultHandshakeTimeoutSeconds is the default handshake timeout in seconds.
const DefaultHandshakeTimeoutSeconds = 30

// DefaultHandshakeRetries is the default number of handshake retry attempts.
const DefaultHandshakeRetries = 3

// Config contains configuration for creating NTCP2 connections and listeners.
// It follows the builder pattern for optional configuration and validation,
// similar to the main ConnConfig but with NTCP2-specific parameters.
type Config struct {
	// Pattern is the Noise protocol pattern for NTCP2
	// Default: "XK" (standard NTCP2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// BobRouterHash is Bob's (the responder's) router hash.
	// Per the I2P NTCP2 spec, both Alice (initiator) and Bob (responder)
	// use RH_B as the AES-256-CBC key for ephemeral key obfuscation.
	// For the responder, this is their own router hash.
	// For the initiator, this is the remote peer's router hash.
	// Required for NTCP2 addressing and AES obfuscation.
	BobRouterHash data.Hash

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity hash.
	// Required for outbound connections, optional for listeners.
	RemoteRouterHash *data.Hash

	// RemoteStaticKey is the remote peer's Curve25519 static public key (32 bytes)
	// Required for initiator connections using XK pattern (pre-message: ← s)
	// Distinct from RemoteRouterHash (which is SHA-256 of RouterIdentity)
	RemoteStaticKey []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration

	// HandshakeRetries is the number of handshake retry attempts
	// Default: 3 attempts (0 = no retries, -1 = infinite retries)
	HandshakeRetries int

	// RetryBackoff is the base delay between retry attempts
	// Actual delay uses exponential backoff: delay = RetryBackoff * (2^attempt)
	// Default: 1 second
	RetryBackoff time.Duration

	// EnableAESObfuscation enables AES-based ephemeral key obfuscation
	// Default: true (recommended for production)
	EnableAESObfuscation bool

	// ObfuscationIV is the 16-byte IV for AES obfuscation
	// If nil, will be derived from router hash (recommended)
	ObfuscationIV []byte

	// EnableSipHashLength enables SipHash-based frame length obfuscation
	// Default: true (recommended for production)
	EnableSipHashLength bool

	// SipHashKeys are the k1, k2 keys for SipHash length obfuscation
	// If empty, will be derived during handshake
	SipHashKeys [2]uint64

	// Modifiers is a list of additional handshake modifiers for custom obfuscation
	// These are applied in addition to NTCP2's standard modifiers
	// Default: empty (no additional modifiers)
	Modifiers []handshake.HandshakeModifier

	// MaxFrameSize is the maximum size of NTCP2 data frames
	// Default: 16384 bytes (16KB)
	MaxFrameSize int

	// FramePaddingEnabled enables random padding in NTCP2 frames
	// Default: true (recommended for traffic analysis resistance)
	FramePaddingEnabled bool

	// MinPaddingSize is the minimum padding size for frames
	// Default: 0 bytes
	MinPaddingSize int

	// MaxPaddingSize is the maximum padding size for frames
	// Default: 64 bytes
	MaxPaddingSize int

	// LocalRouterInfo contains Alice's serialized RouterInfo bytes.
	// Required for outbound NTCP2 connections: its length determines m3p2Len
	// in the message 1 options block and it is sent as the encrypted payload
	// in message 3 part 2.
	LocalRouterInfo []byte

	// StrictRouterInfoVerification, when true, causes the initiator handshake
	// to return a hard error if the configured LocalRouterInfo does not
	// advertise the static key that will be sent in the Noise handshake msg1.
	// Defaults to false so that existing tests using synthetic RouterInfo
	// bytes continue to work. Set to true in production to catch
	// misconfiguration before a silent i2pd interop failure (frame #0 EOF).
	StrictRouterInfoVerification bool

	// sipHashModifier stores the SipHash modifier created during ToConnConfig()
	// so it can be passed to NTCP2Conn for data-phase framing.
	// Access is via atomic.Pointer to avoid data races between the
	// PostHandshakeHook goroutine and SipHashModifier() callers.
	sipHashModifier atomic.Pointer[SipHashLengthModifier]

	// ReplayDetector checks for replayed ephemeral keys during handshakes.
	// If nil, replay detection is disabled (not recommended for production).
	// Shared across all responder connections using this config (typically
	// instantiated once per listener). Initiator connections ignore this field.
	ReplayDetector ReplayDetector

	// AllowReuseAddress, when true, enables SO_REUSEADDR socket option for
	// ListenNTCP2. This reduces restart-race delay by allowing quick rebinding
	// to the same address after shutdown. Use with caution in production as it
	// can allow stale packets from previous incarnations to be delivered.
	// Default: false (conservative, matches net.Listen behavior).
	// AUDIT 7.3: Documented restart-race behavior.
	AllowReuseAddress bool
}

// NewNTCP2Config creates a new NTCP2Config with sensible defaults.
// bobRouterHash is Bob's (the responder's) router hash (RH_B). Per the NTCP2
// spec, both initiator and responder use RH_B for AES ephemeral key obfuscation.
// For a responder, pass your own router hash; for an initiator, pass the remote
// peer's router hash.
// initiator indicates whether this connection will initiate the handshake.
func NewNTCP2Config(bobRouterHash data.Hash, initiator bool) (*Config, error) {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NewNTCP2Config", "initiator": initiator}).Debug("Creating new NTCP2Config")
	return &Config{
		Pattern:              NTCP2Pattern,
		Initiator:            initiator,
		BobRouterHash:        bobRouterHash,
		HandshakeTimeout:     DefaultHandshakeTimeoutSeconds * time.Second,
		ReadTimeout:          0,
		WriteTimeout:         0,
		HandshakeRetries:     DefaultHandshakeRetries,
		RetryBackoff:         1 * time.Second,
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		MaxFrameSize:         DefaultMaxFrameSize,
		FramePaddingEnabled:  true,
		MinPaddingSize:       0,
		MaxPaddingSize:       DefaultMaxPaddingSize,
	}, nil
}

// WithPattern sets the Noise protocol pattern.
// For NTCP2, this should typically remain "XK".
func (nc *Config) WithPattern(pattern string) *Config {
	nc.Pattern = pattern
	return nc
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519. Invalid lengths are ignored;
// call Validate() to check all fields before use.
func (nc *Config) WithStaticKey(key []byte) *Config {
	if len(key) == StaticKeySize {
		nc.StaticKey = make([]byte, StaticKeySize)
		copy(nc.StaticKey, key)
	}
	return nc
}

// WithRemoteRouterHash sets the remote peer's router identity.
// hash must be 32 bytes. Required for outbound connections.
// Invalid lengths are ignored; call Validate() to check all fields before use.
func (nc *Config) WithRemoteRouterHash(hash data.Hash) *Config {
	nc.RemoteRouterHash = &hash
	return nc
}

// WithRemoteStaticKey sets the remote peer's Curve25519 static public key.
// key must be exactly 32 bytes. Required for initiator connections using the
// XK pattern, where the initiator must know the responder's static key as a
// pre-message (← s). This is distinct from RemoteRouterHash (which is
// SHA-256 of the RouterIdentity).
// Invalid lengths are ignored; call Validate() to check all fields before use.
func (nc *Config) WithRemoteStaticKey(key []byte) *Config {
	if len(key) == StaticKeySize {
		nc.RemoteStaticKey = make([]byte, StaticKeySize)
		copy(nc.RemoteStaticKey, key)
	}
	return nc
}

// WithHandshakeTimeout sets the handshake timeout.
func (nc *Config) WithHandshakeTimeout(timeout time.Duration) *Config {
	nc.HandshakeTimeout = timeout
	return nc
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (nc *Config) WithReadTimeout(timeout time.Duration) *Config {
	nc.ReadTimeout = timeout
	return nc
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (nc *Config) WithWriteTimeout(timeout time.Duration) *Config {
	nc.WriteTimeout = timeout
	return nc
}

// WithHandshakeRetries sets the number of handshake retry attempts.
// Use 0 for no retries, -1 for infinite retries.
func (nc *Config) WithHandshakeRetries(retries int) *Config {
	nc.HandshakeRetries = retries
	return nc
}

// WithRetryBackoff sets the base delay between retry attempts.
func (nc *Config) WithRetryBackoff(backoff time.Duration) *Config {
	nc.RetryBackoff = backoff
	return nc
}

// WithAESObfuscation enables or disables AES-based ephemeral key obfuscation.
// When enabled with a custom IV, the IV must be exactly 16 bytes; invalid
// IV lengths are ignored. Call Validate() to check all fields before use.
// Note: Options negotiation (padding limits as 4.4 fixed-point, dummy traffic,
// delay parameters) is the responsibility of the higher-level router transport.
func (nc *Config) WithAESObfuscation(enabled bool, customIV []byte) *Config {
	nc.EnableAESObfuscation = enabled
	if len(customIV) == IVSize {
		nc.ObfuscationIV = make([]byte, IVSize)
		copy(nc.ObfuscationIV, customIV)
	}
	return nc
}

// WithSipHashLength enables or disables SipHash-based frame length obfuscation.
// When enabled with custom keys, both k1 and k2 must be provided.
func (nc *Config) WithSipHashLength(enabled bool, k1, k2 uint64) *Config {
	nc.EnableSipHashLength = enabled
	if enabled && (k1 != 0 || k2 != 0) {
		nc.SipHashKeys[0] = k1
		nc.SipHashKeys[1] = k2
	}
	return nc
}

// WithModifiers sets additional handshake modifiers for custom obfuscation.
// These are applied in addition to NTCP2's standard modifiers.
func (nc *Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *Config {
	// Make defensive copy
	nc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(nc.Modifiers, modifiers)
	return nc
}

// WithLocalRouterInfo sets Alice's serialized RouterInfo bytes for outbound
// NTCP2 connections. The length is used to populate m3p2Len in the message 1
// options block; the bytes are encrypted and sent as message 3 part 2.
func (nc *Config) WithLocalRouterInfo(ri []byte) *Config {
	if len(ri) > 0 {
		nc.LocalRouterInfo = make([]byte, len(ri))
		copy(nc.LocalRouterInfo, ri)
	}
	return nc
}

// WithStrictRouterInfoVerification enables or disables hard-error mode for the
// local RouterInfo / static-key mismatch check. Set to true in production to
// catch misconfiguration before a silent i2pd interop failure.
func (nc *Config) WithStrictRouterInfoVerification(strict bool) *Config {
	nc.StrictRouterInfoVerification = strict
	return nc
}

// WithReplayDetector sets the replay detector for responder handshakes.
// If nil, replay detection is disabled (not recommended for production).
// The detector is shared across all responder connections using this config
// (typically instantiated once per listener). Initiator connections ignore
// this field.
func (nc *Config) WithReplayDetector(detector ReplayDetector) *Config {
	nc.ReplayDetector = detector
	return nc
}

// WithReuseAddress enables SO_REUSEADDR for ListenNTCP2 listener binding.
// When enabled, the listener can quickly rebind to the same port after shutdown,
// reducing restart-race delay. Default is false (conservative).
// Use with caution: stale packets from previous socket instances may arrive.
// AUDIT 7.3: Opt-in SO_REUSEADDR support for fast restart scenarios.
func (nc *Config) WithReuseAddress(allow bool) *Config {
	nc.AllowReuseAddress = allow
	return nc
}

// WithFrameSettings configures NTCP2 frame handling parameters.
// maxSize sets the maximum frame size (default: 16384 bytes).
// paddingEnabled enables random padding (default: true).
// minPadding and maxPadding set the padding size range (default: 0-64 bytes).
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

// Validate checks if the configuration is valid for NTCP2.
func (nc *Config) Validate() error {
	return validation.RunValidators(
		nc.validateBasicConfiguration,
		nc.validateCryptographicParameters,
		nc.validateTimeoutConfiguration,
		nc.validateFrameConfiguration,
		nc.validateModifiers,
	)
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (nc *Config) validateBasicConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.validateBasicConfiguration"}).Debug("Validating NTCP2 basic configuration")
	if err := validation.ValidatePattern(nc.Pattern, "ntcp2"); err != nil {
		return err
	}

	// BobRouterHash validation is implicit via data.Hash type (always 32 bytes).

	return nil
}

// validateCryptographicParameters checks static keys, remote hashes, and obfuscation settings.
func (nc *Config) validateCryptographicParameters() error {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.validateCryptographicParameters"}).Debug("Validating NTCP2 cryptographic parameters")
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
	// m3p2Len = BlockHeaderSize (3) + flag (1) + len(riBytes) + Poly1305Overhead (16)
	// Maximum safe size: 65535 - 20 = 65515 bytes
	const maxRouterInfoSize = 0xFFFF - (BlockHeaderSize + 1 + Poly1305Overhead)
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

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (nc *Config) validateTimeoutConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.validateTimeoutConfiguration"}).Debug("Validating NTCP2 timeout configuration")
	return validation.ValidateTransportConfig(nc.HandshakeTimeout, nc.HandshakeRetries, nc.RetryBackoff, "ntcp2")
}

// validateFrameConfiguration checks frame size and padding settings.
func (nc *Config) validateFrameConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.validateFrameConfiguration"}).Debug("Validating NTCP2 frame configuration")
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
	if nc.MaxFrameSize < minAllowedFrameSize {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			With("min_allowed", minAllowedFrameSize).
			Errorf("max frame size %d is too small (minimum %d bytes required for I2NP block header + AEAD tag)", nc.MaxFrameSize, minAllowedFrameSize)
	}

	if nc.MaxFrameSize > SpecMaxFrameSize {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			With("spec_max", SpecMaxFrameSize).
			Errorf("max frame size %d exceeds spec maximum %d", nc.MaxFrameSize, SpecMaxFrameSize)
	}

	if err := handshake.ValidatePaddingRange("ntcp2", nc.MinPaddingSize, nc.MaxPaddingSize); err != nil {
		return err
	}

	return nil
}

// validateModifiers rejects incompatible modifiers in the NTCP2 modifier chain.
func (nc *Config) validateModifiers() error {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.validateModifiers", "modifier_count": len(nc.Modifiers)}).Debug("Validating NTCP2 modifiers")
	for _, mod := range nc.Modifiers {
		if _, ok := mod.(*handshake.PaddingModifier); ok {
			return oops.
				Code("INCOMPATIBLE_MODIFIER").
				In("ntcp2").
				With("modifier", mod.Name()).
				Errorf("PaddingModifier is not NTCP2-compatible; use NTCP2PaddingModifier")
		}
	}
	return nil
}

// ToConnConfig converts NTCP2Config to a standard ConnConfig for use with NoiseConn.
// This includes setting up NTCP2-specific modifiers based on the configuration.
// A PostHandshakeHook is automatically registered when SipHash length obfuscation
// is enabled — the hook captures the handshake hash for future SipHash key derivation.
func (nc *Config) ToConnConfig() (*noise.ConnConfig, error) {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.ToConnConfig"}).Debug("Converting NTCP2Config to ConnConfig")
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
		log.WithFields(logger.Fields{
			"pkg":                "ntcp2",
			"func":               "NTCP2Config.createPostHandshakeHook",
			"handshake_hash_len": len(h),
			"ask_master_len":     len(askMaster),
			"role":               role,
			"sipk1_ab":           sipKeysAB[0],
			"sipk2_ab":           sipKeysAB[1],
			"sipiv_ab":           sipIVAB,
			"sipk1_ba":           sipKeysBA[0],
			"sipk2_ba":           sipKeysBA[1],
			"sipiv_ba":           sipIVBA,
		}).Debug("PostHandshakeHook: derived per-direction SipHash keys")

		return nil
	}
}

// createBaseConnConfig creates a base ConnConfig with core NTCP2 settings.
func (nc *Config) createBaseConnConfig() *noise.ConnConfig {
	// When no static key is provided, use nil (not a zero-length slice)
	// so the upstream library can distinguish "no key" from "empty key".
	var staticKey []byte
	if len(nc.StaticKey) > 0 {
		staticKey = make([]byte, len(nc.StaticKey))
		copy(staticKey, nc.StaticKey)
	}

	// When no remote static key is provided, use nil so the upstream
	// library can distinguish "no key" from "empty key".
	var remoteKey []byte
	if len(nc.RemoteStaticKey) > 0 {
		remoteKey = make([]byte, len(nc.RemoteStaticKey))
		copy(remoteKey, nc.RemoteStaticKey)
	}

	return &noise.ConnConfig{
		Pattern:          nc.Pattern,
		Initiator:        nc.Initiator,
		StaticKey:        staticKey,
		RemoteKey:        remoteKey,
		HandshakeTimeout: nc.HandshakeTimeout,
		ReadTimeout:      nc.ReadTimeout,
		WriteTimeout:     nc.WriteTimeout,
		HandshakeRetries: nc.HandshakeRetries,
		RetryBackoff:     nc.RetryBackoff,
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
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Config.setupNTCP2Modifiers"}).Debug("Setting up NTCP2-specific modifiers")
	var modifiers []handshake.HandshakeModifier

	aesModifier, err := nc.createAESModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if aesModifier != nil {
		modifiers = append(modifiers, aesModifier)
	}

	sipModifier := nc.createSipHashModifierIfEnabled()
	if sipModifier != nil {
		// Add placeholder to the handshake modifier list (no-op for non-PhaseFinal).
		// Do NOT store as nc.sipHashModifier — that is set by the post-handshake
		// hook with proper per-direction keys. Storing the zero-key placeholder
		// would expose a predictable modifier via SipHashModifier() before the
		// handshake completes.
		modifiers = append(modifiers, sipModifier)
	}

	paddingModifier, err := nc.createPaddingModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if paddingModifier != nil {
		modifiers = append(modifiers, paddingModifier)
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

// createSipHashModifierIfEnabled creates a new SipHash length modifier if enabled.
// A fresh instance is created on every call to prevent shared state between connections.
//
// UNFINALIZED_SPEC(ntcp2): After the Noise XK handshake completes, the router
// transport layer must call DeriveSipHashKeys() to obtain per-direction keys
// and then create a directional modifier via NewSipHashLengthModifierDirectional().
// The placeholder modifier returned here uses shared zero keys and is only
// suitable as a handshake-phase pass-through (SipHash is a no-op before PhaseFinal).
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

// SipHashModifier returns the SipHash length modifier created during ToConnConfig().
//
// PRECONDITION: This method returns nil until the PostHandshakeHook has executed
// during Handshake(). Callers MUST NOT call this method before the handshake completes,
// as the modifier's keys are derived from the handshake state. Calling PropagateSipHash()
// before the handshake will return an error rather than silently no-op.
//
// Returns nil if SipHash length obfuscation is disabled or ToConnConfig() hasn't been called.
// Each call to ToConnConfig() creates a fresh modifier instance, so configs can be safely
// reused for multiple connections without sharing IV state.
func (nc *Config) SipHashModifier() *SipHashLengthModifier {
	return nc.sipHashModifier.Load()
}

// Clone creates a deep copy of this NTCP2Config that is safe to use
// independently (e.g., for per-connection configs on the listener path).
// The atomic.Pointer[SipHashLengthModifier] field is NOT copied — the
// returned config has a fresh zero-value atomic, which is correct
// because the PostHandshakeHook will populate it after the handshake.
//
// IMPORTANT: The Modifiers slice is shallow-copied — individual modifier
// interface values (pointers to AESObfuscationModifier, SipHashLengthModifier,
// etc.) are shared between the original and clone. Since modifiers carry
// mutable state (AES cipher state, SipHash IVs), the clone MUST NOT be
// used concurrently with the original for handshakes. Callers MUST call
// ToConnConfig() on the clone before use, which creates fresh modifier
// instances with independent state. The listener path does this correctly.
// Direct use of Clone() without ToConnConfig() will cause data races
// and corrupt handshake state if both configs are active concurrently.
func (nc *Config) Clone() *Config {
	clone := &Config{
		Pattern:              nc.Pattern,
		Initiator:            nc.Initiator,
		HandshakeTimeout:     nc.HandshakeTimeout,
		ReadTimeout:          nc.ReadTimeout,
		WriteTimeout:         nc.WriteTimeout,
		HandshakeRetries:     nc.HandshakeRetries,
		RetryBackoff:         nc.RetryBackoff,
		EnableAESObfuscation: nc.EnableAESObfuscation,
		EnableSipHashLength:  nc.EnableSipHashLength,
		SipHashKeys:          nc.SipHashKeys,
		MaxFrameSize:         nc.MaxFrameSize,
		FramePaddingEnabled:  nc.FramePaddingEnabled,
		MinPaddingSize:       nc.MinPaddingSize,
		MaxPaddingSize:       nc.MaxPaddingSize,
		ReplayDetector:       nc.ReplayDetector, // Shared across clones for responder
	}
	clone.BobRouterHash = nc.BobRouterHash
	if nc.StaticKey != nil {
		clone.StaticKey = make([]byte, len(nc.StaticKey))
		copy(clone.StaticKey, nc.StaticKey)
	}
	if nc.RemoteRouterHash != nil {
		h := *nc.RemoteRouterHash
		clone.RemoteRouterHash = &h
	}
	if nc.RemoteStaticKey != nil {
		clone.RemoteStaticKey = make([]byte, len(nc.RemoteStaticKey))
		copy(clone.RemoteStaticKey, nc.RemoteStaticKey)
	}
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
