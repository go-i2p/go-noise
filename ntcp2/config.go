package ntcp2

import (
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// NTCP2Config contains configuration for creating NTCP2 connections and listeners.
// It follows the builder pattern for optional configuration and validation,
// similar to the main ConnConfig but with NTCP2-specific parameters.
// Moved from: ntcp2/config.go
type NTCP2Config struct {
	// Pattern is the Noise protocol pattern for NTCP2
	// Default: "XK" (standard NTCP2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// RouterHash is the local router identity (32 bytes)
	// Required for NTCP2 addressing and session establishment
	RouterHash []byte

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity (32 bytes)
	// Required for outbound connections, optional for listeners
	RemoteRouterHash []byte

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
}

// NewNTCP2Config creates a new NTCP2Config with sensible defaults.
// routerHash must be exactly 32 bytes representing the local router identity.
// initiator indicates whether this connection will initiate the handshake.
func NewNTCP2Config(routerHash []byte, initiator bool) (*NTCP2Config, error) {
	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	// Make defensive copy of router hash
	hash := make([]byte, 32)
	copy(hash, routerHash)

	return &NTCP2Config{
		Pattern:              "XK",
		Initiator:            initiator,
		RouterHash:           hash,
		HandshakeTimeout:     30 * time.Second,
		ReadTimeout:          0, // No timeout by default
		WriteTimeout:         0, // No timeout by default
		HandshakeRetries:     3,
		RetryBackoff:         1 * time.Second,
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		MaxFrameSize:         16384, // 16KB
		FramePaddingEnabled:  true,
		MinPaddingSize:       0,
		MaxPaddingSize:       64,
	}, nil
}

// WithPattern sets the Noise protocol pattern.
// For NTCP2, this should typically remain "XK".
func (nc *NTCP2Config) WithPattern(pattern string) *NTCP2Config {
	nc.Pattern = pattern
	return nc
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519.
func (nc *NTCP2Config) WithStaticKey(key []byte) *NTCP2Config {
	if len(key) == 32 {
		nc.StaticKey = make([]byte, 32)
		copy(nc.StaticKey, key)
	}
	return nc
}

// WithRemoteRouterHash sets the remote peer's router identity.
// hash must be 32 bytes. Required for outbound connections.
func (nc *NTCP2Config) WithRemoteRouterHash(hash []byte) *NTCP2Config {
	if len(hash) == 32 {
		nc.RemoteRouterHash = make([]byte, 32)
		copy(nc.RemoteRouterHash, hash)
	}
	return nc
}

// WithHandshakeTimeout sets the handshake timeout.
func (nc *NTCP2Config) WithHandshakeTimeout(timeout time.Duration) *NTCP2Config {
	nc.HandshakeTimeout = timeout
	return nc
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (nc *NTCP2Config) WithReadTimeout(timeout time.Duration) *NTCP2Config {
	nc.ReadTimeout = timeout
	return nc
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (nc *NTCP2Config) WithWriteTimeout(timeout time.Duration) *NTCP2Config {
	nc.WriteTimeout = timeout
	return nc
}

// WithHandshakeRetries sets the number of handshake retry attempts.
// Use 0 for no retries, -1 for infinite retries.
func (nc *NTCP2Config) WithHandshakeRetries(retries int) *NTCP2Config {
	nc.HandshakeRetries = retries
	return nc
}

// WithRetryBackoff sets the base delay between retry attempts.
func (nc *NTCP2Config) WithRetryBackoff(backoff time.Duration) *NTCP2Config {
	nc.RetryBackoff = backoff
	return nc
}

// WithAESObfuscation enables or disables AES-based ephemeral key obfuscation.
// When enabled with a custom IV, the IV must be exactly 16 bytes.
func (nc *NTCP2Config) WithAESObfuscation(enabled bool, customIV []byte) *NTCP2Config {
	nc.EnableAESObfuscation = enabled
	if customIV != nil && len(customIV) == 16 {
		nc.ObfuscationIV = make([]byte, 16)
		copy(nc.ObfuscationIV, customIV)
	}
	return nc
}

// WithSipHashLength enables or disables SipHash-based frame length obfuscation.
// When enabled with custom keys, both k1 and k2 must be provided.
func (nc *NTCP2Config) WithSipHashLength(enabled bool, k1, k2 uint64) *NTCP2Config {
	nc.EnableSipHashLength = enabled
	if enabled && (k1 != 0 || k2 != 0) {
		nc.SipHashKeys[0] = k1
		nc.SipHashKeys[1] = k2
	}
	return nc
}

// WithModifiers sets additional handshake modifiers for custom obfuscation.
// These are applied in addition to NTCP2's standard modifiers.
func (nc *NTCP2Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *NTCP2Config {
	// Make defensive copy
	nc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(nc.Modifiers, modifiers)
	return nc
}

// WithFrameSettings configures NTCP2 frame handling parameters.
// maxSize sets the maximum frame size (default: 16384 bytes).
// paddingEnabled enables random padding (default: true).
// minPadding and maxPadding set the padding size range (default: 0-64 bytes).
func (nc *NTCP2Config) WithFrameSettings(maxSize int, paddingEnabled bool, minPadding, maxPadding int) *NTCP2Config {
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
func (nc *NTCP2Config) Validate() error {
	if err := nc.validateBasicConfiguration(); err != nil {
		return err
	}

	if err := nc.validateCryptographicParameters(); err != nil {
		return err
	}

	if err := nc.validateTimeoutConfiguration(); err != nil {
		return err
	}

	if err := nc.validateFrameConfiguration(); err != nil {
		return err
	}

	return nil
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (nc *NTCP2Config) validateBasicConfiguration() error {
	// Validate pattern (NTCP2 typically uses XK)
	if nc.Pattern == "" {
		return oops.
			Code("MISSING_PATTERN").
			In("ntcp2").
			Errorf("noise pattern is required")
	}

	// Validate router hash
	if len(nc.RouterHash) != 32 {
		return oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(nc.RouterHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	return nil
}

// validateCryptographicParameters checks static keys, remote hashes, and obfuscation settings.
func (nc *NTCP2Config) validateCryptographicParameters() error {
	// Validate static key if provided
	if len(nc.StaticKey) > 0 && len(nc.StaticKey) != 32 {
		return oops.
			Code("INVALID_STATIC_KEY").
			In("ntcp2").
			With("key_length", len(nc.StaticKey)).
			Errorf("static key must be 32 bytes")
	}

	// Validate remote router hash if provided
	if len(nc.RemoteRouterHash) > 0 && len(nc.RemoteRouterHash) != 32 {
		return oops.
			Code("INVALID_REMOTE_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(nc.RemoteRouterHash)).
			Errorf("remote router hash must be 32 bytes")
	}

	// For initiator connections, remote router hash is required
	if nc.Initiator && len(nc.RemoteRouterHash) == 0 {
		return oops.
			Code("MISSING_REMOTE_ROUTER_HASH").
			In("ntcp2").
			Errorf("remote router hash is required for initiator connections")
	}

	// Validate AES obfuscation IV if provided
	if nc.ObfuscationIV != nil && len(nc.ObfuscationIV) != 16 {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ntcp2").
			With("iv_length", len(nc.ObfuscationIV)).
			Errorf("obfuscation IV must be 16 bytes")
	}

	return nil
}

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (nc *NTCP2Config) validateTimeoutConfiguration() error {
	// Validate handshake timeout
	if nc.HandshakeTimeout <= 0 {
		return oops.
			Code("INVALID_HANDSHAKE_TIMEOUT").
			In("ntcp2").
			With("timeout", nc.HandshakeTimeout).
			Errorf("handshake timeout must be positive")
	}

	// Validate retry configuration
	if nc.HandshakeRetries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In("ntcp2").
			With("retries", nc.HandshakeRetries).
			Errorf("handshake retries must be >= -1")
	}

	if nc.RetryBackoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In("ntcp2").
			With("backoff", nc.RetryBackoff).
			Errorf("retry backoff must be non-negative")
	}

	return nil
}

// validateFrameConfiguration checks frame size and padding settings.
func (nc *NTCP2Config) validateFrameConfiguration() error {
	// Validate frame settings
	if nc.MaxFrameSize <= 0 {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			Errorf("max frame size must be positive")
	}

	if nc.MinPaddingSize < 0 {
		return oops.
			Code("INVALID_MIN_PADDING").
			In("ntcp2").
			With("min_padding", nc.MinPaddingSize).
			Errorf("min padding size must be non-negative")
	}

	if nc.MaxPaddingSize < nc.MinPaddingSize {
		return oops.
			Code("INVALID_PADDING_RANGE").
			In("ntcp2").
			With("min_padding", nc.MinPaddingSize).
			With("max_padding", nc.MaxPaddingSize).
			Errorf("max padding size must be >= min padding size")
	}

	return nil
}

// ToConnConfig converts NTCP2Config to a standard ConnConfig for use with NoiseConn.
// This includes setting up NTCP2-specific modifiers based on the configuration.
func (nc *NTCP2Config) ToConnConfig() (*noise.ConnConfig, error) {
	if err := nc.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Wrap(err)
	}

	config := nc.createBaseConnConfig()
	nc.copyStaticKeyIfProvided(config)

	modifiers, err := nc.setupNTCP2Modifiers()
	if err != nil {
		return nil, err
	}

	config.Modifiers = modifiers
	return config, nil
}

// createBaseConnConfig creates a base ConnConfig with core NTCP2 settings.
func (nc *NTCP2Config) createBaseConnConfig() *noise.ConnConfig {
	return &noise.ConnConfig{
		Pattern:          nc.Pattern,
		Initiator:        nc.Initiator,
		StaticKey:        make([]byte, len(nc.StaticKey)),
		HandshakeTimeout: nc.HandshakeTimeout,
		ReadTimeout:      nc.ReadTimeout,
		WriteTimeout:     nc.WriteTimeout,
		HandshakeRetries: nc.HandshakeRetries,
		RetryBackoff:     nc.RetryBackoff,
	}
}

// copyStaticKeyIfProvided copies the static key to the config if one is provided.
func (nc *NTCP2Config) copyStaticKeyIfProvided(config *noise.ConnConfig) {
	if len(nc.StaticKey) > 0 {
		copy(config.StaticKey, nc.StaticKey)
	}
}

// setupNTCP2Modifiers creates and configures all NTCP2-specific handshake modifiers.
func (nc *NTCP2Config) setupNTCP2Modifiers() ([]handshake.HandshakeModifier, error) {
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
		modifiers = append(modifiers, sipModifier)
	}

	modifiers = append(modifiers, nc.Modifiers...)
	return modifiers, nil
}

// createAESModifierIfEnabled creates an AES obfuscation modifier if enabled.
func (nc *NTCP2Config) createAESModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !nc.EnableAESObfuscation {
		return nil, nil
	}

	iv := nc.ObfuscationIV
	if iv == nil {
		// Derive IV from router hash (last 16 bytes)
		iv = nc.RouterHash[16:]
	}

	aesModifier, err := NewAESObfuscationModifier("ntcp2-aes", nc.RouterHash, iv)
	if err != nil {
		return nil, oops.
			Code("AES_MODIFIER_FAILED").
			In("ntcp2").
			Wrap(err)
	}
	return aesModifier, nil
}

// createSipHashModifierIfEnabled creates a SipHash length modifier if enabled.
func (nc *NTCP2Config) createSipHashModifierIfEnabled() handshake.HandshakeModifier {
	if !nc.EnableSipHashLength {
		return nil
	}
	// SipHash keys will be set up during handshake if not provided
	return NewSipHashLengthModifier("ntcp2-siphash", nc.SipHashKeys, 0)
}
