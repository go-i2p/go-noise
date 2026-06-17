package conn

import (
	"sync"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/mod/validation"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// ConnConfig contains configuration for creating a NoiseConn.
// It follows the builder pattern for optional configuration and validation.
type ConnConfig struct {
	// BaseHandshakeConfig embeds the shared timeout, retry, and modifier fields
	// common to all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	Initiator bool

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteKey is the remote peer's static public key (32 bytes for Curve25519)
	// Required for some patterns, optional for others
	RemoteKey []byte

	// CipherSuite specifies the Noise cipher suite to use for the handshake.
	// If nil, defaults to DH25519 + CipherAESGCM + SHA256.
	// Protocols like NTCP2 require DH25519 + CipherChaChaPoly + SHA256.
	CipherSuite noise.CipherSuite

	// ProtocolName overrides the auto-generated Noise protocol name used
	// for InitializeSymmetric(). When set, this exact byte string is used
	// instead of constructing "Noise_" + Pattern.Name + "_" + CipherSuite.Name().
	// Required for protocols like NTCP2 that use non-standard protocol names
	// (e.g., "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256").
	// If nil/empty, the standard Noise protocol name is constructed as usual.
	ProtocolName []byte

	// AdditionalSymmetricKeyLabels specifies labels for Additional Symmetric
	// Key (ASK) derivation at Split() time, per Noise spec §10.3. Each label
	// produces a 32-byte key derived from the chaining key. The derived keys
	// are available via NoiseConn.AdditionalSymmetricKeys() after the
	// handshake completes.
	//
	// For NTCP2, this should be set to [][]byte{[]byte("ask")} to derive
	// the ask_master used for SipHash key derivation.
	AdditionalSymmetricKeyLabels [][]byte

	// PostHandshakeHook is an optional callback invoked after the Noise
	// handshake completes successfully but before the connection transitions
	// to the Established state. This allows protocol layers (e.g., NTCP2)
	// to derive additional key material from the handshake hash, set up
	// data-phase obfuscators, or perform any post-handshake validation.
	//
	// If the hook returns an error, the handshake is considered failed and
	// the connection reverts to the Init state.
	PostHandshakeHook func(*Conn) error

	// cachedChain holds the lazily-initialized ModifierChain built from Modifiers.
	// It is invalidated when the modifier list is mutated via WithModifiers,
	// AddModifier, or ClearModifiers.
	cachedChain *handshake.ModifierChain

	// chainCached indicates whether cachedChain has been computed.
	// Needed to distinguish "no modifiers (nil chain)" from "not yet computed".
	chainCached bool

	// chainMu protects cachedChain and chainCached from concurrent access.
	chainMu sync.Mutex
}

// NewConnConfig creates a new ConnConfig with sensible defaults.
func NewConnConfig(pattern string, initiator bool) *ConnConfig {
	flog("NewConnConfig", logger.Fields{"pattern": pattern, "initiator": initiator}).Debug("Creating new ConnConfig")
	return &ConnConfig{
		Pattern:   pattern,
		Initiator: initiator,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: baseconfig.DefaultHandshakeTimeout,
			ReadTimeout:      0,               // No timeout by default
			WriteTimeout:     0,               // No timeout by default
			HandshakeRetries: 0,               // Default to no retries; use HandshakeWithRetry() for retry semantics
			RetryBackoff:     1 * time.Second, // Default backoff 1 second
		},
	}
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519.
func (c *ConnConfig) WithStaticKey(key []byte) *ConnConfig {
	c.StaticKey = make([]byte, len(key))
	copy(c.StaticKey, key)
	return c
}

// WithRemoteKey sets the remote peer's static public key.
// key must be 32 bytes for Curve25519.
func (c *ConnConfig) WithRemoteKey(key []byte) *ConnConfig {
	c.RemoteKey = make([]byte, len(key))
	copy(c.RemoteKey, key)
	return c
}

// WithHandshakeTimeout sets the handshake timeout.
func (c *ConnConfig) WithHandshakeTimeout(timeout time.Duration) *ConnConfig {
	c.HandshakeTimeout = timeout
	return c
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (c *ConnConfig) WithReadTimeout(timeout time.Duration) *ConnConfig {
	c.ReadTimeout = timeout
	return c
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (c *ConnConfig) WithWriteTimeout(timeout time.Duration) *ConnConfig {
	c.WriteTimeout = timeout
	return c
}

// WithHandshakeRetries sets the number of handshake retry attempts
// used by HandshakeWithRetry. Handshake() always performs a single
// attempt regardless of this setting.
// Use 0 for no retries, -1 for infinite retries.
func (c *ConnConfig) WithHandshakeRetries(retries int) *ConnConfig {
	c.HandshakeRetries = retries
	return c
}

// WithRetryBackoff sets the base delay between retry attempts.
// Actual delay uses exponential backoff: delay = backoff * (2^attempt).
func (c *ConnConfig) WithRetryBackoff(backoff time.Duration) *ConnConfig {
	c.RetryBackoff = backoff
	return c
}

// WithModifiers sets the handshake modifiers for obfuscation and padding.
// Modifiers are applied in the order provided for outbound data and in
// reverse order for inbound data.
func (c *ConnConfig) WithModifiers(modifiers ...handshake.HandshakeModifier) *ConnConfig {
	c.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(c.Modifiers, modifiers)
	c.invalidateModifierCache()
	return c
}

// AddModifier appends a single modifier to the existing modifier list.
func (c *ConnConfig) AddModifier(modifier handshake.HandshakeModifier) *ConnConfig {
	c.Modifiers = append(c.Modifiers, modifier)
	c.invalidateModifierCache()
	return c
}

// ClearModifiers removes all modifiers from the configuration.
func (c *ConnConfig) ClearModifiers() *ConnConfig {
	c.Modifiers = nil
	c.invalidateModifierCache()
	return c
}

// GetModifierChain returns a ModifierChain containing all configured modifiers.
// Returns nil if no modifiers are configured. The chain is lazily initialized
// and cached; subsequent calls return the same instance until the modifier
// list is mutated via WithModifiers, AddModifier, or ClearModifiers.
func (c *ConnConfig) GetModifierChain() *handshake.ModifierChain {
	c.chainMu.Lock()
	defer c.chainMu.Unlock()
	if c.chainCached {
		return c.cachedChain
	}
	if len(c.Modifiers) == 0 {
		c.cachedChain = nil
	} else {
		c.cachedChain = handshake.NewModifierChain("config-chain", c.Modifiers...)
	}
	c.chainCached = true
	return c.cachedChain
}

// invalidateModifierCache resets the cached modifier chain so it will be
// recomputed on the next call to GetModifierChain.
func (c *ConnConfig) invalidateModifierCache() {
	c.chainMu.Lock()
	c.cachedChain = nil
	c.chainCached = false
	c.chainMu.Unlock()
}

// Validate checks if the configuration is valid and complete.
// Returns an error with context if validation fails.
func (c *ConnConfig) Validate() error {
	flog("ConnConfig.Validate", logger.Fields{"pattern": c.Pattern}).Debug("Validating ConnConfig")
	return validation.RunValidators(
		c.validatePattern,
		c.validateHandshakeTimeout,
		c.validateRetryConfig,
		c.validateStaticKeyLength,
		c.validateRemoteKeyLength,
	)
}

// validatePattern checks if the noise pattern is set, non-empty, and recognized.
func (c *ConnConfig) validatePattern() error {
	if err := validation.ValidatePattern(c.Pattern, "noise"); err != nil {
		return err
	}
	if _, err := parseHandshakePattern(c.Pattern); err != nil {
		return oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", c.Pattern).
			Wrapf(err, "unrecognized noise pattern")
	}
	return nil
}

// validateHandshakeTimeout checks if the handshake timeout is positive.
func (c *ConnConfig) validateHandshakeTimeout() error {
	return validation.ValidateHandshakeTimeout(c.HandshakeTimeout, "noise")
}

// validateRetryConfig checks if the retry configuration is valid.
func (c *ConnConfig) validateRetryConfig() error {
	return validation.ValidateRetryConfig(c.HandshakeRetries, c.RetryBackoff, "noise")
}

// validateStaticKeyLength checks if the static key has the correct length for Curve25519.
func (c *ConnConfig) validateStaticKeyLength() error {
	return validation.ValidateKeyLength(c.StaticKey, "static key", "noise")
}

// validateRemoteKeyLength checks if the remote key has the correct length for Curve25519.
func (c *ConnConfig) validateRemoteKeyLength() error {
	return validation.ValidateKeyLength(c.RemoteKey, "remote key", "noise")
}
