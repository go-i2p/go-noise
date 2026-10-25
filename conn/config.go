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

// ConnConfig holds the settings for a Noise connection. It combines the
// common handshake settings (timeouts, retries, and modifiers) with the
// Noise-specific fields that describe which pattern to use and which side of
// the handshake this connection is on.
//
// A ConnConfig is normally built with NewConnConfig and the With* methods,
// then passed to NewNoiseConn. See the package documentation for an overview
// of how the pattern and modifiers work together.
type ConnConfig struct {
	// BaseHandshakeConfig embeds the shared timeout, retry, and modifier fields
	// common to all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern to use, for example
	// "Noise_XX_25519_AESGCM_SHA256". The pattern names the key exchange
	// steps and the cipher suite in one string.
	Pattern string

	// Initiator reports whether this connection starts the handshake
	// (true) or waits for the other side to start it (false).
	Initiator bool

	// StaticKey is this peer's long-term private static key. It must be 32
	// bytes for Curve25519.
	StaticKey []byte

	// RemoteKey is the other peer's static public key. It must be 32 bytes
	// for Curve25519. Some patterns require it; others do not.
	RemoteKey []byte

	// CipherSuite names the Noise cipher suite used for the handshake. If
	// nil, it defaults to DH25519 + CipherChaChaPoly + SHA256, which is the
	// suite NTCP2, SSU2 and the ECIES ratchet all mandate (ntcp2.md / ssu2.md
	// §"Noise Protocol Framework": "Cipher Function: ChaChaPoly"; ecies.md
	// §"3) AEAD (ChaChaPoly)"). Set it explicitly only if you need a different
	// suite for a non-I2P peer.
	CipherSuite noise.CipherSuite

	// ProtocolName overrides the auto-generated Noise protocol name used to
	// initialize the symmetric state. When set, this exact byte string is
	// used instead of constructing "Noise_" + Pattern.Name + "_" +
	// CipherSuite.Name(). Protocols like NTCP2 need this because they use a
	// non-standard protocol name (for example,
	// "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"). If nil or empty,
	// the standard Noise protocol name is constructed as usual.
	ProtocolName []byte

	// AdditionalSymmetricKeyLabels names the labels used to derive
	// Additional Symmetric Keys (ASKs) when the handshake splits into send
	// and receive cipher states, per the go-i2p/noise fork's SplitWithASK (an
	// I2P extension; ASK is not part of base Noise spec §10.3, which is
	// Zero-RTT). Each label produces a
	// 32-byte key derived from the chaining key. The derived keys are
	// available via Conn.AdditionalSymmetricKeys() after the handshake
	// completes.
	//
	// For NTCP2, this should be set to [][]byte{[]byte("ask")} to derive the
	// ask_master used for SipHash key derivation.
	AdditionalSymmetricKeyLabels [][]byte

	// PostHandshakeHook is an optional callback run after the Noise
	// handshake succeeds but before the connection moves to the Established
	// state. It lets a protocol layer (for example, NTCP2) derive extra key
	// material from the handshake hash, set up data-phase obfuscators, or
	// run any post-handshake checks.
	//
	// If the hook returns an error, the handshake is treated as failed and
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

// NewConnConfig creates a new ConnConfig with sensible defaults. The pattern
// names the Noise protocol to use, and initiator selects which side of the
// handshake this connection is on.
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

// WithStaticKey sets this peer's long-term private static key. The key must
// be 32 bytes for Curve25519.
func (c *ConnConfig) WithStaticKey(key []byte) *ConnConfig {
	c.StaticKey = make([]byte, len(key))
	copy(c.StaticKey, key)
	return c
}

// WithRemoteKey sets the other peer's static public key. The key must be 32
// bytes for Curve25519.
func (c *ConnConfig) WithRemoteKey(key []byte) *ConnConfig {
	c.RemoteKey = make([]byte, len(key))
	copy(c.RemoteKey, key)
	return c
}

// WithHandshakeTimeout sets how long the handshake may take before it is
// considered to have failed.
func (c *ConnConfig) WithHandshakeTimeout(timeout time.Duration) *ConnConfig {
	c.HandshakeTimeout = timeout
	return c
}

// WithReadTimeout sets how long a read may block before it times out. A zero
// value means no timeout.
func (c *ConnConfig) WithReadTimeout(timeout time.Duration) *ConnConfig {
	c.ReadTimeout = timeout
	return c
}

// WithWriteTimeout sets how long a write may block before it times out. A
// zero value means no timeout.
func (c *ConnConfig) WithWriteTimeout(timeout time.Duration) *ConnConfig {
	c.WriteTimeout = timeout
	return c
}

// WithHandshakeRetries sets how many times HandshakeWithRetry may retry a
// failed handshake. Handshake() always makes a single attempt regardless of
// this setting. Use 0 for no retries and -1 for unlimited retries.
func (c *ConnConfig) WithHandshakeRetries(retries int) *ConnConfig {
	c.HandshakeRetries = retries
	return c
}

// WithRetryBackoff sets the base delay between handshake retry attempts. The
// actual delay grows with each attempt using exponential backoff:
// delay = backoff * (2^attempt).
func (c *ConnConfig) WithRetryBackoff(backoff time.Duration) *ConnConfig {
	c.RetryBackoff = backoff
	return c
}

// WithModifiers replaces the configured handshake modifiers with the given
// list. Modifiers are the extension point that lets protocols like NTCP2 and
// SSU2 add obfuscation and padding on top of the shared Noise core. They are
// applied in the order provided for outbound data and in reverse order for
// inbound data.
func (c *ConnConfig) WithModifiers(modifiers ...handshake.HandshakeModifier) *ConnConfig {
	c.chainMu.Lock()
	c.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(c.Modifiers, modifiers)
	c.cachedChain = nil
	c.chainCached = false
	c.chainMu.Unlock()
	return c
}

// AddModifier appends a single modifier to the end of the existing modifier
// list.
func (c *ConnConfig) AddModifier(modifier handshake.HandshakeModifier) *ConnConfig {
	c.chainMu.Lock()
	c.Modifiers = append(c.Modifiers, modifier)
	c.cachedChain = nil
	c.chainCached = false
	c.chainMu.Unlock()
	return c
}

// ClearModifiers removes all modifiers from the configuration.
//
// Note: this method is not currently used by any caller in this module.
func (c *ConnConfig) ClearModifiers() *ConnConfig {
	c.chainMu.Lock()
	c.Modifiers = nil
	c.cachedChain = nil
	c.chainCached = false
	c.chainMu.Unlock()
	return c
}

// GetModifierChain returns a ModifierChain containing all configured
// modifiers, or nil if none are configured. The chain is built on first use
// and then cached; repeated calls return the same instance until the modifier
// list is changed via WithModifiers, AddModifier, or ClearModifiers.
func (c *ConnConfig) GetModifierChain() *handshake.ModifierChain {
	c.chainMu.Lock()
	defer c.chainMu.Unlock()
	if c.chainCached {
		return c.cachedChain
	}
	c.cachedChain = buildModifierChain(c.Modifiers)
	c.chainCached = true
	return c.cachedChain
}

func buildModifierChain(modifiers []handshake.HandshakeModifier) *handshake.ModifierChain {
	if len(modifiers) == 0 {
		return nil
	}
	return handshake.NewModifierChain("config-chain", modifiers...)
}

// invalidateModifierCache resets the cached modifier chain so it will be
// recomputed on the next call to GetModifierChain. It is kept for any future
// caller that mutates c.Modifiers directly under chainMu itself;
// WithModifiers, AddModifier, and ClearModifiers now inline this instead of
// calling it separately, so the whole read-modify-write of c.Modifiers
// happens under one lock acquisition.
func (c *ConnConfig) invalidateModifierCache() {
	c.chainMu.Lock()
	c.cachedChain = nil
	c.chainCached = false
	c.chainMu.Unlock()
}

// Validate checks that the configuration is complete and consistent. It
// returns a descriptive error if anything is missing or wrong, such as an
// unrecognized pattern or a static key of the wrong length.
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
