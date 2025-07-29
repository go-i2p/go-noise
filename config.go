package noise

import (
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// ConnConfig contains configuration for creating a NoiseConn.
// It follows the builder pattern for optional configuration and validation.
type ConnConfig struct {
	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	Initiator bool

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteKey is the remote peer's static public key (32 bytes for Curve25519)
	// Required for some patterns, optional for others
	RemoteKey []byte

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

	// Modifiers is a list of handshake modifiers for obfuscation and padding
	// Modifiers are applied in order during outbound processing and in reverse
	// order during inbound processing. Default: empty (no modifiers)
	Modifiers []handshake.HandshakeModifier
}

// NewConnConfig creates a new ConnConfig with sensible defaults.
func NewConnConfig(pattern string, initiator bool) *ConnConfig {
	return &ConnConfig{
		Pattern:          pattern,
		Initiator:        initiator,
		HandshakeTimeout: 30 * time.Second,
		ReadTimeout:      0,               // No timeout by default
		WriteTimeout:     0,               // No timeout by default
		HandshakeRetries: 3,               // Default to 3 retries
		RetryBackoff:     1 * time.Second, // Default backoff 1 second
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

// WithHandshakeRetries sets the number of handshake retry attempts.
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
	return c
}

// AddModifier appends a single modifier to the existing modifier list.
func (c *ConnConfig) AddModifier(modifier handshake.HandshakeModifier) *ConnConfig {
	c.Modifiers = append(c.Modifiers, modifier)
	return c
}

// ClearModifiers removes all modifiers from the configuration.
func (c *ConnConfig) ClearModifiers() *ConnConfig {
	c.Modifiers = nil
	return c
}

// GetModifierChain returns a ModifierChain containing all configured modifiers.
// Returns nil if no modifiers are configured.
func (c *ConnConfig) GetModifierChain() *handshake.ModifierChain {
	if len(c.Modifiers) == 0 {
		return nil
	}
	return handshake.NewModifierChain("config-chain", c.Modifiers...)
}

// Validate checks if the configuration is valid and complete.
// Returns an error with context if validation fails.
func (c *ConnConfig) Validate() error {
	if err := c.validatePattern(); err != nil {
		return err
	}

	if err := c.validateHandshakeTimeout(); err != nil {
		return err
	}

	if err := c.validateRetryConfig(); err != nil {
		return err
	}

	if err := c.validateStaticKeyLength(); err != nil {
		return err
	}

	if err := c.validateRemoteKeyLength(); err != nil {
		return err
	}

	return nil
}

// validatePattern checks if the noise pattern is set and non-empty.
func (c *ConnConfig) validatePattern() error {
	if c.Pattern == "" {
		return oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("config", c).
			Errorf("noise pattern is required")
	}
	return nil
}

// validateHandshakeTimeout checks if the handshake timeout is positive.
func (c *ConnConfig) validateHandshakeTimeout() error {
	if c.HandshakeTimeout <= 0 {
		return oops.
			Code("INVALID_TIMEOUT").
			In("noise").
			With("timeout", c.HandshakeTimeout).
			With("pattern", c.Pattern).
			Errorf("handshake timeout must be positive")
	}
	return nil
}

// validateRetryConfig checks if the retry configuration is valid.
func (c *ConnConfig) validateRetryConfig() error {
	if c.HandshakeRetries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In("noise").
			With("retries", c.HandshakeRetries).
			With("pattern", c.Pattern).
			Errorf("handshake retries must be >= -1 (-1 = infinite, 0 = no retries)")
	}

	if c.RetryBackoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In("noise").
			With("backoff", c.RetryBackoff).
			With("pattern", c.Pattern).
			Errorf("retry backoff must be non-negative")
	}

	return nil
}

// validateStaticKeyLength checks if the static key has the correct length for Curve25519.
func (c *ConnConfig) validateStaticKeyLength() error {
	if len(c.StaticKey) > 0 && len(c.StaticKey) != 32 {
		return oops.
			Code("INVALID_KEY_LENGTH").
			In("noise").
			With("key_length", len(c.StaticKey)).
			With("pattern", c.Pattern).
			Errorf("static key must be 32 bytes for Curve25519")
	}
	return nil
}

// validateRemoteKeyLength checks if the remote key has the correct length for Curve25519.
func (c *ConnConfig) validateRemoteKeyLength() error {
	if len(c.RemoteKey) > 0 && len(c.RemoteKey) != 32 {
		return oops.
			Code("INVALID_KEY_LENGTH").
			In("noise").
			With("key_length", len(c.RemoteKey)).
			With("pattern", c.Pattern).
			Errorf("remote key must be 32 bytes for Curve25519")
	}
	return nil
}
