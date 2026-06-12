// Package baseconfig provides the shared timeout, retry, and modifier fields
// that are common to all Noise configuration types in this module
// (ConnConfig, ListenerConfig, ntcp2.Config, ssu2/config.SSU2Config).
//
// Embedding BaseHandshakeConfig in each concrete config type ensures the
// fields are defined in one place, eliminating the risk of inconsistent
// field names or default values across the four config types.
package baseconfig

import (
	"time"

	"github.com/go-i2p/go-noise/handshake"
)

// DefaultHandshakeTimeout is the default maximum time for handshake completion
// across all Noise configuration types.
const DefaultHandshakeTimeout = 30 * time.Second

// BaseHandshakeConfig holds the five timeout/retry fields and the modifier
// slice that are duplicated across every Noise config type. Embed this struct
// in each concrete config to promote these fields into the outer type.
//
// The embedding approach preserves Go's builder pattern: the concrete type's
// With* methods still return the concrete pointer, while the underlying field
// assignments continue to work via field promotion (e.g. c.HandshakeTimeout
// still resolves to c.BaseHandshakeConfig.HandshakeTimeout).
type BaseHandshakeConfig struct {
	// HandshakeTimeout is the maximum time to wait for handshake completion.
	// Default: 30 seconds.
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake.
	// Default: no timeout (0).
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake.
	// Default: no timeout (0).
	WriteTimeout time.Duration

	// HandshakeRetries is the number of handshake retry attempts.
	// 0 = no retries, -1 = infinite retries.
	HandshakeRetries int

	// RetryBackoff is the base delay between retry attempts.
	// Actual delay uses exponential backoff: delay = RetryBackoff * (2^attempt).
	// Default: 1 second.
	RetryBackoff time.Duration

	// Modifiers is a list of handshake modifiers for obfuscation and padding.
	// Modifiers are applied in order during outbound processing and in reverse
	// order during inbound processing. Default: empty (no modifiers).
	Modifiers []handshake.HandshakeModifier
}

// RoleString returns "initiator" when initiator is true, "responder" otherwise.
// Used as a log field value when logging connection role information.
func RoleString(initiator bool) string {
	if initiator {
		return "initiator"
	}
	return "responder"
}
