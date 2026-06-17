// Package noise provides a high-level wrapper around the go-i2p/noise package
// implementing net.Conn, net.Listener, and net.Addr interfaces for the Noise Protocol Framework.
// It supports extensible handshake modification for implementing I2P's NTCP2 and SSU2 transport protocols.
package conn

import (
	"fmt"
	"net"

	"github.com/go-i2p/logger"
)

// Addr implements net.Addr for Noise Protocol connections.
// It wraps an underlying net.Addr and adds Noise-specific addressing information.
type Addr struct {
	// underlying is the wrapped network address (TCP, UDP, etc.)
	underlying net.Addr
	// pattern is the Noise protocol pattern being used (e.g., "Noise_XX_25519_AESGCM_SHA256")
	pattern string
	// role indicates if this is an initiator or responder address
	role string
}

// NewNoiseAddr creates a new NoiseAddr wrapping an underlying network address.
// pattern should be a valid Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256").
// role should be either "initiator" or "responder"; other values are logged as warnings.
func NewNoiseAddr(underlying net.Addr, pattern, role string) *Addr {
	flog("NewNoiseAddr", logger.Fields{"pattern": pattern, "role": role}).Debug("Creating new NoiseAddr")

	// Validate role if provided (for consistency with ntcp2 and ssu2)
	if role != "" && role != "initiator" && role != "responder" {
		flog("NewNoiseAddr", logger.Fields{"role": role}).
			Warn("invalid role value; expected 'initiator' or 'responder'")
	}

	return &Addr{
		underlying: underlying,
		pattern:    pattern,
		role:       role,
	}
}

// Network returns the network type, prefixed with "noise+" to indicate Noise wrapping.
// For example, "noise+tcp" for Noise over TCP or "noise+udp" for Noise over UDP.
func (na *Addr) Network() string {
	if na.underlying == nil {
		return "noise"
	}
	return "noise+" + na.underlying.Network()
}

// String returns a string representation of the Noise address.
// Format: "noise://[pattern]/[role]/[underlying_address]"
// Example: "noise://Noise_XX_25519_AESGCM_SHA256/initiator/192.168.1.1:8080"
func (na *Addr) String() string {
	if na.underlying == nil {
		return fmt.Sprintf("noise://%s/%s", na.pattern, na.role)
	}
	return fmt.Sprintf("noise://%s/%s/%s", na.pattern, na.role, na.underlying.String())
}

// Underlying returns the wrapped network address.
// This allows access to the original address when needed.
func (na *Addr) Underlying() net.Addr {
	return na.underlying
}

// Pattern returns the Noise protocol pattern.
func (na *Addr) Pattern() string {
	return na.pattern
}

// Role returns the role (initiator or responder).
func (na *Addr) Role() string {
	return na.role
}
