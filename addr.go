// Package noise provides a high-level wrapper around the flynn/noise package
// implementing net.Conn, net.Listener, and net.Addr interfaces for the Noise Protocol Framework.
// It supports extensible handshake modification for implementing I2P's NTCP2 and SSU2 transport protocols.
package noise

import (
	"fmt"
	"net"
)

// NoiseAddr implements net.Addr for Noise Protocol connections.
// It wraps an underlying net.Addr and adds Noise-specific addressing information.
type NoiseAddr struct {
	// underlying is the wrapped network address (TCP, UDP, etc.)
	underlying net.Addr
	// pattern is the Noise protocol pattern being used (e.g., "Noise_XX_25519_AESGCM_SHA256")
	pattern string
	// role indicates if this is an initiator or responder address
	role string
}

// NewNoiseAddr creates a new NoiseAddr wrapping an underlying network address.
// pattern should be a valid Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256").
// role should be either "initiator" or "responder".
func NewNoiseAddr(underlying net.Addr, pattern, role string) *NoiseAddr {
	return &NoiseAddr{
		underlying: underlying,
		pattern:    pattern,
		role:       role,
	}
}

// Network returns the network type, prefixed with "noise+" to indicate Noise wrapping.
// For example, "noise+tcp" for Noise over TCP or "noise+udp" for Noise over UDP.
func (na *NoiseAddr) Network() string {
	if na.underlying == nil {
		return "noise"
	}
	return "noise+" + na.underlying.Network()
}

// String returns a string representation of the Noise address.
// Format: "noise://[pattern]/[role]/[underlying_address]"
// Example: "noise://Noise_XX_25519_AESGCM_SHA256/initiator/192.168.1.1:8080"
func (na *NoiseAddr) String() string {
	if na.underlying == nil {
		return fmt.Sprintf("noise://%s/%s", na.pattern, na.role)
	}
	return fmt.Sprintf("noise://%s/%s/%s", na.pattern, na.role, na.underlying.String())
}

// Underlying returns the wrapped network address.
// This allows access to the original address when needed.
func (na *NoiseAddr) Underlying() net.Addr {
	return na.underlying
}

// Pattern returns the Noise protocol pattern.
func (na *NoiseAddr) Pattern() string {
	return na.pattern
}

// Role returns the role (initiator or responder).
func (na *NoiseAddr) Role() string {
	return na.role
}
