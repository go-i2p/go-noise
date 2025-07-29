// Package ntcp2 provides NTCP2-specific implementations for the Noise Protocol Framework
// supporting I2P's NTCP2 transport protocol with router identity and session management.
package ntcp2

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/samber/oops"
)

// NTCP2Addr implements net.Addr for NTCP2 transport connections.
// It provides I2P-specific addressing information including router identity,
// destination hash, and session parameters for the NTCP2 protocol.
// Moved from: ntcp2/addr.go
type NTCP2Addr struct {
	// underlying is the TCP network address
	underlying net.Addr
	// routerHash is the 32-byte I2P router identity hash
	routerHash []byte
	// destHash is the 32-byte destination hash (optional, nil for router-to-router)
	destHash []byte
	// sessionTag is the 8-byte session tag for this connection (optional)
	sessionTag []byte
	// role indicates if this is an initiator or responder address
	role string
}

// NewNTCP2Addr creates a new NTCP2Addr with the specified TCP address and router hash.
// routerHash must be exactly 32 bytes representing the I2P router identity.
// role should be either "initiator" or "responder".
func NewNTCP2Addr(underlying net.Addr, routerHash []byte, role string) (*NTCP2Addr, error) {
	if underlying == nil {
		return nil, oops.
			Code("INVALID_UNDERLYING_ADDR").
			In("ntcp2").
			Errorf("underlying address cannot be nil")
	}

	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	if role != "initiator" && role != "responder" {
		return nil, oops.
			Code("INVALID_ROLE").
			In("ntcp2").
			With("role", role).
			Errorf("role must be 'initiator' or 'responder'")
	}

	// Make defensive copy of router hash
	hash := make([]byte, 32)
	copy(hash, routerHash)

	return &NTCP2Addr{
		underlying: underlying,
		routerHash: hash,
		role:       role,
	}, nil
}

// WithDestinationHash sets the destination hash for tunnel connections.
// destHash must be exactly 32 bytes or nil for router-to-router connections.
func (na *NTCP2Addr) WithDestinationHash(destHash []byte) (*NTCP2Addr, error) {
	if destHash != nil && len(destHash) != 32 {
		return nil, oops.
			Code("INVALID_DEST_HASH").
			In("ntcp2").
			With("hash_length", len(destHash)).
			Errorf("destination hash must be exactly 32 bytes or nil")
	}

	// Create new instance with defensive copy
	newAddr := &NTCP2Addr{
		underlying: na.underlying,
		routerHash: make([]byte, 32),
		role:       na.role,
	}
	copy(newAddr.routerHash, na.routerHash)

	if destHash != nil {
		newAddr.destHash = make([]byte, 32)
		copy(newAddr.destHash, destHash)
	}

	if na.sessionTag != nil {
		newAddr.sessionTag = make([]byte, 8)
		copy(newAddr.sessionTag, na.sessionTag)
	}

	return newAddr, nil
}

// WithSessionTag sets the session tag for this connection.
// sessionTag must be exactly 8 bytes or nil.
func (na *NTCP2Addr) WithSessionTag(sessionTag []byte) (*NTCP2Addr, error) {
	if sessionTag != nil && len(sessionTag) != 8 {
		return nil, oops.
			Code("INVALID_SESSION_TAG").
			In("ntcp2").
			With("tag_length", len(sessionTag)).
			Errorf("session tag must be exactly 8 bytes or nil")
	}

	// Create new instance with defensive copy
	newAddr := &NTCP2Addr{
		underlying: na.underlying,
		routerHash: make([]byte, 32),
		role:       na.role,
	}
	copy(newAddr.routerHash, na.routerHash)

	if na.destHash != nil {
		newAddr.destHash = make([]byte, 32)
		copy(newAddr.destHash, na.destHash)
	}

	if sessionTag != nil {
		newAddr.sessionTag = make([]byte, 8)
		copy(newAddr.sessionTag, sessionTag)
	}

	return newAddr, nil
}

// Network returns "ntcp2" to identify this as an NTCP2 transport address.
// This implements the net.Addr interface requirement.
func (na *NTCP2Addr) Network() string {
	return "ntcp2"
}

// String returns a string representation of the NTCP2 address.
// Format: "ntcp2://[router_hash]/[role]/[tcp_address][?dest=dest_hash][&session=session_tag]"
// Router hash and optional parameters are base64 encoded for readability.
func (na *NTCP2Addr) String() string {
	if na.underlying == nil {
		return "ntcp2://invalid"
	}

	// Base64 encode router hash for readability
	routerB64 := base64.URLEncoding.EncodeToString(na.routerHash)

	// Build base address
	addr := fmt.Sprintf("ntcp2://%s/%s/%s", routerB64, na.role, na.underlying.String())

	// Add optional destination hash
	if na.destHash != nil {
		destB64 := base64.URLEncoding.EncodeToString(na.destHash)
		addr += "?dest=" + destB64
	}

	// Add optional session tag
	if na.sessionTag != nil {
		separator := "?"
		if na.destHash != nil {
			separator = "&"
		}
		sessionB64 := base64.URLEncoding.EncodeToString(na.sessionTag)
		addr += separator + "session=" + sessionB64
	}

	return addr
}

// RouterHash returns a copy of the router identity hash.
// The returned slice is a defensive copy to prevent external modification.
func (na *NTCP2Addr) RouterHash() []byte {
	if na.routerHash == nil {
		return nil
	}
	hash := make([]byte, 32)
	copy(hash, na.routerHash)
	return hash
}

// DestinationHash returns a copy of the destination hash, or nil for router-to-router connections.
// The returned slice is a defensive copy to prevent external modification.
func (na *NTCP2Addr) DestinationHash() []byte {
	if na.destHash == nil {
		return nil
	}
	hash := make([]byte, 32)
	copy(hash, na.destHash)
	return hash
}

// SessionTag returns a copy of the session tag, or nil if not set.
// The returned slice is a defensive copy to prevent external modification.
func (na *NTCP2Addr) SessionTag() []byte {
	if na.sessionTag == nil {
		return nil
	}
	tag := make([]byte, 8)
	copy(tag, na.sessionTag)
	return tag
}

// Role returns the connection role ("initiator" or "responder").
func (na *NTCP2Addr) Role() string {
	return na.role
}

// UnderlyingAddr returns the underlying TCP network address.
func (na *NTCP2Addr) UnderlyingAddr() net.Addr {
	return na.underlying
}

// IsRouterToRouter returns true if this is a router-to-router connection (no destination hash).
func (na *NTCP2Addr) IsRouterToRouter() bool {
	return na.destHash == nil
}

// IsTunnelConnection returns true if this is a tunnel connection (has destination hash).
func (na *NTCP2Addr) IsTunnelConnection() bool {
	return na.destHash != nil
}
