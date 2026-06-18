// Package ssu2 provides SSU2-specific implementations for the Noise Protocol Framework
// supporting I2P's SSU2 transport protocol with UDP-based connections and NAT traversal.
package config

import (
	"crypto/rand"
	"fmt"
	"net"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Addr implements net.Addr for SSU2 transport connections.
// It provides I2P-specific addressing information including router identity,
// connection ID, and optional introducer support for NAT traversal.
//
// AUDIT 3.4 — Placeholder RouterHash for Responder Connections:
// For responder connections (listener-accepted), the initial routerHash is a
// placeholder derived from the peer's ephemeral key (SHA256 of ephemeral).
// This is because at SessionRequest time, the responder cannot yet authenticate
// the peer's static identity. The placeholder is sufficient for pre-establishment
// routing/dedup (which keys on initiatorConnID + remoteAddr, not RouterHash).
//
// **CRITICAL: After the handshake completes and the peer is authenticated, the
// router layer MUST call UpdateRouterHash(realHash) to replace the placeholder
// with the true identity hash.** This is accessed via SSU2Conn.GetSSU2Addr()
// after the connection enters StateEstablished.
//
// Failure to update the hash may cause:
// - Duplicate inbound sessions per peer if other dedup mechanisms key on RouterHash
// - Incorrect peer identification in higher layers that cache or index sessions by RouterHash
// - Stale session entries that never expire if keying on the placeholder hash
//
// For initiator connections (dial path), the RouterHash is supplied upfront via
// SSU2Config and does not require updating; UpdateRouterHash should not be called.
type SSU2Addr struct {
	// underlying is the UDP network address
	underlying net.Addr
	// routerHash is the I2P router identity hash (placeholder for responders until UpdateRouterHash is called)
	routerHash data.Hash
	// connectionID is the 8-byte SSU2 connection identifier
	connectionID uint64
	// role indicates if this is an initiator or responder address
	role string
	// destHash is the destination hash (optional, nil for router-to-router)
	destHash *data.Hash
	// introducerAddr is the UDP address of an introducer for NAT traversal (optional)
	introducerAddr net.Addr
}

// NewSSU2Addr creates a new SSU2Addr with the specified UDP address, router hash, connection ID, and role.
// routerHash is the I2P router identity hash.
// connID should be a cryptographically secure random 8-byte value (use GenerateConnectionID).
// role should be either "initiator" or "responder".
func NewSSU2Addr(underlying net.Addr, routerHash data.Hash, connID uint64, role string) (*SSU2Addr, error) {
	flog("NewSSU2Addr", logger.Fields{"role": role, "connID": connID}).Debug("Creating new SSU2Addr")
	if underlying == nil {
		return nil, oops.
			Code("INVALID_UNDERLYING_ADDR").
			In("ssu2").
			Errorf("underlying address cannot be nil")
	}

	// M-6: connID==0 is rejected because SSU2Addr represents established session
	// addresses. The spec uses dest_conn_id=0 only in SessionRequest headers
	// (initiator doesn't know responder's ID yet), which is handled at the
	// packet layer, not the addressing layer.
	if connID == 0 {
		return nil, oops.
			Code("INVALID_CONNECTION_ID").
			In("ssu2").
			Errorf("connection ID cannot be zero (reserved for handshake)")
	}

	if role != "initiator" && role != "responder" {
		return nil, oops.
			Code("INVALID_ROLE").
			In("ssu2").
			With("role", role).
			Errorf("role must be 'initiator' or 'responder'")
	}

	return &SSU2Addr{
		underlying:   underlying,
		routerHash:   routerHash,
		connectionID: connID,
		role:         role,
	}, nil
}

// WithDestinationHash sets the destination hash for tunnel connections.
// Returns a new SSU2Addr instance (immutable pattern).
func (sa *SSU2Addr) WithDestinationHash(destHash data.Hash) *SSU2Addr {
	flog("WithDestinationHash", logger.Fields{"connID": sa.connectionID}).Debug("WithDestinationHash: setting destination hash")
	return sa.copyWithModifications(func(newAddr *SSU2Addr) {
		h := destHash
		newAddr.destHash = &h
	})
}

// WithIntroducer sets the introducer address for NAT traversal.
// introducerAddr is the UDP address of the introducer service.
// Returns a new SSU2Addr instance (immutable pattern).
func (sa *SSU2Addr) WithIntroducer(introducerAddr net.Addr) (*SSU2Addr, error) {
	flog("WithIntroducer", logger.Fields{"introducerAddr": introducerAddr}).Debug("WithIntroducer: setting introducer address")
	if introducerAddr == nil {
		return nil, oops.
			Code("INVALID_INTRODUCER_ADDR").
			In("ssu2").
			Errorf("introducer address cannot be nil")
	}

	return sa.copyWithModifications(func(newAddr *SSU2Addr) {
		newAddr.introducerAddr = introducerAddr
	}), nil
}

// copyWithModifications creates a defensive copy and applies modifications.
// Helper function to maintain immutability pattern while reducing code duplication.
func (sa *SSU2Addr) copyWithModifications(modify func(*SSU2Addr)) *SSU2Addr {
	flog("copyWithModifications", logger.Fields{"connID": sa.connectionID}).Debug("copyWithModifications: creating defensive copy of SSU2Addr")
	newAddr := &SSU2Addr{
		underlying:   sa.underlying,
		connectionID: sa.connectionID,
		role:         sa.role,
		routerHash:   sa.routerHash,
	}

	if sa.destHash != nil {
		h := *sa.destHash
		newAddr.destHash = &h
	}

	if sa.introducerAddr != nil {
		newAddr.introducerAddr = sa.introducerAddr
	}

	modify(newAddr)
	return newAddr
}

// UpdateRouterHash replaces the router hash with the given value.
// **This is the REQUIRED hook for the router layer to supply the real RouterHash
// for responder connections (listener-accepted).**
//
// AUDIT 3.4 — Placeholder RouterHash Hook:
// For responder connections, the SSU2Addr is initially created with a placeholder
// routerHash (SHA256 of ephemeral key) because the responder cannot yet authenticate
// the peer's identity from the SessionRequest alone. After the handshake completes
// and the peer is authenticated (at StateEstablished), the router layer MUST call
// UpdateRouterHash(realHash) to replace the placeholder with the true peer identity hash.
//
// **Access pattern:** After establishing a responder connection:
//
//	conn := listener.Accept() // or await connection from listener
//	addr := conn.GetSSU2Addr()
//	realHash := computeRouterHash(conn) // Your router layer computes real hash
//	addr.UpdateRouterHash(realHash)
//
// **Why this matters:** Session dedup in go-noise keys on (initiatorConnID, remoteAddr),
// so the placeholder does not affect go-noise's dedup correctness. However:
// - Higher-level dedup systems may key on RouterHash
// - Peer identification/caching may use RouterHash as a stable identifier
// - Failure to update could cause duplicate sessions in router layer accounting
//
// For initiator connections (DialSSU2, DialSSU2WithConn), the RouterHash is supplied
// upfront via SSU2Config and this method should NOT be called.
func (sa *SSU2Addr) UpdateRouterHash(hash data.Hash) {
	sa.routerHash = hash
}

// Network returns "ssu2" to identify this as an SSU2 transport address.
// This implements the net.Addr interface requirement.
func (sa *SSU2Addr) Network() string {
	return "ssu2"
}

// String returns a string representation of the SSU2 address.
// Format: "ssu2://[router_hash]:[conn_id]/[role]/[udp_address][?dest=dest_hash][&introducer=introducer_addr]"
// Router hash is base64 encoded for readability.
func (sa *SSU2Addr) String() string {
	if sa.underlying == nil {
		return "ssu2://invalid"
	}

	// I2P base64 encode router hash for readability
	routerB64 := i2pbase64.EncodeToString(sa.routerHash[:])

	// Build base address with connection ID
	addr := fmt.Sprintf("ssu2://%s:%d/%s/%s",
		routerB64, sa.connectionID, sa.role, sa.underlying.String())

	// Add optional destination hash
	if sa.destHash != nil {
		destB64 := i2pbase64.EncodeToString(sa.destHash[:])
		addr += "?dest=" + destB64
	}

	// Add optional introducer address
	if sa.introducerAddr != nil {
		separator := "?"
		if sa.destHash != nil {
			separator = "&"
		}
		addr += separator + "introducer=" + sa.introducerAddr.String()
	}

	return addr
}

// RouterHash returns the router identity hash.
func (sa *SSU2Addr) RouterHash() data.Hash {
	return sa.routerHash
}

// ConnectionID returns the SSU2 connection identifier.
func (sa *SSU2Addr) ConnectionID() uint64 {
	return sa.connectionID
}

// Role returns the connection role ("initiator" or "responder").
func (sa *SSU2Addr) Role() string {
	return sa.role
}

// UnderlyingAddr returns the underlying UDP network address.
func (sa *SSU2Addr) UnderlyingAddr() net.Addr {
	return sa.underlying
}

// DestinationHash returns the destination hash, or nil for router-to-router connections.
func (sa *SSU2Addr) DestinationHash() *data.Hash {
	if sa.destHash == nil {
		return nil
	}
	h := *sa.destHash
	return &h
}

// IntroducerAddr returns the introducer address, or nil if no introducer is used.
func (sa *SSU2Addr) IntroducerAddr() net.Addr {
	return sa.introducerAddr
}

// IsDirectConnection returns true if this is a direct connection (no introducer).
func (sa *SSU2Addr) IsDirectConnection() bool {
	return sa.introducerAddr == nil
}

// IsIntroducedConnection returns true if this connection uses an introducer for NAT traversal.
func (sa *SSU2Addr) IsIntroducedConnection() bool {
	return sa.introducerAddr != nil
}

// IsRouterToRouter returns true if this is a router-to-router connection (no destination hash).
func (sa *SSU2Addr) IsRouterToRouter() bool {
	return sa.destHash == nil
}

// IsTunnelConnection returns true if this is a tunnel connection (has destination hash).
func (sa *SSU2Addr) IsTunnelConnection() bool {
	return sa.destHash != nil
}

// GenerateConnectionID generates a cryptographically secure random connection ID.
// The ID is guaranteed to be non-zero (zero is reserved for handshake).
// This is a convenience function for creating SSU2 addresses.
func GenerateConnectionID() (uint64, error) {
	var id uint64
	buf := make([]byte, 8)

	// Loop until we get a non-zero ID (probability of zero is negligible)
	for id == 0 {
		if _, err := rand.Read(buf); err != nil {
			return 0, oops.
				Code("RANDOM_GENERATION_FAILED").
				In("ssu2").
				Wrap(err)
		}

		// Convert bytes to uint64 (big-endian)
		id = uint64(buf[0])<<56 | uint64(buf[1])<<48 |
			uint64(buf[2])<<40 | uint64(buf[3])<<32 |
			uint64(buf[4])<<24 | uint64(buf[5])<<16 |
			uint64(buf[6])<<8 | uint64(buf[7])
	}

	return id, nil
}

// NewMockSSU2Addr creates a minimal SSU2Addr with only the connectionID set.
// It is intended for use in tests that need a placeholder address.
func NewMockSSU2Addr(connID uint64) *SSU2Addr {
	return &SSU2Addr{connectionID: connID}
}
