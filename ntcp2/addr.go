// Package ntcp2 provides NTCP2-specific implementations for the Noise Protocol Framework
// supporting I2P's NTCP2 transport protocol with router identity and session management.
package ntcp2

import (
	"fmt"
	"net"
	"sync"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Addr implements net.Addr for NTCP2 transport connections.
// It provides I2P-specific addressing information including router identity,
// destination hash, and session parameters for the NTCP2 protocol.
type Addr struct {
	// mu protects routerHash from concurrent access
	mu sync.RWMutex
	// underlying is the TCP network address
	underlying net.Addr
	// routerHash is the I2P router identity hash
	routerHash data.Hash
	// role indicates if this is an initiator or responder address
	role string
}

// NewNTCP2Addr creates a new NTCP2Addr with the specified TCP address and router hash.
// routerHash is the I2P router identity hash.
// role should be either "initiator" or "responder".
func NewNTCP2Addr(underlying net.Addr, routerHash data.Hash, role string) (*Addr, error) {
	flog("NewNTCP2Addr", logger.Fields{"role": role}).Debug("Creating new NTCP2Addr")
	if underlying == nil {
		return nil, oops.
			Code("INVALID_UNDERLYING_ADDR").
			In("ntcp2").
			Errorf("underlying address cannot be nil")
	}

	if role != "initiator" && role != "responder" {
		return nil, oops.
			Code("INVALID_ROLE").
			In("ntcp2").
			With("role", role).
			Errorf("role must be 'initiator' or 'responder'")
	}

	return &Addr{
		underlying: underlying,
		routerHash: routerHash,
		role:       role,
	}, nil
}

// Network returns "ntcp2" to identify this as an NTCP2 transport address.
// This implements the net.Addr interface requirement.
func (na *Addr) Network() string {
	return "ntcp2"
}

// String returns a string representation of the NTCP2 address.
// Format: "ntcp2://[router_hash]/[role]/[tcp_address][?dest=dest_hash]"
// Router hash and optional parameters are base64 encoded for readability.
func (na *Addr) String() string {
	if na.underlying == nil {
		return "ntcp2://invalid"
	}

	na.mu.RLock()
	routerB64 := i2pbase64.EncodeToString(na.routerHash[:])
	na.mu.RUnlock()

	return fmt.Sprintf("ntcp2://%s/%s/%s", routerB64, na.role, na.underlying.String())
}

// RouterHash returns the router identity hash.
func (na *Addr) RouterHash() data.Hash {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash
}

// IdentHash returns the router identity hash as a fixed-size [32]byte array.
func (na *Addr) IdentHash() [32]byte {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash.Bytes()
}

// SetRouterHash updates the router identity hash.
// This is used to update a placeholder zero hash after the Noise handshake
// reveals the remote peer's static key.
func (na *Addr) SetRouterHash(routerHash data.Hash) {
	flog("NTCP2Addr.SetRouterHash").Debug("Updating router identity hash")
	na.mu.Lock()
	na.routerHash = routerHash
	na.mu.Unlock()
}

// Role returns the connection role ("initiator" or "responder").
func (na *Addr) Role() string {
	return na.role
}

// UnderlyingAddr returns the underlying TCP network address.
func (na *Addr) UnderlyingAddr() net.Addr {
	return na.underlying
}
