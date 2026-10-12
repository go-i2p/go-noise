// Package ntcp2 implements NTCP2, the transport protocol I2P routers use to
// talk to each other over TCP.
//
// # How it works
//
// NTCP2 is built on the Noise Protocol Framework, a set of rules for
// securely exchanging messages. Before any real data flows, the two routers
// run a short handshake. The handshake lets each side prove who it is and
// agree on shared secrets. After that, every message is encrypted and
// authenticated, so each router can trust both the sender and the content.
//
// NTCP2 uses the Noise pattern
// Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256. The parts mean:
//
//   - XK: the base pattern. The side that starts the connection already
//     knows the other side's long-term public key, which keeps the
//     handshake short.
//   - 25519: key exchange on the X25519 curve (RFC 7748).
//   - ChaChaPoly: encryption with ChaCha20-Poly1305 (RFC 7539), which also
//     checks that messages were not tampered with.
//   - SHA256: the hash function used to turn shared secrets into keys.
//
// # NTCP2 extensions
//
// NTCP2 adds a few I2P-specific twists on top of plain Noise_XK:
//
//   - The short-lived public keys in the first two handshake messages are
//     hidden with AES encryption, using a key based on the router's
//     identity.
//   - Random padding is added to messages 1 and 2 (outside the encryption)
//     and to message 3 and every data frame (inside the encryption), so
//     message sizes do not give away how much data is really being sent.
//   - Data frames start with a two-byte length field, and that field is
//     scrambled with SipHash-2-4, the same trick obfs4 uses.
//
// The handshake follows a fixed order: SessionRequest, SessionCreated,
// SessionConfirmed. Only after those three messages do the routers exchange
// data frames. Every NTCP2 message is at most 65537 bytes.
//
// # Using this package
//
// DialNTCP2 connects to a remote router; ListenNTCP2 accepts incoming
// connections. Both hand back a Conn, which works like a net.Conn: use Read
// and Write to send and receive I2P messages. A Config controls the
// handshake timeout, padding, and other options. Protocol constants (sizes,
// limits, block types) live in constants.go.
//
// See [I2P Spec: NTCP2](https://i2p.net/en/docs/specs/ntcp2/) for details.
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
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

// Addr is the address of an NTCP2 connection. It wraps the plain TCP
// address and adds I2P-specific information: which router is on the other
// end (its router hash) and whether this side started the connection
// ("initiator") or accepted it ("responder").
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

// NewNTCP2Addr creates an Addr from a TCP address, a router hash, and a
// role. The router hash identifies the I2P router on the other end of the
// connection. The role must be "initiator" (this side dialed out) or
// "responder" (this side accepted the connection).
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

// Network returns "ntcp2", identifying this as an NTCP2 address.
func (na *Addr) Network() string {
	return "ntcp2"
}

// String returns the address as a readable string in the form
// "ntcp2://[router_hash]/[role]/[tcp_address]". The router hash is
// base64-encoded so it is safe to print.
func (na *Addr) String() string {
	if na.underlying == nil {
		return "ntcp2://invalid"
	}

	na.mu.RLock()
	routerB64 := i2pbase64.EncodeToString(na.routerHash[:])
	na.mu.RUnlock()

	return fmt.Sprintf("ntcp2://%s/%s/%s", routerB64, na.role, na.underlying.String())
}

// RouterHash returns the identity hash of the router on the other end of
// the connection.
func (na *Addr) RouterHash() data.Hash {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash
}

// IdentHash returns the router identity hash as a fixed-size [32]byte
// array, which is easier to use in Go code than a slice.
func (na *Addr) IdentHash() [32]byte {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash.Bytes()
}

// SetRouterHash updates the router identity hash. The handshake reveals the
// remote router's real identity, so this is used to replace the placeholder
// zero hash that was set before the handshake finished.
func (na *Addr) SetRouterHash(routerHash data.Hash) {
	flog("NTCP2Addr.SetRouterHash").Debug("Updating router identity hash")
	na.mu.Lock()
	na.routerHash = routerHash
	na.mu.Unlock()
}

// Role returns "initiator" if this side started the connection, or
// "responder" if this side accepted it.
func (na *Addr) Role() string {
	return na.role
}

// UnderlyingAddr returns the plain TCP address that this NTCP2 address
// wraps.
func (na *Addr) UnderlyingAddr() net.Addr {
	return na.underlying
}
