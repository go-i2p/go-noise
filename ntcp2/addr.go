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
//   - hs2+hs3: an extra MixHash() before handshake messages 2 and 3, mixing
//     in the *cleartext padding* that follows messages 1 and 2. The name is
//     the message index, not "hash the key": ntcp2.rst writes it as
//     "// MixHash(padding)" in the KDF pseudocode for both steps. Padding is
//     outside the AEAD frame, so mixing it in is what makes tampering with it
//     cause the next message to fail.
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
//     scrambled with SipHash-2-4, the same trick obfs4 uses. This length
//     obfuscation is NTCP2-only; SSU2 has no length field at all because its
//     datagram length is the message length.
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
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
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
	// mu protects routerHash and hashResolved from concurrent access
	mu sync.RWMutex
	// underlying is the TCP network address
	underlying net.Addr
	// routerHash is the I2P router identity hash. Until the real identity is
	// known it holds a placeholder (see hashResolved).
	routerHash data.Hash
	// hashResolved is true when routerHash is the real SHA-256 of the peer's
	// RouterIdentity, and false when it is a placeholder derived from the peer's
	// static key (or not yet known at all).
	hashResolved bool
	// role indicates if this is an initiator or responder address
	role string
}

// NewNTCP2Addr creates an Addr from a TCP address, a router hash, and a
// role. The router hash identifies the I2P router on the other end of the
// connection. The role must be "initiator" (this side dialed out) or
// "responder" (this side accepted the connection).
//
// A non-zero hash is treated as the real router identity hash; a zero hash is
// treated as "not yet known". Use [NewNTCP2AddrResolved] when the hash is
// known to be a placeholder (e.g. SHA-256 of the peer's static key), so that
// [Addr.RouterHashResolved] reports it accurately.
func NewNTCP2Addr(underlying net.Addr, routerHash data.Hash, role string) (*Addr, error) {
	return newNTCP2Addr(underlying, routerHash, role, !routerHash.IsZero())
}

// NewNTCP2AddrResolved creates an Addr and records whether routerHash is the
// peer's real router identity hash (resolved true) or a stand-in that must not
// be used as an identity or as the AES obfuscation key (resolved false).
func NewNTCP2AddrResolved(underlying net.Addr, routerHash data.Hash, role string, resolved bool) (*Addr, error) {
	return newNTCP2Addr(underlying, routerHash, role, resolved)
}

func newNTCP2Addr(underlying net.Addr, routerHash data.Hash, role string, resolved bool) (*Addr, error) {
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
		underlying:   underlying,
		routerHash:   routerHash,
		hashResolved: resolved,
		role:         role,
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

// RouterHash returns the router hash of the router on the other end of the
// connection.
//
// Naming caveat: until the peer's RouterIdentity has been seen, this may be a
// *placeholder* — SHA-256 of the peer's 32-byte Noise static key, or the zero
// hash — and not the I2P router hash. The real RH is defined over the serialized
// RouterIdentity (ntcp2.md uses RH_A/RH_B for exactly that value, and it is what
// NTCP2's AES ephemeral-key obfuscation is keyed with), so a placeholder must
// never be used as an obfuscation key or as a netdb identity. Call
// [Addr.RouterHashResolved] to tell the two apart. It exists only so the
// transport layer can correlate a connection with a peer it has not yet looked
// up.
func (na *Addr) RouterHash() data.Hash {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash
}

// RouterHashResolved reports whether [Addr.RouterHash] holds the peer's real
// router identity hash.
//
// It is false before the handshake reveals the peer's RouterIdentity, while the
// address still carries a placeholder. The router transport layer is expected to
// call [Addr.SetRouterHash] once it has parsed and verified the RouterInfo block
// from handshake message 3; at that point this starts returning true.
func (na *Addr) RouterHashResolved() bool {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.hashResolved
}

// IdentHash returns the router identity hash as a fixed-size [32]byte
// array, which is easier to use in Go code than a slice.
func (na *Addr) IdentHash() [32]byte {
	na.mu.RLock()
	defer na.mu.RUnlock()
	return na.routerHash.Bytes()
}

// SetRouterHash records the peer's real router identity hash, computed as
// SHA-256 over the serialized RouterIdentity. Calling this marks the address as
// resolved ([Addr.RouterHashResolved] starts returning true), so it should only
// be used once the RouterInfo block has been parsed and verified.
func (na *Addr) SetRouterHash(routerHash data.Hash) {
	flog("NTCP2Addr.SetRouterHash").Debug("Updating router identity hash")
	na.mu.Lock()
	na.routerHash = routerHash
	na.hashResolved = true
	na.mu.Unlock()
}

// SetPlaceholderRouterHash stores a stand-in hash that is NOT the peer's router
// identity (typically SHA-256 of the peer's Noise static key), used to
// correlate a connection with a peer that has not yet been looked up. The
// address stays unresolved, so callers cannot mistake it for RH_A/RH_B.
func (na *Addr) SetPlaceholderRouterHash(hash data.Hash) {
	flog("NTCP2Addr.SetPlaceholderRouterHash").Debug("Storing placeholder router hash")
	na.mu.Lock()
	na.routerHash = hash
	na.hashResolved = false
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
