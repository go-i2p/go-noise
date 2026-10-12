// This file implements the Coordinator, which wires SSU2 peer tests and
// relays into live sessions.
//
// # What the Coordinator does
//
// SSU2 has two extra features beyond carrying I2NP messages: peer testing
// (checking whether a peer can be reached from outside its network) and
// relaying (having a third router forward messages between two peers that
// cannot reach each other directly). The state machines for these features
// live in the go-i2p/path package (re-exported by this package). The
// Coordinator connects those state machines to a live session: it turns
// inbound PeerTest and Relay blocks into responses, and it verifies the
// signatures on those blocks.
//
// # Layering
//
// The Coordinator never resolves sessions or imports the router
// (go-i2p/go-i2p). It only decides *what* to send and *to which peer*.
// Actual delivery is delegated to an injected Dispatcher, which the router
// implements.
//
// # Threading model
//
// A single Coordinator is shared by the local router across all of its SSU2
// sessions. BuildCallbacks is called once per established session with that
// peer's router hash and Ed25519 signing key. It returns closures that read
// and write the Coordinator's shared, mutex-guarded state. Peer-test and
// relay flows span three peers and three distinct sessions (Alice<->Bob,
// Bob<->Charlie), so cross-session state such as the per-nonce context lives
// on the shared Coordinator, not on a per-connection object.
//
// # Peer-test signature semantics
//
// In a peer test, three routers take the roles of Alice (initiator), Bob
// (relay), and Charlie (responder). Bob never signs; he forwards Alice's
// signature (message 1 -> message 2) and Charlie's signature (message 3 ->
// message 4), only changing the message code and the included router hash.
// Only Alice (messages 1/2) and Charlie (messages 3/4) produce signatures.
// The same is true of relaying: Bob forwards Alice's request signature into
// the RelayIntro; only Alice and Charlie sign.
//
// See [I2P Spec: SSU2](https://i2p.net/en/docs/specs/ssu2/) for details.
package ssu2

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ssu2ProtocolVersion is the SSU2 version byte carried in peer-test and relay
// messages (1 = SSU1, 2 = SSU2).
const ssu2ProtocolVersion uint8 = 2

// relayTokenLen is the length of the session-request token Charlie returns in
// an accepted RelayResponse.
const relayTokenLen = 8

// PeerKeyResolver looks up a peer's Ed25519 signing public key from its
// router hash (the 32-byte identity that identifies a router on the I2P
// network). It is used to verify signatures. It returns ok=false when the key
// is unknown; in that case verification fails closed (the signature is
// rejected). The router backs this with its network database; go-noise never
// resolves identities itself.
type PeerKeyResolver func(routerHash data.Hash) (ed25519.PublicKey, bool)

// SendTarget describes a set of outbound SSU2 blocks and where they must be
// delivered. RouterHash identifies a known peer (the common case); Addr is set
// for out-of-session delivery, such as a hole-punch probe sent to a raw
// endpoint that has no session yet.
type SendTarget struct {
	// RouterHash is the destination peer's router identity hash. Zero when the
	// destination is identified only by Addr.
	RouterHash data.Hash

	// Addr is the destination UDP endpoint, used for out-of-session delivery.
	// nil when the destination is identified only by RouterHash.
	Addr *net.UDPAddr

	// Blocks are the SSU2 blocks to deliver to the destination.
	Blocks []*SSU2Block
}

// Dispatcher delivers Coordinator-produced blocks to a peer. The router
// implements this interface; it owns session resolution and the actual UDP
// write. Keeping delivery behind an interface preserves the layering rule
// that go-noise must not depend on the router.
type Dispatcher interface {
	Dispatch(target SendTarget) error
}

// DispatcherFunc adapts an ordinary function to the Dispatcher interface.
type DispatcherFunc func(SendTarget) error

// Dispatch implements Dispatcher.
func (f DispatcherFunc) Dispatch(t SendTarget) error { return f(t) }

// CharlieSelector picks a responder ("Charlie") for a peer test that the local
// router is relaying as "Bob". It returns ok=false when no suitable peer is
// available, in which case the peer test is dropped. The router supplies this
// from its peer database.
type CharlieSelector func() (hash data.Hash, addr *net.UDPAddr, ok bool)

// CoordinatorConfig configures a Coordinator. Dispatcher, PeerTest and Relay
// are required; the remaining fields enable specific roles and default to safe
// no-ops or fail-closed behavior when omitted.
type CoordinatorConfig struct {
	// LocalRouterHash is the local router's identity hash. It is used as the
	// Bob hash when the local router acts as Bob, and as the Alice or Charlie
	// hash when it is the initiator or responder.
	LocalRouterHash data.Hash

	// SigningKey is the local router's Ed25519 signing private key. It is used
	// when the local router is Alice (signs peer-test and relay requests) or
	// Charlie (signs peer-test and relay responses). It is never used when
	// acting purely as Bob, because Bob never signs.
	SigningKey ed25519.PrivateKey

	// KeyResolver resolves a remote router hash to its signing public key. It
	// is used to verify forwarded signatures whose signer is not the
	// directly-connected peer (for example, Charlie verifying Alice's
	// signature in a RelayIntro). If nil, such verifications fail closed.
	KeyResolver PeerKeyResolver

	// Dispatcher delivers outbound blocks. Required.
	Dispatcher Dispatcher

	// PeerTest is the shared peer-test state manager. Required.
	PeerTest *PeerTestManager

	// Relay is the shared relay/introducer state manager. Required.
	Relay *RelayManager

	// Introducers is the optional introducer registry used when the local
	// router is an introduced peer publishing its introducers.
	Introducers *IntroducerRegistry

	// SelectCharlie picks a responder when relaying a peer test as Bob. If nil,
	// inbound peer-test requests (message 1) are acknowledged-as-dropped.
	SelectCharlie CharlieSelector

	// LocalExternal is the local router's believed external endpoint, embedded
	// as Charlie's address in relay responses. May be nil if unknown.
	LocalExternal *net.UDPAddr

	// Now returns the current time; defaults to time.Now. Injectable for tests.
	Now func() time.Time
}

// ptRole identifies the local router's role in a specific peer-test or relay
// exchange, keyed by nonce.
type ptRole uint8

const (
	roleUnknown ptRole = iota
	roleAlice          // initiator
	roleBob            // relay
	roleCharlie        // responder
)

// nonceContext records the cross-peer identities the local router has
// legitimately learned for a given test/relay nonce. Each router populates
// this only from its own knowledge: Alice from the peers she chose, Bob from
// the session (Alice) plus the relay-tag registry (Charlie), Charlie from the
// forwarded RelayIntro / msg 2 router hash.
type nonceContext struct {
	role        ptRole
	aliceHash   data.Hash
	charlieHash data.Hash
	aliceAddr   *net.UDPAddr
	charlieAddr *net.UDPAddr
	aliceIP     net.IP
	alicePort   uint16
	relayTag    uint32
	createdAt   time.Time
}

// relayClient records a peer for which the local router has agreed to act as
// an introducer (Bob), mapping the allocated relay tag to that peer's router
// hash and address so inbound RelayRequests can be resolved and verified.
type relayClient struct {
	hash data.Hash
	addr *net.UDPAddr
}

// Coordinator wires the peer-test and relay state machines into session
// callbacks. A single instance is shared across all of the local router's
// SSU2 sessions.
type Coordinator struct {
	cfg CoordinatorConfig

	mu      sync.Mutex
	nonces  map[uint32]*nonceContext
	clients map[uint32]relayClient // relay tag -> introduced peer
}

// NewCoordinator creates a Coordinator. Dispatcher, PeerTest and Relay are
// required; it returns an error if any of them is missing.
func NewCoordinator(cfg CoordinatorConfig) (*Coordinator, error) {
	if cfg.Dispatcher == nil {
		return nil, oops.Code("ssu2_coordinator_config").Errorf("Dispatcher is required")
	}
	if cfg.PeerTest == nil {
		return nil, oops.Code("ssu2_coordinator_config").Errorf("PeerTest manager is required")
	}
	if cfg.Relay == nil {
		return nil, oops.Code("ssu2_coordinator_config").Errorf("Relay manager is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Coordinator{
		cfg:     cfg,
		nonces:  make(map[uint32]*nonceContext),
		clients: make(map[uint32]relayClient),
	}, nil
}

// RegisterRelayClient records that the local router (acting as Bob) has agreed
// to act as an introducer for the peer identified by routerHash/addr,
// reachable via the given relay tag. A relay tag is a small number that
// identifies an introducer relationship. It both records the tag-to-hash
// mapping the Coordinator needs to verify inbound RelayRequests and registers
// the peer with the shared relay manager.
func (c *Coordinator) RegisterRelayClient(relayTag uint32, routerHash data.Hash, addr *net.UDPAddr) error {
	if relayTag == 0 {
		return oops.Code("ssu2_relay_client").Errorf("relay tag must be non-zero")
	}
	if addr == nil {
		return oops.Code("ssu2_relay_client").Errorf("addr is required")
	}
	c.mu.Lock()
	c.clients[relayTag] = relayClient{hash: routerHash, addr: addr}
	c.mu.Unlock()
	if err := c.cfg.Relay.RegisterIntroducer(addr, routerHash, relayTag); err != nil {
		return oops.Wrapf(err, "register relay client with manager")
	}
	return nil
}

// IntroducerOptions builds the SSU2 RouterAddress option map that advertises
// the local router's current introducers, so that introduced peers can be
// contacted through them. It bridges the shared relay manager's live
// introducer set to the wire encoding (the itag/ih/iexp option keys). Expired
// or invalid entries are skipped by the wire encoder.
func (c *Coordinator) IntroducerOptions() (map[string]string, error) {
	infos := c.cfg.Relay.GetIntroducers()
	published := make([]wire.PublishedIntroducer, 0, len(infos))
	for _, info := range infos {
		if info == nil {
			continue
		}
		hash := make([]byte, len(info.RouterHash))
		copy(hash, info.RouterHash[:])
		published = append(published, wire.PublishedIntroducer{
			RouterHash: hash,
			RelayTag:   info.RelayTag,
			ExpiresAt:  info.ExpiresAt,
		})
	}
	opts, err := wire.IntroducersToRouterAddressOptions(published)
	if err != nil {
		return nil, oops.Wrapf(err, "encode introducer options")
	}
	return opts, nil
}

// resolveKey returns the signing public key for hash. When hash equals the
// directly-connected peer's hash, the peer's key is preferred (it was
// authenticated by the handshake). Otherwise the configured KeyResolver is
// consulted.
func (c *Coordinator) resolveKey(hash, peerHash data.Hash, peerKey ed25519.PublicKey) (ed25519.PublicKey, bool) {
	if hash == peerHash && peerKey != nil {
		return peerKey, true
	}
	if c.cfg.KeyResolver == nil {
		return nil, false
	}
	return c.cfg.KeyResolver(hash)
}

// ctxFor returns the nonce context for nonce, creating it if absent.
func (c *Coordinator) ctxFor(nonce uint32) *nonceContext {
	nc, ok := c.nonces[nonce]
	if !ok {
		nc = &nonceContext{createdAt: c.cfg.Now()}
		c.nonces[nonce] = nc
	}
	return nc
}

// newToken returns a fresh random session-request token.
func newToken() ([]byte, error) {
	tok := make([]byte, relayTokenLen)
	if _, err := rand.Read(tok); err != nil {
		return nil, oops.Wrapf(err, "generate relay token")
	}
	return tok, nil
}

// hashFromSlice converts a 32-byte slice to a data.Hash, returning an error on
// the wrong length.
func hashFromSlice(b []byte) (data.Hash, error) {
	var h data.Hash
	if len(b) != len(h) {
		return h, oops.Code("ssu2_hash").With("len", len(b)).Errorf("router hash must be %d bytes", len(h))
	}
	copy(h[:], b)
	return h, nil
}

// flogc is a small helper that returns a structured coordinator log entry.
func flogc(fn string, fields logger.Fields) *logger.Entry {
	if fields == nil {
		fields = logger.Fields{}
	}
	return flog(fn, fields)
}
