package ssu2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRouter bundles a coordinator with the identity another router needs to
// address and authenticate it.
type testRouter struct {
	name string
	hash data.Hash
	pub  ed25519.PublicKey
	c    *Coordinator
}

// testNet is a synchronous in-process delivery fabric routing SendTargets by
// router hash and replaying the session's Verify-then-On dispatch contract.
type testNet struct {
	mu      sync.Mutex
	routers map[data.Hash]*testRouter
	trace   []string
	failed  []error
}

func newTestNet() *testNet {
	return &testNet{routers: make(map[data.Hash]*testRouter)}
}

func (n *testNet) register(r *testRouter) { n.routers[r.hash] = r }

// dispatch routes a SendTarget from src to its destination router.
func (n *testNet) dispatch(srcHash data.Hash, srcPub ed25519.PublicKey, t SendTarget) error {
	dst, ok := n.routers[t.RouterHash]
	if !ok {
		return fmt.Errorf("no route to %x", t.RouterHash[:4])
	}
	cb := dst.c.BuildCallbacks(srcHash, srcPub)
	for _, blk := range t.Blocks {
		if err := n.deliverBlock(dst, cb, blk); err != nil {
			n.mu.Lock()
			n.failed = append(n.failed, err)
			n.mu.Unlock()
			return err
		}
	}
	return nil
}

func (n *testNet) record(dst *testRouter, label string) {
	n.mu.Lock()
	n.trace = append(n.trace, dst.name+":"+label)
	n.mu.Unlock()
}

func (n *testNet) deliverBlock(dst *testRouter, cb DataHandlerCallbacks, blk *SSU2Block) error {
	switch blk.Type {
	case BlockTypePeerTest:
		pt, err := DecodePeerTestBlock(blk)
		if err != nil {
			return err
		}
		n.record(dst, "PeerTest/"+pt.MessageCode.String())
		if err := cb.VerifyPeerTestSignature(pt); err != nil {
			return fmt.Errorf("verify peer test (%s) at %s: %w", pt.MessageCode, dst.name, err)
		}
		return cb.OnPeerTest(blk)
	case BlockTypeRelayRequest:
		rr, err := DecodeRelayRequest(blk)
		if err != nil {
			return err
		}
		n.record(dst, "RelayRequest")
		if err := cb.VerifyRelayRequestSignature(rr); err != nil {
			return fmt.Errorf("verify relay request at %s: %w", dst.name, err)
		}
		return cb.OnRelayRequest(blk)
	case BlockTypeRelayIntro:
		ri, err := DecodeRelayIntro(blk)
		if err != nil {
			return err
		}
		n.record(dst, "RelayIntro")
		if err := cb.VerifyRelayIntroSignature(ri); err != nil {
			return fmt.Errorf("verify relay intro at %s: %w", dst.name, err)
		}
		return cb.OnRelayIntro(blk)
	case BlockTypeRelayResponse:
		rp, err := DecodeRelayResponse(blk)
		if err != nil {
			return err
		}
		n.record(dst, "RelayResponse")
		if err := cb.VerifyRelayResponseSignature(rp); err != nil {
			return fmt.Errorf("verify relay response at %s: %w", dst.name, err)
		}
		return cb.OnRelayResponse(blk)
	default:
		return nil
	}
}

func mkRouterHash(pub ed25519.PublicKey) data.Hash {
	return data.Hash(sha256.Sum256(pub))
}

// makeTestRouter builds a router with a fresh keypair and a coordinator wired
// into the given net.
func makeTestRouter(t *testing.T, n *testNet, name string, ext *net.UDPAddr, cfgMut func(*CoordinatorConfig)) *testRouter {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	hash := mkRouterHash(pub)

	keyring := func(h data.Hash) (ed25519.PublicKey, bool) {
		n.mu.Lock()
		r, ok := n.routers[h]
		n.mu.Unlock()
		if !ok {
			return nil, false
		}
		return r.pub, true
	}

	cfg := CoordinatorConfig{
		LocalRouterHash: hash,
		SigningKey:      priv,
		KeyResolver:     keyring,
		PeerTest:        NewPeerTestManager(nil),
		Relay:           NewRelayManager(nil),
		LocalExternal:   ext,
		Dispatcher: DispatcherFunc(func(tg SendTarget) error {
			return n.dispatch(hash, pub, tg)
		}),
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	coord, err := NewCoordinator(cfg)
	require.NoError(t, err)

	r := &testRouter{name: name, hash: hash, pub: pub, c: coord}
	n.register(r)
	return r
}

func udp(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// TestCoordinatorPeerTestFullExchange drives the four signed peer-test messages
// across three in-process routers (Alice -> Bob -> Charlie -> Bob -> Alice) and
// asserts every signature verifies and the message sequence is correct.
func TestCoordinatorPeerTestFullExchange(t *testing.T) {
	tn := newTestNet()

	aliceExt := udp("203.0.113.10", 21000)
	bobExt := udp("198.51.100.20", 22000)
	charlieExt := udp("192.0.2.30", 23000)

	bob := makeTestRouter(t, tn, "Bob", bobExt, nil)
	charlie := makeTestRouter(t, tn, "Charlie", charlieExt, nil)

	// Bob selects Charlie as the responder.
	bob.c.cfg.SelectCharlie = func() (data.Hash, *net.UDPAddr, bool) {
		return charlie.hash, charlieExt, true
	}

	alice := makeTestRouter(t, tn, "Alice", aliceExt, nil)

	nonce, err := alice.c.StartPeerTest(bob.hash, bobExt, aliceExt)
	require.NoError(t, err)
	require.NotZero(t, nonce)

	tn.mu.Lock()
	failed := append([]error(nil), tn.failed...)
	trace := append([]string(nil), tn.trace...)
	tn.mu.Unlock()

	require.Empty(t, failed, "no verification/dispatch errors expected: %v", failed)
	assert.Equal(t, []string{
		"Bob:PeerTest/Request",
		"Charlie:PeerTest/Relay",
		"Bob:PeerTest/Response",
		"Alice:PeerTest/Result",
	}, trace)
}

// TestCoordinatorRelayFullExchange drives the relay sequence
// (RelayRequest -> RelayIntro -> RelayResponse -> forwarded RelayResponse)
// across Alice, Bob and Charlie and asserts signatures verify end to end.
func TestCoordinatorRelayFullExchange(t *testing.T) {
	tn := newTestNet()

	aliceExt := udp("203.0.113.10", 21000)
	bobExt := udp("198.51.100.20", 22000)
	charlieExt := udp("192.0.2.30", 23000)

	bob := makeTestRouter(t, tn, "Bob", bobExt, nil)
	charlie := makeTestRouter(t, tn, "Charlie", charlieExt, nil)
	alice := makeTestRouter(t, tn, "Alice", aliceExt, nil)

	const relayTag = uint32(0x1234abcd)
	// Bob has agreed to introduce Charlie under relayTag.
	require.NoError(t, bob.c.RegisterRelayClient(relayTag, charlie.hash, charlieExt))

	nonce, err := alice.c.StartRelay(bob.hash, bobExt, charlie.hash, relayTag, aliceExt)
	require.NoError(t, err)
	require.NotZero(t, nonce)

	tn.mu.Lock()
	failed := append([]error(nil), tn.failed...)
	trace := append([]string(nil), tn.trace...)
	tn.mu.Unlock()

	require.Empty(t, failed, "no verification/dispatch errors expected: %v", failed)
	assert.Equal(t, []string{
		"Bob:RelayRequest",
		"Charlie:RelayIntro",
		"Bob:RelayResponse",
		"Alice:RelayResponse",
	}, trace)
}

// TestCoordinatorIntroducerOptionsRoundTrip verifies that introducers
// registered with the relay manager are published into RouterAddress options
// and parse back correctly.
func TestCoordinatorIntroducerOptionsRoundTrip(t *testing.T) {
	tn := newTestNet()
	bobExt := udp("198.51.100.20", 22000)
	bob := makeTestRouter(t, tn, "Bob", bobExt, nil)

	charlieExt := udp("192.0.2.30", 23000)
	charliePub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	charlieHash := mkRouterHash(charliePub)
	const relayTag = uint32(99)

	require.NoError(t, bob.c.RegisterRelayClient(relayTag, charlieHash, charlieExt))

	opts, err := bob.c.IntroducerOptions()
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	parsed, err := wire.IntroducersFromRouterAddress(opts)
	require.NoError(t, err)
	require.Len(t, parsed, 1)
	assert.Equal(t, relayTag, parsed[0].RelayTag)
	assert.Equal(t, charlieHash[:], parsed[0].RouterHash)
}

// TestCoordinatorRejectsBadPeerTestSignature ensures a tampered peer-test
// signature is rejected by verification rather than acted upon.
func TestCoordinatorRejectsBadPeerTestSignature(t *testing.T) {
	tn := newTestNet()
	bobExt := udp("198.51.100.20", 22000)
	charlieExt := udp("192.0.2.30", 23000)
	aliceExt := udp("203.0.113.10", 21000)

	bob := makeTestRouter(t, tn, "Bob", bobExt, nil)
	charlie := makeTestRouter(t, tn, "Charlie", charlieExt, nil)
	bob.c.cfg.SelectCharlie = func() (data.Hash, *net.UDPAddr, bool) {
		return charlie.hash, charlieExt, true
	}
	alice := makeTestRouter(t, tn, "Alice", aliceExt, nil)

	// Build a valid msg 1 signed by Alice, then corrupt the signature before
	// delivery; verification (using Alice's authenticated key) must reject it.
	cb := bob.c.BuildCallbacks(alice.hash, alice.pub)

	ts := uint32(1_700_000_000)
	sig, err := SignPeerTest(alice.c.cfg.SigningKey, bob.hash, nil, ssu2ProtocolVersion, 42, ts, uint16(aliceExt.Port), aliceExt.IP)
	require.NoError(t, err)
	sig[0] ^= 0xFF // tamper

	pt := &PeerTestBlock{
		MessageCode: PeerTestRequest,
		Version:     ssu2ProtocolVersion,
		Nonce:       42,
		Timestamp:   ts,
		AlicePort:   uint16(aliceExt.Port),
		AliceIP:     aliceExt.IP.To4(),
		Signature:   sig,
	}
	err = cb.VerifyPeerTestSignature(pt)
	require.Error(t, err, "tampered signature must be rejected")
}
