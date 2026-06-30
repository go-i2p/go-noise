package ssu2

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// BuildCallbacks returns DataHandlerCallbacks bound to a single SSU2 session
// with the given peer (identified by its router hash and authenticated Ed25519
// signing key). The returned closures read and mutate the shared Coordinator
// state, so cross-session peer-test/relay flows resolve correctly.
//
// remoteKey may be nil if the peer's signing key is not yet known; in that case
// any verification whose signer is the directly-connected peer fails closed.
func (c *Coordinator) BuildCallbacks(remoteHash data.Hash, remoteKey ed25519.PublicKey) DataHandlerCallbacks {
	return DataHandlerCallbacks{
		VerifyPeerTestSignature: func(b *PeerTestBlock) error {
			return c.verifyPeerTest(remoteHash, remoteKey, b)
		},
		VerifyRelayRequestSignature: func(b *RelayRequestBlock) error {
			return c.verifyRelayRequest(remoteHash, remoteKey, b)
		},
		VerifyRelayResponseSignature: func(b *RelayResponseBlock) error {
			return c.verifyRelayResponse(remoteHash, remoteKey, b)
		},
		VerifyRelayIntroSignature: func(b *RelayIntroBlock) error {
			return c.verifyRelayIntro(remoteHash, remoteKey, b)
		},
		OnPeerTest: func(raw *SSU2Block) error {
			return c.onPeerTest(remoteHash, raw)
		},
		OnRelayRequest: func(raw *SSU2Block) error {
			return c.onRelayRequest(remoteHash, raw)
		},
		OnRelayResponse: func(raw *SSU2Block) error {
			return c.onRelayResponse(remoteHash, raw)
		},
		OnRelayIntro: func(raw *SSU2Block) error {
			return c.onRelayIntro(remoteHash, raw)
		},
	}
}

// ─── Signature verification ────────────────────────────────────────────────

func (c *Coordinator) verifyPeerTest(remoteHash data.Hash, remoteKey ed25519.PublicKey, b *PeerTestBlock) error {
	if b == nil {
		return oops.Code("ssu2_peertest_verify").Errorf("nil block")
	}
	var bobHash data.Hash
	var aliceHashPtr *data.Hash
	var signerKey ed25519.PublicKey
	var ok bool

	switch b.MessageCode {
	case PeerTestRequest: // msg 1: local = Bob, signer = Alice (connected peer)
		bobHash = c.cfg.LocalRouterHash
		signerKey, ok = remoteKey, remoteKey != nil
	case PeerTestRelay: // msg 2: local = Charlie, signer = Alice (block hash)
		if b.RouterHash == nil {
			return oops.Code("ssu2_peertest_verify").Errorf("msg 2 missing router hash")
		}
		bobHash = remoteHash // connected peer is Bob
		signerKey, ok = c.resolveKey(*b.RouterHash, remoteHash, remoteKey)
	case PeerTestResponse: // msg 3: local = Bob, signer = Charlie (connected peer)
		bobHash = c.cfg.LocalRouterHash
		ah, found := c.lookupAliceHash(b.Nonce)
		if !found {
			return oops.Code("ssu2_peertest_verify").With("nonce", b.Nonce).Errorf("no test context for msg 3")
		}
		aliceHashPtr = &ah
		signerKey, ok = remoteKey, remoteKey != nil
	case PeerTestResult: // msg 4: local = Alice, signer = Charlie (block hash)
		if b.RouterHash == nil {
			return oops.Code("ssu2_peertest_verify").Errorf("msg 4 missing router hash")
		}
		bobHash = remoteHash // connected peer is Bob
		ah := c.cfg.LocalRouterHash
		aliceHashPtr = &ah
		signerKey, ok = c.resolveKey(*b.RouterHash, remoteHash, remoteKey)
	default:
		// Messages 5-7 (probe/reply/confirmation) carry optional signatures and
		// are delivered for hole-punch handling; nothing to verify here.
		return nil
	}

	if !ok || signerKey == nil {
		return oops.Code("ssu2_peertest_verify").With("msg", uint8(b.MessageCode)).Errorf("no signing key for peer test signer")
	}
	valid, err := VerifyPeerTestSignature(signerKey, b.Signature, bobHash, aliceHashPtr, b.Version, b.Nonce, b.Timestamp, b.AlicePort, net.IP(b.AliceIP))
	if err != nil {
		return oops.Wrapf(err, "verify peer test signature")
	}
	if !valid {
		return oops.Code("ssu2_peertest_verify").With("msg", uint8(b.MessageCode)).Errorf("invalid peer test signature")
	}
	return nil
}

func (c *Coordinator) verifyRelayRequest(remoteHash data.Hash, remoteKey ed25519.PublicKey, b *RelayRequestBlock) error {
	if b == nil {
		return oops.Code("ssu2_relayreq_verify").Errorf("nil block")
	}
	// local = Bob; signer = Alice (connected peer); charlie hash from relay tag.
	charlieHash, ok := c.lookupRelayClientHash(b.RelayTag)
	if !ok {
		return oops.Code("ssu2_relayreq_verify").With("relayTag", b.RelayTag).Errorf("unknown relay tag")
	}
	if remoteKey == nil {
		return oops.Code("ssu2_relayreq_verify").Errorf("no signing key for relay request signer")
	}
	valid, err := VerifyRelayRequestSignature(remoteKey, b.Signature, c.cfg.LocalRouterHash, charlieHash, b.Nonce, b.RelayTag, b.Timestamp, b.Version, b.AlicePort, b.AliceIP)
	if err != nil {
		return oops.Wrapf(err, "verify relay request signature")
	}
	if !valid {
		return oops.Code("ssu2_relayreq_verify").Errorf("invalid relay request signature")
	}
	return nil
}

func (c *Coordinator) verifyRelayIntro(remoteHash data.Hash, remoteKey ed25519.PublicKey, b *RelayIntroBlock) error {
	if b == nil {
		return oops.Code("ssu2_relayintro_verify").Errorf("nil block")
	}
	// local = Charlie; signer = Alice (block hash). The intro carries Alice's
	// original relay-request signature, so the same signed data and verifier
	// apply, with Bob = connected peer and Charlie = local.
	aliceHash, err := hashFromSlice(b.AliceRouterHash)
	if err != nil {
		return oops.Wrapf(err, "relay intro alice hash")
	}
	signerKey, ok := c.resolveKey(aliceHash, remoteHash, remoteKey)
	if !ok || signerKey == nil {
		return oops.Code("ssu2_relayintro_verify").Errorf("no signing key for relay intro signer")
	}
	valid, err := VerifyRelayRequestSignature(signerKey, b.Signature, remoteHash, c.cfg.LocalRouterHash, b.Nonce, b.AliceRelayTag, b.Timestamp, b.Version, b.AlicePort, b.AliceIP)
	if err != nil {
		return oops.Wrapf(err, "verify relay intro signature")
	}
	if !valid {
		return oops.Code("ssu2_relayintro_verify").Errorf("invalid relay intro signature")
	}
	return nil
}

func (c *Coordinator) verifyRelayResponse(remoteHash data.Hash, remoteKey ed25519.PublicKey, b *RelayResponseBlock) error {
	if b == nil {
		return oops.Code("ssu2_relayresp_verify").Errorf("nil block")
	}
	if len(b.Signature) == 0 {
		// No signature present (e.g. a bare Bob rejection without csz); nothing
		// to verify.
		return nil
	}
	role, _ := c.lookupRole(b.Nonce)

	var bobHash data.Hash
	var signerKey ed25519.PublicKey
	var ok bool

	switch role {
	case roleBob:
		// We relayed; the response comes from Charlie (connected peer).
		bobHash = c.cfg.LocalRouterHash
		signerKey, ok = remoteKey, remoteKey != nil
	case roleAlice:
		// Forwarded response from Bob (connected peer). Bob = remoteHash.
		bobHash = remoteHash
		if b.Code >= 1 && b.Code <= 63 {
			// Bob's own rejection: signer is Bob (connected peer).
			signerKey, ok = remoteKey, remoteKey != nil
		} else {
			// Accept (0) or Charlie rejection (>=64): signer is Charlie.
			charlieHash, found := c.lookupCharlieHash(b.Nonce)
			if !found {
				return oops.Code("ssu2_relayresp_verify").With("nonce", b.Nonce).Errorf("no relay context for response")
			}
			signerKey, ok = c.resolveKey(charlieHash, remoteHash, remoteKey)
		}
	default:
		return oops.Code("ssu2_relayresp_verify").With("nonce", b.Nonce).Errorf("no relay context for response")
	}

	if !ok || signerKey == nil {
		return oops.Code("ssu2_relayresp_verify").Errorf("no signing key for relay response signer")
	}
	valid, err := VerifyRelayResponseSignature(signerKey, b.Signature, bobHash, b.Nonce, b.Timestamp, b.Version, b.CharliePort, b.CharlieIP)
	if err != nil {
		return oops.Wrapf(err, "verify relay response signature")
	}
	if !valid {
		return oops.Code("ssu2_relayresp_verify").Errorf("invalid relay response signature")
	}
	return nil
}

// ─── Inbound dispatch (role logic) ─────────────────────────────────────────

func (c *Coordinator) onPeerTest(remoteHash data.Hash, raw *SSU2Block) error {
	b, err := DecodePeerTestBlock(raw)
	if err != nil {
		return oops.Wrapf(err, "decode peer test block")
	}
	switch b.MessageCode {
	case PeerTestRequest:
		return c.bobRelayPeerTest(remoteHash, b)
	case PeerTestRelay:
		return c.charlieRespondPeerTest(remoteHash, b)
	case PeerTestResponse:
		return c.bobForwardPeerTestResult(remoteHash, b)
	case PeerTestResult:
		return c.aliceRecordPeerTestResult(b)
	default:
		// Messages 5-7 are direct Alice<->Charlie hole-punch probes handled by
		// the hole-punch coordinator, not here.
		return nil
	}
}

// bobRelayPeerTest handles msg 1 (Alice -> Bob): select a responder and forward
// Alice's signed request as msg 2 (Bob -> Charlie).
func (c *Coordinator) bobRelayPeerTest(aliceHash data.Hash, b *PeerTestBlock) error {
	if c.cfg.SelectCharlie == nil {
		flogc("bobRelayPeerTest", logger.Fields{"nonce": b.Nonce}).Debug("no Charlie selector; dropping peer test")
		return nil
	}
	charlieHash, charlieAddr, ok := c.cfg.SelectCharlie()
	if !ok {
		flogc("bobRelayPeerTest", logger.Fields{"nonce": b.Nonce}).Debug("no responder available; dropping peer test")
		return nil
	}

	c.mu.Lock()
	nc := c.ctxFor(b.Nonce)
	nc.role = roleBob
	nc.aliceHash = aliceHash
	nc.charlieHash = charlieHash
	nc.charlieAddr = charlieAddr
	nc.aliceIP = cloneBytes(b.AliceIP)
	nc.alicePort = b.AlicePort
	c.mu.Unlock()

	ah := aliceHash
	msg2 := &PeerTestBlock{
		MessageCode: PeerTestRelay,
		Code:        b.Code,
		RouterHash:  &ah, // Charlie learns Alice's hash
		Version:     b.Version,
		Nonce:       b.Nonce,
		Timestamp:   b.Timestamp,
		AlicePort:   b.AlicePort,
		AliceIP:     cloneBytes(b.AliceIP),
		Signature:   cloneBytes(b.Signature), // forward Alice's signature
	}
	blk, err := EncodePeerTestBlock(msg2)
	if err != nil {
		return oops.Wrapf(err, "encode peer test msg 2")
	}
	return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: charlieHash, Addr: charlieAddr, Blocks: []*SSU2Block{blk}})
}

// charlieRespondPeerTest handles msg 2 (Bob -> Charlie): sign and return msg 3
// (Charlie -> Bob).
func (c *Coordinator) charlieRespondPeerTest(bobHash data.Hash, b *PeerTestBlock) error {
	if b.RouterHash == nil {
		return oops.Code("ssu2_peertest").Errorf("msg 2 missing alice router hash")
	}
	if c.cfg.SigningKey == nil {
		return oops.Code("ssu2_peertest").Errorf("no signing key to respond to peer test")
	}
	aliceHash := *b.RouterHash

	c.mu.Lock()
	nc := c.ctxFor(b.Nonce)
	nc.role = roleCharlie
	nc.aliceHash = aliceHash
	nc.aliceIP = cloneBytes(b.AliceIP)
	nc.alicePort = b.AlicePort
	c.mu.Unlock()

	sig, err := SignPeerTest(c.cfg.SigningKey, bobHash, &aliceHash, b.Version, b.Nonce, b.Timestamp, b.AlicePort, net.IP(b.AliceIP))
	if err != nil {
		return oops.Wrapf(err, "sign peer test msg 3")
	}
	msg3 := &PeerTestBlock{
		MessageCode: PeerTestResponse,
		Code:        0, // accept
		Version:     b.Version,
		Nonce:       b.Nonce,
		Timestamp:   b.Timestamp,
		AlicePort:   b.AlicePort,
		AliceIP:     cloneBytes(b.AliceIP),
		Signature:   sig,
	}
	blk, err := EncodePeerTestBlock(msg3)
	if err != nil {
		return oops.Wrapf(err, "encode peer test msg 3")
	}
	return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: bobHash, Blocks: []*SSU2Block{blk}})
}

// bobForwardPeerTestResult handles msg 3 (Charlie -> Bob): forward Charlie's
// signed response as msg 4 (Bob -> Alice).
func (c *Coordinator) bobForwardPeerTestResult(charlieHash data.Hash, b *PeerTestBlock) error {
	c.mu.Lock()
	nc := c.nonces[b.Nonce]
	if nc == nil {
		c.mu.Unlock()
		return oops.Code("ssu2_peertest").With("nonce", b.Nonce).Errorf("no test context for msg 3")
	}
	aliceHash := nc.aliceHash
	aliceAddr := nc.aliceAddr
	nc.charlieHash = charlieHash
	c.mu.Unlock()

	ch := charlieHash
	msg4 := &PeerTestBlock{
		MessageCode: PeerTestResult,
		Code:        b.Code,
		RouterHash:  &ch, // Alice learns Charlie's hash
		Version:     b.Version,
		Nonce:       b.Nonce,
		Timestamp:   b.Timestamp,
		AlicePort:   b.AlicePort,
		AliceIP:     cloneBytes(b.AliceIP),
		Signature:   cloneBytes(b.Signature), // forward Charlie's signature
	}
	blk, err := EncodePeerTestBlock(msg4)
	if err != nil {
		return oops.Wrapf(err, "encode peer test msg 4")
	}
	return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: aliceHash, Addr: aliceAddr, Blocks: []*SSU2Block{blk}})
}

// aliceRecordPeerTestResult handles msg 4 (Bob -> Alice): record the test
// outcome.
func (c *Coordinator) aliceRecordPeerTestResult(b *PeerTestBlock) error {
	if b.RouterHash != nil {
		c.mu.Lock()
		if nc := c.nonces[b.Nonce]; nc != nil {
			nc.charlieHash = *b.RouterHash
		}
		c.mu.Unlock()
	}
	result := &TestResult{
		Reachable: b.Code == 0,
		TestTime:  c.cfg.Now(),
	}
	if err := c.cfg.PeerTest.CompleteTest(b.Nonce, result); err != nil {
		// The message was validly processed; a missing local test record is not
		// a protocol error, so log and continue rather than tearing the session.
		flogc("aliceRecordPeerTestResult", logger.Fields{"nonce": b.Nonce, "err": err.Error()}).Debug("could not complete local peer test")
	}
	return nil
}

func (c *Coordinator) onRelayRequest(aliceHash data.Hash, raw *SSU2Block) error {
	b, err := DecodeRelayRequest(raw)
	if err != nil {
		return oops.Wrapf(err, "decode relay request")
	}
	c.mu.Lock()
	client, ok := c.clients[b.RelayTag]
	if !ok {
		c.mu.Unlock()
		flogc("onRelayRequest", logger.Fields{"relayTag": b.RelayTag}).Debug("no introduced peer for relay tag; dropping")
		return nil
	}
	nc := c.ctxFor(b.Nonce)
	nc.role = roleBob
	nc.aliceHash = aliceHash
	nc.charlieHash = client.hash
	nc.charlieAddr = client.addr
	c.mu.Unlock()

	ah := aliceHash
	intro := &RelayIntroBlock{
		AliceRouterHash: cloneBytes(ah[:]),
		Nonce:           b.Nonce,
		AliceRelayTag:   b.RelayTag,
		Timestamp:       b.Timestamp,
		Version:         b.Version,
		AlicePort:       b.AlicePort,
		AliceIP:         b.AliceIP,
		Signature:       cloneBytes(b.Signature), // forward Alice's signature
	}
	blk, err := EncodeRelayIntro(intro)
	if err != nil {
		return oops.Wrapf(err, "encode relay intro")
	}
	return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: client.hash, Addr: client.addr, Blocks: []*SSU2Block{blk}})
}

func (c *Coordinator) onRelayIntro(bobHash data.Hash, raw *SSU2Block) error {
	b, err := DecodeRelayIntro(raw)
	if err != nil {
		return oops.Wrapf(err, "decode relay intro")
	}
	if c.cfg.SigningKey == nil {
		return oops.Code("ssu2_relay").Errorf("no signing key to answer relay intro")
	}
	aliceHash, err := hashFromSlice(b.AliceRouterHash)
	if err != nil {
		return oops.Wrapf(err, "relay intro alice hash")
	}

	c.mu.Lock()
	nc := c.ctxFor(b.Nonce)
	nc.role = roleCharlie
	nc.aliceHash = aliceHash
	nc.relayTag = b.AliceRelayTag
	nc.aliceIP = cloneBytes(b.AliceIP)
	nc.alicePort = b.AlicePort
	c.mu.Unlock()

	token, err := newToken()
	if err != nil {
		return err
	}
	var charlieIP net.IP
	var charliePort uint16
	if c.cfg.LocalExternal != nil {
		charlieIP = c.cfg.LocalExternal.IP
		charliePort = uint16(c.cfg.LocalExternal.Port)
	}
	ts := uint32(c.cfg.Now().Unix())
	sig, err := SignRelayResponse(c.cfg.SigningKey, bobHash, b.Nonce, ts, ssu2ProtocolVersion, charliePort, charlieIP)
	if err != nil {
		return oops.Wrapf(err, "sign relay response")
	}
	resp := &RelayResponseBlock{
		Code:        0, // accepted
		Nonce:       b.Nonce,
		Timestamp:   ts,
		Version:     ssu2ProtocolVersion,
		CharliePort: charliePort,
		CharlieIP:   charlieIP,
		Signature:   sig,
		Token:       token,
	}
	blk, err := EncodeRelayResponse(resp)
	if err != nil {
		return oops.Wrapf(err, "encode relay response")
	}
	return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: bobHash, Blocks: []*SSU2Block{blk}})
}

func (c *Coordinator) onRelayResponse(remoteHash data.Hash, raw *SSU2Block) error {
	b, err := DecodeRelayResponse(raw)
	if err != nil {
		return oops.Wrapf(err, "decode relay response")
	}
	c.mu.Lock()
	nc := c.nonces[b.Nonce]
	var role ptRole
	var aliceHash data.Hash
	var aliceAddr *net.UDPAddr
	if nc != nil {
		role = nc.role
		aliceHash = nc.aliceHash
		aliceAddr = nc.aliceAddr
	}
	c.mu.Unlock()

	switch role {
	case roleBob:
		// Forward Charlie's response to Alice unchanged.
		return c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: aliceHash, Addr: aliceAddr, Blocks: []*SSU2Block{raw}})
	case roleAlice:
		flogc("onRelayResponse", logger.Fields{"nonce": b.Nonce, "code": b.Code, "accepted": b.Code == 0}).Debug("relay response received")
		return nil
	default:
		flogc("onRelayResponse", logger.Fields{"nonce": b.Nonce}).Debug("relay response for unknown nonce; dropping")
		return nil
	}
}

// ─── Initiation helpers (local router as Alice) ────────────────────────────

// StartPeerTest initiates a peer test toward bobHash/bobAddr. aliceExternal is
// the local router's believed external endpoint, embedded in the signed
// request. It returns the test nonce.
func (c *Coordinator) StartPeerTest(bobHash data.Hash, bobAddr, aliceExternal *net.UDPAddr) (uint32, error) {
	if c.cfg.SigningKey == nil {
		return 0, oops.Code("ssu2_peertest").Errorf("no signing key to initiate peer test")
	}
	if aliceExternal == nil {
		return 0, oops.Code("ssu2_peertest").Errorf("alice external address required")
	}
	nonce, err := c.cfg.PeerTest.InitiatePeerTest(bobAddr)
	if err != nil {
		return 0, oops.Wrapf(err, "initiate peer test")
	}
	alicePort := uint16(aliceExternal.Port)
	aliceIP := aliceExternal.IP

	c.mu.Lock()
	nc := c.ctxFor(nonce)
	nc.role = roleAlice
	nc.aliceHash = c.cfg.LocalRouterHash
	nc.aliceIP = cloneBytes(aliceIP)
	nc.alicePort = alicePort
	c.mu.Unlock()

	ts := uint32(c.cfg.Now().Unix())
	sig, err := SignPeerTest(c.cfg.SigningKey, bobHash, nil, ssu2ProtocolVersion, nonce, ts, alicePort, aliceIP)
	if err != nil {
		return 0, oops.Wrapf(err, "sign peer test msg 1")
	}
	msg1 := &PeerTestBlock{
		MessageCode: PeerTestRequest,
		Version:     ssu2ProtocolVersion,
		Nonce:       nonce,
		Timestamp:   ts,
		AlicePort:   alicePort,
		AliceIP:     cloneBytes(aliceIP),
		Signature:   sig,
	}
	blk, err := EncodePeerTestBlock(msg1)
	if err != nil {
		return 0, oops.Wrapf(err, "encode peer test msg 1")
	}
	if err := c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: bobHash, Addr: bobAddr, Blocks: []*SSU2Block{blk}}); err != nil {
		return 0, oops.Wrapf(err, "dispatch peer test msg 1")
	}
	return nonce, nil
}

// StartRelay initiates a relay request asking bobHash to introduce the local
// router to charlieHash via the given relay tag. aliceExternal is the local
// router's believed external endpoint. It returns the relay nonce.
func (c *Coordinator) StartRelay(bobHash data.Hash, bobAddr *net.UDPAddr, charlieHash data.Hash, relayTag uint32, aliceExternal *net.UDPAddr) (uint32, error) {
	if c.cfg.SigningKey == nil {
		return 0, oops.Code("ssu2_relay").Errorf("no signing key to initiate relay")
	}
	if aliceExternal == nil {
		return 0, oops.Code("ssu2_relay").Errorf("alice external address required")
	}
	if relayTag == 0 {
		return 0, oops.Code("ssu2_relay").Errorf("relay tag must be non-zero")
	}
	nonce, err := randomNonce()
	if err != nil {
		return 0, err
	}
	alicePort := uint16(aliceExternal.Port)
	aliceIP := aliceExternal.IP

	c.mu.Lock()
	nc := c.ctxFor(nonce)
	nc.role = roleAlice
	nc.aliceHash = c.cfg.LocalRouterHash
	nc.charlieHash = charlieHash
	nc.relayTag = relayTag
	nc.aliceIP = cloneBytes(aliceIP)
	nc.alicePort = alicePort
	c.mu.Unlock()

	ts := uint32(c.cfg.Now().Unix())
	sig, err := SignRelayRequest(c.cfg.SigningKey, bobHash, charlieHash, nonce, relayTag, ts, ssu2ProtocolVersion, alicePort, aliceIP)
	if err != nil {
		return 0, oops.Wrapf(err, "sign relay request")
	}
	req := &RelayRequestBlock{
		Nonce:     nonce,
		RelayTag:  relayTag,
		Timestamp: ts,
		Version:   ssu2ProtocolVersion,
		AlicePort: alicePort,
		AliceIP:   aliceIP,
		Signature: sig,
	}
	blk, err := EncodeRelayRequest(req)
	if err != nil {
		return 0, oops.Wrapf(err, "encode relay request")
	}
	if err := c.cfg.Dispatcher.Dispatch(SendTarget{RouterHash: bobHash, Addr: bobAddr, Blocks: []*SSU2Block{blk}}); err != nil {
		return 0, oops.Wrapf(err, "dispatch relay request")
	}
	return nonce, nil
}

// ─── Shared-state accessors ────────────────────────────────────────────────

func (c *Coordinator) lookupAliceHash(nonce uint32) (data.Hash, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if nc := c.nonces[nonce]; nc != nil {
		return nc.aliceHash, true
	}
	return data.Hash{}, false
}

func (c *Coordinator) lookupCharlieHash(nonce uint32) (data.Hash, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if nc := c.nonces[nonce]; nc != nil {
		return nc.charlieHash, true
	}
	return data.Hash{}, false
}

func (c *Coordinator) lookupRole(nonce uint32) (ptRole, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if nc := c.nonces[nonce]; nc != nil {
		return nc.role, true
	}
	return roleUnknown, false
}

func (c *Coordinator) lookupRelayClientHash(relayTag uint32) (data.Hash, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[relayTag]; ok {
		return client.hash, true
	}
	return data.Hash{}, false
}

// ─── small helpers ─────────────────────────────────────────────────────────

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func randomNonce() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, oops.Wrapf(err, "generate relay nonce")
	}
	n := binary.BigEndian.Uint32(buf[:])
	if n == 0 {
		n = 1
	}
	return n, nil
}

var _ = time.Now
