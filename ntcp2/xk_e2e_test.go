package ntcp2

import (
	"context"
	"crypto/sha256"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"

	noise "github.com/go-i2p/go-noise"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXKHandshake_NTCP2_FullE2E exercises the complete NTCP2 pipeline:
//
//  1. Generate Curve25519 keypairs for initiator and responder
//  2. Set up NTCP2Config for both sides with SipHash enabled
//  3. TCP connection via localhost
//  4. XK handshake (initiator ↔ responder)
//  5. PostHandshakeHook derives per-direction SipHash keys
//  6. PropagateSipHash() installs SipHash-obfuscated framing
//  7. Bidirectional data exchange over framed I/O
//  8. Verify PeerStatic, ChannelBinding, NonceExhaustionImminent
//
// This test is the "most critical test gap" from AUDIT.md — without it,
// interoperability bugs between go-noise and other I2P implementations
// would not be caught.
func TestXKHandshake_NTCP2_FullE2E(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly, // NTCP2 mandates ChaChaPoly
		upstreamnoise.HashSHA256,
	)

	// ── Step 1: Generate real Curve25519 keypairs ──────────────────────
	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate initiator keypair")

	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate responder keypair")

	// ── Step 2: Create test router hashes (SHA-256 of RouterIdentity) ─
	var initiatorHash data.Hash
	copy(initiatorHash[:], "initiator-hash-32-bytes-long!!!!")

	var responderHash data.Hash
	copy(responderHash[:], "responder-hash-32-bytes-long!!!!")

	// ── Step 3: Build NTCP2Config for responder ───────────────────────
	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err, "create responder NTCP2Config")

	responderConfig = responderConfig.
		WithStaticKey(responderKP.Private).
		WithAESObfuscation(false, nil)

	// SipHash is enabled by default — this is what we want to test.

	// ── Step 4: Build NTCP2Config for initiator ───────────────────────
	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err, "create initiator NTCP2Config")

	initiatorConfig = initiatorConfig.
		WithStaticKey(initiatorKP.Private).
		WithRemoteRouterHash(responderHash).
		WithRemoteStaticKey(responderKP.Public).
		WithAESObfuscation(false, nil).
		WithLocalRouterInfo(fakeRouterInfoWithKey(initiatorKP.Public))

	// ── Step 5: Start TCP listener ────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "start TCP listener")
	defer ln.Close()

	// ── Step 6: Responder goroutine ───────────────────────────────────
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Accept raw TCP connection
		rawConn, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}

		// Create per-connection config (clone for isolation)
		perConnConfig := responderConfig.Clone()
		perConnConfig.Initiator = false

		// Convert to Noise ConnConfig
		connConfig, err := perConnConfig.ToConnConfig()
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		// Create NoiseConn
		noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		// Create NTCP2Conn
		responderAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), responderHash, "responder")
		remoteAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), initiatorHash, "initiator")
		ntcp2Conn, err := NewNTCP2Conn(noiseConn, responderAddr, remoteAddr)
		if err != nil {
			noiseConn.Close()
			responderErr = err
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		// Perform XK handshake (responder side)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ntcp2Conn.Handshake(ctx); err != nil {
			ntcp2Conn.Close()
			responderErr = err
			return
		}

		responderNTCP2 = ntcp2Conn
	}()

	// ── Step 7: Initiator side ────────────────────────────────────────
	initiatorNTCP2 := dialAndHandshakeInitiator(t, ln.Addr().String(), initiatorConfig, initiatorHash, responderHash, &wg, &responderErr)

	// Wait for responder to complete handshake
	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}
	defer initiatorNTCP2.Close()
	defer responderNTCP2.Close()

	// ── Step 8: Verify SipHash obfuscation is active ──────────────────
	assert.NotNil(t, initiatorNTCP2.lengthObfuscator.Load(),
		"initiator should have SipHash obfuscator after PropagateSipHash")
	assert.NotNil(t, responderNTCP2.lengthObfuscator.Load(),
		"responder should have SipHash obfuscator after PropagateSipHash")

	// ── Step 9: Bidirectional framed data exchange ─────────────────────
	// Initiator → Responder
	payload1 := []byte("hello from initiator via NTCP2 XK framed I/O")
	n, err := initiatorNTCP2.Write(payload1)
	require.NoError(t, err, "initiator write")
	assert.Equal(t, len(payload1), n, "initiator write byte count")

	buf := make([]byte, 4096)
	n, err = responderNTCP2.Read(buf)
	require.NoError(t, err, "responder read")
	assert.Equal(t, string(payload1), string(buf[:n]),
		"responder should receive initiator's message intact")

	// Responder → Initiator
	payload2 := []byte("reply from responder via NTCP2 XK framed I/O")
	n, err = responderNTCP2.Write(payload2)
	require.NoError(t, err, "responder write")
	assert.Equal(t, len(payload2), n, "responder write byte count")

	n, err = initiatorNTCP2.Read(buf)
	require.NoError(t, err, "initiator read")
	assert.Equal(t, string(payload2), string(buf[:n]),
		"initiator should receive responder's reply intact")

	// ── Step 10: Verify handshake metadata ────────────────────────────
	// PeerStatic: initiator sees responder's public key, responder sees initiator's
	assert.Equal(t, responderKP.Public, initiatorNTCP2.PeerStaticKey(),
		"initiator PeerStatic should be responder's public key")
	assert.Equal(t, initiatorKP.Public, responderNTCP2.PeerStaticKey(),
		"responder PeerStatic should be initiator's public key")

	// HandshakeHash: both sides should have the same channel binding
	assert.NotNil(t, initiatorNTCP2.HandshakeHash(), "initiator should have handshake hash")
	assert.NotNil(t, responderNTCP2.HandshakeHash(), "responder should have handshake hash")
	assert.Equal(t, initiatorNTCP2.HandshakeHash(), responderNTCP2.HandshakeHash(),
		"both sides should share the same handshake hash")

	// Nonce counters should reflect the frames sent
	assert.False(t, initiatorNTCP2.NonceExhaustionImminent(),
		"nonce exhaustion should not be imminent after a few frames")
	assert.False(t, responderNTCP2.NonceExhaustionImminent(),
		"nonce exhaustion should not be imminent after a few frames")

	t.Log("Full NTCP2 XK handshake + SipHash key derivation + framed I/O succeeded")
}

// TestXKHandshake_NTCP2_MultipleMessages exercises framed I/O with multiple
// messages to verify nonce counter advancement and SipHash mask sequencing.
func TestXKHandshake_NTCP2_MultipleMessages(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	buf := make([]byte, 4096)

	// Send 10 messages in each direction to exercise nonce advancement
	for i := 0; i < 10; i++ {
		// Initiator → Responder
		msg := []byte("message from initiator #" + string(rune('0'+i)))
		n, err := initiatorConn.Write(msg)
		require.NoError(t, err, "initiator write %d", i)
		assert.Equal(t, len(msg), n)

		n, err = responderConn.Read(buf)
		require.NoError(t, err, "responder read %d", i)
		assert.Equal(t, string(msg), string(buf[:n]))

		// Responder → Initiator
		reply := []byte("reply from responder #" + string(rune('0'+i)))
		n, err = responderConn.Write(reply)
		require.NoError(t, err, "responder write %d", i)
		assert.Equal(t, len(reply), n)

		n, err = initiatorConn.Read(buf)
		require.NoError(t, err, "initiator read %d", i)
		assert.Equal(t, string(reply), string(buf[:n]))
	}

	t.Log("10 bidirectional NTCP2 framed messages exchanged successfully")
}

// TestXKHandshake_NTCP2_LargePayload verifies frame splitting works with
// the config's MaxFrameSize by sending a payload larger than one frame.
func TestXKHandshake_NTCP2_LargePayload(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	// Create a payload larger than DefaultMaxFrameSize (16384).
	// This should trigger frame splitting in writeFramed.
	largePayload := make([]byte, 32768)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	// Initiator sends large payload
	n, err := initiatorConn.Write(largePayload)
	require.NoError(t, err, "write large payload")
	assert.Equal(t, len(largePayload), n, "should write full payload")

	// Responder reads — may need multiple Read calls to get all data
	received := make([]byte, 0, len(largePayload))
	buf := make([]byte, 4096)
	for len(received) < len(largePayload) {
		n, err = responderConn.Read(buf)
		require.NoError(t, err, "read large payload chunk")
		received = append(received, buf[:n]...)
	}

	assert.Equal(t, largePayload, received, "large payload should be received intact")

	t.Log("Large payload (32KB) frame splitting + reassembly succeeded")
}

// TestXKHandshake_NTCP2_ConfigMaxFrameSize verifies that the config's
// MaxFrameSize is respected in frame splitting after handshake.
func TestXKHandshake_NTCP2_ConfigMaxFrameSize(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	// getMaxFrameSize should return the config value (DefaultMaxFrameSize=16384)
	assert.Equal(t, DefaultMaxFrameSize, initiatorConn.getMaxFrameSize(),
		"initiator should use config MaxFrameSize")
	assert.Equal(t, DefaultMaxFrameSize, responderConn.getMaxFrameSize(),
		"responder should use config MaxFrameSize")
}

// TestXKHandshake_NTCP2_CloseAfterHandshake verifies clean connection teardown.
func TestXKHandshake_NTCP2_CloseAfterHandshake(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)

	// Close initiator
	err := initiatorConn.Close()
	assert.NoError(t, err, "initiator close")

	// Close responder
	err = responderConn.Close()
	assert.NoError(t, err, "responder close")

	// Verify broken flag is NOT set (clean close)
	assert.False(t, initiatorConn.broken.Load(), "initiator should not be broken after clean close")
	assert.False(t, responderConn.broken.Load(), "responder should not be broken after clean close")
}

// ============================================================================
// Test helper: dials, creates NTCP2Conn, and performs initiator handshake
// ============================================================================

// dialAndHandshakeInitiator dials the given address, creates an NTCP2Conn for
// the initiator, and performs the XK handshake. On handshake failure it waits
// for wg and fatals with both errors. The caller must close the returned conn.
func dialAndHandshakeInitiator(
	t *testing.T,
	addr string,
	initiatorConfig *Config,
	initiatorHash, responderHash data.Hash,
	wg *sync.WaitGroup,
	responderErr *error,
) *Conn {
	t.Helper()
	rawConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)

	connConfig, err := initiatorConfig.ToConnConfig()
	require.NoError(t, err)

	noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
	require.NoError(t, err)

	iAddr, err := NewNTCP2Addr(rawConn.LocalAddr(), initiatorHash, "initiator")
	require.NoError(t, err)
	rAddr, err := NewNTCP2Addr(rawConn.RemoteAddr(), responderHash, "responder")
	require.NoError(t, err)

	ntcp2Conn, err := NewNTCP2Conn(noiseConn, iAddr, rAddr)
	require.NoError(t, err)
	ntcp2Conn.SetNTCP2Config(initiatorConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = ntcp2Conn.Handshake(ctx)
	if err != nil {
		ntcp2Conn.Close()
		wg.Wait()
		t.Fatalf("initiator handshake: %v (responder err: %v)", err, *responderErr)
	}

	return ntcp2Conn
}

// ============================================================================
// Test helper: creates a fully handshaked initiator↔responder NTCP2 pair
// ============================================================================

func setupHandshakedPair(t *testing.T) (initiator, responder *Conn) {
	t.Helper()

	p := newTestXKConfigPair(t)

	// TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Responder goroutine
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()

		rawConn, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}

		perConnConfig := p.responderConfig.Clone()
		perConnConfig.Initiator = false
		connConfig, err := perConnConfig.ToConnConfig()
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		rAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), p.responderHash, "responder")
		iAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), p.initiatorHash, "initiator")
		ntcp2Conn, err := NewNTCP2Conn(noiseConn, rAddr, iAddr)
		if err != nil {
			noiseConn.Close()
			responderErr = err
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ntcp2Conn.Handshake(ctx); err != nil {
			ntcp2Conn.Close()
			responderErr = err
			return
		}

		responderNTCP2 = ntcp2Conn
	}()

	initiatorNTCP2 := dialAndHandshakeInitiator(t, ln.Addr().String(), p.initiatorConfig, p.initiatorHash, p.responderHash, &wg, &responderErr)

	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}

	return initiatorNTCP2, responderNTCP2
}

// TestInboundRouterHash verifies that after a completed XK handshake the
// responder (inbound) side exposes SHA-256(initiator_static_key) as the remote
// router hash, rather than the raw key bytes or all zeros.
//
// Before AUDIT 5.3: RouterHash was set to the raw 32-byte Noise static public
// key via data.NewHashFromSlice, which is not SHA-256(RouterIdentity).
// After AUDIT 5.3: RouterHash is SHA-256(static_key), a closer approximation
// to the I2P router-hash definition until the full RouterIdentity is available.
func TestInboundRouterHash(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	var initiatorHash data.Hash
	copy(initiatorHash[:], "initiator-hash-32-bytes-long!!!!")
	var responderHash data.Hash
	copy(responderHash[:], "responder-hash-32-bytes-long!!!!")

	// --- Responder config (listener) ---
	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	responderConfig = responderConfig.
		WithStaticKey(responderKP.Private).
		WithAESObfuscation(false, nil)
	// Note: responderConfig.RemoteRouterHash is nil — the listener does NOT
	// know the initiator's identity ahead of time.

	// --- Initiator config ---
	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err)
	initiatorConfig = initiatorConfig.
		WithStaticKey(initiatorKP.Private).
		WithRemoteRouterHash(responderHash).
		WithRemoteStaticKey(responderKP.Public).
		WithAESObfuscation(false, nil).
		WithLocalRouterInfo(fakeRouterInfoWithKey(initiatorKP.Public))

	// --- Start NTCP2 listener ---
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, responderConfig)

	// --- Responder goroutine: AcceptWithHandshake ---
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ntcp2Ln.AcceptWithHandshake(ctx)
		if err != nil {
			responderErr = err
			return
		}
		responderNTCP2 = conn.(*Conn)
	}()

	// --- Initiator: dial + handshake ---
	initiatorNTCP2 := dialAndHandshakeInitiator(t, tcpAddr.String(),
		initiatorConfig, initiatorHash, responderHash, &wg, &responderErr)
	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder: %v", responderErr)
	}
	defer initiatorNTCP2.Close()
	defer responderNTCP2.Close()

	// --- Assertions ---
	// The responder's RouterHash() should be SHA-256(initiator static key),
	// not all zeros and not the raw key bytes (AUDIT 5.3).
	responderRemoteHash := responderNTCP2.RouterHash()

	assert.False(t, responderRemoteHash.IsZero(),
		"responder remote router hash must not be all zeros after handshake")

	// RouterHash should equal SHA-256(PeerStaticKey), not the raw key.
	peerKey := responderNTCP2.PeerStaticKey()
	expectedHash := data.HashData(peerKey)
	assert.Equal(t, expectedHash, responderRemoteHash,
		"responder RouterHash should equal SHA-256(PeerStaticKey) after PropagatePeerStaticKey")

	// Verify SHA-256(initiator static public key) matches independently.
	expectedHashBytes := sha256.Sum256(initiatorKP.Public)
	rhBytes := responderRemoteHash.Bytes()
	assert.Equal(t, expectedHashBytes, rhBytes,
		"responder RouterHash should be SHA-256 of the initiator's actual static public key")
}

// TestXKHandshake_NTCP2_AESObfuscation exercises the full NTCP2 pipeline with
// AES-CBC ephemeral key obfuscation enabled, matching the production code path.
//
// All other XK e2e tests disable AES obfuscation via WithAESObfuscation(false, nil),
// meaning the AES modifier is never exercised in the handshake context. This test
// closes that gap by:
//  1. Using a shared 16-byte IV (simulating the "i=" value from the netdb)
//  2. Passing the responder's router hash (RH_B) to both sides as the AES key
//  3. Running the full XK handshake with AES-encrypted ephemeral keys
//  4. Verifying bidirectional SipHash-framed data exchange after handshake
func TestXKHandshake_NTCP2_AESObfuscation(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	// ── Step 1: Generate real Curve25519 keypairs ──────────────────────
	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate initiator keypair")

	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate responder keypair")

	// ── Step 2: Create test router hashes ─────────────────────────────
	var initiatorHash data.Hash
	copy(initiatorHash[:], "initiator-hash-32-bytes-long!!!!")

	var responderHash data.Hash
	copy(responderHash[:], "responder-hash-32-bytes-long!!!!")

	// ── Step 3: Shared AES IV (simulates Bob's published "i=" value) ──
	aesIV := make([]byte, IVSize)
	_, err = rand.Read(aesIV)
	require.NoError(t, err, "generate AES IV")

	// ── Step 4: Build NTCP2Config for responder (Bob) ─────────────────
	// Per the NTCP2 spec, the responder passes its own router hash as RH_B.
	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err, "create responder NTCP2Config")

	responderConfig = responderConfig.
		WithStaticKey(responderKP.Private).
		WithAESObfuscation(true, aesIV) // AES ENABLED with shared IV

	// ── Step 5: Build NTCP2Config for initiator (Alice) ───────────────
	// Per the NTCP2 spec, the initiator also uses RH_B (the responder's hash)
	// as the first parameter. Both sides must use the same AES key (RH_B).
	initiatorConfig, err := NewNTCP2Config(responderHash, true) // NOTE: responderHash, not initiatorHash
	require.NoError(t, err, "create initiator NTCP2Config")

	initiatorConfig = initiatorConfig.
		WithStaticKey(initiatorKP.Private).
		WithRemoteRouterHash(responderHash).
		WithRemoteStaticKey(responderKP.Public).
		WithAESObfuscation(true, aesIV). // AES ENABLED with same IV
		WithLocalRouterInfo(fakeRouterInfoWithKey(initiatorKP.Public))

	// ── Step 6: Start TCP listener ────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "start TCP listener")
	defer ln.Close()

	// ── Step 7: Responder goroutine ───────────────────────────────────
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()

		rawConn, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}

		perConnConfig := responderConfig.Clone()
		perConnConfig.Initiator = false

		connConfig, err := perConnConfig.ToConnConfig()
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		responderAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), responderHash, "responder")
		remoteAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), initiatorHash, "initiator")
		ntcp2Conn, err := NewNTCP2Conn(noiseConn, responderAddr, remoteAddr)
		if err != nil {
			noiseConn.Close()
			responderErr = err
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ntcp2Conn.Handshake(ctx); err != nil {
			ntcp2Conn.Close()
			responderErr = err
			return
		}

		responderNTCP2 = ntcp2Conn
	}()

	// ── Step 8: Initiator side ────────────────────────────────────────
	initiatorNTCP2 := dialAndHandshakeInitiator(t, ln.Addr().String(),
		initiatorConfig, initiatorHash, responderHash, &wg, &responderErr)

	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake failed (AES enabled): %v", responderErr)
	}
	defer initiatorNTCP2.Close()
	defer responderNTCP2.Close()

	// ── Step 9: Verify SipHash obfuscation is active ──────────────────
	assert.NotNil(t, initiatorNTCP2.lengthObfuscator.Load(),
		"initiator should have SipHash obfuscator after handshake")
	assert.NotNil(t, responderNTCP2.lengthObfuscator.Load(),
		"responder should have SipHash obfuscator after handshake")

	// ── Step 10: Bidirectional framed data exchange ────────────────────
	payload1 := []byte("hello from initiator via NTCP2 XK with AES obfuscation")
	n, err := initiatorNTCP2.Write(payload1)
	require.NoError(t, err, "initiator write")
	assert.Equal(t, len(payload1), n, "initiator write byte count")

	buf := make([]byte, 4096)
	n, err = responderNTCP2.Read(buf)
	require.NoError(t, err, "responder read")
	assert.Equal(t, string(payload1), string(buf[:n]),
		"responder should receive initiator's message intact")

	payload2 := []byte("reply from responder via NTCP2 XK with AES obfuscation")
	n, err = responderNTCP2.Write(payload2)
	require.NoError(t, err, "responder write")
	assert.Equal(t, len(payload2), n, "responder write byte count")

	n, err = initiatorNTCP2.Read(buf)
	require.NoError(t, err, "initiator read")
	assert.Equal(t, string(payload2), string(buf[:n]),
		"initiator should receive responder's reply intact")

	// ── Step 11: Verify handshake metadata ────────────────────────────
	assert.Equal(t, responderKP.Public, initiatorNTCP2.PeerStaticKey(),
		"initiator PeerStatic should be responder's public key")
	assert.Equal(t, initiatorKP.Public, responderNTCP2.PeerStaticKey(),
		"responder PeerStatic should be initiator's public key")

	assert.Equal(t, initiatorNTCP2.HandshakeHash(), responderNTCP2.HandshakeHash(),
		"both sides should share the same handshake hash")

	t.Log("Full NTCP2 XK handshake with AES obfuscation + SipHash framing succeeded")
}
