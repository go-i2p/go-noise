package ntcp2

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResponderCapturesPeerRouterInfo verifies that after a successful
// inbound NTCP2 XK handshake, the responder side surfaces the decrypted
// message-3 part-2 payload (Alice's RouterInfo block) via
// PeerMessage3Payload() / PeerRouterInfoBytes().
//
// This is the upstream fix for the OBEP-cannot-reply bug: without access
// to Alice's RouterInfo, a 1-hop OBEP has no way to deliver a
// ShortTunnelBuildReply directly back to her NTCP2 address.
func TestResponderCapturesPeerRouterInfo(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	var initiatorHash, responderHash data.Hash
	copy(initiatorHash[:], "initiator-hash-32-bytes-long!!!!")
	copy(responderHash[:], "responder-hash-32-bytes-long!!!!")

	// A distinguishable RouterInfo payload so we can assert byte-equality.
	// It must embed the initiator's static public key as an `s=` option so the
	// always-on RouterInfo/static-key verification accepts it.
	aliceRI := []byte("ALICE-ROUTER-INFO-s=" + i2pbase64.EncodeToString(initiatorKP.Public) + "-FOR-TESTING")

	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	responderConfig = responderConfig.
		WithStaticKey(responderKP.Private).
		WithAESObfuscation(false, nil)

	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err)
	initiatorConfig = initiatorConfig.
		WithStaticKey(initiatorKP.Private).
		WithRemoteRouterHash(responderHash).
		WithRemoteStaticKey(responderKP.Public).
		WithAESObfuscation(false, nil).
		WithLocalRouterInfo(aliceRI)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *Conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		rawConn, aerr := ln.Accept()
		if aerr != nil {
			responderErr = aerr
			return
		}
		perConnConfig := responderConfig.Clone()
		perConnConfig.Initiator = false
		connConfig, cerr := perConnConfig.ToConnConfig()
		if cerr != nil {
			rawConn.Close()
			responderErr = cerr
			return
		}
		noiseConn, nerr := noise.NewNoiseConn(rawConn, connConfig)
		if nerr != nil {
			rawConn.Close()
			responderErr = nerr
			return
		}
		responderAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), responderHash, "responder")
		remoteAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), initiatorHash, "initiator")
		ntcp2Conn, werr := NewNTCP2Conn(noiseConn, responderAddr, remoteAddr)
		if werr != nil {
			noiseConn.Close()
			responderErr = werr
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if herr := ntcp2Conn.Handshake(ctx); herr != nil {
			ntcp2Conn.Close()
			responderErr = herr
			return
		}
		responderNTCP2 = ntcp2Conn
	}()

	initiatorNTCP2 := dialAndHandshakeInitiator(t, ln.Addr().String(), initiatorConfig, initiatorHash, responderHash, &wg, &responderErr)
	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}
	defer initiatorNTCP2.Close()
	defer responderNTCP2.Close()

	// Initiator side never receives msg3 from itself; payload should be nil.
	assert.Nil(t, initiatorNTCP2.PeerMessage3Payload(),
		"initiator must not have a captured msg3 payload")
	assert.Nil(t, initiatorNTCP2.PeerRouterInfoBytes(),
		"initiator must not have a parsed RouterInfo")

	// Responder side: full payload should be available and contain the RI block.
	payload := responderNTCP2.PeerMessage3Payload()
	require.NotNil(t, payload, "responder must capture msg3 payload")
	require.GreaterOrEqual(t, len(payload), 4+len(aliceRI),
		"payload must include block header + flag byte + RI bytes")
	assert.Equal(t, byte(routerInfoBlockType), payload[0], "first block must be RouterInfo (type 2)")
	assert.Equal(t, byte(0x00), payload[3], "RouterInfo flag byte must be 0x00 (no flood request)")

	// Convenience parse: just the inner RI bytes.
	ri := responderNTCP2.PeerRouterInfoBytes()
	require.NotNil(t, ri, "PeerRouterInfoBytes must locate the RouterInfo block")
	assert.Equal(t, aliceRI, ri,
		"PeerRouterInfoBytes must return Alice's RouterInfo bytes verbatim")

	// Defensive-copy contract: mutating the returned slice must not affect
	// the next call's result.
	if len(ri) > 0 {
		ri[0] ^= 0xFF
	}
	ri2 := responderNTCP2.PeerRouterInfoBytes()
	assert.Equal(t, aliceRI, ri2,
		"PeerRouterInfoBytes must return an independent copy each call")
}
