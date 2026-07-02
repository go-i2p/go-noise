package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// mustDerivePublic derives the X25519 static public key from a private static
// key, mirroring the handshake package's internal derivation.
func mustDerivePublic(t *testing.T, priv []byte) []byte {
	t.Helper()
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	require.NoError(t, err)
	return pub
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

// permissiveValidator accepts any RouterInfo. The DialViaListener e2e test
// exercises the transport/header-protection demux path (the socket-reuse fix),
// not RouterInfo authentication, so we deliberately bypass the default
// static-key-binding validator to avoid constructing full signed RouterInfos.
func permissiveValidator(_, _ []byte) error { return nil }

// TestE2EHandshake_DialViaListener_CompletesHandshake is the regression oracle
// for the socket-reuse handshake fix (go-noise commit 859815f). It stands up
// two REAL bound UDP listeners — a responder and an initiator — and drives a
// full Noise XK handshake where the initiator reuses its own listener socket
// via DialSSU2ViaListener.
//
// This is the empirical end-to-end proof that the fix works: the responder's
// SessionCreated reply, header-protected with the handshake-derived
// SessCreateHeaderKey, must be routed back to the pending outbound connection
// through the listener's parseInboundPacket -> TrialDeobfuscate path. Prior to
// the fix, that reply was dropped (nil header protector registered), so this
// handshake could never complete.
//
// This test now also asserts that the RESPONDER (Bob) reaches Established, which
// requires the listener to decode inbound SessionConfirmed short headers via
// AcceptedSessionRegistry trial-deobfuscation (the fix for the responder-side
// listener gap).
func TestE2EHandshake_DialViaListener_CompletesHandshake(t *testing.T) {
	// --- Responder (Bob) identity + keys ---
	serverHash := generateRandomHash()
	serverStaticPriv := randomKey(t)
	serverStaticPub := mustDerivePublic(t, serverStaticPriv)
	serverIntroKey := randomKey(t)

	// --- Initiator (Alice) identity + keys ---
	clientHash := generateRandomHash()
	clientStaticPriv := randomKey(t)
	clientStaticPub := mustDerivePublic(t, clientStaticPriv)
	clientIntroKey := randomKey(t)

	// --- Responder listener config ---
	serverConfig, err := NewSSU2Config(serverHash, false) // responder
	require.NoError(t, err)
	serverConfig.WithStaticKey(serverStaticPriv)
	serverConfig.IntroKey = serverIntroKey
	serverConfig.RouterInfoValidator = permissiveValidator
	serverConfig.WithHandshakeTimeout(5 * time.Second)

	responderListener, err := ListenSSU2(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, serverConfig)
	require.NoError(t, err)
	defer responderListener.Close()

	respAddr := responderListener.Addr().(*SSU2Addr).UnderlyingAddr().(*net.UDPAddr)

	// Responder accepts in the background and drives its side of the XK
	// handshake. Accept() returns a not-yet-established connection; the caller
	// must call Handshake() to process the buffered SessionRequest, emit
	// SessionCreated, and await SessionConfirmed.
	type acceptResult struct {
		conn *SSU2Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, aerr := responderListener.Accept()
		if aerr != nil {
			acceptCh <- acceptResult{err: aerr}
			return
		}
		sc, ok := c.(*SSU2Conn)
		if !ok {
			acceptCh <- acceptResult{err: fmt.Errorf("accepted conn is not *SSU2Conn: %T", c)}
			return
		}
		hctx, hcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer hcancel()
		if herr := sc.Handshake(hctx); herr != nil {
			acceptCh <- acceptResult{conn: sc, err: herr}
			return
		}
		acceptCh <- acceptResult{conn: sc}
	}()

	// --- Initiator's own bound listener (provides the reused socket) ---
	clientListenerConfig, err := NewSSU2Config(clientHash, false) // responder-style local listener
	require.NoError(t, err)
	clientListenerConfig.WithStaticKey(clientStaticPriv)
	clientListenerConfig.IntroKey = clientIntroKey
	clientListenerConfig.RouterInfoValidator = permissiveValidator
	clientListenerConfig.WithHandshakeTimeout(5 * time.Second)

	initiatorListener, err := ListenSSU2(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, clientListenerConfig)
	require.NoError(t, err)
	defer initiatorListener.Close()

	// --- Per-dial initiator config targeting the responder ---
	dialConfig, err := NewSSU2Config(clientHash, true) // initiator
	require.NoError(t, err)
	dialConfig.WithStaticKey(clientStaticPriv)
	dialConfig.WithRemoteRouterHash(serverHash)
	dialConfig.WithRemoteStaticKey(serverStaticPub)
	// IntroKey is the initiator's OWN local intro key: NewHeaderProtectorManager
	// requires a 32-byte local intro key or the conn is built without a header
	// protector (leaving notifySessCreateKey unable to arm the SessionCreated
	// protector on the pending-outbound registry). RemoteIntroKey is Bob's intro
	// key, used to obfuscate the SessionRequest and to build the Retry/
	// SessionCreated k_header_1.
	dialConfig.IntroKey = clientIntroKey
	dialConfig.RemoteIntroKey = serverIntroKey
	// ConnectionID must be set non-zero: NewSSU2Conn resolves a random connID for
	// the SSU2Addr (the pending-outbound registry key) when config.ConnectionID
	// is 0, but the handshake still advertises config.ConnectionID as the source
	// conn ID. Leaving it 0 makes the responder echo destConnID=0, which never
	// matches the (random) registry key, so the SessionCreated reply is dropped.
	var idBuf [8]byte
	_, err = rand.Read(idBuf[:])
	require.NoError(t, err)
	dialConfig.ConnectionID = binary.BigEndian.Uint64(idBuf[:]) | 1
	dialConfig.WithHandshakeTimeout(5 * time.Second)
	// Build a fake LocalRouterInfo that passes verifyPeerRouterInfoStaticKey.
	// That check does: bytes.Contains(peerRouterInfo, i2pbase64(remoteStaticKey)).
	// I2P base64 is standard base64 with '+' replaced by '-' and '/' by '~'.
	i2pB64 := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
	claimRI := append([]byte("fake-ri:"), []byte(i2pB64.EncodeToString(clientStaticPub))...)
	dialConfig.WithLocalRouterInfo(claimRI)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The core assertion: the initiator drives a full XK handshake over its own
	// reused listener socket and COMPLETES it. Completion requires that the
	// responder's SessionCreated reply — header-protected with the handshake-
	// derived SessCreateHeaderKey — is demultiplexed back to the pending
	// outbound connection via parseInboundPacket -> TrialDeobfuscate. Before the
	// socket-reuse fix (859815f) that reply was dropped (nil header protector)
	// and this call could only ever time out.
	conn, err := initiatorListener.DialSSU2ViaListener(ctx, respAddr, dialConfig)
	require.NoError(t, err, "initiator handshake via listener must complete")
	require.NotNil(t, conn, "established connection must be non-nil")
	defer conn.Close()
	require.True(t, conn.IsInitiator(), "completed connection must be the initiator side")

	// Assert that the RESPONDER (Bob) also reaches Established. This requires the
	// listener to decode the inbound SessionConfirmed short header via
	// AcceptedSessionRegistry trial-deobfuscation (the responder-side listener
	// fix — the subject of this issue). Before the fix, the listener had no
	// per-session protector for sessionConfirmedHeader2, so SessionConfirmed was
	// silently dropped and the responder always timed out.
	result := <-acceptCh
	require.NoError(t, result.err, "responder handshake must complete without error")
	require.NotNil(t, result.conn, "responder established connection must be non-nil")
}
