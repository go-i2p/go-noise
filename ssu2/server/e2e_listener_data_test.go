package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	i2pcrand "github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/require"
)

// e2eListenerPair stands up a listener-owned responder socket and a
// dedicated-socket initiator (the topology a router uses: one shared listen
// socket answers inbound dials), completes the Noise XK handshake, and returns
// both established connections plus a cleanup func.
func e2eListenerPair(t *testing.T) (initiator, responder *SSU2Conn, cleanup func()) {
	t.Helper()

	serverHash := generateRandomHash()
	serverStaticPriv := randomKey(t)
	serverStaticPub := mustDerivePublic(t, serverStaticPriv)
	serverIntroKey := randomKey(t)
	clientHash := generateRandomHash()
	clientStaticPriv := randomKey(t)
	clientStaticPub := mustDerivePublic(t, clientStaticPriv)
	clientIntroKey := randomKey(t)

	serverConfig, err := NewSSU2Config(serverHash, false)
	require.NoError(t, err)
	serverConfig.WithStaticKey(serverStaticPriv)
	serverConfig.IntroKey = serverIntroKey
	// A responder sends data-phase packets with k_header_1 = the receiver's
	// (Alice's) intro key (ssu2.md §"Header Encryption KDF"). buildConnConfig
	// copies this listener config onto every accepted responder conn, so the
	// responder can send as well as receive only when RemoteIntroKey is set --
	// exactly how the go-i2p router configures its listener.
	serverConfig.RemoteIntroKey = clientIntroKey
	serverConfig.RouterInfoValidator = permissiveValidator
	serverConfig.WithHandshakeTimeout(5 * time.Second).WithDestroyTimeout(100 * time.Millisecond)

	responderListener, err := ListenSSU2(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, serverConfig)
	require.NoError(t, err)
	respAddr := responderListener.Addr().(*SSU2Addr).UnderlyingAddr().(*net.UDPAddr)

	acceptCh := make(chan *SSU2Conn, 1)
	go func() {
		c, aerr := responderListener.Accept()
		if aerr != nil {
			acceptCh <- nil
			return
		}
		sc := c.(*SSU2Conn)
		hctx, hcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer hcancel()
		_ = sc.Handshake(hctx) // drive the responder half of XK
		acceptCh <- sc
	}()

	// Dedicated initiator socket (the consumer's topology).
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	dialConfig, err := NewSSU2Config(clientHash, true)
	require.NoError(t, err)
	var idBuf [8]byte
	_, err = i2pcrand.Read(idBuf[:])
	require.NoError(t, err)
	i2pB64 := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
	claimRI := append([]byte("fake-ri:"), []byte(i2pB64.EncodeToString(clientStaticPub))...)
	dialConfig = dialConfig.
		WithStaticKey(clientStaticPriv).
		WithConnectionID(binary.BigEndian.Uint64(idBuf[:]) | 1).
		WithRemoteRouterHash(serverHash).
		WithRemoteStaticKey(serverStaticPub).
		WithLocalRouterInfo(claimRI).
		WithDestroyTimeout(100 * time.Millisecond).
		WithHandshakeTimeout(5 * time.Second)
	dialConfig.IntroKey = clientIntroKey
	dialConfig.RemoteIntroKey = serverIntroKey

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	initiator, err = DialSSU2WithConn(clientPC, respAddr, dialConfig)
	require.NoError(t, err)
	require.NoError(t, initiator.Handshake(ctx), "initiator handshake must complete")

	responder = <-acceptCh
	require.NotNil(t, responder, "responder must accept a connection")

	cleanup = func() {
		initiator.Close()
		responder.Close()
		responderListener.Close()
		clientPC.Close()
	}
	return initiator, responder, cleanup
}

// TestE2E_ListenerDataPhase_InboundDataReachesResponder is the regression oracle
// for the listener inbound-data interop defect. A router runs one shared SSU2
// listen socket; inbound Data packets for an accepted (responder-role) session
// are deobfuscated and routed by ssu2/server, then handed to the connection via
// ProcessInboundPacket.
//
// Two defects blocked that path, both fixed here:
//
//  1. Header deobfuscation discrimination. The SessionConfirmed and Data inbound
//     protectors share k_header_1 (the introduction key), which masks bytes 0-7
//     (the dest conn ID). They differ only in k_header_2, which masks bytes 8-15
//     including the message-type byte at 12. trialDeobfuscateWithProtector used
//     to match on the dest conn ID alone, so the first-tried protector
//     (SessionConfirmed) false-matched an inbound Data packet -- the dest ID
//     still decrypted correctly via the shared k_header_1, but the type byte came
//     out as garbage under the wrong k_header_2 -- and the correct Data protector
//     was never reached. The fix requires the decrypted type byte to equal the
//     protector's expected type.
//
//  2. Payload AEAD decryption. The Noise-AEAD payload decryption ran only in the
//     dedicated-socket read path (parseInboundPacket), so a listener-routed Data
//     packet reached ProcessInboundPacket still encrypted and its blocks failed
//     to deserialize. The fix moves decryption into ProcessInboundPacket, the
//     single funnel both the own-socket and listener-routed paths share.
//
// Without either fix, initiator->responder data delivery over the listen socket
// silently times out -- exactly the failure the go-i2p consumer hit
// (TestSessionIntegration_ClientToServerI2NP).
func TestE2E_ListenerDataPhase_InboundDataReachesResponder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e listener data-phase test in short mode")
	}

	initiator, responder, cleanup := e2eListenerPair(t)
	defer cleanup()

	payload := []byte("hello over the ssu2 listener data phase")

	go func() {
		_, _ = initiator.Write(payload)
	}()

	readCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := io.ReadAtLeast(responder, buf, len(payload))
		if err != nil {
			readCh <- nil
			return
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		readCh <- out
	}()

	select {
	case got := <-readCh:
		require.NotNil(t, got, "responder must receive the initiator's data over the listen socket")
		require.Equal(t, payload, got, "payload must round-trip intact")
	case <-time.After(8 * time.Second):
		t.Fatal("responder did not receive inbound data within 8s (listener data-phase receive regression)")
	}

	// Reverse direction: responder -> initiator over the dedicated-socket read
	// path, proving the decrypt move into ProcessInboundPacket did not break the
	// own-socket path (which now also decrypts there).
	back := []byte("reply from the responder")
	go func() {
		_, _ = responder.Write(back)
	}()
	ireadCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := io.ReadAtLeast(initiator, buf, len(back))
		if err != nil {
			ireadCh <- nil
			return
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		ireadCh <- out
	}()
	select {
	case got := <-ireadCh:
		require.NotNil(t, got, "initiator must receive the responder's reply")
		require.Equal(t, back, got, "reverse payload must round-trip intact")
	case <-time.After(8 * time.Second):
		t.Fatal("initiator did not receive the responder's reply within 8s")
	}
}
