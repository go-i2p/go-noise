package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

// TestOwnSocketInitiatorRetryRoundTrip is the regression oracle for the SSU2
// initiator Retry bug on the OWN-SOCKET dial path (DialSSU2, the default Dialer
// returned by NewDialer).
//
// Unlike TestInitiatorRetryRoundTrip_AcceptedByResponder — which delivers an
// already-deobfuscated Retry via ProcessInboundPacket, the way the listener-routed
// path (DialSSU2ViaListener) does — this test feeds the captured i2pd Retry as a
// RAW, still-header-protected datagram through the connection's own read path
// (readOnePacket -> parseInboundPacket -> decryptInboundHeader). That is exactly
// what happens when the initiator owns the socket and runs its own recvLoop.
//
// During handshake, expectedInboundHeaderType() returns HeaderTypeSessionCreated,
// so the Retry must be deobfuscated with the Retry protector (k_header_2 =
// remoteIntroKey), not the SessionCreated protector (k_header_2 =
// sessCreateHeader2). Before the fix, the wrong k_header_2 unmasked the type byte
// to garbage, the packet failed to parse as a Retry, and handleRetryResponse never
// ran — the handshake timed out with "failed to receive SessionCreated".
func TestOwnSocketInitiatorRetryRoundTrip(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)

	// Responder intro key: obfuscates the SessionRequest and seals / header-
	// protects the captured Retry.
	responderIntroKey := make([]byte, wire.HeaderKeySize)
	rk, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	copy(responderIntroKey, rk.Private)

	config := createTestConfig(t)
	config.IntroKey = make([]byte, wire.HeaderKeySize)
	ik, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	copy(config.IntroKey, ik.Private)
	config.RemoteIntroKey = make([]byte, wire.HeaderKeySize)
	copy(config.RemoteIntroKey, responderIntroKey)
	config.RemoteStaticKey = respPub

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}
	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// 1. Initial tokenless SessionRequest, so SessCreateHeaderKey is derived and
	//    the conn is in the handshaking state where expectedInboundHeaderType()
	//    returns SessionCreated.
	initial, err := conn.sendSessionRequest()
	require.NoError(t, err)
	require.NotNil(t, initial)
	select {
	case <-initConn.writeChan:
	case <-time.After(time.Second):
		t.Fatal("initial SessionRequest was not sent")
	}

	require.GreaterOrEqual(t, len(initial.Header), 24)
	initDestConnID := initial.Header[0:8]
	initSrcConnID := initial.Header[16:24]

	// 2. Build a faithful captured i2pd Retry carrying token T (raw, header-
	//    protected wire bytes).
	tokenT := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	retryDatagram, issuedToken := buildCapturedI2pdRetry(
		t, responderIntroKey, initSrcConnID, initDestConnID, tokenT,
		remoteAddr.IP, uint16(remoteAddr.Port),
	)
	require.Equal(t, tokenT, issuedToken)

	// 3. Feed the RAW Retry datagram through the connection's OWN read path. This
	//    exercises decryptInboundHeader's SessionCreated-vs-Retry trial, which is
	//    the fix under test. readOnePacket deobfuscates, deserializes, and routes
	//    the Retry to the handshake queue via ProcessInboundPacket.
	raw := make([]byte, len(retryDatagram))
	copy(raw, retryDatagram)
	require.True(t, conn.readOnePacket(raw, remoteAddr),
		"own-socket read path must parse the Retry (decryptInboundHeader trial fix)")

	// 4. The Retry must reach recvQueue so handleRetryResponse can consume it.
	var delivered *SSU2Packet
	select {
	case delivered = <-conn.recvQueue:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Retry did not reach recvQueue via the own-socket read path (deobfuscation regression)")
	}
	require.Equal(t, MessageTypeRetry, delivered.MessageType)

	// 5. Drive handleRetryResponse: it extracts T and resends a tokened
	//    SessionRequest. Capture that request from the wire and assert the token
	//    survived in header bytes 24-31.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := conn.handleRetryResponse(ctx, delivered)
		done <- err
	}()

	var tokenedWire []byte
	select {
	case wp := <-initConn.writeChan:
		tokenedWire = wp.data
	case <-time.After(2 * time.Second):
		t.Fatal("no tokened SessionRequest was sent after Retry")
	}

	sessReqProtector, err := wire.NewHeaderProtectorFromIntroKey(responderIntroKey, wire.HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NoError(t, sessReqProtector.DecryptHeaderForPacket(tokenedWire))

	tokened := &SSU2Packet{}
	require.NoError(t, tokened.Deserialize(tokenedWire))
	require.Equal(t, MessageTypeSessionRequest, tokened.MessageType)
	require.GreaterOrEqual(t, len(tokened.Header), 32)
	require.Equal(t, tokenT, tokened.Header[24:32],
		"tokened SessionRequest must carry the Retry token in header bytes 24-31")

	// Let handleRetryResponse finish (it times out awaiting SessionCreated).
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}
