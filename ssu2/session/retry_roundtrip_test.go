package session

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

// buildCapturedI2pdRetry constructs a spec-compliant Retry datagram exactly as
// i2pd emits it in response to a tokenless SessionRequest, and returns both the
// obfuscated wire bytes and the 8-byte token it carries.
//
// It mirrors ssu2.rst §"Retry" / §"KDF for Retry":
//   - header: dest = initiator source conn ID, src = initiator dest conn ID,
//     type=Retry(9), ver=2, netid, token in bytes 24-31
//   - payload: DateTime + Address blocks, ChaCha20-Poly1305 sealed with the
//     responder intro key, cleartext header as AD, header packet number as nonce
//   - header protection: k_header_1 = k_header_2 = responder intro key
//
// This is the "captured i2pd Retry packet" the regression test drives.
func buildCapturedI2pdRetry(t *testing.T, responderIntroKey, initiatorSrcConnID, initiatorDestConnID []byte, token []byte, remoteIP net.IP, remotePort uint16) (wireDatagram []byte, issuedToken []byte) {
	t.Helper()

	issuedToken = make([]byte, 8)
	copy(issuedToken, token)

	header := make([]byte, wire.LongHeaderSize)
	// Retry dest = initiator's source conn ID; Retry src = initiator's dest conn ID.
	copy(header[0:8], initiatorSrcConnID)
	copy(header[16:24], initiatorDestConnID)
	packetNumber := uint32(0x0badf00d)
	header[8] = byte(packetNumber >> 24)
	header[9] = byte(packetNumber >> 16)
	header[10] = byte(packetNumber >> 8)
	header[11] = byte(packetNumber)
	header[12] = wire.MessageTypeRetry
	header[13] = wire.SSU2ProtocolVersion
	header[14] = wire.MainNetworkID
	header[15] = 0
	copy(header[24:32], issuedToken)

	// Required Retry payload blocks: DateTime (now) + Address.
	dateTimeData := make([]byte, 4)
	binary.BigEndian.PutUint32(dateTimeData, uint32(time.Now().Unix()))
	blocks := []*wire.SSU2Block{
		wire.NewSSU2Block(wire.BlockTypeDateTime, dateTimeData),
		wire.EncodeAddressBlock(remoteIP, remotePort),
	}
	payload, err := wire.SerializeBlocks(blocks)
	require.NoError(t, err)

	// AEAD-seal the payload with the responder intro key, cleartext header as AD.
	ciphertext, mac, err := wire.EncryptIntroKeyAEAD(responderIntroKey, header, payload, packetNumber)
	require.NoError(t, err)

	pkt := wire.NewSSU2Packet(wire.MessageTypeRetry, packetNumber)
	pkt.Header = header
	pkt.Payload = ciphertext
	pkt.MAC = mac

	datagram, err := pkt.Serialize()
	require.NoError(t, err)

	// Header protection last (AEAD already committed to the cleartext header).
	protector, err := wire.NewHeaderProtectorFromIntroKey(responderIntroKey, wire.HeaderTypeRetry)
	require.NoError(t, err)
	require.NoError(t, protector.EncryptHeader(datagram))

	return datagram, issuedToken
}

// TestInitiatorRetryRoundTrip_AcceptedByResponder is the regression oracle for
// the SSU2 initiator Retry bug reported against i2pd.
//
// It drives a FULL initiator Retry round-trip against a captured i2pd-style
// Retry packet and asserts the resulting tokened SessionRequest is ACCEPTED by
// a responder handshake handler — the exact property i2pd violated when it
// logged "SessionRequest token mismatch".
//
// Flow:
//  1. The initiator builds its initial SessionRequest (token=0) and sends it.
//  2. We capture the initiator's source/dest conn IDs from that request and
//     build a faithful captured Retry (token T) exactly as i2pd emits it.
//  3. The Retry is deobfuscated (as the listener's retryProtector does) and
//     delivered via ProcessInboundPacket — exercising the routing fix that
//     previously dropped it.
//  4. handleRetryResponse extracts T and resends a tokened SessionRequest.
//  5. We capture that tokened SessionRequest, deobfuscate it, and feed it to a
//     fresh responder handshake handler, which must ACCEPT it (ProcessSessionRequest
//     returns no error) and echo the same token.
//
// Before the fix, step 3 dropped the Retry, so handleRetryResponse never ran and
// no tokened SessionRequest was ever produced — the handshake timed out with
// "failed to receive SessionCreated: handshake timeout after 3 retransmits".
func TestInitiatorRetryRoundTrip_AcceptedByResponder(t *testing.T) {
	initConn, respConn, initPriv, _, respPriv, respPub := setupConnPair(t)
	_ = respConn

	// Responder intro key: used to obfuscate the SessionRequest and to seal /
	// header-protect the captured Retry.
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

	// 1. Initial SessionRequest (token=0).
	initial, err := conn.sendSessionRequest()
	require.NoError(t, err)
	require.NotNil(t, initial)

	// Drain the initial SessionRequest datagram from the mock socket.
	select {
	case <-initConn.writeChan:
	case <-time.After(time.Second):
		t.Fatal("initial SessionRequest was not sent")
	}

	// Capture the initiator's conn IDs as they appear on the wire (deobfuscated
	// header): dest = bytes 0-7, src = bytes 16-23.
	require.GreaterOrEqual(t, len(initial.Header), 24)
	initDestConnID := initial.Header[0:8]
	initSrcConnID := initial.Header[16:24]

	// 2. Build a faithful captured i2pd Retry carrying token T.
	tokenT := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	retryDatagram, issuedToken := buildCapturedI2pdRetry(
		t, responderIntroKey, initSrcConnID, initDestConnID, tokenT,
		remoteAddr.IP, uint16(remoteAddr.Port),
	)
	require.Equal(t, tokenT, issuedToken)

	// 3. Deobfuscate the Retry exactly as the listener's retryProtector does,
	//    then deliver it via ProcessInboundPacket (the routing fix under test).
	deobfuscated := make([]byte, len(retryDatagram))
	copy(deobfuscated, retryDatagram)
	retryProtector, err := wire.NewHeaderProtectorFromIntroKey(responderIntroKey, wire.HeaderTypeRetry)
	require.NoError(t, err)
	require.NoError(t, retryProtector.DecryptHeaderForPacket(deobfuscated))

	retryPacket := &SSU2Packet{}
	require.NoError(t, retryPacket.Deserialize(deobfuscated))
	require.Equal(t, MessageTypeRetry, retryPacket.MessageType)

	conn.ProcessInboundPacket(retryPacket)

	// The Retry must now be on recvQueue (the routing fix). If it were dropped,
	// handleRetryResponse would never see it.
	var delivered *SSU2Packet
	select {
	case delivered = <-conn.recvQueue:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Retry was dropped by ProcessInboundPacket (routing regression)")
	}
	require.Equal(t, MessageTypeRetry, delivered.MessageType)

	// 4. Drive handleRetryResponse. It extracts the token, resends a tokened
	//    SessionRequest, then waits for SessionCreated (which we don't supply),
	//    so run it in the background and capture the tokened request from the wire.
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

	// 5. Deobfuscate the tokened SessionRequest and assert the token survived.
	//    The initiator obfuscates the SessionRequest with the responder intro key.
	sessReqProtector, err := wire.NewHeaderProtectorFromIntroKey(responderIntroKey, wire.HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NoError(t, sessReqProtector.DecryptHeaderForPacket(tokenedWire))

	tokened := &SSU2Packet{}
	require.NoError(t, tokened.Deserialize(tokenedWire))
	require.Equal(t, MessageTypeSessionRequest, tokened.MessageType)
	require.GreaterOrEqual(t, len(tokened.Header), 32)
	gotToken := tokened.Header[24:32]
	require.Equal(t, tokenT, gotToken, "tokened SessionRequest must carry the Retry token in header bytes 24-31")

	// The crux: a responder handshake handler must ACCEPT the tokened request.
	// This is exactly what i2pd failed to do ("token mismatch").
	responderHandler, err := ssu2hs.NewHandshakeHandler(false, respPriv, nil, nil)
	require.NoError(t, err)
	defer responderHandler.Close()

	_, err = responderHandler.ProcessSessionRequest(tokened)
	require.NoError(t, err, "responder must accept the tokened SessionRequest")

	// Let handleRetryResponse finish (it will time out awaiting SessionCreated).
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}
