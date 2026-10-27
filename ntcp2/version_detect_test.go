package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// obfuscatedResponderConfig returns a responder config with AES obfuscation
// enabled and a real 16-byte IV, which is the configuration §"Version Detection"
// describes: a router published as "NTCP" always carries the obfuscation IV.
func obfuscatedResponderConfig(t *testing.T) *Config {
	t.Helper()
	var routerHash data.Hash
	copy(routerHash[:], "version-detect-responder-hash!!!")
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	iv := make([]byte, IVSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	return config.WithAESObfuscation(true, iv)
}

// fakeMsg1 builds bytes that look like the start of an NTCP2 message 1 to a
// responder holding cfg: the 32-byte X key is AES-256-CBC encrypted with RH_B and
// the published IV, and decrypts to a point whose high bit is clear. The remaining
// 32 bytes are opaque — stage one of detection never looks past the X key.
func fakeMsg1(t *testing.T, cfg *Config, xKey []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(cfg.BobRouterHash[:])
	require.NoError(t, err)
	out := make([]byte, ntcp2MinMsg1Size)
	cipher.NewCBCEncrypter(block, cfg.ObfuscationIV).CryptBlocks(out[:StaticKeySize], xKey)
	_, err = rand.Read(out[StaticKeySize:])
	require.NoError(t, err)
	return out
}

func validCurvePoint(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, StaticKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	// The high bit of the last byte must be clear for a valid public key.
	key[StaticKeySize-1] &= 0x7F
	return key
}

func TestClassifyNTCP2_ValidMsg1IsNTCP2(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)
	msg1 := fakeMsg1(t, cfg, validCurvePoint(t))

	assert.True(t, classifyNTCP2(cfg, msg1),
		"a message 1 whose X key decrypts to a valid curve point must stay NTCP2")
}

func TestClassifyNTCP2_InvalidCurvePointIsNTCP1(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)

	// Random bytes decrypt to a point with the high bit set about half the time;
	// force it so the test is deterministic.
	xKey := validCurvePoint(t)
	xKey[StaticKeySize-1] |= 0x80
	msg1 := fakeMsg1(t, cfg, xKey)

	assert.False(t, classifyNTCP2(cfg, msg1),
		"stage one of §\"Version Detection\" rejects a non-curve-point X key")
}

func TestClassifyNTCP2_ShortStreamIsInconclusive(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)

	// Fewer than 64 bytes cannot be an NTCP2 message 1, but there is also no
	// stage-one test to run, so the handshake decides.
	assert.True(t, classifyNTCP2(cfg, make([]byte, 16)))
}

func TestClassifyNTCP2_WithoutObfuscationDefersToHandshake(t *testing.T) {
	cfg := newTestResponderConfigNoAES(t)

	assert.True(t, classifyNTCP2(cfg, make([]byte, ntcp2MinMsg1Size)),
		"with no IV there is no key-dependent test; the AEAD check decides")
}

func TestDetectNTCPVersion_LongStreamIsNTCP1(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// An NTCP version 1 start-of-connection message is 336 bytes.
		_, _ = client.Write(make([]byte, ntcp1SizeThreshold))
	}()

	initial, proto, err := detectNTCPVersion(cfg, server, time.Now().Add(2*time.Second))
	require.NoError(t, err)
	assert.Equal(t, protocolNTCP1, proto)
	assert.GreaterOrEqual(t, len(initial), ntcp1SizeThreshold,
		"\"If the initial received data is 288 or more bytes, the incoming connection is version 1\"")
}

func TestDetectNTCPVersion_Msg1IsNTCP2(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	msg1 := fakeMsg1(t, cfg, validCurvePoint(t))
	go func() {
		_, _ = client.Write(msg1)
		// Then stay silent, as a conforming initiator does while awaiting msg2.
		time.Sleep(500 * time.Millisecond)
	}()

	start := time.Now()
	initial, proto, err := detectNTCPVersion(cfg, server, time.Now().Add(2*time.Second))
	require.NoError(t, err)
	assert.Equal(t, protocolNTCP2, proto)
	assert.Equal(t, msg1, initial, "the bytes consumed for detection must be replayable")
	assert.Less(t, time.Since(start), 500*time.Millisecond,
		"a plausible message 1 is decided on without waiting out the detection window")
}

func TestDetectNTCPVersion_PrefetchReplaysBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// The prefetched bytes are the ones detection already took off the wire, so the
	// socket must only ever deliver what came after them.
	go func() {
		_, _ = client.Write([]byte("... second read"))
	}()

	wrapped := newPrefetchConn(server, []byte("ntcp2 message one"))

	got := make([]byte, len("ntcp2 message one... second read"))
	_, err := io.ReadFull(wrapped, got)
	require.NoError(t, err)
	assert.Equal(t, "ntcp2 message one... second read", string(got))

	tcp := asTCPConn(wrapped)
	assert.Nil(t, tcp, "a net.Pipe is not a TCP connection")
}

func TestAsTCPConn_LooksThroughWrappers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	wrapped := newPrefetchConn(client, []byte("x"))
	assert.NotNil(t, asTCPConn(wrapped), "the *net.TCPConn must be reachable through the wrapper")
	assert.NotNil(t, asTCPConn(client))
}

// recordingDetector captures the version-1 handoff so a test can assert the
// listener routed the legacy connection out rather than into the NTCP2 handshake.
type recordingDetector struct {
	conn      net.Conn
	initial   []byte
	connected chan struct{}
}

func (d *recordingDetector) DetectNTCP1(conn net.Conn, initial []byte) {
	d.conn = conn
	d.initial = initial
	close(d.connected)
}

func TestAccept_DetectsNTCP1AndHandsOff(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)
	detector := &recordingDetector{connected: make(chan struct{})}
	cfg = cfg.WithVersionDetector(detector)

	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, cfg)

	// Detection happens inside Accept, so the accept loop has to be running.
	accepted := make(chan error, 1)
	go func() {
		conn, err := ntcp2Ln.Accept()
		if conn != nil {
			conn.Close()
		}
		accepted <- err
	}()

	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// 336 bytes is the smallest NTCP1 start-of-connection message and crosses the
	// 288-byte threshold on its own.
	legacy := make([]byte, 336)
	_, err = conn.Write(legacy)
	require.NoError(t, err)

	select {
	case <-detector.connected:
	case <-time.After(3 * time.Second):
		t.Fatal("the listener must hand an NTCP1 connection to the VersionDetector")
	}

	assert.Equal(t, legacy, detector.initial,
		"the detector must receive the bytes the listener consumed")
	assert.NotNil(t, detector.conn, "the detector takes ownership of the connection")

	// Accept must not have surfaced the legacy connection as an NTCP2 one; it
	// keeps waiting instead. Closing the listener unblocks it.
	require.NoError(t, ntcp2Ln.Close())
	select {
	case err := <-accepted:
		assert.Error(t, err, "a closed listener must unblock Accept")
	case <-time.After(3 * time.Second):
		t.Error("Accept() never resumed after the version-1 handoff")
	}
}

func TestAccept_NoDetectorClosesNTCP1(t *testing.T) {
	cfg := obfuscatedResponderConfig(t)
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, cfg)

	accepted := make(chan error, 1)
	go func() {
		conn, err := ntcp2Ln.Accept()
		if conn != nil {
			conn.Close()
		}
		accepted <- err
	}()

	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(make([]byte, 336))
	require.NoError(t, err)

	// With no version 1 transport registered, the listener cannot serve the
	// connection, so it closes it rather than running the NTCP2 handshake on it.
	deadline := time.Now().Add(3 * time.Second)
	if tcp, ok := conn.(*net.TCPConn); ok {
		require.NoError(t, tcp.SetReadDeadline(deadline))
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	assert.Error(t, err, "an NTCP1 connection with nowhere to go must be closed")

	require.NoError(t, ntcp2Ln.Close())
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Error("Accept() never resumed")
	}
}
