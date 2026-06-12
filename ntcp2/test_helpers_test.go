package ntcp2

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"

	noise "github.com/go-i2p/go-noise"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustRandomBytes generates a random byte slice of the given size,
// failing the test if crypto/rand returns an error.
func mustRandomBytes(t testing.TB, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// deterministicBytes returns a byte slice of the given size where
// each byte is (offset + index). Useful for repeatable test data.
func deterministicBytes(size int, offset byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = offset + byte(i)
	}
	return b
}

// testNTCP2Listener holds a fully-wired NTCP2 listener backed by a real
// TCP listener, with random router‐hash and config.
type testNTCP2Listener struct {
	listener   *Listener
	tcpAddr    net.Addr
	routerHash data.Hash
}

// newTestNTCP2Listener creates a real TCP listener on localhost, generates a
// random router‐hash, and wraps both in an NTCP2Listener. The TCP and NTCP2
// listeners are registered with t.Cleanup.
func newTestNTCP2Listener(t *testing.T) testNTCP2Listener {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcpLn.Close() })

	routerHash := generateRandomHash()

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	return testNTCP2Listener{
		listener:   ln,
		tcpAddr:    tcpLn.Addr(),
		routerHash: routerHash,
	}
}

// pipedNTCP2Conn holds all the pieces created by newPipedNTCP2Conn, so
// callers can access the raw pipe ends and the SipHash modifier, if set.
type pipedNTCP2Conn struct {
	conn    *Conn
	client  net.Conn // client end of net.Pipe (used by NoiseConn)
	server  net.Conn // server end of net.Pipe (for test writes/reads)
	noise   *noise.NoiseConn
	localA  *Addr
	remoteA *Addr
}

// newPipedNTCP2Conn creates an *NTCP2Conn backed by a net.Pipe(), wired
// through a NoiseConn with the XK pattern. Both pipe ends are registered
// with t.Cleanup so callers don't need explicit defers.
func newPipedNTCP2Conn(t *testing.T) pipedNTCP2Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	t.Cleanup(func() { noiseConn.Close() })

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	// Mark the connection as established so framing tests can exercise the
	// data-phase Read/Write paths without triggering the handshake guard.
	conn.established.Store(true)

	return pipedNTCP2Conn{
		conn:    conn,
		client:  client,
		server:  server,
		noise:   noiseConn,
		localA:  localAddr,
		remoteA: remoteAddr,
	}
}

// withSipHash attaches a SipHashLengthModifier with the given keys to the
// connection and returns the modifier (useful for mask probing).
func (p pipedNTCP2Conn) withSipHash(keys [2]uint64) *SipHashLengthModifier {
	slm := NewSipHashLengthModifier("test", keys, 0)
	p.conn.SetLengthObfuscator(slm)
	return slm
}

// newTestAESModifier creates an AESObfuscationModifier with fixed, deterministic
// routerHash and IV values. Used by audit tests that verify Close() zeroing.
func newTestAESModifier(t *testing.T) *AESObfuscationModifier {
	t.Helper()
	routerHash := make([]byte, RouterHashSize)
	copy(routerHash, "test-router-hash-32-bytes-long!!")
	iv := make([]byte, IVSize)
	copy(iv, "1234567890123456")
	mod, err := NewAESObfuscationModifier("test-aes", routerHash, iv)
	require.NoError(t, err)
	return mod
}

// createTestNTCP2ConnWithSLM creates an *NTCP2Conn backed by a mockNoiseConn
// with a SipHashLengthModifier attached. Common setup for nonce exhaustion tests.
func createTestNTCP2ConnWithSLM(t *testing.T) *Conn {
	t.Helper()
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)
	return conn
}

// testCryptoMaterial holds random byte slices commonly needed by NTCP2 tests.
type testCryptoMaterial struct {
	routerHash    data.Hash
	staticKey     []byte
	remoteHash    data.Hash
	obfuscationIV []byte
}

// newTestCryptoMaterial generates random test key material for NTCP2 tests.
func newTestCryptoMaterial(t *testing.T) testCryptoMaterial {
	t.Helper()
	return testCryptoMaterial{
		routerHash:    generateRandomHash(),
		staticKey:     generateRandomBytes(32),
		remoteHash:    generateRandomHash(),
		obfuscationIV: generateRandomBytes(16),
	}
}

// newTestNTCP2ConfigSimple creates a basic NTCP2Config with a random router hash.
// Use this for tests that only need a valid config without specific key material.
func newTestNTCP2ConfigSimple(t *testing.T, initiator bool) *Config {
	t.Helper()
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, initiator)
	require.NoError(t, err)
	return config
}

// newTestInitiatorConfig creates a fully-configured NTCP2Config for an
// initiator with random key material, a remote static key, and AES obfuscation.
// Returns the config and the underlying crypto material for assertions.
func newTestInitiatorConfig(t *testing.T) (*Config, testCryptoMaterial) {
	t.Helper()
	m := newTestCryptoMaterial(t)
	config := newTestInitiatorConfigFrom(t, m)
	return config, m
}

// newTestInitiatorConfigFrom builds a fully-configured initiator NTCP2Config
// from the given crypto material.
func newTestInitiatorConfigFrom(t *testing.T, m testCryptoMaterial) *Config {
	t.Helper()
	config, err := NewNTCP2Config(m.routerHash, true)
	require.NoError(t, err)
	config = config.
		WithStaticKey(m.staticKey).
		WithRemoteRouterHash(m.remoteHash).
		WithRemoteStaticKey(generateRandomBytes(32)).
		WithAESObfuscation(true, m.obfuscationIV)
	return config
}

// newTestResponderConfigWithKey creates a responder NTCP2Config with random
// router hash and static key, suitable for clone/listener tests.
func newTestResponderConfigWithKey(t *testing.T) *Config {
	t.Helper()
	routerHash := generateRandomHash()
	staticKey := generateRandomBytes(32)
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	return config.WithStaticKey(staticKey)
}

// newTestResponderConfigNoAES creates a responder NTCP2Config with a fixed
// router hash and AES obfuscation disabled, suitable for listener tests.
func newTestResponderConfigNoAES(t *testing.T) *Config {
	t.Helper()
	var routerHash data.Hash
	copy(routerHash[:], "responder-hash-32-bytes-long!!!!")

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	return config.WithAESObfuscation(false, nil)
}

// testXKConfigPair holds a matched initiator/responder config pair for XK tests.
type testXKConfigPair struct {
	initiatorConfig *Config
	responderConfig *Config
	initiatorHash   data.Hash
	responderHash   data.Hash
}

// newTestXKConfigPair creates a matched initiator+responder NTCP2Config pair
// with ChaChaPoly cipher suite, freshly generated Curve25519 keypairs,
// and deterministic router hashes. AES obfuscation is disabled.
func newTestXKConfigPair(t *testing.T) testXKConfigPair {
	t.Helper()

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
		WithLocalRouterInfo([]byte("fake-initiator-router-info"))

	return testXKConfigPair{
		initiatorConfig: initiatorConfig,
		responderConfig: responderConfig,
		initiatorHash:   initiatorHash,
		responderHash:   responderHash,
	}
}

// assertSipHashFrameRoundTrip writes a SipHash-obfuscated frame from writer

// startTestNTCP2Listener creates a real TCP listener, wraps it in an
// NTCP2Listener with the given config, and registers cleanup. Returns
// the NTCP2Listener and the TCP address for dialing.
func startTestNTCP2Listener(t *testing.T, config *Config) (*Listener, net.Addr) {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcpLn.Close() })

	ntcp2Ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)
	t.Cleanup(func() { ntcp2Ln.Close() })
	return ntcp2Ln, tcpLn.Addr()
}

// assertSipHashFrameRoundTrip writes a SipHash-obfuscated frame from writer
// to reader using senderSLM/receiverSLM, then verifies deobfuscation recovers
// the original payload. direction is used in assertion messages.
func assertSipHashFrameRoundTrip(
	t *testing.T,
	writer, reader net.Conn,
	senderSLM, receiverSLM *SipHashLengthModifier,
	payload []byte,
	direction string,
) {
	t.Helper()

	outMask := senderSLM.NextOutboundMask()
	frameLen := uint16(len(payload))
	frame := make([]byte, FrameLengthFieldSize+len(payload))
	binary.BigEndian.PutUint16(frame[:FrameLengthFieldSize], frameLen^outMask)
	copy(frame[FrameLengthFieldSize:], payload)

	_, err := writer.Write(frame)
	require.NoError(t, err)

	lengthBuf := make([]byte, FrameLengthFieldSize)
	_, err = io.ReadFull(reader, lengthBuf)
	require.NoError(t, err)

	inMask := receiverSLM.NextInboundMask()
	recovered := binary.BigEndian.Uint16(lengthBuf) ^ inMask
	assert.Equal(t, frameLen, recovered, fmt.Sprintf("%s: SipHash deobfuscation must recover original length", direction))

	buf := make([]byte, recovered)
	_, err = io.ReadFull(reader, buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf, fmt.Sprintf("%s: payload must survive SipHash framing round-trip", direction))
}

// newNTCP2TestModifier creates a deterministic (TestMode) NTCP2 padding modifier.
func newNTCP2TestModifier(t *testing.T, name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error) {
	t.Helper()
	mod, err := NewNTCP2PaddingModifier(name, minPadding, maxPadding, useAEADPadding)
	if err != nil {
		return nil, err
	}
	return mod.WithTestMode(), nil
}
