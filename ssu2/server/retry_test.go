package server

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingPacketConn records packets written through it so tests can inspect
// the exact bytes a listener put on the wire.
type capturingPacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	written [][]byte
}

func (c *capturingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	cp := make([]byte, len(p))
	copy(cp, p)
	c.written = append(c.written, cp)
	c.mu.Unlock()
	return len(p), nil
}

func (c *capturingPacketConn) last() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.written) == 0 {
		return nil, false
	}
	return c.written[len(c.written)-1], true
}

func newCapturingListener(t *testing.T, introKey []byte) (*SSU2Listener, *capturingPacketConn) {
	t.Helper()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	cap := &capturingPacketConn{PacketConn: pc}

	routerHash := generateRandomHash()
	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	config.DestroyTimeout = 0
	config.RouterInfoValidator = DefaultRouterInfoValidator
	config.IntroKey = introKey

	staticKey := make([]byte, 32)
	for i := range staticKey {
		staticKey[i] = byte(i + 0xA0)
	}
	config = config.WithStaticKey(staticKey)

	listener, err := NewSSU2Listener(cap, config)
	require.NoError(t, err)

	return listener, cap
}

// TestSendRetry_IsAEADSealedAndHeaderProtected pins ssu2.rst "Retry (Type 9)"
// and "KDF for Retry": the payload must be ChaCha20-Poly1305 sealed under the
// intro key with the cleartext header as AD, and the header itself must be
// obfuscated with k_header_1 = k_header_2 = bik.
func TestSendRetry_IsAEADSealedAndHeaderProtected(t *testing.T) {
	introKey := make([]byte, 32)
	for i := range introKey {
		introKey[i] = byte(i + 1)
	}

	listener, cap := newCapturingListener(t, introKey)
	t.Cleanup(func() { listener.Close() })

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 8877}
	token := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	originalHeader := make([]byte, LongHeaderSize)
	// Alice's source conn ID (bytes 16-23) becomes Bob's dest conn ID.
	originalHeader[16] = 0xAA

	require.NoError(t, listener.sendRetry(remoteAddr, token, originalHeader, 0, nil))

	wire, ok := cap.last()
	require.True(t, ok, "Retry must be written to the socket")

	// A conformant peer first removes header protection with Bob's intro key.
	protector, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeRetry)
	require.NoError(t, err)

	deobfuscated := make([]byte, len(wire))
	copy(deobfuscated, wire)
	require.NoError(t, protector.DecryptHeader(deobfuscated),
		"Retry header must be obfuscated with the intro key")

	packet := &SSU2Packet{}
	require.NoError(t, packet.Deserialize(deobfuscated))
	assert.Equal(t, uint8(MessageTypeRetry), packet.MessageType)

	// The dest connection ID must round-trip to Alice's source ID.
	assert.Equal(t, originalHeader[16], deobfuscated[0],
		"dest conn ID must echo the initiator's source conn ID")

	// The token travels in header bytes 24-31, not in a payload block.
	assert.Equal(t, token, deobfuscated[24:32], "Retry token must be in header bytes 24-31")

	// The payload must authenticate and decode to the spec's block set.
	plaintext, err := DecryptIntroKeyAEAD(introKey, packet.Header, packet.Payload, packet.MAC, packet.PacketNumber)
	require.NoError(t, err, "Retry payload must verify under the intro-key AEAD")

	blocks, err := DeserializeBlocks(plaintext)
	require.NoError(t, err)
	assert.NotNil(t, FindBlockByType(blocks, BlockTypeDateTime), "Retry requires a DateTime block")
	assert.NotNil(t, FindBlockByType(blocks, BlockTypeAddress), "Retry requires an Address block")
	assert.Nil(t, FindBlockByType(blocks, BlockTypeNewToken),
		"New Token is not an allowed Retry payload block; the token is a header field")

	// The Address block must report the peer's observed address (port first).
	addrBlock := FindBlockByType(blocks, BlockTypeAddress)
	decoded, err := DecodeAddressBlock(addrBlock)
	require.NoError(t, err)
	assert.Equal(t, remoteAddr.IP.To4(), decoded.IP)
	assert.EqualValues(t, remoteAddr.Port, decoded.Port)
}

// TestSendRetry_FailsClosedWithoutIntroKey verifies the listener refuses to
// emit a plaintext Retry when the intro key is unavailable, rather than
// producing a packet conformant peers cannot read.
func TestSendRetry_FailsClosedWithoutIntroKey(t *testing.T) {
	listener, cap := newCapturingListener(t, nil)
	t.Cleanup(func() { listener.Close() })

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 8877}
	err := listener.sendRetry(remoteAddr, []byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, LongHeaderSize), 0, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IntroKey")
	_, wrote := cap.last()
	assert.False(t, wrote, "no Retry may be sent without the intro key")
}
