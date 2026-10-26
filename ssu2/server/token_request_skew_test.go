// Tests for ssu2.md §"Token Request" -> §"Notes": "Bob must reject connections
// where the timestamp value is too far off from the current time. Call the
// maximum delta time D." and "Bob MAY send a Retry message containing a zero
// token and a Termination block with a clock skew reason code if the timestamp
// in the DateTime block is too far skewed."
//
// §"Token Request" -> §"Payload" lists the DateTime block as required; Java I2P
// InboundEstablishState2 throws "No DateTime block in Session/Token Request".

package server

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenRequestSpec builds an intro-key Token Request spec whose DateTime block
// carries the supplied timestamp.
func tokenRequestSpec(ts time.Time) *IntroKeyMessageSpec {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(ts.Unix()))
	return &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x1122334455667788,
		SourceConnID: 0x99aabbccddeeff00,
		Token:        make([]byte, TokenSize),
		Blocks: []*SSU2Block{
			NewSSU2Block(BlockTypeDateTime, b[:]),
			NewSSU2Block(BlockTypePadding, make([]byte, 24)),
		},
	}
}

// listenerAndClient spins up a listener (with intro key) on a real UDP socket
// plus a client socket bound to a real address, so the listener's Retry writes
// are deliverable and readable by the client.
func listenerAndClient(t *testing.T) (*SSU2Listener, *net.UDPConn, *net.UDPAddr, []byte) {
	t.Helper()
	introKey := randomKey(t)

	serverPC := createMockPacketConn(t)
	config := createValidConfig(t)
	config.FirstSightRequired = false
	key := make([]byte, 32)
	copy(key, introKey)
	config.IntroKey = key

	listener, err := NewSSU2Listener(serverPC, config)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { clientPC.Close() })
	clientAddr := clientPC.LocalAddr().(*net.UDPAddr)

	return listener, clientPC, clientAddr, introKey
}

// TestProcessTokenRequest_ClockSkewZeroTokenRetry proves a Token Request whose
// DateTime is outside the skew window is answered with a Retry carrying a zero
// token, and allocates no token state.
func TestProcessTokenRequest_ClockSkewZeroTokenRetry(t *testing.T) {
	listener, clientPC, clientAddr, introKey := listenerAndClient(t)

	wire, _, err := BuildIntroKeyMessage(introKey, tokenRequestSpec(time.Now().Add(-10*time.Minute)))
	require.NoError(t, err)

	packet, ok := listener.parseInboundPacket(wire, testPeerAddr())
	require.True(t, ok, "listener must decode the inbound TokenRequest")

	_ = listener.processTokenRequest(packet, clientAddr)

	assert.Equal(t, 0, listener.tokenCache.Size(),
		"a clock-skewed Token Request must not allocate a token")

	// Read the rejection Retry on the client socket.
	require.NoError(t, clientPC.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1500)
	n, _, err := clientPC.ReadFromUDP(buf)
	require.NoError(t, err, "expected a Retry datagram in response to the skewed request")

	retry, ok := listener.parseInboundPacket(buf[:n], testPeerAddr())
	require.True(t, ok, "the response must be a decodable intro-key message")
	assert.Equal(t, uint8(MessageTypeRetry), retry.MessageType)
	assert.True(t, isAllZero(retry.Header[24:32]),
		"the clock-skew rejection Retry must carry a zero token")
}

// TestProcessTokenRequest_FreshTimestampProceeds proves an in-window Token
// Request is accepted and allocates a token.
func TestProcessTokenRequest_FreshTimestampProceeds(t *testing.T) {
	listener, _, clientAddr, introKey := listenerAndClient(t)

	wire, _, err := BuildIntroKeyMessage(introKey, tokenRequestSpec(time.Now()))
	require.NoError(t, err)

	packet, ok := listener.parseInboundPacket(wire, testPeerAddr())
	require.True(t, ok)

	require.NoError(t, listener.processTokenRequest(packet, clientAddr))
	assert.Equal(t, 1, listener.tokenCache.Size())
}

// TestProcessTokenRequest_MissingDateTimeDropsSilently proves a Token Request
// without the required DateTime block is dropped without allocating token state.
func TestProcessTokenRequest_MissingDateTimeDropsSilently(t *testing.T) {
	listener, _, clientAddr, introKey := listenerAndClient(t)

	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x1122334455667788,
		SourceConnID: 0x99aabbccddeeff00,
		Token:        make([]byte, TokenSize),
		Blocks:       []*SSU2Block{NewSSU2Block(BlockTypePadding, make([]byte, 24))},
	}
	wire, _, err := BuildIntroKeyMessage(introKey, spec)
	require.NoError(t, err)

	packet, ok := listener.parseInboundPacket(wire, testPeerAddr())
	require.True(t, ok)

	require.Error(t, listener.processTokenRequest(packet, clientAddr))
	assert.Equal(t, 0, listener.tokenCache.Size(),
		"a malformed Token Request must not allocate a token")
}
