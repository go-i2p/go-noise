package wire

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GN-012: the intro-key message builder/openers (BuildIntroKeyMessage /
// OpenIntroKeyMessage) and their helpers were never exercised. These messages
// arrive straight off the wire from untrusted peers, so both the happy round
// trip and every reject path (bad key, tampered ciphertext, truncated packet)
// must be pinned down.

func introKeyForTest() []byte {
	k := make([]byte, HeaderKeySize)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func tokenRequestSpec() *IntroKeyMessageSpec {
	return &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x0102030405060708,
		SourceConnID: 0x1112131415161718,
		Token:        nil, // Token Request carries a zero token field
		Blocks: []*SSU2Block{
			NewDateTimeBlock(),
		},
	}
}

func TestBuildIntroKeyMessage_NilSpec(t *testing.T) {
	_, _, err := BuildIntroKeyMessage(introKeyForTest(), nil)
	require.Error(t, err)
}

func TestBuildIntroKeyMessage_BadIntroKey(t *testing.T) {
	_, _, err := BuildIntroKeyMessage([]byte{1, 2, 3}, tokenRequestSpec())
	require.Error(t, err)
}

// A well-formed Token Request must build, serialize, and open back to the same
// blocks under the receiver's intro key.
func TestIntroKeyMessage_RoundTrip(t *testing.T) {
	key := introKeyForTest()
	spec := tokenRequestSpec()

	packet, pn, err := BuildIntroKeyMessage(key, spec)
	require.NoError(t, err)
	require.NotEmpty(t, packet)
	assert.Greater(t, pn, uint32(0))
	assert.GreaterOrEqual(t, len(packet), MinPacketSize, "a compliant datagram is at least MinPacketSize")

	pkt, blocks, err := OpenIntroKeyMessage(key, packet)
	require.NoError(t, err)
	require.NotNil(t, pkt)
	assert.Equal(t, spec.MessageType, pkt.MessageType)
	assert.Equal(t, pn, pkt.PacketNumber)

	dest, err := pkt.DecodeConnectionID()
	require.NoError(t, err)
	assert.Equal(t, spec.DestConnID, dest, "dest conn ID must round-trip through header bytes 0-7")

	require.NotEmpty(t, blocks)
	assert.Equal(t, BlockTypeDateTime, blocks[0].Type)
}

// The header must be laid out per spec: type at 12, version at 13, network at 14.
// We recover the cleartext header by opening with the same key.
func TestIntroKeyMessage_HeaderLayout(t *testing.T) {
	key := introKeyForTest()
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypePeerTest,
		DestConnID:   0xdeadbeefcafebabe,
		SourceConnID: 0x0123456789abcdef,
		NetworkID:    3,
		Token:        []byte{0xaa, 0xbb, 0xcc, 0xdd},
		Blocks:       []*SSU2Block{NewDateTimeBlock()},
	}

	packet, _, err := BuildIntroKeyMessage(key, spec)
	require.NoError(t, err)

	pkt, _, err := OpenIntroKeyMessage(key, packet)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(pkt.Header), LongHeaderSize)
	assert.Equal(t, spec.DestConnID, binary.BigEndian.Uint64(pkt.Header[0:8]))
	assert.Equal(t, spec.SourceConnID, binary.BigEndian.Uint64(pkt.Header[16:24]))
	assert.Equal(t, uint8(3), pkt.Header[14], "network ID must land at header byte 14")
	assert.Equal(t, SSU2ProtocolVersion, pkt.Header[13])
}

// Opening with the wrong intro key must fail (header de-obfuscation or AEAD),
// never return a bogus packet.
func TestOpenIntroKeyMessage_WrongKey(t *testing.T) {
	key := introKeyForTest()
	packet, _, err := BuildIntroKeyMessage(key, tokenRequestSpec())
	require.NoError(t, err)

	other := make([]byte, HeaderKeySize)
	copy(other, key)
	other[0] ^= 0xff

	_, _, err = OpenIntroKeyMessage(other, packet)
	require.Error(t, err, "a mismatched intro key must not open the message")
}

// A flipped ciphertext byte must fail AEAD authentication.
func TestOpenIntroKeyMessage_TamperedCiphertext(t *testing.T) {
	key := introKeyForTest()
	packet, _, err := BuildIntroKeyMessage(key, tokenRequestSpec())
	require.NoError(t, err)

	// Flip a byte in the payload region (after the 32-byte header, before the
	// trailing 16-byte MAC).
	require.Greater(t, len(packet), LongHeaderSize+16)
	packet[LongHeaderSize+1] ^= 0x01

	_, _, err = OpenIntroKeyMessage(key, packet)
	require.Error(t, err, "tampered ciphertext must fail AEAD verification")
}

// A truncated datagram must be rejected rather than panicking.
func TestOpenIntroKeyMessage_Truncated(t *testing.T) {
	key := introKeyForTest()
	packet, _, err := BuildIntroKeyMessage(key, tokenRequestSpec())
	require.NoError(t, err)

	_, _, err = OpenIntroKeyMessage(key, packet[:10])
	require.Error(t, err)

	_, _, err = OpenIntroKeyMessage(key, nil)
	require.Error(t, err)
}

func TestOpenIntroKeyMessage_BadKeyLength(t *testing.T) {
	_, _, err := OpenIntroKeyMessage([]byte{1, 2, 3}, []byte("whatever"))
	require.Error(t, err)
}

// An empty block list must still produce a compliant datagram: the payload is
// floored to MinPayloadSize with a padding block.
func TestBuildIntroKeyMessage_EmptyPayloadFloored(t *testing.T) {
	key := introKeyForTest()
	spec := &IntroKeyMessageSpec{
		MessageType: MessageTypeHolePunch,
		Blocks:      nil,
	}
	packet, _, err := BuildIntroKeyMessage(key, spec)
	require.NoError(t, err)

	pkt, blocks, err := OpenIntroKeyMessage(key, packet)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(pkt.Payload)+len(pkt.MAC), MinPayloadSize)
	// The floored payload deserializes to at least one (padding) block.
	assert.NotEmpty(t, blocks)
}

func TestIntroKeyHeaderTypeFor(t *testing.T) {
	assert.Equal(t, HeaderTypeRetry, introKeyHeaderTypeFor(MessageTypeRetry))
	assert.Equal(t, HeaderTypeTokenRequest, introKeyHeaderTypeFor(MessageTypeTokenRequest))
	assert.Equal(t, HeaderTypePeerTest, introKeyHeaderTypeFor(MessageTypePeerTest))
	assert.Equal(t, HeaderTypeHolePunch, introKeyHeaderTypeFor(MessageTypeHolePunch))
	// Unknown types fall back to the long-header Retry case.
	assert.Equal(t, HeaderTypeRetry, introKeyHeaderTypeFor(0xFF))
}

func TestIntroKeyMessageSpec_NetworkID(t *testing.T) {
	assert.Equal(t, uint8(MainNetworkID), (&IntroKeyMessageSpec{}).networkID(), "zero defaults to main network")
	assert.Equal(t, uint8(3), (&IntroKeyMessageSpec{NetworkID: 3}).networkID())
}

func TestNonceConnectionIDs(t *testing.T) {
	const nonce = uint32(0x12345678)
	dest, src := NonceConnectionIDs(nonce)
	assert.Equal(t, (uint64(nonce)<<32)|uint64(nonce), dest)
	assert.Equal(t, ^dest, src, "source must be the bitwise complement of dest")

	// Deterministic for a given nonce.
	dest2, src2 := NonceConnectionIDs(nonce)
	assert.Equal(t, dest, dest2)
	assert.Equal(t, src, src2)
}

func TestNewDateTimeBlock(t *testing.T) {
	b := NewDateTimeBlock()
	require.NotNil(t, b)
	assert.Equal(t, BlockTypeDateTime, b.Type)
	require.Len(t, b.Data, 4)

	got := binary.BigEndian.Uint32(b.Data)
	now := uint32(time.Now().Unix())
	// Within a minute of now (guards against a wrong epoch or byte order).
	assert.InDelta(t, float64(now), float64(got), 60)
}

func TestNewAddressBlockForAddr(t *testing.T) {
	t.Run("nil yields zero IPv4", func(t *testing.T) {
		b := NewAddressBlockForAddr(nil)
		require.NotNil(t, b)
		assert.Equal(t, BlockTypeAddress, b.Type)
		ab, err := DecodeAddressBlock(b)
		require.NoError(t, err)
		assert.True(t, ab.IP.Equal(net.IPv4zero))
		assert.Equal(t, uint16(0), ab.Port)
	})

	t.Run("nil IP inside addr yields zero IPv4", func(t *testing.T) {
		b := NewAddressBlockForAddr(&net.UDPAddr{})
		ab, err := DecodeAddressBlock(b)
		require.NoError(t, err)
		assert.True(t, ab.IP.Equal(net.IPv4zero))
	})

	t.Run("IPv4 round trips", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 8123}
		b := NewAddressBlockForAddr(addr)
		ab, err := DecodeAddressBlock(b)
		require.NoError(t, err)
		assert.True(t, ab.IP.Equal(net.ParseIP("203.0.113.7")))
		assert.Equal(t, uint16(8123), ab.Port)
	})

	t.Run("IPv6 round trips", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9000}
		b := NewAddressBlockForAddr(addr)
		ab, err := DecodeAddressBlock(b)
		require.NoError(t, err)
		assert.True(t, ab.IP.Equal(net.ParseIP("2001:db8::1")))
		assert.Equal(t, uint16(9000), ab.Port)
	})
}

// buildIntroKeyHeader must place the token at bytes 24-31 and leave the flag
// byte zero.
func TestBuildIntroKeyHeader_Layout(t *testing.T) {
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypeRetry,
		DestConnID:   0x0102030405060708,
		SourceConnID: 0x090a0b0c0d0e0f10,
		Token:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	hdr := buildIntroKeyHeader(spec, 0x0a0b0c0d)
	require.Len(t, hdr, LongHeaderSize)

	assert.Equal(t, uint64(0x0102030405060708), binary.BigEndian.Uint64(hdr[0:8]))
	assert.Equal(t, uint32(0x0a0b0c0d), binary.BigEndian.Uint32(hdr[8:12]))
	assert.Equal(t, MessageTypeRetry, hdr[12])
	assert.Equal(t, SSU2ProtocolVersion, hdr[13])
	assert.Equal(t, uint8(MainNetworkID), hdr[14])
	assert.Equal(t, byte(0), hdr[15], "flag byte must be zero")
	assert.Equal(t, uint64(0x090a0b0c0d0e0f10), binary.BigEndian.Uint64(hdr[16:24]))
	assert.True(t, bytes.Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}, hdr[24:32]))
}
