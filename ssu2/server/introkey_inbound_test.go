package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Spec: ssu2.rst §"Header Encryption KDF" splits the third header part by
// message family:
//
//	"For Session Request and Session Created only: packet[16:63] = ChaCha20..."
//	"For Retry, Token Request, Peer Test, and Hole Punch only: packet[16:31] = ChaCha20"
//
// and §"Header Validation" explains the receiver learns which case applies
// only AFTER removing the XOR masks, because the type byte lives at offset 12:
//
//	"Decrypting the next 8 bytes of the header will then reveal the message
//	 type and be able to determine if it is a short or long header."
//
// These tests pin that the listener's intro-key decode path distinguishes the
// two families by the revealed type byte rather than by whatever header type
// the protector happened to be configured with.

func TestParseInboundPacket_TokenRequestLongHeaderRoundTrips(t *testing.T) {
	introKey := randomKey(t)
	l := newTestListenerWithIntroKey(t, introKey)

	// A realistic TokenRequest: DateTime + Padding blocks, so the datagram is
	// well over 64 bytes and the 48-byte extension branch would corrupt it if
	// the protector assumed a SessionRequest layout.
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x1122334455667788,
		SourceConnID: 0x99aabbccddeeff00,
		Token:        make([]byte, TokenSize),
		Blocks: []*SSU2Block{
			NewDateTimeBlock(),
			NewSSU2Block(BlockTypePadding, make([]byte, 24)),
		},
	}
	wire, _, err := BuildIntroKeyMessage(introKey, spec)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(wire), 64, "test must exercise a >64-byte long-header packet")

	packet, ok := l.parseInboundPacket(wire)
	require.True(t, ok, "listener must decode an inbound TokenRequest")
	require.Equal(t, uint8(MessageTypeTokenRequest), packet.MessageType)

	plaintext, err := DecryptIntroKeyAEAD(introKey, packet.Header, packet.Payload, packet.MAC, packet.PacketNumber)
	require.NoError(t, err, "decoded header must be the true cleartext header (AEAD ad binding)")

	blocks, err := DeserializeBlocks(plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, blocks)
}

func TestParseInboundPacket_PeerTestLongHeaderRoundTrips(t *testing.T) {
	introKey := randomKey(t)
	l := newTestListenerWithIntroKey(t, introKey)

	dest, src := NonceConnectionIDs(0xdeadbeef)
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks: []*SSU2Block{
			NewDateTimeBlock(),
			NewAddressBlockForAddr(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 8080}),
			NewSSU2Block(BlockTypePadding, make([]byte, 20)),
		},
	}
	wire, _, err := BuildIntroKeyMessage(introKey, spec)
	require.NoError(t, err)

	packet, ok := l.parseInboundPacket(wire)
	require.True(t, ok, "listener must decode an inbound PeerTest message")
	require.Equal(t, uint8(MessageTypePeerTest), packet.MessageType)

	_, err = DecryptIntroKeyAEAD(introKey, packet.Header, packet.Payload, packet.MAC, packet.PacketNumber)
	require.NoError(t, err, "decoded header must match the AEAD associated data")
}

// newTestListenerWithIntroKey builds a listener whose inbound header protector
// is initialised from introKey, matching production configuration.
func newTestListenerWithIntroKey(t *testing.T, introKey []byte) *SSU2Listener {
	t.Helper()
	pc := createMockPacketConn(t)
	config := createValidConfig(t)
	key := make([]byte, 32)
	copy(key, introKey)
	config.IntroKey = key
	listener, err := NewSSU2Listener(pc, config)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	require.NotNil(t, listener.introHeaderProtector.Load())
	return listener
}
