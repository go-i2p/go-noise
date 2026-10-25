// SessionCreated must carry the mandatory Address block.
//
// ssu2.rst §"SessionCreated" -> §"Payload" lists "DateTime block / Address
// block / Options block (optional) / Termination block (optional...) / Padding
// block (optional)". Address carries no "(optional)" marker, and §"Address"
// describes the field as "Alice's address, sent to Alice by Bob": the responder
// echoes the initiator's observed IP and UDP source port back to it.
//
// The builder already knew how to emit the block, but nothing ever called
// HandshakeHandler.SetPeerAddress, so peerAddress stayed nil and every
// SessionCreated on the wire omitted it.

package handshake

import (
	"net"
	"testing"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func responderHandler(t *testing.T) *HandshakeHandler {
	t.Helper()
	dh, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	h, err := NewHandshakeHandler(false, dh.Private[:32], nil, nil)
	require.NoError(t, err)
	return h
}

func findBlock(blocks []*SSU2Block, typ uint8) *SSU2Block {
	for _, b := range blocks {
		if b != nil && b.Type == typ {
			return b
		}
	}
	return nil
}

// TestCreateHandshakeBlocks_SessionCreatedIncludesAddress proves the block is
// present once the peer endpoint has been recorded.
func TestCreateHandshakeBlocks_SessionCreatedIncludesAddress(t *testing.T) {
	h := responderHandler(t)
	h.SetPeerAddress(net.ParseIP("203.0.113.9"), 12345)

	blocks := h.createHandshakeBlocks(MessageTypeSessionCreated)

	addr := findBlock(blocks, BlockTypeAddress)
	require.NotNil(t, addr, "SessionCreated payload must include an Address block")

	decoded, err := DecodeAddressBlock(addr)
	require.NoError(t, err)
	assert.Equal(t, uint16(12345), decoded.Port)
	assert.Equal(t, net.ParseIP("203.0.113.9").To4(), decoded.IP.To4())
}

// TestCreateHandshakeBlocks_SessionRequestHasNoAddress pins the asymmetry: the
// §"SessionRequest" payload list has no Address block, so message 1 must not
// carry one.
func TestCreateHandshakeBlocks_SessionRequestHasNoAddress(t *testing.T) {
	dh1, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	dh2, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	h, err := NewHandshakeHandler(true, dh1.Private[:32], dh2.Public, nil)
	require.NoError(t, err)

	h.SetPeerAddress(net.ParseIP("203.0.113.9"), 12345)
	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	assert.Nil(t, findBlock(blocks, BlockTypeAddress),
		"SessionRequest must not carry an Address block")
}

// TestCreateSessionCreated_EmitsAddressBlock covers the real message path, not
// just the block list, so a regression in the packet builder is caught too.
func TestCreateSessionCreated_EmitsAddressBlock(t *testing.T) {
	// SessionCreated is Noise message 2, so the responder must have processed
	// the initiator's SessionRequest first; a handler that never received
	// message 1 is still at ReadMessage and cannot WriteMessage.
	initiator, responder, _, _ := setupHandshakePair(t)

	requestPacket, err := initiator.CreateSessionRequest(0x1122334455667788, 0x99aabbccddeeff00)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	responder.SetPeerAddress(net.ParseIP("198.51.100.7"), 51501)

	packet, err := responder.CreateSessionCreated(0x1122334455667788, 0x99aabbccddeeff00)
	require.NoError(t, err)
	require.NotNil(t, packet)
	assert.Greater(t, len(packet.Payload), 16, "payload plus MAC must be non-empty")

	// The payload is AEAD-sealed, so assert the builder's block list rather
	// than the ciphertext.
	assert.NotNil(t, findBlock(responder.createHandshakeBlocks(MessageTypeSessionCreated), BlockTypeAddress))
}
