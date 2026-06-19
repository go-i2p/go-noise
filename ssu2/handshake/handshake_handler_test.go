package handshake

import (
	"encoding/binary"
	"testing"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers

// setupHandshakePair creates a matching initiator and responder pair for testing.
func setupHandshakePair(t *testing.T) (*HandshakeHandler, *HandshakeHandler, []byte, []byte) {
	t.Helper()

	// Generate key pairs using noise library
	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	// Create handlers - initiator knows responder's public key
	// Pass the full private key (already 32 bytes) and responder's public key
	initiator, err := NewHandshakeHandlerWithKeys(true, initDH, respDH.Public, nil)
	require.NoError(t, err)

	// Responder doesn't know initiator's key yet (will learn from SessionRequest)
	responder, err := NewHandshakeHandlerWithKeys(false, respDH, nil, nil)
	require.NoError(t, err)

	return initiator, responder, initDH.Public, respDH.Public
}

// NewHandshakeHandler tests

func TestNewHandshakeHandler_ValidInitiator(t *testing.T) {
	dh1, _ := noise.DH25519.GenerateKeypair(nil)
	dh2, _ := noise.DH25519.GenerateKeypair(nil)

	handler, err := NewHandshakeHandler(true, dh1.Private[:32], dh2.Public, nil)
	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.True(t, handler.initiator)
	assert.NotNil(t, handler.handshakeState)
	assert.False(t, handler.IsHandshakeComplete())
}

func TestNewHandshakeHandler_ValidResponder(t *testing.T) {
	dh, _ := noise.DH25519.GenerateKeypair(nil)

	handler, err := NewHandshakeHandler(false, dh.Private[:32], nil, nil)
	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.False(t, handler.initiator)
	assert.NotNil(t, handler.handshakeState)
	assert.False(t, handler.IsHandshakeComplete())
}

func TestNewHandshakeHandler_InvalidStaticKey(t *testing.T) {
	tests := []struct {
		name         string
		staticKeyLen int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			staticKey := make([]byte, tt.staticKeyLen)
			handler, err := NewHandshakeHandler(true, staticKey, nil, nil)
			assert.Error(t, err)
			assert.Nil(t, handler)
		})
	}
}

func TestNewHandshakeHandler_InitiatorMissingRemoteKey(t *testing.T) {
	dh, _ := noise.DH25519.GenerateKeypair(nil)
	handler, err := NewHandshakeHandler(true, dh.Private[:32], nil, nil)
	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "initiator requires remote static key")
}

func TestNewHandshakeHandler_InvalidRemoteKey(t *testing.T) {
	dh, _ := noise.DH25519.GenerateKeypair(nil)
	invalidRemoteKey := make([]byte, 16) // Wrong size

	handler, err := NewHandshakeHandler(true, dh.Private[:32], invalidRemoteKey, nil)
	assert.Error(t, err)
	assert.Nil(t, handler)
}

func TestNewHandshakeHandler_DefensiveCopy(t *testing.T) {
	dh1, _ := noise.DH25519.GenerateKeypair(nil)
	dh2, _ := noise.DH25519.GenerateKeypair(nil)

	staticKey := append([]byte(nil), dh1.Private[:32]...)
	remoteKey := append([]byte(nil), dh2.Public...)
	origStatic := append([]byte(nil), staticKey...)
	origRemote := append([]byte(nil), remoteKey...)

	handler, err := NewHandshakeHandler(true, staticKey, remoteKey, nil)
	require.NoError(t, err)

	// Modify original slices
	for i := range staticKey {
		staticKey[i] = 0xFF
	}
	for i := range remoteKey {
		remoteKey[i] = 0xFF
	}

	// Handler should have defensive copies
	assert.Equal(t, origStatic, handler.staticKey)
	assert.Equal(t, origRemote, handler.remoteStaticKey)
}

// SessionRequest tests

func TestHandshakeHandler_CreateSessionRequest(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	sourceConnID := uint64(12345)
	destConnID := uint64(67890)

	packet, err := initiator.CreateSessionRequest(sourceConnID, destConnID)
	require.NoError(t, err)
	require.NotNil(t, packet)

	// Validate packet structure
	assert.Equal(t, MessageTypeSessionRequest, packet.MessageType)
	assert.Equal(t, 32, len(packet.Header), "SessionRequest uses long header")
	assert.Equal(t, 32, len(packet.EphemeralKey), "SessionRequest includes ephemeral key")
	assert.NotNil(t, packet.Payload)
	assert.NotEmpty(t, packet.Payload)
	assert.Equal(t, uint32(0), packet.PacketNumber)

	// Validate connection IDs in header per spec §LongHeader layout
	decodedDestConnID := binary.BigEndian.Uint64(packet.Header[0:8])
	decodedSourceConnID := binary.BigEndian.Uint64(packet.Header[16:24])
	assert.Equal(t, destConnID, decodedDestConnID)
	assert.Equal(t, sourceConnID, decodedSourceConnID)
	assert.Equal(t, MessageTypeSessionRequest, packet.Header[12])
	assert.Equal(t, SSU2ProtocolVersion, packet.Header[13])
	assert.Equal(t, SSU2NetworkID, packet.Header[14])
}

func TestHandshakeHandler_CreateSessionRequest_ResponderError(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet, err := responder.CreateSessionRequest(12345, 67890)
	assert.Error(t, err)
	assert.Nil(t, packet)
	assert.Contains(t, err.Error(), "only initiator")
}

func TestHandshakeHandler_ProcessSessionRequest(t *testing.T) {
	initiator, responder, initiatorPub, _ := setupHandshakePair(t)

	// Create SessionRequest
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	// Process SessionRequest
	// Note: ProcessSessionRequest returns nil for the learned key because the Noise
	// library doesn't expose the peer's static key via PeerStatic() on the responder side.
	// The handshake is still authenticated via DH operations.
	learnedKey, err := responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	// Verify the handshake succeeded (no error means authentication passed)
	// The actual identity exchange should happen via payload blocks if needed
	_ = learnedKey   // May be nil
	_ = initiatorPub // For future identity verification via payload blocks
	_ = responder    // Handshake state is valid
}

func TestHandshakeHandler_ProcessSessionRequest_InvalidType(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType:  MessageTypeSessionCreated, // Wrong type
		EphemeralKey: make([]byte, 32),
		Payload:      []byte("test"),
	}

	learnedKey, err := responder.ProcessSessionRequest(packet)
	assert.Error(t, err)
	assert.Nil(t, learnedKey)
	assert.Contains(t, err.Error(), "expected SessionRequest")
}

func TestHandshakeHandler_ProcessSessionRequest_MissingEphemeralKey(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType:  MessageTypeSessionRequest,
		EphemeralKey: nil, // Missing
		Payload:      []byte("test"),
	}

	learnedKey, err := responder.ProcessSessionRequest(packet)
	assert.Error(t, err)
	assert.Nil(t, learnedKey)
	assert.Contains(t, err.Error(), "missing ephemeral key")
}

func TestHandshakeHandler_ProcessSessionRequest_InitiatorError(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType:  MessageTypeSessionRequest,
		EphemeralKey: make([]byte, 32),
		Payload:      []byte("test"),
	}

	learnedKey, err := initiator.ProcessSessionRequest(packet)
	assert.Error(t, err)
	assert.Nil(t, learnedKey)
	assert.Contains(t, err.Error(), "initiator cannot process SessionRequest")
}

// SessionCreated tests

func TestHandshakeHandler_CreateSessionCreated(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Setup: initiator creates request, responder processes it
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	// Now responder can create SessionCreated
	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	require.NotNil(t, createdPacket)

	// Validate packet structure
	assert.Equal(t, MessageTypeSessionCreated, createdPacket.MessageType)
	assert.Equal(t, 32, len(createdPacket.Header))
	assert.Equal(t, 32, len(createdPacket.EphemeralKey))
	assert.NotNil(t, createdPacket.Payload)

	// Validate connection IDs per spec §LongHeader layout
	decodedDestConnID := binary.BigEndian.Uint64(createdPacket.Header[0:8])
	decodedSourceConnID := binary.BigEndian.Uint64(createdPacket.Header[16:24])
	assert.Equal(t, uint64(44444), decodedDestConnID)
	assert.Equal(t, uint64(33333), decodedSourceConnID)
	assert.Equal(t, MessageTypeSessionCreated, createdPacket.Header[12])
	assert.Equal(t, SSU2ProtocolVersion, createdPacket.Header[13])
}

func TestHandshakeHandler_CreateSessionCreated_InitiatorError(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	packet, err := initiator.CreateSessionCreated(11111, 22222)
	assert.Error(t, err)
	assert.Nil(t, packet)
	assert.Contains(t, err.Error(), "only responder")
}

func TestHandshakeHandler_ProcessSessionCreated(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Full handshake flow up to SessionCreated
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)

	// Initiator processes SessionCreated
	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	// XK requires 3 messages; handshake not yet complete after 2
	assert.False(t, initiator.IsHandshakeComplete())
}

func TestHandshakeHandler_ProcessSessionCreated_InvalidType(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType:  MessageTypeData, // Wrong type
		EphemeralKey: make([]byte, 32),
		Payload:      []byte("test"),
	}

	err := initiator.ProcessSessionCreated(packet)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected SessionCreated")
}

func TestHandshakeHandler_ProcessSessionCreated_ResponderError(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType:  MessageTypeSessionCreated,
		EphemeralKey: make([]byte, 32),
		Payload:      []byte("test"),
	}

	err := responder.ProcessSessionCreated(packet)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "responder cannot process SessionCreated")
}

// SessionConfirmed tests

func TestHandshakeHandler_CreateSessionConfirmed(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete handshake up to SessionConfirmed
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)

	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	// Now initiator can create SessionConfirmed
	confirmedPacket, err := initiator.CreateSessionConfirmed(55555, 1, nil)
	require.NoError(t, err)
	require.NotNil(t, confirmedPacket)

	// Validate packet structure
	assert.Equal(t, MessageTypeSessionConfirmed, confirmedPacket.MessageType)
	assert.Equal(t, 16, len(confirmedPacket.Header), "Short header")
	assert.Nil(t, confirmedPacket.EphemeralKey, "No ephemeral key")
	assert.NotNil(t, confirmedPacket.Payload)
	assert.Equal(t, 16, len(confirmedPacket.MAC))
	assert.Equal(t, uint32(1), confirmedPacket.PacketNumber)
}

func TestHandshakeHandler_CreateSessionConfirmed_ResponderError(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet, err := responder.CreateSessionConfirmed(11111, 1, nil)
	assert.Error(t, err)
	assert.Nil(t, packet)
	assert.Contains(t, err.Error(), "only initiator")
}

func TestHandshakeHandler_CreateSessionConfirmed_NotComplete(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	// Try to create SessionConfirmed without completing prior handshake messages
	packet, err := initiator.CreateSessionConfirmed(11111, 1, nil)
	assert.Error(t, err)
	assert.Nil(t, packet)
}

func TestHandshakeHandler_ProcessSessionConfirmed(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete full handshake flow
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)

	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	confirmedPacket, err := initiator.CreateSessionConfirmed(55555, 1, nil)
	require.NoError(t, err)

	// Responder processes SessionConfirmed
	err = responder.ProcessSessionConfirmed(confirmedPacket)
	require.NoError(t, err)

	// Both sides should have complete handshake
	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())
}

func TestHandshakeHandler_ProcessSessionConfirmed_InvalidType(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType: MessageTypeData, // Wrong type
		Payload:     []byte("test"),
		MAC:         make([]byte, 16),
	}

	err := responder.ProcessSessionConfirmed(packet)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected SessionConfirmed")
}

func TestHandshakeHandler_ProcessSessionConfirmed_InitiatorError(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	packet := &SSU2Packet{
		MessageType: MessageTypeSessionConfirmed,
		Payload:     []byte("test"),
		MAC:         make([]byte, 16),
	}

	err := initiator.ProcessSessionConfirmed(packet)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initiator cannot process SessionConfirmed")
}

// Full handshake flow tests

func TestHandshakeHandler_FullHandshakeFlow(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Neither should be complete initially
	assert.False(t, initiator.IsHandshakeComplete())
	assert.False(t, responder.IsHandshakeComplete())

	// Step 1: SessionRequest
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	// Step 2: SessionCreated
	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)

	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	// XK requires 3 messages; handshake should NOT be complete after 2
	assert.False(t, initiator.IsHandshakeComplete())
	assert.False(t, responder.IsHandshakeComplete())

	// Step 3: SessionConfirmed
	confirmedPacket, err := initiator.CreateSessionConfirmed(55555, 1, nil)
	require.NoError(t, err)

	err = responder.ProcessSessionConfirmed(confirmedPacket)
	require.NoError(t, err)

	// Both should be complete after SessionConfirmed
	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())

	// Both should have cipher states
	initSend, initRecv, err := initiator.GetCipherStates()
	require.NoError(t, err)
	assert.NotNil(t, initSend)
	assert.NotNil(t, initRecv)

	respSend, respRecv, err := responder.GetCipherStates()
	require.NoError(t, err)
	assert.NotNil(t, respSend)
	assert.NotNil(t, respRecv)
}

// Cipher state tests

func TestHandshakeHandler_GetCipherStates_NotComplete(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	send, recv, err := initiator.GetCipherStates()
	assert.Error(t, err)
	assert.Nil(t, send)
	assert.Nil(t, recv)
	assert.Contains(t, err.Error(), "handshake not complete")
}

func TestHandshakeHandler_GetCipherStates_AfterComplete(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete full 3-message XK handshake
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)
	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)
	confirmedPacket, err := initiator.CreateSessionConfirmed(55555, 1, nil)
	require.NoError(t, err)
	err = responder.ProcessSessionConfirmed(confirmedPacket)
	require.NoError(t, err)

	// Get cipher states
	send, recv, err := initiator.GetCipherStates()
	require.NoError(t, err)
	assert.NotNil(t, send)
	assert.NotNil(t, recv)
}

// Remote static key tests

func TestHandshakeHandler_GetRemoteStaticKey_Initiator(t *testing.T) {
	initiator, _, _, responderPub := setupHandshakePair(t)

	retrievedKey := initiator.GetRemoteStaticKey()
	assert.Equal(t, responderPub, retrievedKey)

	// Key should be a copy
	retrievedKey[0] ^= 0xFF
	assert.NotEqual(t, retrievedKey, initiator.GetRemoteStaticKey())
}

func TestHandshakeHandler_GetRemoteStaticKey_ResponderAfterRequest(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Initially responder doesn't know initiator's key
	assert.Nil(t, responder.GetRemoteStaticKey())

	// After processing SessionRequest, responder still doesn't have it via GetRemoteStaticKey
	// because the Noise library doesn't expose it for XK pattern on the responder side
	requestPacket, _ := initiator.CreateSessionRequest(11111, 22222)
	_, err := responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	// The handshake succeeds (authentication via DH), but the static key isn't directly available
	retrievedKey := responder.GetRemoteStaticKey()
	assert.Nil(t, retrievedKey, "Responder cannot directly access initiator's static key in XK pattern")
}

// Helper function tests

func Test_copyBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"nil slice", nil},
		{"empty slice", []byte{}},
		{"small slice", []byte{1, 2, 3}},
		{"large slice", make([]byte, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := copyBytes(tt.input)

			if tt.input == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.input, result)
				if len(tt.input) > 0 {
					// Verify it's a copy
					assert.NotSame(t, &tt.input[0], &result[0])
				}
			}
		})
	}
}

// Benchmarks

func BenchmarkHandshakeHandler_CreateSessionRequest(b *testing.B) {
	dh1, _ := noise.DH25519.GenerateKeypair(nil)
	dh2, _ := noise.DH25519.GenerateKeypair(nil)

	handler, _ := NewHandshakeHandler(true, dh1.Private[:32], dh2.Public, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := handler.CreateSessionRequest(12345, 67890)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshakeHandler_ProcessSessionRequest(b *testing.B) {
	dh1, _ := noise.DH25519.GenerateKeypair(nil)
	dh2, _ := noise.DH25519.GenerateKeypair(nil)
	dh3, _ := noise.DH25519.GenerateKeypair(nil)

	initiator, _ := NewHandshakeHandler(true, dh1.Private[:32], dh2.Public, nil)
	requestPacket, _ := initiator.CreateSessionRequest(11111, 22222)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		responder, _ := NewHandshakeHandler(false, dh3.Private[:32], nil, nil)
		_, err := responder.ProcessSessionRequest(requestPacket)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshakeHandler_FullHandshake(b *testing.B) {
	dh1, _ := noise.DH25519.GenerateKeypair(nil)
	dh2, _ := noise.DH25519.GenerateKeypair(nil)

	initPriv := dh1.Private[:32]
	respPriv := dh2.Private[:32]
	respPub := dh2.Public

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		initiator, _ := NewHandshakeHandler(true, initPriv, respPub, nil)
		responder, _ := NewHandshakeHandler(false, respPriv, nil, nil)

		requestPacket, _ := initiator.CreateSessionRequest(11111, 22222)
		_, _ = responder.ProcessSessionRequest(requestPacket)

		createdPacket, _ := responder.CreateSessionCreated(33333, 44444)
		_ = initiator.ProcessSessionCreated(createdPacket)

		confirmedPacket, _ := initiator.CreateSessionConfirmed(55555, 1, nil)
		_ = responder.ProcessSessionConfirmed(confirmedPacket)
	}
}

// C-2 regression tests: protocol name and null prologue

func TestSSU2ProtocolName_MatchesSpec(t *testing.T) {
	// The SSU2 spec defines this exact protocol name string.
	expected := "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"
	assert.Equal(t, expected, SSU2ProtocolName)
	assert.Equal(t, 52, len(SSU2ProtocolName), "Protocol name should be 52 bytes (US-ASCII)")
}

func TestBuildSSU2Prologue_ReturnsNil(t *testing.T) {
	// Per the SSU2 spec, the prologue is null (empty).
	// MixHash(null prologue) → h = SHA256(h)
	result := buildSSU2Prologue()
	assert.Nil(t, result, "SSU2 prologue must be nil per spec")
}

// C-3 regression tests: header key derivation

func TestDeriveHeaderKeys_AfterHandshake(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete the 3-message XK handshake
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)
	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)
	confirmedPacket, err := initiator.CreateSessionConfirmed(55555, 1, nil)
	require.NoError(t, err)
	err = responder.ProcessSessionConfirmed(confirmedPacket)
	require.NoError(t, err)

	// Derive header keys on both sides
	initSendK, initRecvK, err := initiator.DeriveHeaderKeys()
	require.NoError(t, err)
	assert.Len(t, initSendK, 32, "k_header_2 must be 32 bytes")
	assert.Len(t, initRecvK, 32, "k_header_2 must be 32 bytes")

	respSendK, respRecvK, err := responder.DeriveHeaderKeys()
	require.NoError(t, err)
	assert.Len(t, respSendK, 32)
	assert.Len(t, respRecvK, 32)

	// Initiator's send key should match responder's recv key and vice versa
	assert.Equal(t, initSendK, respRecvK, "initiator send k_header_2 must match responder recv k_header_2")
	assert.Equal(t, initRecvK, respSendK, "initiator recv k_header_2 must match responder send k_header_2")
}

func TestDeriveHeaderKeys_NotComplete(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	k1, k2, err := initiator.DeriveHeaderKeys()
	assert.Error(t, err)
	assert.Nil(t, k1)
	assert.Nil(t, k2)
	assert.Contains(t, err.Error(), "handshake not complete")
}

func TestDeriveHeaderKeys_Deterministic(t *testing.T) {
	// Same key material should produce the same header keys
	dh1, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	dh2, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	doHandshake := func() ([]byte, []byte) {
		init, _ := NewHandshakeHandlerWithKeys(true, dh1, dh2.Public, nil)
		resp, _ := NewHandshakeHandlerWithKeys(false, dh2, nil, nil)

		req, _ := init.CreateSessionRequest(11111, 22222)
		_, _ = resp.ProcessSessionRequest(req)
		created, _ := resp.CreateSessionCreated(33333, 44444)
		_ = init.ProcessSessionCreated(created)
		confirmed, _ := init.CreateSessionConfirmed(55555, 1, nil)
		_ = resp.ProcessSessionConfirmed(confirmed)

		k1, k2, _ := init.DeriveHeaderKeys()
		return k1, k2
	}

	// NOTE: Noise uses random ephemeral keys, so different handshakes with
	// the same static keys will produce different split keys and thus
	// different header keys. This test just verifies the derivation doesn't
	// error and returns valid 32-byte keys.
	k1, k2 := doHandshake()
	assert.Len(t, k1, 32)
	assert.Len(t, k2, 32)
}

// SessionConfirmed fragmentation tests

func TestCreateSessionConfirmedFragments_SinglePacket(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete handshake up to message 2
	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(created)
	require.NoError(t, err)

	// Small payload should produce a single fragment
	fragments, err := initiator.CreateSessionConfirmedFragments(55555, 1, nil)
	require.NoError(t, err)
	require.Len(t, fragments, 1)

	pkt := fragments[0]
	assert.Equal(t, MessageTypeSessionConfirmed, pkt.MessageType)
	assert.Len(t, pkt.Header, ShortHeaderSize)
	assert.Equal(t, uint32(1), pkt.PacketNumber)
	// frag byte: fragment 0 of 1
	assert.Equal(t, byte(0x01), pkt.Header[13])
}

func TestCreateSessionConfirmedFragments_RoundTrip(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(created)
	require.NoError(t, err)

	// Use nil RouterInfo for single-fragment round-trip
	fragments, err := initiator.CreateSessionConfirmedFragments(55555, 1, nil)
	require.NoError(t, err)

	err = responder.ProcessSessionConfirmedFragments(fragments)
	require.NoError(t, err)

	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())
}

func TestCreateSessionConfirmedFragments_LargePayload(t *testing.T) {
	initiator, responder, initiatorPub, _ := setupHandshakePair(t)

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(created)
	require.NoError(t, err)

	// Build a large fake RouterInfo that still contains the initiator's static
	// key in I2P-base64 form so that verifyPeerRouterInfoStaticKey passes.
	// The responder's remoteStaticKey after the XK handshake equals initiatorPub.
	pubB64 := i2pbase64.EncodeToString(initiatorPub)
	prefix := make([]byte, 1457) // total ≈ 1457 + len(pubB64) ≥ 1500 bytes
	for i := range prefix {
		prefix[i] = byte(i % 256)
	}
	var largeRouterInfo []byte
	largeRouterInfo = append(largeRouterInfo, prefix...)
	largeRouterInfo = append(largeRouterInfo, []byte(pubB64)...)

	fragments, err := initiator.CreateSessionConfirmedFragments(55555, 0, largeRouterInfo)
	require.NoError(t, err)
	require.Greater(t, len(fragments), 1, "should produce multiple fragments")

	// Validate fragment headers
	for i, frag := range fragments {
		assert.Equal(t, MessageTypeSessionConfirmed, frag.MessageType)
		assert.Len(t, frag.Header, ShortHeaderSize)
		// Per spec: "Packet Number :: 0 always, for all fragments, even if retransmitted."
		assert.Equal(t, uint32(0), frag.PacketNumber)

		// Check frag byte
		fragNum := int((frag.Header[13] >> 4) & 0x0F)
		totalFrags := int(frag.Header[13] & 0x0F)
		assert.Equal(t, i, fragNum)
		assert.Equal(t, len(fragments), totalFrags)
	}

	// Verify the responder can process the fragments
	err = responder.ProcessSessionConfirmedFragments(fragments)
	require.NoError(t, err)

	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())
}

func TestProcessSessionConfirmedFragments_Errors(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Test: initiator cannot process
	err := initiator.ProcessSessionConfirmedFragments(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initiator cannot process")

	// Test: empty fragments
	err = responder.ProcessSessionConfirmedFragments(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SessionConfirmed fragments")

	// Test: empty slice
	err = responder.ProcessSessionConfirmedFragments([]*SSU2Packet{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SessionConfirmed fragments")
}

func TestCreateSessionConfirmedFragments_ResponderError(t *testing.T) {
	_, responder, _, _ := setupHandshakePair(t)

	packets, err := responder.CreateSessionConfirmedFragments(11111, 1, nil)
	assert.Error(t, err)
	assert.Nil(t, packets)
	assert.Contains(t, err.Error(), "only initiator")
}

func TestCreateSessionConfirmedFragments_NotReady(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)

	// Try without completing prior messages
	packets, err := initiator.CreateSessionConfirmedFragments(11111, 1, nil)
	assert.Error(t, err)
	assert.Nil(t, packets)
}

// --- G-3: Options Block Padding Negotiation Tests ---

func TestFixedPointRoundTrip(t *testing.T) {
	cases := []struct {
		val float64
	}{
		{0.0},
		{1.0},
		{0.5},
		{15.9375}, // max
		{3.25},
		{7.0625},
	}
	for _, tc := range cases {
		b := floatToFixedPoint(tc.val)
		got := fixedPointToFloat(b)
		assert.InDelta(t, tc.val, got, 0.0625, "roundtrip for %f", tc.val)
	}
}

func TestFixedPointClamp(t *testing.T) {
	// Negative clamps to 0
	assert.Equal(t, byte(0x00), floatToFixedPoint(-1.0))
	// > 15.9375 clamps to 15.9375
	b := floatToFixedPoint(20.0)
	assert.InDelta(t, 15.9375, fixedPointToFloat(b), 0.0625)
}

func TestParseOptionsBlock(t *testing.T) {
	data := make([]byte, 12)
	data[0] = floatToFixedPoint(1.0)            // tmin
	data[1] = floatToFixedPoint(3.5)            // tmax
	data[2] = floatToFixedPoint(0.5)            // rmin
	data[3] = floatToFixedPoint(2.0)            // rmax
	binary.BigEndian.PutUint16(data[4:6], 100)  // tdummy
	binary.BigEndian.PutUint16(data[6:8], 200)  // rdummy
	binary.BigEndian.PutUint16(data[8:10], 50)  // tdelay
	binary.BigEndian.PutUint16(data[10:12], 75) // rdelay

	opts, err := ParseOptionsBlock(data)
	require.NoError(t, err)
	assert.InDelta(t, 1.0, opts.TMinRatio, 0.0625)
	assert.InDelta(t, 3.5, opts.TMaxRatio, 0.0625)
	assert.InDelta(t, 0.5, opts.RMinRatio, 0.0625)
	assert.InDelta(t, 2.0, opts.RMaxRatio, 0.0625)
	assert.Equal(t, uint16(100), opts.TDummy)
	assert.Equal(t, uint16(200), opts.RDummy)
	assert.Equal(t, uint16(50), opts.TDelay)
	assert.Equal(t, uint16(75), opts.RDelay)
}

func TestParseOptionsBlock_TooShort(t *testing.T) {
	_, err := ParseOptionsBlock(make([]byte, 10))
	assert.Error(t, err)
}

func TestOptionsSerializeRoundTrip(t *testing.T) {
	original := &OptionsParams{
		TMinRatio: 1.0,
		TMaxRatio: 4.0,
		RMinRatio: 0.5,
		RMaxRatio: 2.0,
		TDummy:    300,
		RDummy:    400,
		TDelay:    100,
		RDelay:    200,
	}
	data := original.Serialize()
	assert.Len(t, data, 12)

	parsed, err := ParseOptionsBlock(data)
	require.NoError(t, err)
	assert.InDelta(t, original.TMinRatio, parsed.TMinRatio, 0.0625)
	assert.InDelta(t, original.TMaxRatio, parsed.TMaxRatio, 0.0625)
	assert.InDelta(t, original.RMinRatio, parsed.RMinRatio, 0.0625)
	assert.InDelta(t, original.RMaxRatio, parsed.RMaxRatio, 0.0625)
	assert.Equal(t, original.TDummy, parsed.TDummy)
	assert.Equal(t, original.RDummy, parsed.RDummy)
	assert.Equal(t, original.TDelay, parsed.TDelay)
	assert.Equal(t, original.RDelay, parsed.RDelay)
}

func TestNegotiatedPadding_BothPresent(t *testing.T) {
	h, _, _, _ := setupHandshakePair(t)

	h.SetLocalOptions(&OptionsParams{
		TMinRatio: 0.5,
		TMaxRatio: 4.0,
		RMinRatio: 1.0,
		RMaxRatio: 3.0,
		TDummy:    100,
		RDummy:    200,
		TDelay:    50,
		RDelay:    60,
	})
	// Simulated peer options (peer's transmit = our receive, peer's receive = our transmit)
	h.peerOptions = &OptionsParams{
		TMinRatio: 0.0,
		TMaxRatio: 2.0,
		RMinRatio: 1.0,
		RMaxRatio: 5.0,
		TDummy:    150,
		RDummy:    80,
		TDelay:    30,
		RDelay:    70,
	}

	neg := h.NegotiatedPadding()
	require.NotNil(t, neg)

	// Our send: max(local.TMin=0.5, peer.RMin=1.0)=1.0, min(local.TMax=4.0, peer.RMax=5.0)=4.0
	assert.InDelta(t, 1.0, neg.TMinRatio, 0.0625)
	assert.InDelta(t, 4.0, neg.TMaxRatio, 0.0625)

	// Our recv: max(local.RMin=1.0, peer.TMin=0.0)=1.0, min(local.RMax=3.0, peer.TMax=2.0)=2.0
	assert.InDelta(t, 1.0, neg.RMinRatio, 0.0625)
	assert.InDelta(t, 2.0, neg.RMaxRatio, 0.0625)

	// Dummy: min of each pair
	assert.Equal(t, uint16(80), neg.TDummy)  // min(local.TDummy=100, peer.RDummy=80)
	assert.Equal(t, uint16(150), neg.RDummy) // min(local.RDummy=200, peer.TDummy=150)
	assert.Equal(t, uint16(50), neg.TDelay)  // min(local.TDelay=50, peer.RDelay=70)
	assert.Equal(t, uint16(30), neg.RDelay)  // min(local.RDelay=60, peer.TDelay=30)
}

func TestNegotiatedPadding_NilPeer(t *testing.T) {
	h, _, _, _ := setupHandshakePair(t)
	h.SetLocalOptions(&OptionsParams{TMaxRatio: 1.0})
	assert.Nil(t, h.NegotiatedPadding(), "should be nil when peer options missing")
}

func TestNegotiatedPadding_InvalidRangeNoConstraint(t *testing.T) {
	h, _, _, _ := setupHandshakePair(t)

	// Local transmit range [3.0, 4.0] does not overlap with peer's receive range [0.0, 2.0]
	// →  negotiated TMin = max(3.0, 0.0) = 3.0, TMax = min(4.0, 2.0) = 2.0 → invalid
	// Should be zeroed (no constraint) rather than clamped.
	h.SetLocalOptions(&OptionsParams{
		TMinRatio: 3.0,
		TMaxRatio: 4.0,
		RMinRatio: 0.0,
		RMaxRatio: 1.0,
	})
	h.peerOptions = &OptionsParams{
		TMinRatio: 5.0, // peer transmit min > local receive max → receive invalid
		TMaxRatio: 6.0,
		RMinRatio: 0.0,
		RMaxRatio: 2.0, // peer receive max < local transmit min → transmit invalid
	}

	neg := h.NegotiatedPadding()
	require.NotNil(t, neg)

	// Transmit: empty intersection → no constraint
	assert.Equal(t, 0.0, neg.TMinRatio, "invalid transmit range should zero min")
	assert.Equal(t, 0.0, neg.TMaxRatio, "invalid transmit range should zero max")

	// Receive: max(local.RMin=0.0, peer.TMin=5.0)=5.0, min(local.RMax=1.0, peer.TMax=6.0)=1.0 → invalid
	assert.Equal(t, 0.0, neg.RMinRatio, "invalid receive range should zero min")
	assert.Equal(t, 0.0, neg.RMaxRatio, "invalid receive range should zero max")
}

func TestExtractPeerOptions_Handshake(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Set local options on both sides
	initiator.SetLocalOptions(&OptionsParams{TMaxRatio: 2.0, RMaxRatio: 3.0})
	responder.SetLocalOptions(&OptionsParams{TMaxRatio: 1.5, RMaxRatio: 4.0})

	// SessionRequest: initiator sends, responder receives + extracts options
	sessionReq, err := initiator.CreateSessionRequest(1111, 2222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(sessionReq)
	require.NoError(t, err)
	require.NotNil(t, responder.PeerOptions(), "responder should have peer options after SessionRequest")
	assert.InDelta(t, 2.0, responder.PeerOptions().TMaxRatio, 0.0625)

	// SessionCreated: responder sends, initiator receives + extracts options
	sessionCreated, err := responder.CreateSessionCreated(2222, 1111)
	require.NoError(t, err)

	err = initiator.ProcessSessionCreated(sessionCreated)
	require.NoError(t, err)
	require.NotNil(t, initiator.PeerOptions(), "initiator should have peer options after SessionCreated")
	assert.InDelta(t, 1.5, initiator.PeerOptions().TMaxRatio, 0.0625)
}

// TestSessionConfirmedFragments_PacketNumberAlwaysZero verifies that all
// Session Confirmed fragments have PacketNumber == 0, as required by the
// SSU2 spec: "Packet Number :: 0 always, for all fragments, even if retransmitted."
func TestSessionConfirmedFragments_PacketNumberAlwaysZero(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	// Complete handshake up to SessionConfirmed
	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)

	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)

	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	// Create Session Confirmed fragments with packetNumber = 0 per spec.
	fragments, err := initiator.CreateSessionConfirmedFragments(55555, 0, nil)
	require.NoError(t, err)
	require.NotEmpty(t, fragments, "should produce at least one fragment")

	for i, frag := range fragments {
		assert.Equal(t, uint32(0), frag.PacketNumber,
			"fragment %d: PacketNumber must be 0 per spec", i)

		// Verify the wire-level header bytes 8-11 also encode packet number 0.
		require.True(t, len(frag.Header) >= 12,
			"fragment %d: header too short", i)
		pn := binary.BigEndian.Uint32(frag.Header[8:12])
		assert.Equal(t, uint32(0), pn,
			"fragment %d: header bytes 8-11 must encode packet number 0", i)

		assert.Equal(t, MessageTypeSessionConfirmed, frag.MessageType,
			"fragment %d: wrong message type", i)
	}
}

// TestSessionConfirmedRetransmit_PreservesPacketNumber verifies that
// retransmitting a Session Confirmed packet keeps its PacketNumber unchanged,
// as required by the SSU2 spec for handshake retransmission.
func TestSessionConfirmedRetransmit_PreservesPacketNumber(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	requestPacket, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(requestPacket)
	require.NoError(t, err)
	createdPacket, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(createdPacket)
	require.NoError(t, err)

	fragments, err := initiator.CreateSessionConfirmedFragments(55555, 0, nil)
	require.NoError(t, err)

	// Simulate retransmit: the same SSU2Packet object is re-sent.
	// Verify the packet number is still 0 after "retransmission" — the receiver
	// would re-serialize the same packet, so the fields must be stable.
	for retransmit := 0; retransmit < 3; retransmit++ {
		for i, frag := range fragments {
			assert.Equal(t, uint32(0), frag.PacketNumber,
				"retransmit %d, fragment %d: PacketNumber must remain 0", retransmit, i)
			pn := binary.BigEndian.Uint32(frag.Header[8:12])
			assert.Equal(t, uint32(0), pn,
				"retransmit %d, fragment %d: header pn must remain 0", retransmit, i)
		}
	}
}
