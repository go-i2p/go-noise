package wire

import (
	"bytes"
	"testing"
	"time"
)

// buildValidHeader returns a headerSize-byte header with protocol version
// and network ID bytes correctly set for long-header message types (bytes
// 13/14), and message type embedded at byte 12. Deserialize itself embeds
// the message type at byte 12, so this is primarily needed for
// Serialize()->Deserialize() round trips and for hand-built Deserialize()
// inputs.
func buildValidHeader(headerSize int, msgType uint8) []byte {
	h := make([]byte, headerSize)
	h[12] = msgType
	if headerSize == LongHeaderSize {
		h[13] = SSU2ProtocolVersion
		h[14] = SSU2NetworkID
	}
	return h
}

func newRoundTripPacket(msgType uint8, payload []byte) *SSU2Packet {
	p := NewSSU2Packet(msgType, 42)
	p.Header = buildValidHeader(p.getHeaderSize(), msgType)
	if p.hasEphemeralKey() {
		p.EphemeralKey = bytes.Repeat([]byte{0xAB}, EphemeralKeySize)
	}
	p.Payload = payload
	p.MAC = bytes.Repeat([]byte{0xCD}, MACSize)
	return p
}

// TestSSU2Packet_SerializeDeserializeRoundTrip covers every message
// type/header-size combination (short header, long header, long header with
// ephemeral key), confirming Serialize()->Deserialize() reproduces the
// original fields.
func TestSSU2Packet_SerializeDeserializeRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		payload []byte
	}{
		{"SessionRequest (long header + ephemeral key)", MessageTypeSessionRequest, []byte("session-request-payload")},
		{"SessionCreated (long header + ephemeral key)", MessageTypeSessionCreated, []byte("session-created-payload")},
		{"SessionConfirmed (short header)", MessageTypeSessionConfirmed, []byte("session-confirmed-payload-bytes")},
		{"Data (short header)", MessageTypeData, []byte("data-phase-payload")},
		{"PeerTest (long header)", MessageTypePeerTest, []byte("peer-test-payload-data")},
		{"Retry (long header)", MessageTypeRetry, []byte("retry-payload-data")},
		{"TokenRequest (long header)", MessageTypeTokenRequest, []byte("token-request-payload")},
		{"HolePunch (long header)", MessageTypeHolePunch, []byte("hole-punch-payload-data")},
		{"empty payload (long header, satisfies MinPacketSize without payload)", MessageTypeRetry, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newRoundTripPacket(tt.msgType, tt.payload)

			data, err := original.Serialize()
			if err != nil {
				t.Fatalf("Serialize() error = %v", err)
			}

			restored := &SSU2Packet{}
			if err := restored.Deserialize(data); err != nil {
				t.Fatalf("Deserialize() error = %v", err)
			}

			if restored.MessageType != tt.msgType {
				t.Errorf("MessageType = %d, want %d", restored.MessageType, tt.msgType)
			}
			if !bytes.Equal(restored.Header, original.Header) {
				t.Errorf("Header mismatch: got %x, want %x", restored.Header, original.Header)
			}
			if original.hasEphemeralKey() && !bytes.Equal(restored.EphemeralKey, original.EphemeralKey) {
				t.Errorf("EphemeralKey mismatch: got %x, want %x", restored.EphemeralKey, original.EphemeralKey)
			}
			wantPayload := tt.payload
			if len(wantPayload) == 0 {
				if len(restored.Payload) != 0 {
					t.Errorf("expected empty payload, got %x", restored.Payload)
				}
			} else if !bytes.Equal(restored.Payload, wantPayload) {
				t.Errorf("Payload mismatch: got %x, want %x", restored.Payload, wantPayload)
			}
			if !bytes.Equal(restored.MAC, original.MAC) {
				t.Errorf("MAC mismatch: got %x, want %x", restored.MAC, original.MAC)
			}
		})
	}
}

func TestSSU2Packet_Deserialize_TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 10, MinPacketSize - 1} {
		data := make([]byte, n)
		p := &SSU2Packet{}
		if err := p.Deserialize(data); err == nil {
			t.Errorf("Deserialize() with %d bytes: expected error, got nil", n)
		}
	}
}

func TestSSU2Packet_Deserialize_ExactlyMinPacketSize(t *testing.T) {
	// Short-header message type (Data) with no ephemeral key: header(16) +
	// MAC(16) + 8 bytes of payload = 40 bytes (MinPacketSize).
	data := make([]byte, MinPacketSize)
	data[12] = MessageTypeData

	p := &SSU2Packet{}
	if err := p.Deserialize(data); err != nil {
		t.Fatalf("Deserialize() at exactly MinPacketSize error = %v", err)
	}
}

func TestSSU2Packet_Deserialize_InvalidProtocolVersion(t *testing.T) {
	data := make([]byte, MinPacketSize+LongHeaderSize+EphemeralKeySize)
	data[12] = MessageTypeSessionRequest
	data[13] = SSU2ProtocolVersion + 1 // wrong version
	data[14] = SSU2NetworkID

	p := &SSU2Packet{}
	err := p.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for invalid protocol version")
	}
}

func TestSSU2Packet_Deserialize_WrongNetworkID(t *testing.T) {
	data := make([]byte, MinPacketSize+LongHeaderSize+EphemeralKeySize)
	data[12] = MessageTypeSessionRequest
	data[13] = SSU2ProtocolVersion
	data[14] = SSU2NetworkID + 1 // wrong network

	p := &SSU2Packet{}
	err := p.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for wrong network ID")
	}
}

// TestSSU2Packet_Deserialize_TruncatedEphemeralKey verifies a packet that
// declares a SessionRequest/SessionCreated message type (which requires an
// ephemeral key) but is too short to actually contain one is rejected
// rather than reading past the buffer.
func TestSSU2Packet_Deserialize_TruncatedEphemeralKey(t *testing.T) {
	// Only long enough for MinPacketSize, but SessionRequest needs
	// headerSize(32) + EphemeralKeySize(32) + MACSize(16) = 80 bytes.
	data := make([]byte, MinPacketSize)
	data[12] = MessageTypeSessionRequest
	data[13] = SSU2ProtocolVersion
	data[14] = SSU2NetworkID

	p := &SSU2Packet{}
	if err := p.Deserialize(data); err == nil {
		t.Fatal("expected error for truncated ephemeral key")
	}
}

func TestSSU2Packet_Deserialize_UnknownMessageType(t *testing.T) {
	// Unknown message types default to long-header handling (getHeaderSize's
	// default case); the protocol version/network ID check must still pass
	// bounds-safely and either accept or reject without panicking.
	data := make([]byte, MinPacketSize+LongHeaderSize)
	data[12] = 255 // not any known MessageType* constant
	data[13] = SSU2ProtocolVersion
	data[14] = SSU2NetworkID

	p := &SSU2Packet{}
	_ = p.Deserialize(data) // must not panic; error or success both acceptable
}

func TestSSU2Packet_GetHeaderSize(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    int
	}{
		{MessageTypeSessionConfirmed, ShortHeaderSize},
		{MessageTypeData, ShortHeaderSize},
		{MessageTypeSessionRequest, LongHeaderSize},
		{MessageTypeSessionCreated, LongHeaderSize},
		{MessageTypePeerTest, LongHeaderSize},
		{MessageTypeRetry, LongHeaderSize},
		{MessageTypeTokenRequest, LongHeaderSize},
		{MessageTypeHolePunch, LongHeaderSize},
	}
	for _, tt := range tests {
		p := NewSSU2Packet(tt.msgType, 0)
		if got := p.GetHeaderSize(); got != tt.want {
			t.Errorf("msgType %d: GetHeaderSize() = %d, want %d", tt.msgType, got, tt.want)
		}
	}
}

func TestSSU2Packet_HasEphemeralKey(t *testing.T) {
	tests := []struct {
		msgType uint8
		want    bool
	}{
		{MessageTypeSessionRequest, true},
		{MessageTypeSessionCreated, true},
		{MessageTypeSessionConfirmed, false},
		{MessageTypeData, false},
		{MessageTypeRetry, false},
	}
	for _, tt := range tests {
		p := NewSSU2Packet(tt.msgType, 0)
		if got := p.HasEphemeralKey(); got != tt.want {
			t.Errorf("msgType %d: HasEphemeralKey() = %v, want %v", tt.msgType, got, tt.want)
		}
	}
}

func TestSSU2Packet_Serialize_InvalidHeaderSize(t *testing.T) {
	p := NewSSU2Packet(MessageTypeData, 0)
	p.Header = make([]byte, ShortHeaderSize-1) // wrong size
	p.MAC = make([]byte, MACSize)

	if _, err := p.Serialize(); err == nil {
		t.Fatal("expected error for invalid header size")
	}
}

func TestSSU2Packet_Serialize_InvalidMACSize(t *testing.T) {
	p := NewSSU2Packet(MessageTypeData, 0)
	p.Header = make([]byte, ShortHeaderSize)
	p.MAC = make([]byte, MACSize-1) // wrong size

	if _, err := p.Serialize(); err == nil {
		t.Fatal("expected error for invalid MAC size")
	}
}

func TestSSU2Packet_Serialize_MissingEphemeralKey(t *testing.T) {
	p := NewSSU2Packet(MessageTypeSessionRequest, 0)
	p.Header = buildValidHeader(LongHeaderSize, MessageTypeSessionRequest)
	p.EphemeralKey = make([]byte, EphemeralKeySize-1) // wrong size
	p.MAC = make([]byte, MACSize)

	if _, err := p.Serialize(); err == nil {
		t.Fatal("expected error for wrong ephemeral key size")
	}
}

func TestSSU2Packet_Timestamp_SetOnDeserialize(t *testing.T) {
	data := make([]byte, MinPacketSize)
	data[12] = MessageTypeData

	before := time.Now()
	p := &SSU2Packet{}
	if err := p.Deserialize(data); err != nil {
		t.Fatalf("Deserialize() error = %v", err)
	}
	if p.Timestamp.Before(before) {
		t.Error("expected Timestamp to be set to approximately now during Deserialize")
	}
}

func TestSSU2Packet_PacketNumber_ParsedFromHeader(t *testing.T) {
	original := newRoundTripPacket(MessageTypeData, []byte("payload-bytes")) // long enough to satisfy MinPacketSize
	original.Header[8] = 0x00
	original.Header[9] = 0x00
	original.Header[10] = 0x01
	original.Header[11] = 0x02 // packet number = 0x00000102

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	restored := &SSU2Packet{}
	if err := restored.Deserialize(data); err != nil {
		t.Fatalf("Deserialize() error = %v", err)
	}
	if restored.PacketNumber != 0x00000102 {
		t.Errorf("PacketNumber = %#x, want %#x", restored.PacketNumber, 0x00000102)
	}
}

// ============================================================================
// Fuzz target
// ============================================================================

// FuzzSSU2Packet_Deserialize fuzzes SSU2Packet.Deserialize, the outermost
// pre-authentication parser for every inbound SSU2 datagram (AUDIT.md
// cross-cutting concerns: this was one of four pre-auth parser families
// flagged with zero fuzz coverage). It only asserts the parser never panics
// on arbitrary or boundary-crafted input; errors are an expected, correct
// outcome for malformed data.
//
// Run with: go test -fuzz=FuzzSSU2Packet_Deserialize ./ssu2/wire/
func FuzzSSU2Packet_Deserialize(f *testing.F) {
	// Seed with a variety of valid, boundary, and malformed packets.
	f.Add([]byte{})
	f.Add(make([]byte, MinPacketSize-1))
	f.Add(make([]byte, MinPacketSize))

	shortValid := make([]byte, MinPacketSize)
	shortValid[12] = MessageTypeData
	f.Add(shortValid)

	longValidNoEphemeral := make([]byte, MinPacketSize+LongHeaderSize-ShortHeaderSize)
	longValidNoEphemeral[12] = MessageTypeRetry
	longValidNoEphemeral[13] = SSU2ProtocolVersion
	longValidNoEphemeral[14] = SSU2NetworkID
	f.Add(longValidNoEphemeral)

	if sessionReq := newRoundTripPacket(MessageTypeSessionRequest, []byte("payload")); sessionReq != nil {
		if data, err := sessionReq.Serialize(); err == nil {
			f.Add(data)
		}
	}

	// Truncated ephemeral key: declares SessionRequest but too short.
	truncated := make([]byte, MinPacketSize)
	truncated[12] = MessageTypeSessionRequest
	truncated[13] = SSU2ProtocolVersion
	truncated[14] = SSU2NetworkID
	f.Add(truncated)

	// Wrong protocol version / network ID.
	wrongVersion := make([]byte, MinPacketSize+LongHeaderSize)
	wrongVersion[12] = MessageTypeSessionRequest
	wrongVersion[13] = 0xFF
	wrongVersion[14] = SSU2NetworkID
	f.Add(wrongVersion)

	// Maximum-size boundary.
	maxSize := make([]byte, MaxPacketSizeIPv6)
	maxSize[12] = MessageTypeData
	f.Add(maxSize)

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &SSU2Packet{}
		_ = p.Deserialize(data) // errors are fine; panics are not
	})
}
