package ssu2

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSU2Packet verifies basic packet creation
func TestNewSSU2Packet(t *testing.T) {
	tests := []struct {
		name          string
		msgType       uint8
		packetNum     uint32
		wantMsgType   uint8
		wantPacketNum uint32
	}{
		{
			name:          "SessionRequest",
			msgType:       MessageTypeSessionRequest,
			packetNum:     0,
			wantMsgType:   MessageTypeSessionRequest,
			wantPacketNum: 0,
		},
		{
			name:          "SessionCreated",
			msgType:       MessageTypeSessionCreated,
			packetNum:     1,
			wantMsgType:   MessageTypeSessionCreated,
			wantPacketNum: 1,
		},
		{
			name:          "Data with sequence",
			msgType:       MessageTypeData,
			packetNum:     12345,
			wantMsgType:   MessageTypeData,
			wantPacketNum: 12345,
		},
		{
			name:          "Max packet number",
			msgType:       MessageTypeData,
			packetNum:     MaxPacketNumber,
			wantMsgType:   MessageTypeData,
			wantPacketNum: MaxPacketNumber,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			pkt := NewSSU2Packet(tt.msgType, tt.packetNum)
			after := time.Now()

			assert.Equal(t, tt.wantMsgType, pkt.MessageType)
			assert.Equal(t, tt.wantPacketNum, pkt.PacketNumber)
			assert.False(t, pkt.Timestamp.IsZero())
			assert.True(t, pkt.Timestamp.After(before) || pkt.Timestamp.Equal(before))
			assert.True(t, pkt.Timestamp.Before(after) || pkt.Timestamp.Equal(after))
		})
	}
}

// TestSSU2Packet_hasEphemeralKey tests ephemeral key detection
func TestSSU2Packet_hasEphemeralKey(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		wantKey bool
	}{
		{"SessionRequest has key", MessageTypeSessionRequest, true},
		{"SessionCreated has key", MessageTypeSessionCreated, true},
		{"SessionConfirmed no key", MessageTypeSessionConfirmed, false},
		{"Data no key", MessageTypeData, false},
		{"PeerTest no key", MessageTypePeerTest, false},
		{"Retry no key", MessageTypeRetry, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			got := pkt.HasEphemeralKey()
			assert.Equal(t, tt.wantKey, got)
		})
	}
}

// TestSSU2Packet_getHeaderSize tests header size determination
func TestSSU2Packet_getHeaderSize(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		wantSize int
	}{
		{"SessionRequest long header", MessageTypeSessionRequest, LongHeaderSize},
		{"SessionCreated long header", MessageTypeSessionCreated, LongHeaderSize},
		{"SessionConfirmed short header", MessageTypeSessionConfirmed, ShortHeaderSize},
		{"Data short header", MessageTypeData, ShortHeaderSize},
		{"PeerTest long header", MessageTypePeerTest, LongHeaderSize},
		{"Retry long header", MessageTypeRetry, LongHeaderSize},
		{"TokenRequest long header", MessageTypeTokenRequest, LongHeaderSize},
		{"HolePunch long header", MessageTypeHolePunch, LongHeaderSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			got := pkt.GetHeaderSize()
			assert.Equal(t, tt.wantSize, got)
		})
	}
}

// TestSSU2Packet_Serialize_Valid tests serialization of valid packets
func TestSSU2Packet_Serialize_Valid(t *testing.T) {
	tests := []struct {
		name          string
		setupPacket   func() *SSU2Packet
		wantSize      int
		wantHasEphKey bool
	}{
		{
			name: "SessionRequest with ephemeral key",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeSessionRequest, 0)
				pkt.Header = make([]byte, LongHeaderSize)
				pkt.EphemeralKey = make([]byte, EphemeralKeySize)
				pkt.Payload = []byte("test payload")
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantSize:      LongHeaderSize + EphemeralKeySize + 12 + MACSize,
			wantHasEphKey: true,
		},
		{
			name: "Data without ephemeral key",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeData, 100)
				pkt.Header = make([]byte, ShortHeaderSize)
				pkt.Payload = []byte("data content")
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantSize:      ShortHeaderSize + 12 + MACSize,
			wantHasEphKey: false,
		},
		{
			name: "SessionConfirmed with minimal payload",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeSessionConfirmed, 2)
				pkt.Header = make([]byte, ShortHeaderSize)
				pkt.Payload = []byte("12345678") // 8 bytes for 40 byte total
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantSize:      MinPacketSize,
			wantHasEphKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := tt.setupPacket()
			data, err := pkt.Serialize()

			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, len(data))

			// Verify header is at start
			assert.Equal(t, pkt.Header, data[0:len(pkt.Header)])

			// Verify MAC is at end
			assert.Equal(t, pkt.MAC, data[len(data)-MACSize:])

			// Check ephemeral key presence if expected
			if tt.wantHasEphKey {
				keyStart := len(pkt.Header)
				assert.Equal(t, pkt.EphemeralKey, data[keyStart:keyStart+EphemeralKeySize])
			}
		})
	}
}

// TestSSU2Packet_Serialize_Invalid tests serialization errors
func TestSSU2Packet_Serialize_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		setupPacket func() *SSU2Packet
		wantErrMsg  string
	}{
		{
			name: "Wrong header size",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeData, 0)
				pkt.Header = make([]byte, 10) // Wrong size
				pkt.Payload = []byte("test")
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantErrMsg: "invalid header size",
		},
		{
			name: "Missing ephemeral key when required",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeSessionRequest, 0)
				pkt.Header = make([]byte, LongHeaderSize)
				pkt.EphemeralKey = make([]byte, 10) // Wrong size
				pkt.Payload = []byte("test")
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantErrMsg: "invalid ephemeral key size",
		},
		{
			name: "Ephemeral key present when not required",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeData, 0)
				pkt.Header = make([]byte, ShortHeaderSize)
				pkt.EphemeralKey = make([]byte, EphemeralKeySize) // Should be empty
				pkt.Payload = []byte("test")
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantErrMsg: "ephemeral key present",
		},
		{
			name: "Wrong MAC size",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeData, 0)
				pkt.Header = make([]byte, ShortHeaderSize)
				pkt.Payload = []byte("test")
				pkt.MAC = make([]byte, 10) // Wrong size
				return pkt
			},
			wantErrMsg: "invalid MAC size",
		},
		{
			name: "Packet too large",
			setupPacket: func() *SSU2Packet {
				pkt := NewSSU2Packet(MessageTypeData, 0)
				pkt.Header = make([]byte, ShortHeaderSize)
				pkt.Payload = make([]byte, MaxPacketSizeIPv4) // Too large
				pkt.MAC = make([]byte, MACSize)
				return pkt
			},
			wantErrMsg: "packet too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := tt.setupPacket()
			_, err := pkt.Serialize()

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// TestSSU2Packet_Deserialize_Valid tests deserialization of valid packets
func TestSSU2Packet_Deserialize_Valid(t *testing.T) {
	tests := []struct {
		name        string
		msgType     uint8
		createData  func() []byte
		wantHeader  int
		wantEphKey  int
		wantPayload int
		wantMAC     int
	}{
		{
			name:    "SessionRequest with ephemeral key",
			msgType: MessageTypeSessionRequest,
			createData: func() []byte {
				data := make([]byte, 0, 128)
				hdr := make([]byte, LongHeaderSize)
				hdr[13] = SSU2ProtocolVersion
				hdr[14] = SSU2NetworkID
				data = append(data, hdr...)                            // Header
				data = append(data, make([]byte, EphemeralKeySize)...) // Ephemeral key
				data = append(data, []byte("test payload content")...) // Payload
				data = append(data, make([]byte, MACSize)...)          // MAC
				return data
			},
			wantHeader:  LongHeaderSize,
			wantEphKey:  EphemeralKeySize,
			wantPayload: 20,
			wantMAC:     MACSize,
		},
		{
			name:    "Data without ephemeral key",
			msgType: MessageTypeData,
			createData: func() []byte {
				data := make([]byte, 0, 128)
				hdr := make([]byte, ShortHeaderSize)
				hdr[12] = MessageTypeData                      // type byte at offset 12
				data = append(data, hdr...)                    // Header
				data = append(data, []byte("data payload")...) // Payload (need 8+ bytes for MinPacketSize)
				data = append(data, make([]byte, MACSize)...)  // MAC
				return data
			},
			wantHeader:  ShortHeaderSize,
			wantEphKey:  0,
			wantPayload: 12,
			wantMAC:     MACSize,
		},
		{
			name:    "SessionConfirmed with minimal payload",
			msgType: MessageTypeSessionConfirmed,
			createData: func() []byte {
				data := make([]byte, 0, 128)
				hdr := make([]byte, ShortHeaderSize)
				hdr[12] = MessageTypeSessionConfirmed         // type byte at offset 12
				data = append(data, hdr...)                   // Header
				data = append(data, []byte("12345678")...)    // Minimal payload for 40 byte packet
				data = append(data, make([]byte, MACSize)...) // MAC
				return data
			},
			wantHeader:  ShortHeaderSize,
			wantEphKey:  0,
			wantPayload: 8,
			wantMAC:     MACSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			data := tt.createData()

			err := pkt.Deserialize(data)
			require.NoError(t, err)

			assert.Equal(t, tt.wantHeader, len(pkt.Header))
			assert.Equal(t, tt.wantEphKey, len(pkt.EphemeralKey))
			assert.Equal(t, tt.wantPayload, len(pkt.Payload))
			assert.Equal(t, tt.wantMAC, len(pkt.MAC))
			assert.False(t, pkt.Timestamp.IsZero())
		})
	}
}

// TestSSU2Packet_Deserialize_Invalid tests deserialization errors
func TestSSU2Packet_Deserialize_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		msgType    uint8
		data       []byte
		wantErrMsg string
	}{
		{
			name:       "Data too short - absolute minimum",
			msgType:    MessageTypeData,
			data:       make([]byte, MinPacketSize-1),
			wantErrMsg: "packet too short",
		},
		{
			name:       "Data too short - missing MAC",
			msgType:    MessageTypeData,
			data:       make([]byte, ShortHeaderSize+10), // Header + partial payload, no MAC
			wantErrMsg: "packet too short",
		},
		{
			name:    "SessionRequest missing ephemeral key",
			msgType: MessageTypeSessionRequest,
			data: func() []byte {
				d := make([]byte, LongHeaderSize+MACSize)
				d[13] = SSU2ProtocolVersion
				d[14] = SSU2NetworkID
				return d
			}(),
			wantErrMsg: "packet too short",
		},
		{
			name:       "Empty data",
			msgType:    MessageTypeData,
			data:       []byte{},
			wantErrMsg: "packet too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			err := pkt.Deserialize(tt.data)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// TestSSU2Packet_RoundTrip verifies serialize/deserialize consistency
func TestSSU2Packet_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		payload []byte
	}{
		{"SessionRequest", MessageTypeSessionRequest, []byte("request data")},
		{"SessionCreated", MessageTypeSessionCreated, []byte("created data")},
		{"SessionConfirmed", MessageTypeSessionConfirmed, []byte("confirmed")},
		{"Data", MessageTypeData, []byte("application data content")},
		{"Data with minimal payload", MessageTypeData, []byte("12345678")}, // 8 bytes for 40 byte minimum
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original packet
			original := NewSSU2Packet(tt.msgType, 42)
			original.Header = make([]byte, original.GetHeaderSize())
			for i := range original.Header {
				original.Header[i] = byte(i) // Fill with test pattern
			}
			// Long headers must contain valid protocol version/netID (G-4).
			if original.GetHeaderSize() == LongHeaderSize {
				original.Header[13] = SSU2ProtocolVersion
				original.Header[14] = SSU2NetworkID
			}
			if original.HasEphemeralKey() {
				original.EphemeralKey = make([]byte, EphemeralKeySize)
				for i := range original.EphemeralKey {
					original.EphemeralKey[i] = byte(100 + i) // Fill with test pattern
				}
			}
			original.Payload = tt.payload
			original.MAC = make([]byte, MACSize)
			for i := range original.MAC {
				original.MAC[i] = byte(200 + i) // Fill with test pattern
			}

			// Serialize
			data, err := original.Serialize()
			require.NoError(t, err)

			// Deserialize into new packet
			restored := NewSSU2Packet(tt.msgType, 0)
			err = restored.Deserialize(data)
			require.NoError(t, err)

			// Compare fields
			assert.Equal(t, original.MessageType, restored.MessageType)
			assert.Equal(t, original.Header, restored.Header)
			assert.Equal(t, original.EphemeralKey, restored.EphemeralKey)
			assert.Equal(t, original.Payload, restored.Payload)
			assert.Equal(t, original.MAC, restored.MAC)
		})
	}
}

// TestSSU2Packet_Size tests size calculation
func TestSSU2Packet_Size(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		payload  []byte
		wantSize int
	}{
		{
			name:     "SessionRequest",
			msgType:  MessageTypeSessionRequest,
			payload:  []byte("test"),
			wantSize: LongHeaderSize + EphemeralKeySize + 4 + MACSize,
		},
		{
			name:     "Data",
			msgType:  MessageTypeData,
			payload:  []byte("hello world"),
			wantSize: ShortHeaderSize + 11 + MACSize,
		},
		{
			name:     "Minimal payload",
			msgType:  MessageTypeSessionConfirmed,
			payload:  []byte("12345678"), // 8 bytes for 40 byte minimum
			wantSize: MinPacketSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			pkt.Header = make([]byte, pkt.GetHeaderSize())
			if pkt.HasEphemeralKey() {
				pkt.EphemeralKey = make([]byte, EphemeralKeySize)
			}
			pkt.Payload = tt.payload
			pkt.MAC = make([]byte, MACSize)

			assert.Equal(t, tt.wantSize, pkt.Size())
		})
	}
}

// TestSSU2Packet_Clone tests packet cloning
func TestSSU2Packet_Clone(t *testing.T) {
	original := NewSSU2Packet(MessageTypeData, 123)
	original.Header = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	original.Payload = []byte("test payload")
	original.MAC = []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	original.Timestamp = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	clone := original.Clone()

	// Verify values match
	assert.Equal(t, original.MessageType, clone.MessageType)
	assert.Equal(t, original.PacketNumber, clone.PacketNumber)
	assert.Equal(t, original.Timestamp, clone.Timestamp)
	assert.Equal(t, original.Header, clone.Header)
	assert.Equal(t, original.Payload, clone.Payload)
	assert.Equal(t, original.MAC, clone.MAC)

	// Verify deep copy (modifying clone doesn't affect original)
	clone.Header[0] = 99
	clone.Payload[0] = 'X'
	clone.MAC[0] = 88

	assert.NotEqual(t, original.Header[0], clone.Header[0])
	assert.NotEqual(t, original.Payload[0], clone.Payload[0])
	assert.NotEqual(t, original.MAC[0], clone.MAC[0])
}

// TestSSU2Packet_CloneWithEphemeralKey tests cloning packet with ephemeral key
func TestSSU2Packet_CloneWithEphemeralKey(t *testing.T) {
	original := NewSSU2Packet(MessageTypeSessionRequest, 0)
	original.Header = make([]byte, LongHeaderSize)
	original.EphemeralKey = make([]byte, EphemeralKeySize)
	for i := range original.EphemeralKey {
		original.EphemeralKey[i] = byte(i)
	}
	original.Payload = []byte("handshake")
	original.MAC = make([]byte, MACSize)

	clone := original.Clone()

	assert.Equal(t, original.EphemeralKey, clone.EphemeralKey)

	// Verify deep copy
	clone.EphemeralKey[0] = 255
	assert.NotEqual(t, original.EphemeralKey[0], clone.EphemeralKey[0])
}

// TestSSU2Packet_Getters tests all getter methods
func TestSSU2Packet_Getters(t *testing.T) {
	msgType := MessageTypeData
	packetNum := uint32(9999)
	timestamp := time.Now()

	pkt := &SSU2Packet{
		MessageType:  msgType,
		PacketNumber: packetNum,
		Timestamp:    timestamp,
	}

	assert.Equal(t, msgType, pkt.GetMessageType())
	assert.Equal(t, packetNum, pkt.GetPacketNumber())
	assert.Equal(t, timestamp, pkt.GetTimestamp())
}

// TestSSU2Packet_SetPacketNumber tests packet number setter
func TestSSU2Packet_SetPacketNumber(t *testing.T) {
	pkt := NewSSU2Packet(MessageTypeData, 100)
	assert.Equal(t, uint32(100), pkt.GetPacketNumber())

	pkt.SetPacketNumber(200)
	assert.Equal(t, uint32(200), pkt.GetPacketNumber())

	pkt.SetPacketNumber(MaxPacketNumber)
	assert.Equal(t, uint32(MaxPacketNumber), pkt.GetPacketNumber())
}

// TestSSU2Packet_IsHandshakePacket tests handshake packet detection
func TestSSU2Packet_IsHandshakePacket(t *testing.T) {
	tests := []struct {
		name          string
		msgType       uint8
		wantHandshake bool
	}{
		{"SessionRequest is handshake", MessageTypeSessionRequest, true},
		{"SessionCreated is handshake", MessageTypeSessionCreated, true},
		{"SessionConfirmed is handshake", MessageTypeSessionConfirmed, true},
		{"Data is not handshake", MessageTypeData, false},
		{"PeerTest is not handshake", MessageTypePeerTest, false},
		{"Retry is not handshake", MessageTypeRetry, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			assert.Equal(t, tt.wantHandshake, pkt.IsHandshakePacket())
		})
	}
}

// TestSSU2Packet_IsDataPacket tests data packet detection
func TestSSU2Packet_IsDataPacket(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		wantData bool
	}{
		{"Data is data packet", MessageTypeData, true},
		{"SessionRequest is not data", MessageTypeSessionRequest, false},
		{"SessionCreated is not data", MessageTypeSessionCreated, false},
		{"SessionConfirmed is not data", MessageTypeSessionConfirmed, false},
		{"PeerTest is not data", MessageTypePeerTest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(tt.msgType, 0)
			assert.Equal(t, tt.wantData, pkt.IsDataPacket())
		})
	}
}

// TestSSU2Packet_ConnectionID tests connection ID encoding/decoding
func TestSSU2Packet_ConnectionID(t *testing.T) {
	tests := []struct {
		name   string
		connID uint64
	}{
		{"Zero", 0},
		{"Small value", 12345},
		{"Large value", 0xFFFFFFFFFFFFFFFF},
		{"Random value", 0x123456789ABCDEF0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewSSU2Packet(MessageTypeData, 0)
			pkt.Header = make([]byte, ShortHeaderSize)

			// Encode
			err := pkt.EncodeConnectionID(tt.connID)
			require.NoError(t, err)

			// Decode
			decoded, err := pkt.DecodeConnectionID()
			require.NoError(t, err)
			assert.Equal(t, tt.connID, decoded)
		})
	}
}

// TestSSU2Packet_ConnectionID_Errors tests connection ID error handling
func TestSSU2Packet_ConnectionID_Errors(t *testing.T) {
	t.Run("Decode from short header", func(t *testing.T) {
		pkt := NewSSU2Packet(MessageTypeData, 0)
		pkt.Header = make([]byte, 4) // Too short

		_, err := pkt.DecodeConnectionID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header too short")
	})

	t.Run("Encode to short header", func(t *testing.T) {
		pkt := NewSSU2Packet(MessageTypeData, 0)
		pkt.Header = make([]byte, 4) // Too short

		err := pkt.EncodeConnectionID(12345)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header too short")
	})
}

// TestSSU2Packet_ConnectionID_BigEndian verifies connection IDs use big-endian encoding per spec
func TestSSU2Packet_ConnectionID_BigEndian(t *testing.T) {
	pkt := NewSSU2Packet(MessageTypeData, 0)
	pkt.Header = make([]byte, ShortHeaderSize)

	// Known value: 0x0102030405060708
	// Big-endian wire bytes: [01 02 03 04 05 06 07 08]
	err := pkt.EncodeConnectionID(0x0102030405060708)
	require.NoError(t, err)

	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	assert.Equal(t, expected, pkt.Header[0:8], "connection ID must be big-endian on wire")

	decoded, err := pkt.DecodeConnectionID()
	require.NoError(t, err)
	assert.Equal(t, uint64(0x0102030405060708), decoded)
}

// TestSSU2Packet_Constants verifies constant values match spec
func TestSSU2Packet_Constants(t *testing.T) {
	assert.Equal(t, 16, ShortHeaderSize)
	assert.Equal(t, 32, LongHeaderSize)
	assert.Equal(t, 32, EphemeralKeySize)
	assert.Equal(t, 16, MACSize)
	assert.Equal(t, 40, MinPacketSize)
	assert.Equal(t, 1472, MaxPacketSizeIPv4)
	assert.Equal(t, 1452, MaxPacketSizeIPv6)

	// Message types
	assert.Equal(t, uint8(0), MessageTypeSessionRequest)
	assert.Equal(t, uint8(1), MessageTypeSessionCreated)
	assert.Equal(t, uint8(2), MessageTypeSessionConfirmed)
	assert.Equal(t, uint8(6), MessageTypeData)
	assert.Equal(t, uint8(7), MessageTypePeerTest)
	assert.Equal(t, uint8(9), MessageTypeRetry)
	assert.Equal(t, uint8(10), MessageTypeTokenRequest)
	assert.Equal(t, uint8(11), MessageTypeHolePunch)
}

// Benchmark tests
func BenchmarkSSU2Packet_NewPacket(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewSSU2Packet(MessageTypeData, uint32(i))
	}
}

func BenchmarkSSU2Packet_Serialize(b *testing.B) {
	pkt := NewSSU2Packet(MessageTypeData, 0)
	pkt.Header = make([]byte, ShortHeaderSize)
	pkt.Payload = make([]byte, 100)
	pkt.MAC = make([]byte, MACSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkt.Serialize()
	}
}

func BenchmarkSSU2Packet_Deserialize(b *testing.B) {
	// Create test data
	data := make([]byte, ShortHeaderSize+100+MACSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := NewSSU2Packet(MessageTypeData, 0)
		_ = pkt.Deserialize(data)
	}
}

func BenchmarkSSU2Packet_Clone(b *testing.B) {
	pkt := NewSSU2Packet(MessageTypeData, 0)
	pkt.Header = make([]byte, ShortHeaderSize)
	pkt.Payload = make([]byte, 100)
	pkt.MAC = make([]byte, MACSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.Clone()
	}
}

func BenchmarkSSU2Packet_RoundTrip(b *testing.B) {
	original := NewSSU2Packet(MessageTypeData, 0)
	original.Header = make([]byte, ShortHeaderSize)
	original.Payload = make([]byte, 100)
	original.MAC = make([]byte, MACSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := original.Serialize()
		pkt := NewSSU2Packet(MessageTypeData, 0)
		_ = pkt.Deserialize(data)
	}
}

// TestSSU2Packet_LargePayload tests handling of maximum size payloads
func TestSSU2Packet_LargePayload(t *testing.T) {
	pkt := NewSSU2Packet(MessageTypeData, 0)
	pkt.Header = make([]byte, ShortHeaderSize)
	// Maximum payload = MaxPacketSizeIPv6 - header - MAC (IPv6 is the stricter limit)
	maxPayloadSize := MaxPacketSizeIPv6 - ShortHeaderSize - MACSize
	pkt.Payload = make([]byte, maxPayloadSize)
	pkt.MAC = make([]byte, MACSize)

	// Should serialize successfully at max size
	data, err := pkt.Serialize()
	require.NoError(t, err)
	assert.Equal(t, MaxPacketSizeIPv6, len(data))

	// Should deserialize successfully
	restored := NewSSU2Packet(MessageTypeData, 0)
	err = restored.Deserialize(data)
	require.NoError(t, err)
	assert.Equal(t, maxPayloadSize, len(restored.Payload))
}

// TestSSU2Packet_ZeroFields tests behavior with zero/nil fields
func TestSSU2Packet_ZeroFields(t *testing.T) {
	t.Run("Nil payload is allowed", func(t *testing.T) {
		// Uses a long-header message type (Retry) with no ephemeral key, so
		// header(32) + MAC(16) = 48 bytes already satisfies MinPacketSize(40)
		// with a nil payload. A short-header type (e.g. Data) with a nil
		// payload would total only 32 bytes, which validate() now correctly
		// rejects as below MinPacketSize (see AUDIT.md Level 5 item 3) -- use
		// "Minimal payload" below to cover that boundary instead.
		pkt := NewSSU2Packet(MessageTypeRetry, 0)
		pkt.Header = make([]byte, LongHeaderSize)
		pkt.Payload = nil // Explicitly nil
		pkt.MAC = make([]byte, MACSize)

		data, err := pkt.Serialize()
		require.NoError(t, err)
		assert.NotNil(t, data)
	})

	t.Run("Minimal payload", func(t *testing.T) {
		pkt := NewSSU2Packet(MessageTypeSessionConfirmed, 0)
		pkt.Header = make([]byte, ShortHeaderSize)
		pkt.Payload = []byte("12345678") // 8 bytes for 40 byte minimum
		pkt.MAC = make([]byte, MACSize)

		data, err := pkt.Serialize()
		require.NoError(t, err)
		assert.Equal(t, MinPacketSize, len(data))

		restored := NewSSU2Packet(MessageTypeSessionConfirmed, 0)
		err = restored.Deserialize(data)
		require.NoError(t, err)
		assert.NotNil(t, restored.Payload)
		assert.Equal(t, 8, len(restored.Payload))
	})

	t.Run("Below minimum packet size is rejected by Serialize", func(t *testing.T) {
		// Regression test for AUDIT.md Level 5 item 3: Serialize() (via
		// validate()) must reject a packet whose total wire size is below
		// MinPacketSize, symmetric with Deserialize()'s own check --
		// otherwise Serialize() could produce a packet that no spec-compliant
		// receiver (including this codebase's own Deserialize) would accept.
		pkt := NewSSU2Packet(MessageTypeData, 0) // short header, no ephemeral key
		pkt.Header = make([]byte, ShortHeaderSize)
		pkt.Payload = nil // header(16) + MAC(16) = 32 bytes, below the 40-byte minimum
		pkt.MAC = make([]byte, MACSize)

		_, err := pkt.Serialize()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "packet too small")
	})
}

// TestSSU2Packet_BinaryContent tests packets with binary (non-UTF8) content
func TestSSU2Packet_BinaryContent(t *testing.T) {
	pkt := NewSSU2Packet(MessageTypeData, 0)
	pkt.Header = make([]byte, ShortHeaderSize)
	// Fill with all possible byte values
	pkt.Payload = make([]byte, 256)
	for i := range pkt.Payload {
		pkt.Payload[i] = byte(i)
	}
	pkt.MAC = make([]byte, MACSize)
	for i := range pkt.MAC {
		pkt.MAC[i] = byte(255 - i)
	}

	data, err := pkt.Serialize()
	require.NoError(t, err)

	restored := NewSSU2Packet(MessageTypeData, 0)
	err = restored.Deserialize(data)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(pkt.Payload, restored.Payload))
	assert.True(t, bytes.Equal(pkt.MAC, restored.MAC))
}
