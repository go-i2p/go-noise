package wire

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Packet represents an SSU2 protocol packet with encrypted header and payload.
// SSU2 packets follow the wire format defined in ssu2.rst:
//   - Encrypted header (16 or 32 bytes depending on message type)
//   - Optional ephemeral key (32 bytes for SessionRequest/Created only)
//   - ChaCha20-encrypted payload (variable length)
//   - Poly1305 MAC (16 bytes)
//
// All packets are immutable after creation. Encryption/decryption happens
// via the Encrypt/Decrypt methods which operate on the wire format.
type SSU2Packet struct {
	// Header contains the encrypted header bytes (16 or 32 bytes)
	// Length depends on message type per ssu2.rst
	Header []byte

	// EphemeralKey is the optional X25519 ephemeral public key (32 bytes)
	// Only present in SessionRequest (type 0) and SessionCreated (type 1)
	EphemeralKey []byte

	// Payload is the ChaCha20-encrypted blocks section
	// Contains one or more SSU2Block structures
	Payload []byte

	// MAC is the Poly1305 authentication tag (16 bytes)
	// Authenticates header, ephemeral key, and payload
	MAC []byte

	// MessageType identifies the packet type (0-11 per ssu2.rst)
	// 0=SessionRequest, 1=SessionCreated, 2=SessionConfirmed, 6=Data, etc.
	MessageType uint8

	// PacketNumber is the sequence number for ordering and ACKs
	// Valid range: 0 to 2^32-1 (MaxPacketNumber)
	PacketNumber uint32

	// Timestamp records when packet was created or received
	// Used for RTT estimation and debugging
	Timestamp time.Time
}

// Message type constants from ssu2.rst
const (
	MessageTypeSessionRequest   uint8 = 0
	MessageTypeSessionCreated   uint8 = 1
	MessageTypeSessionConfirmed uint8 = 2
	MessageTypeData             uint8 = 6
	MessageTypePeerTest         uint8 = 7
	MessageTypeRetry            uint8 = 9
	MessageTypeTokenRequest     uint8 = 10
	MessageTypeHolePunch        uint8 = 11
)

// Header size constants from ssu2.rst
const (
	ShortHeaderSize  = 16 // SessionConfirmed, Data
	LongHeaderSize   = 32 // SessionRequest, SessionCreated, PeerTest, Retry, TokenRequest, HolePunch
	EphemeralKeySize = 32 // X25519 public key
	MACSize          = 16 // Poly1305 MAC
)

// Size constraints from ssu2.rst
const (
	MinPacketSize     = 40   // Minimum valid packet size
	MaxPacketSizeIPv4 = 1472 // 1500 Ethernet MTU - 20 IPv4 header - 8 UDP header
	MaxPacketSizeIPv6 = 1452 // 1500 Ethernet MTU - 40 IPv6 header - 8 UDP header
)

// SSU2 long header field constants per specification
const (
	SSU2ProtocolVersion uint8 = 2 // Protocol version at header byte 13
	SSU2NetworkID       uint8 = 2 // Network ID (I2P mainnet) at header byte 14
)

// NewSSU2Packet creates a new SSU2 packet with the specified message type.
// The packet is initially empty and must be populated with Serialize or by
// setting the fields directly.
//
// Parameters:
//   - msgType: Message type constant (0-11)
//   - packetNum: Sequence number for this packet
//
// Returns a new SSU2Packet with timestamp set to now.
func NewSSU2Packet(msgType uint8, packetNum uint32) *SSU2Packet {
	flog("NewSSU2Packet", logger.Fields{"messageType": msgType, "packetNum": packetNum}).Debug("NewSSU2Packet: creating new packet")
	return &SSU2Packet{
		MessageType:  msgType,
		PacketNumber: packetNum,
		Timestamp:    time.Now(),
	}
}

// hasEphemeralKey returns true if this message type includes an ephemeral key.
// Only SessionRequest (0) and SessionCreated (1) include ephemeral keys.
func (p *SSU2Packet) hasEphemeralKey() bool {
	return p.MessageType == MessageTypeSessionRequest ||
		p.MessageType == MessageTypeSessionCreated
}

// HasEphemeralKey returns true if this message type includes an ephemeral key.
func (p *SSU2Packet) HasEphemeralKey() bool {
	return p.hasEphemeralKey()
}

// getHeaderSize returns the expected header size for this message type.
// Returns 32 bytes for long header messages, 16 bytes for short header messages.
func (p *SSU2Packet) getHeaderSize() int {
	switch p.MessageType {
	case MessageTypeSessionConfirmed, MessageTypeData:
		return ShortHeaderSize
	default:
		return LongHeaderSize
	}
}

// GetHeaderSize returns the expected header size for this message type.
func (p *SSU2Packet) GetHeaderSize() int {
	return p.getHeaderSize()
}

// Serialize converts the packet to wire format for transmission.
// The wire format is: Header || EphemeralKey? || Payload || MAC
//
// Returns:
//   - []byte: Wire format packet data
//   - error: If packet is invalid or incomplete
func (p *SSU2Packet) Serialize() ([]byte, error) {
	flog("Serialize", logger.Fields{"messageType": p.MessageType, "packetNum": p.PacketNumber}).Debug("Serialize: serializing packet to wire format")
	// Validate packet structure
	if err := p.validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid packet")
	}

	// Embed the message type at header byte 12 (I2P SSU2 spec: type byte at
	// offset 12 in both short and long headers). This must happen after
	// validate() confirms len(Header) >= ShortHeaderSize (16), so index 12
	// is always valid.
	p.Header[12] = p.MessageType

	// Calculate total size
	size := len(p.Header) + len(p.Payload) + len(p.MAC)
	if p.hasEphemeralKey() {
		size += len(p.EphemeralKey)
	}

	// Allocate buffer
	buf := make([]byte, 0, size)

	// Append components in order
	buf = append(buf, p.Header...)
	if p.hasEphemeralKey() && len(p.EphemeralKey) > 0 {
		buf = append(buf, p.EphemeralKey...)
	}
	buf = append(buf, p.Payload...)
	buf = append(buf, p.MAC...)

	return buf, nil
}

// Deserialize parses wire format data into this packet structure.
// The packet's MessageType must be set before calling Deserialize so we
// know the expected header size and whether to parse an ephemeral key.
//
// Parameters:
//   - data: Wire format packet bytes
//
// Returns error if data is malformed or too short.
func (p *SSU2Packet) Deserialize(data []byte) error {
	flog("Deserialize", logger.Fields{"dataLen": len(data)}).Debug("Deserialize: parsing wire format data")
	if len(data) < MinPacketSize {
		return oops.Errorf("packet too short: %d bytes (minimum %d)", len(data), MinPacketSize)
	}

	p.MessageType = data[12]
	headerSize := p.getHeaderSize()

	if err := p.validateLongHeader(data, headerSize); err != nil {
		return err
	}

	if err := p.parsePacketSections(data, headerSize); err != nil {
		return err
	}

	p.PacketNumber = binary.BigEndian.Uint32(p.Header[8:12])
	p.Timestamp = time.Now()

	return nil
}

// validateLongHeader checks protocol version and network ID for long-header messages.
func (p *SSU2Packet) validateLongHeader(data []byte, headerSize int) error {
	flog("validateLongHeader", logger.Fields{"headerSize": headerSize}).Debug("validateLongHeader: validating long header fields")
	if headerSize != LongHeaderSize {
		return nil
	}
	if data[13] != SSU2ProtocolVersion {
		return oops.Errorf("unsupported protocol version: %d (expected %d)", data[13], SSU2ProtocolVersion)
	}
	if data[14] != SSU2NetworkID {
		return oops.Errorf("wrong network ID: %d (expected %d)", data[14], SSU2NetworkID)
	}
	return nil
}

// parsePacketSections extracts header, ephemeral key, payload, and MAC from wire data.
func (p *SSU2Packet) parsePacketSections(data []byte, headerSize int) error {
	flog("parsePacketSections", logger.Fields{"dataLen": len(data), "headerSize": headerSize}).Debug("parsePacketSections: extracting packet sections")
	hasEphemeral := p.hasEphemeralKey()
	minSize := headerSize + MACSize
	if hasEphemeral {
		minSize += EphemeralKeySize
	}
	if len(data) < minSize {
		return oops.Errorf("packet too short: %d bytes (expected at least %d)", len(data), minSize)
	}

	p.Header = make([]byte, headerSize)
	copy(p.Header, data[:headerSize])
	offset := headerSize

	if hasEphemeral {
		p.EphemeralKey = make([]byte, EphemeralKeySize)
		copy(p.EphemeralKey, data[offset:offset+EphemeralKeySize])
		offset += EphemeralKeySize
	}

	macStart := len(data) - MACSize
	if macStart < offset {
		return oops.Errorf("invalid packet structure: MAC position %d < offset %d", macStart, offset)
	}

	if payloadSize := macStart - offset; payloadSize > 0 {
		p.Payload = make([]byte, payloadSize)
		copy(p.Payload, data[offset:macStart])
	}

	p.MAC = make([]byte, MACSize)
	copy(p.MAC, data[macStart:])
	return nil
}

// validate checks that the packet has all required fields populated correctly.
func (p *SSU2Packet) validate() error {
	flog("validate", logger.Fields{"messageType": p.MessageType}).Debug("validate: validating packet structure")
	// Check header size
	expectedHeaderSize := p.getHeaderSize()
	if len(p.Header) != expectedHeaderSize {
		return oops.Errorf("invalid header size: got %d, expected %d for message type %d",
			len(p.Header), expectedHeaderSize, p.MessageType)
	}

	// Check ephemeral key if required
	if p.hasEphemeralKey() {
		if len(p.EphemeralKey) != EphemeralKeySize {
			return oops.Errorf("invalid ephemeral key size: got %d, expected %d",
				len(p.EphemeralKey), EphemeralKeySize)
		}
	} else if len(p.EphemeralKey) > 0 {
		return oops.Errorf("ephemeral key present for message type %d (should be empty)", p.MessageType)
	}

	// Check MAC
	if len(p.MAC) != MACSize {
		return oops.Errorf("invalid MAC size: got %d, expected %d", len(p.MAC), MACSize)
	}

	// Payload can be empty for some message types, so just check it's not too large
	totalSize := len(p.Header) + len(p.Payload) + len(p.MAC)
	if p.hasEphemeralKey() {
		totalSize += len(p.EphemeralKey)
	}

	if totalSize > MaxPacketSizeIPv6 {
		return oops.Errorf("packet too large: %d bytes (maximum %d for IPv6, %d for IPv4)",
			totalSize, MaxPacketSizeIPv6, MaxPacketSizeIPv4)
	}

	return nil
}

// Size returns the total wire format size in bytes.
func (p *SSU2Packet) Size() int {
	size := len(p.Header) + len(p.Payload) + len(p.MAC)
	if p.hasEphemeralKey() && len(p.EphemeralKey) > 0 {
		size += len(p.EphemeralKey)
	}
	return size
}

// Clone creates a deep copy of the packet.
// Useful for retransmission scenarios where the same packet needs to be sent multiple times.
func (p *SSU2Packet) Clone() *SSU2Packet {
	flog("Clone", logger.Fields{"messageType": p.MessageType, "packetNum": p.PacketNumber}).Debug("Clone: creating deep copy of packet")
	clone := &SSU2Packet{
		MessageType:  p.MessageType,
		PacketNumber: p.PacketNumber,
		Timestamp:    p.Timestamp,
	}

	if len(p.Header) > 0 {
		clone.Header = make([]byte, len(p.Header))
		copy(clone.Header, p.Header)
	}

	if len(p.EphemeralKey) > 0 {
		clone.EphemeralKey = make([]byte, len(p.EphemeralKey))
		copy(clone.EphemeralKey, p.EphemeralKey)
	}

	if len(p.Payload) > 0 {
		clone.Payload = make([]byte, len(p.Payload))
		copy(clone.Payload, p.Payload)
	}

	if len(p.MAC) > 0 {
		clone.MAC = make([]byte, len(p.MAC))
		copy(clone.MAC, p.MAC)
	}

	return clone
}

// SetPacketNumber updates the packet number in the packet structure.
// Note: This does NOT update the encrypted header - caller must re-encrypt if needed.
func (p *SSU2Packet) SetPacketNumber(num uint32) {
	p.PacketNumber = num
}

// GetPacketNumber returns the packet sequence number.
func (p *SSU2Packet) GetPacketNumber() uint32 {
	return p.PacketNumber
}

// GetMessageType returns the message type.
func (p *SSU2Packet) GetMessageType() uint8 {
	return p.MessageType
}

// GetTimestamp returns when the packet was created or received.
func (p *SSU2Packet) GetTimestamp() time.Time {
	return p.Timestamp
}

// IsHandshakePacket returns true if this is a handshake message type.
func (p *SSU2Packet) IsHandshakePacket() bool {
	return p.MessageType == MessageTypeSessionRequest ||
		p.MessageType == MessageTypeSessionCreated ||
		p.MessageType == MessageTypeSessionConfirmed
}

// IsDataPacket returns true if this is a data message.
func (p *SSU2Packet) IsDataPacket() bool {
	return p.MessageType == MessageTypeData
}

// DecodeConnectionID extracts the connection ID from the packet header.
// The connection ID is encoded in the first 8 bytes of the header (big-endian)
// per the SSU2 spec: "Destination Connection ID: 8-byte big-endian integer".
func (p *SSU2Packet) DecodeConnectionID() (uint64, error) {
	flog("DecodeConnectionID").Debug("DecodeConnectionID: extracting connection ID from header")
	if len(p.Header) < 8 {
		return 0, oops.Errorf("header too short to contain connection ID: %d bytes", len(p.Header))
	}

	// Connection ID is first 8 bytes (big-endian per spec)
	connID := binary.BigEndian.Uint64(p.Header[0:8])
	return connID, nil
}

// EncodeConnectionID sets the connection ID in the packet header.
// The connection ID is stored in the first 8 bytes (big-endian)
// per the SSU2 spec: "Destination Connection ID: 8-byte big-endian integer".
func (p *SSU2Packet) EncodeConnectionID(connID uint64) error {
	flog("EncodeConnectionID", logger.Fields{"connID": connID}).Debug("EncodeConnectionID: setting connection ID in header")
	if len(p.Header) < 8 {
		return oops.Errorf("header too short to store connection ID: %d bytes", len(p.Header))
	}

	// Store connection ID in first 8 bytes (big-endian per spec)
	binary.BigEndian.PutUint64(p.Header[0:8], connID)
	return nil
}
