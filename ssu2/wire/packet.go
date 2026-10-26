package wire

import (
	"encoding/binary"
	"net"
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

	// Source is the UDP address the datagram was received from, set by
	// the reader (never serialized on the wire). Connection migration needs
	// it after the receive-window dedup decision (ssu2.md §"Connection
	// Migration" -> §"Initiating Path Validation": validate a new source
	// only if the packet "is not a duplicate packet number, AND ... successfully
	// decrypts"), so it must travel with the packet rather than being consumed
	// at parse time.
	Source net.Addr

	// IsIPv4 records the address family of the datagram's peer — the source for
	// an inbound packet, the destination for an outbound one. It selects the
	// legal total packet size at Serialize/Deserialize time, per ssu2.md §"Max
	// I2NP Message Size": "IPv4: … Max message size is MTU - 28 … IPv6: … Max
	// message size is MTU - 48." Zero (unknown family) uses the conservative
	// IPv6 limit. Never serialized on the wire.
	IsIPv4 bool

	// NetworkID is header byte 14 of a long header — the I2P network the packet
	// belongs to. Deserialize records the value found on the wire; the
	// config-aware session and listener layers compare it against their own
	// network ID and drop mismatches, per ssu2.md §"Header" ("2: SSU 2") and
	// proposal 147, which exists so test-network traffic fails fast. The wire
	// layer does not decide which network is correct. Short-header messages
	// (Session Confirmed, Data) carry no network ID and leave this zero.
	NetworkID uint8
}

// maxTotalSize returns the largest legal datagram size for the packet's address
// family. ssu2.md §"Max I2NP Message Size" budgets IPv4 20 bytes more than IPv6
// (the IP header difference), so an IPv4 session may send up to
// MaxPacketSizeIPv4 while an IPv6 session is capped at MaxPacketSizeIPv6.
func (p *SSU2Packet) maxTotalSize() int {
	if p.IsIPv4 {
		return MaxPacketSizeIPv4
	}
	return MaxPacketSizeIPv6
}

// minTotalSize returns the smallest legal datagram size for this message type.
//
// ssu2.md §"SessionRequest (Type 0)" / §"SessionCreated (Type 1)": "Minimum
// Size: 88". The intro-key family (Retry, Token Request, Peer Test, Hole
// Punch) has no per-message "Minimum Size" line, but each carries a 32-byte
// long header, an 8-byte minimum payload and a 16-byte MAC, and the spec's
// header-protection construction requires the last 24 bytes of the packet to be
// payload + MAC — hence 56. Reference: Java SSU2Util.MIN_HANDSHAKE_DATA_LEN
// (88) and SSU2Header.trialDecryptIntroKeyHeader (56).
func (p *SSU2Packet) minTotalSize() int {
	switch p.MessageType {
	case MessageTypeSessionRequest, MessageTypeSessionCreated:
		return MinHandshakePacketSize
	case MessageTypeRetry, MessageTypeTokenRequest, MessageTypePeerTest, MessageTypeHolePunch:
		return MinIntroKeyMessageSize
	default:
		return MinPacketSize
	}
}

// IsIPv4Addr reports whether addr is an IPv4 (or IPv4-mapped) endpoint. A nil
// or unparseable address is treated as IPv6 so that the conservative, smaller
// packet budget applies.
func IsIPv4Addr(addr net.Addr) bool {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil || udp.IP == nil {
		return false
	}
	return udp.IP.To4() != nil
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
	MinPacketSize = 40 // Minimum valid packet size
	// MinPayloadSize is the smallest plaintext block payload a message may
	// carry. The Header Encryption KDF section states: "This KDF uses the last
	// 24 bytes of the packet as the IV for the two ChaCha20 operations. As all
	// packets end with a 16 byte MAC, this requires that all packet payloads are
	// a minimum of 8 bytes." The per-message sections add: "The minimum payload
	// size is 8 bytes ... If the requirement is not met, a Padding block must be
	// included."
	//
	// This is a constraint on the plaintext blocks, not on SSU2Packet.Payload
	// after AEAD encryption: encryption always adds a 16-byte tag, so an
	// encrypted payload clears the floor automatically and a wire-layer check
	// would be both redundant and unable to see the plaintext it is about.
	//
	// Enforcement lives in ssu2/session: encryptDataPayload pads outbound
	// plaintext payloads up to this floor (via wire.PadPayloadToMin) before
	// encryption, and decryptInboundPayload rejects inbound payloads that
	// decrypt to less than this floor.
	MinPayloadSize    = 8
	MaxPacketSizeIPv4 = 1472 // 1500 Ethernet MTU - 20 IPv4 header - 8 UDP header
	MaxPacketSizeIPv6 = 1452 // 1500 Ethernet MTU - 40 IPv6 header - 8 UDP header

	// MinHandshakePacketSize is the smallest legal Session Request or Session
	// Created datagram: 32-byte long header + 32-byte ephemeral key + 8-byte
	// minimum payload + 16-byte MAC. ssu2.md §"SessionRequest (Type 0)" and
	// §"SessionCreated (Type 1)" both state "Size: 80 + payload size. Minimum
	// Size: 88". Reference: Java SSU2Util.MIN_HANDSHAKE_DATA_LEN =
	// SESSION_HEADER_SIZE (64) + TOTAL_PROT_SAMPLE_LEN (24) = 88, enforced in
	// SSU2Header.trialDecryptHandshakeHeader.
	MinHandshakePacketSize = 88

	// MinIntroKeyMessageSize is the smallest legal Retry / Token Request / Peer
	// Test / Hole Punch datagram: 32-byte long header + 8-byte minimum payload +
	// 16-byte MAC. Reference: Java SSU2Header.trialDecryptIntroKeyHeader
	// ("packet must be 56 bytes min").
	MinIntroKeyMessageSize = 56

	// MaxPacketNumber is the largest 32-bit packet number (2^32 - 1).
	// ssu2.rst §"Packet Numbering": "When a max of 2**32 packets have been
	// sent, wrapping the packet number back to the first packet number, that
	// session is no longer valid."
	MaxPacketNumber uint32 = 0xFFFFFFFF
)

// SSU2 long header field constants per specification
const (
	SSU2ProtocolVersion uint8 = 2 // Protocol version at header byte 13

	// MainNetworkID is the header byte 14 value for the I2P main network
	// (ssu2.md §"Header": "2: SSU 2 (required)"). It is a default, not a
	// requirement: proposal 147 assigns different IDs to test networks so that
	// cross-network connections fail fast, so the value in force is
	// configuration (SSU2Config.NetworkID), and this constant only names the
	// main-network value.
	MainNetworkID uint8 = 2
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

// CarriesNetworkID reports whether this message's header contains the network
// ID field at all.
//
// ssu2.md §"Header": the network ID is long-header byte 14, so only the
// long-header types (Session Request, Session Created, Peer Test, Retry, Token
// Request, Hole Punch) carry it. Session Confirmed and Data use the 16-byte
// short header, which has no such field, and leave NetworkID zero.
//
// Callers must use this instead of testing NetworkID == 0 to mean "not
// recorded": a long header that actually declares netid 0 is declaring a
// network no deployment uses, and §"Header Validation" requires the receiver to
// drop it — "If the version is != 2, or the netid is != the expected value
// (generally 2, except in test networks), the receiver should drop the message."
func (p *SSU2Packet) CarriesNetworkID() bool {
	return p.getHeaderSize() == LongHeaderSize
}

// RecordedNetworkID returns the network ID the packet's header declares, and
// whether a long header is present at all.
//
// This reads header byte 14 rather than the NetworkID field, because the field
// is only stamped by Deserialize. A packet built in memory by a handshake
// helper carries the value in its header but has not round-tripped through the
// wire, and must not be mistaken for "no network ID".
func (p *SSU2Packet) RecordedNetworkID() (uint8, bool) {
	if !p.CarriesNetworkID() || len(p.Header) < LongHeaderSize {
		return 0, false
	}
	return p.Header[14], true
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

	// Per-message-type floor, applied as soon as the type is known and before
	// any cryptographic work: ssu2.md §"SessionRequest (Type 0)" /
	// §"SessionCreated (Type 1)" state "Minimum Size: 88", and the intro-key
	// family requires 56 for header protection to have its 24-byte sample.
	// Reference: Java SSU2Header.trialDecryptHandshakeHeader rejects anything
	// below SSU2Util.MIN_HANDSHAKE_DATA_LEN outright.
	if minSize := p.minTotalSize(); len(data) < minSize {
		return oops.Errorf("packet too short for message type %d: %d bytes (minimum %d)",
			p.MessageType, len(data), minSize)
	}

	headerSize := p.getHeaderSize()

	// Record the network ID for the caller to compare against its own
	// configuration; the wire layer has no policy about which network is
	// correct. The version byte, by contrast, is a format fact: this
	// implementation only speaks SSU2 version 2, so it is enforced here.
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

// validateLongHeader checks the protocol version and records the network ID for
// long-header messages.
//
// The version byte is a format fact and is enforced here: this implementation
// only speaks SSU2 version 2 (ssu2.md §"Header": "2: SSU 2 (required)").
//
// The network ID is deliberately NOT enforced at the wire layer. Proposal 147
// ("I2P Network ID") makes it a deployment-scoped value — the main network uses
// 2, each test network uses something else, so cross-network connections fail
// fast — which means the correct value depends on configuration, not on the
// protocol. Callers compare the recorded value against their configured
// network ID; see ssu2/session and ssu2/server.
func (p *SSU2Packet) validateLongHeader(data []byte, headerSize int) error {
	flog("validateLongHeader", logger.Fields{"headerSize": headerSize}).Debug("validateLongHeader: validating long header fields")
	if headerSize != LongHeaderSize {
		return nil
	}
	if data[13] != SSU2ProtocolVersion {
		return oops.Errorf("unsupported protocol version: %d (expected %d)", data[13], SSU2ProtocolVersion)
	}
	p.NetworkID = data[14]
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

	if totalSize > p.maxTotalSize() {
		return oops.Errorf("packet too large: %d bytes (maximum %d for %s)",
			totalSize, p.maxTotalSize(), packetFamily(p.IsIPv4))
	}

	// Symmetric with Deserialize()'s minimum-size check: a packet built with
	// an empty/near-empty payload could otherwise pass validate() here but
	// then be rejected by any spec-compliant receiver (including this same
	// codebase's own Deserialize) as "packet too short". The floor is
	// per-message-type: ssu2.md §"SessionRequest (Type 0)" / §"SessionCreated
	// (Type 1)" require 88 bytes minimum, the intro-key family 56.
	if minSize := p.minTotalSize(); totalSize < minSize {
		return oops.Errorf("packet too small: %d bytes (minimum %d for message type %d)",
			totalSize, minSize, p.MessageType)
	}

	return nil
}

// packetFamily names an address family for error messages.
func packetFamily(isIPv4 bool) string {
	if isIPv4 {
		return "IPv4"
	}
	return "IPv6"
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
