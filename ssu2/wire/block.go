package wire

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Block represents an SSU2 protocol block within a packet payload.
// Blocks use TLV (Type-Length-Value) encoding:
//   - Type: 1 byte (block type identifier)
//   - Length: 2 bytes (big-endian, length of Value field only)
//   - Value: variable length data
//
// SSU2 packets can contain multiple blocks concatenated together.
// Block types are defined in ssu2.rst specification.
type SSU2Block struct {
	// Type identifies the block type (0-254)
	// See BlockType* constants for valid values
	Type uint8

	// Data contains the block payload (Value in TLV encoding)
	// Length is implicit from len(Data)
	Data []byte
}

// TokenSize is the size of SSU2 retry tokens in bytes.
// Per SSU2 spec, tokens are 8-byte randomly-generated unsigned big-endian integers.
const TokenSize = 8

// Block type constants from ssu2.rst
const (
	BlockTypeDateTime          uint8 = 0   // Timestamp block (4 bytes, seconds since epoch)
	BlockTypeOptions           uint8 = 1   // Connection options (12+ bytes)
	BlockTypeRouterInfo        uint8 = 2   // RouterInfo structure (variable)
	BlockTypeI2NPMessage       uint8 = 3   // I2NP message (variable)
	BlockTypeFirstFragment     uint8 = 4   // First fragment of message (variable)
	BlockTypeFollowOnFragment  uint8 = 5   // Subsequent fragment (variable)
	BlockTypeTermination       uint8 = 6   // Connection termination (9+ bytes)
	BlockTypeRelayRequest      uint8 = 7   // Relay request (variable)
	BlockTypeRelayResponse     uint8 = 8   // Relay response (variable)
	BlockTypeRelayIntro        uint8 = 9   // Relay introduction (variable)
	BlockTypePeerTest          uint8 = 10  // Peer test message (variable)
	BlockTypeNextNonce         uint8 = 11  // Nonce rekeying (8 bytes)
	BlockTypeACK               uint8 = 12  // Acknowledgment (5+ bytes)
	BlockTypeAddress           uint8 = 13  // Address block (9 or 21 bytes)
	BlockTypeReserved14        uint8 = 14  // Reserved per spec (do not use)
	BlockTypeRelayTagRequest   uint8 = 15  // Request relay tag (0 bytes data)
	BlockTypeRelayTag          uint8 = 16  // Relay tag assignment (4 bytes)
	BlockTypeNewToken          uint8 = 17  // New session token (12 bytes data, 15 bytes on wire)
	BlockTypePathChallenge     uint8 = 18  // Path validation challenge (variable)
	BlockTypePathResponse      uint8 = 19  // Path validation response (variable)
	BlockTypeFirstPacketNumber uint8 = 20  // Initial packet number for data phase (4 bytes)
	BlockTypeCongestion        uint8 = 21  // Congestion experience signaling (1 byte)
	BlockTypePadding           uint8 = 254 // Padding block (variable)
)

// Minimum block data sizes from ssu2.rst
const (
	minBlockHeaderSize       = 3     // Type (1) + Length (2)
	minDateTimeSize          = 4     // Timestamp data (seconds since epoch)
	minOptionsSize           = 12    // Options data (per spec minimum)
	minTerminationSize       = 9     // Termination data: valid-data-packets-received(8) + reason(1) per spec
	minNextNonceSize         = 8     // Next nonce (8 bytes)
	minACKSize               = 5     // ACK data
	minReserved14Size        = 0     // Reserved block type (no data expected)
	minAddressSizeIPv4       = 6     // IPv4 address: port(2) + IP(4)
	minAddressSizeIPv6       = 18    // IPv6 address: port(2) + IP(16)
	minRelayTagRequestSize   = 0     // Relay tag request: empty data per spec (size=0)
	minRelayTagSize          = 4     // Relay tag data: relay_tag(4) per spec
	minNewTokenSize          = 12    // New token data: 4 expiration + 8 token
	minFirstPacketNumberSize = 4     // Initial packet number (4 bytes)
	minCongestionSize        = 1     // Congestion experience (1 byte)
	maxBlockLength           = 65535 // Maximum length field value (2 bytes)
)

var blockTypeNames = map[uint8]string{
	BlockTypeDateTime:          "DateTime",
	BlockTypeOptions:           "Options",
	BlockTypeRouterInfo:        "RouterInfo",
	BlockTypeI2NPMessage:       "I2NPMessage",
	BlockTypeFirstFragment:     "FirstFragment",
	BlockTypeFollowOnFragment:  "FollowOnFragment",
	BlockTypeTermination:       "Termination",
	BlockTypeRelayRequest:      "RelayRequest",
	BlockTypeRelayResponse:     "RelayResponse",
	BlockTypeRelayIntro:        "RelayIntro",
	BlockTypePeerTest:          "PeerTest",
	BlockTypeNextNonce:         "NextNonce",
	BlockTypeACK:               "ACK",
	BlockTypeAddress:           "Address",
	BlockTypeReserved14:        "Reserved14",
	BlockTypeRelayTagRequest:   "RelayTagRequest",
	BlockTypeRelayTag:          "RelayTag",
	BlockTypeNewToken:          "NewToken",
	BlockTypePathChallenge:     "PathChallenge",
	BlockTypePathResponse:      "PathResponse",
	BlockTypeFirstPacketNumber: "FirstPacketNumber",
	BlockTypeCongestion:        "Congestion",
	BlockTypePadding:           "Padding",
}

// NewSSU2Block creates a new block with the specified type and data.
//
// Parameters:
//   - blockType: Block type constant (BlockType*)
//   - data: Block payload data
//
// Returns a new SSU2Block ready for serialization.
func NewSSU2Block(blockType uint8, data []byte) *SSU2Block {
	return &SSU2Block{
		Type: blockType,
		Data: data,
	}
}

// Serialize encodes the block to wire format (TLV encoding).
// Format: [Type:1][Length:2][Data:Length]
//
// The Length field is big-endian and contains only the data length,
// not including the 3-byte header.
//
// Returns:
//   - []byte: Wire format block data
//   - error: If block is invalid or data too large
func (b *SSU2Block) Serialize() ([]byte, error) {
	flog("Serialize", logger.Fields{"blockType": b.Type, "dataLen": len(b.Data)}).Debug("Serialize: encoding block to wire format")
	// Validate block
	if err := b.validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid block")
	}

	// Allocate buffer: Type (1) + Length (2) + Data
	dataLen := len(b.Data)
	buf := make([]byte, minBlockHeaderSize+dataLen)

	// Encode Type
	buf[0] = b.Type

	// Encode Length (big-endian, 2 bytes)
	binary.BigEndian.PutUint16(buf[1:3], uint16(dataLen))

	// Copy Data
	if dataLen > 0 {
		copy(buf[3:], b.Data)
	}

	return buf, nil
}

// Deserialize decodes a block from wire format.
// Reads the TLV structure and populates this block's fields.
//
// Parameters:
//   - data: Wire format block data (must be at least 3 bytes)
//
// Returns:
//   - int: Number of bytes consumed from data
//   - error: If data is malformed or too short
func (b *SSU2Block) Deserialize(data []byte) (int, error) {
	flog("Deserialize", logger.Fields{"dataLen": len(data)}).Debug("Deserialize: decoding block from wire format")
	// Check minimum size
	if len(data) < minBlockHeaderSize {
		return 0, oops.Errorf("block too short: %d bytes (minimum %d)", len(data), minBlockHeaderSize)
	}

	// Decode Type
	b.Type = data[0]

	// Decode Length (big-endian)
	dataLen := int(binary.BigEndian.Uint16(data[1:3]))

	// Check if we have enough data
	totalLen := minBlockHeaderSize + dataLen
	if len(data) < totalLen {
		return 0, oops.Errorf("insufficient data: have %d bytes, need %d (header + %d data)",
			len(data), totalLen, dataLen)
	}

	// Extract Data
	if dataLen > 0 {
		b.Data = make([]byte, dataLen)
		copy(b.Data, data[3:3+dataLen])
	} else {
		b.Data = nil
	}

	// Validate decoded block
	if err := b.validate(); err != nil {
		return 0, oops.Wrapf(err, "invalid decoded block")
	}

	return totalLen, nil
}

// blockMinSizes maps block types to their minimum data sizes per ssu2.rst.
var blockMinSizes = map[uint8]int{
	BlockTypeDateTime:          minDateTimeSize,
	BlockTypeOptions:           minOptionsSize,
	BlockTypeTermination:       minTerminationSize,
	BlockTypeNextNonce:         minNextNonceSize,
	BlockTypeACK:               minACKSize,
	BlockTypeReserved14:        minReserved14Size,
	BlockTypeAddress:           minAddressSizeIPv4,
	BlockTypeRelayTagRequest:   minRelayTagRequestSize,
	BlockTypeRelayTag:          minRelayTagSize,
	BlockTypeNewToken:          minNewTokenSize,
	BlockTypeFirstPacketNumber: minFirstPacketNumberSize,
	BlockTypeCongestion:        minCongestionSize,
}

// validate checks that the block meets minimum size requirements per ssu2.rst.
func (b *SSU2Block) validate() error {
	dataLen := len(b.Data)

	// Check maximum length
	if dataLen > maxBlockLength {
		return oops.Errorf("block data too large: %d bytes (maximum %d)", dataLen, maxBlockLength)
	}

	// Validate minimum size for known block types
	if minSize, ok := blockMinSizes[b.Type]; ok && dataLen < minSize {
		return oops.Errorf("%s block too short: %d bytes (minimum %d)",
			GetBlockTypeName(b.Type), dataLen, minSize)
	}

	return nil
}

// Size returns the total wire format size in bytes (header + data).
func (b *SSU2Block) Size() int {
	return minBlockHeaderSize + len(b.Data)
}

// GetType returns the block type.
func (b *SSU2Block) GetType() uint8 {
	return b.Type
}

// GetData returns the block data payload.
func (b *SSU2Block) GetData() []byte {
	return b.Data
}

// enforceBlockOrder reorders blocks so that Padding (254) is last and
// Termination (6) is second-to-last, per spec §Blocks.
// Returns a new slice; the original is not modified.
func enforceBlockOrder(blocks []*SSU2Block) []*SSU2Block {
	flog("enforceBlockOrder", logger.Fields{"blockCount": len(blocks)}).Debug("enforceBlockOrder: reordering blocks per spec")
	var termBlock, padBlock *SSU2Block
	normal := make([]*SSU2Block, 0, len(blocks))

	for _, b := range blocks {
		switch b.Type {
		case BlockTypeTermination:
			termBlock = b
		case BlockTypePadding:
			padBlock = b
		default:
			normal = append(normal, b)
		}
	}

	if termBlock != nil {
		normal = append(normal, termBlock)
	}
	if padBlock != nil {
		normal = append(normal, padBlock)
	}

	return normal
}

// SerializeBlocks serializes multiple blocks into a single byte slice.
// This is useful for creating packet payloads that contain multiple blocks.
// Blocks are automatically reordered per spec §Blocks: Padding (254) is
// placed last, and Termination (6) second-to-last.
//
// Parameters:
//   - blocks: Slice of blocks to serialize
//
// Returns:
//   - []byte: Concatenated wire format of all blocks
//   - error: If any block fails to serialize
func SerializeBlocks(blocks []*SSU2Block) ([]byte, error) {
	flog("SerializeBlocks", logger.Fields{"blockCount": len(blocks)}).Debug("SerializeBlocks: serializing multiple blocks")
	if len(blocks) == 0 {
		return []byte{}, nil
	}

	// Enforce spec-required block ordering
	ordered := enforceBlockOrder(blocks)

	// Calculate total size
	totalSize := 0
	for _, block := range ordered {
		totalSize += block.Size()
	}

	// Allocate buffer
	buf := make([]byte, 0, totalSize)

	// Serialize each block
	for i, block := range ordered {
		data, err := block.Serialize()
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize block %d (type %d)", i, block.Type)
		}
		buf = append(buf, data...)
	}

	return buf, nil
}

// DeserializeBlocks deserializes multiple blocks from a byte slice.
// Reads blocks until all data is consumed or an error occurs.
//
// Parameters:
//   - data: Wire format data containing one or more blocks
//
// Returns:
//   - []*SSU2Block: Slice of deserialized blocks
//   - error: If deserialization fails
func DeserializeBlocks(data []byte) ([]*SSU2Block, error) {
	flog("DeserializeBlocks", logger.Fields{"dataLen": len(data)}).Debug("DeserializeBlocks: deserializing blocks from data")
	if len(data) == 0 {
		return []*SSU2Block{}, nil
	}

	blocks := make([]*SSU2Block, 0)
	offset := 0

	for offset < len(data) {
		block := &SSU2Block{}
		consumed, err := block.Deserialize(data[offset:])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to deserialize block at offset %d", offset)
		}

		blocks = append(blocks, block)
		offset += consumed
	}

	return blocks, nil
}

// IsKnownBlockType returns true if the block type is defined in the SSU2 specification.
func IsKnownBlockType(blockType uint8) bool {
	_, ok := blockTypeNames[blockType]
	return ok
}

// GetBlockTypeName returns a human-readable name for the block type.
func GetBlockTypeName(blockType uint8) string {
	if name, ok := blockTypeNames[blockType]; ok {
		return name
	}
	return "Unknown"
}
