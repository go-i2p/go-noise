package ratchet

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// BlockType identifies the type of a payload block.
// Spec ref: ratchet.md §"Unencrypted data".
type BlockType byte

const (
	// BlockDateTime is a timestamp block (type 0). Required first in New Session messages.
	// Contains a 4-byte unsigned Unix timestamp in seconds.
	BlockDateTime BlockType = 0

	// BlockTermination signals session teardown (type 4).
	// Must be the last non-padding block. Only in Existing Session messages.
	BlockTermination BlockType = 4

	// BlockOptions passes session parameters (type 5).
	//
	// WARNING: this block type is currently unimplemented in the I2P ECIES
	// spec (ratchet.md §"Unencrypted data"). No deployed I2P router will
	// process an Options block. Do not include this block type in any
	// outgoing message until the spec is finalised.
	// Spec ref: ratchet.md §"Unencrypted data" — "type 5: options (unimplemented)".
	BlockOptions BlockType = 5

	// BlockMessageNumber carries the previous tag set message count (type 6).
	// Contains a 2-byte big-endian PN value.
	BlockMessageNumber BlockType = 6

	// BlockNextKey carries a DH ratchet public key for forward secrecy (type 7).
	// Only in Existing Session messages.
	BlockNextKey BlockType = 7

	// BlockAck acknowledges previously received messages (type 8).
	// Only in Existing Session messages.
	BlockAck BlockType = 8

	// BlockAckRequest requests an in-band acknowledgment (type 9).
	// Only in Existing Session messages.
	BlockAckRequest BlockType = 9

	// BlockGarlicClove carries a single garlic clove (type 11).
	BlockGarlicClove BlockType = 11

	// BlockPadding fills remaining space in a frame (type 254).
	// Must be the last block if present.
	BlockPadding BlockType = 254
)

// blockHeaderSize is the size of a block header: 1 byte type + 2 bytes length.
const blockHeaderSize = 3

// maxBlockDataSize is the maximum data size for a single block (65516 bytes).
// Max ChaChaPoly frame = 65535, minus Poly1305 tag (16) = 65519, minus header (3) = 65516.
const maxBlockDataSize = 65516

// maxPayloadSize is the maximum total unencrypted payload size (65519 bytes).
const maxPayloadSize = 65519

// NextKeyFlag bit definitions for the NextKey block's flag byte.
// Spec ref: ratchet.md §"Next DH Ratchet Public Key".
const (
	// NextKeyFlagKeyPresent indicates the 32-byte public key is included.
	NextKeyFlagKeyPresent byte = 1 << 0
	// NextKeyFlagReverse indicates this is a reverse key (bit 1).
	NextKeyFlagReverse byte = 1 << 1
	// NextKeyFlagRequestReverse requests a reverse key from the peer (bit 2).
	// Only valid when bit 1 is not set.
	NextKeyFlagRequestReverse byte = 1 << 2
)

// TerminationReason indicates why a session is being terminated.
type TerminationReason byte

const (
	// TerminationNormal indicates normal close or unspecified reason.
	TerminationNormal TerminationReason = 0
	// TerminationReceived indicates a termination was received from the peer.
	TerminationReceived TerminationReason = 1
)

// PayloadBlock represents a single block within an ECIES-X25519-AEAD-Ratchet payload.
// Each block has a 1-byte type, 2-byte big-endian length, and variable-length data.
// Spec ref: ratchet.md §"Unencrypted data".
type PayloadBlock struct {
	Type BlockType
	Data []byte
}

// Constructor pattern for payload blocks:
// - Create a minimally sized byte slice for the block body
// - Encode fixed-width fields in network order when required
// - Copy variable payload bytes directly into the body
// - Return PayloadBlock{Type: ..., Data: body} without side effects
// This keeps block creation uniform across New*Block helpers and makes wire
// layout auditing straightforward.

// NewDateTimeBlock creates a DateTime block with the given timestamp.
// The timestamp is stored as a 4-byte unsigned big-endian Unix seconds value.
func NewDateTimeBlock(t time.Time) PayloadBlock {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(t.Unix()))
	return PayloadBlock{Type: BlockDateTime, Data: data}
}

// NewTerminationBlock creates a Termination block with the given reason and optional data.
func NewTerminationBlock(reason TerminationReason, additionalData []byte) PayloadBlock {
	data := make([]byte, 1+len(additionalData))
	data[0] = byte(reason)
	copy(data[1:], additionalData)
	return PayloadBlock{Type: BlockTermination, Data: data}
}

// NewMessageNumberBlock creates a Message Number block with the given PN value.
// PN is the index of the last tag sent in the previous tag set (2 bytes, big-endian).
func NewMessageNumberBlock(pn uint16) PayloadBlock {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, pn)
	return PayloadBlock{Type: BlockMessageNumber, Data: data}
}

// NewNextKeyBlock creates a Next Key block for DH ratchet key exchange.
// If pubKey is non-nil, the 32-byte key is included and the key-present flag is set.
// Set reverse=true for a reverse key, requestReverse=true to request one (forward only).
func NewNextKeyBlock(keyID uint16, pubKey *[32]byte, reverse, requestReverse bool) PayloadBlock {
	var flags byte
	if pubKey != nil {
		flags |= NextKeyFlagKeyPresent
	}
	if reverse {
		flags |= NextKeyFlagReverse
	} else if requestReverse {
		flags |= NextKeyFlagRequestReverse
	}

	size := 3 // flags(1) + keyID(2)
	if pubKey != nil {
		size += 32
	}
	data := make([]byte, size)
	data[0] = flags
	binary.BigEndian.PutUint16(data[1:3], keyID)
	if pubKey != nil {
		writeArray32(data[3:35], *pubKey)
	}
	return PayloadBlock{Type: BlockNextKey, Data: data}
}

// AckEntry represents a single acknowledgment of a received message.
type AckEntry struct {
	TagSetID uint16
	N        uint16
}

// NewAckBlock creates an Ack block acknowledging one or more received messages.
func NewAckBlock(acks []AckEntry) PayloadBlock {
	data := make([]byte, 4*len(acks))
	for i, ack := range acks {
		binary.BigEndian.PutUint16(data[i*4:], ack.TagSetID)
		binary.BigEndian.PutUint16(data[i*4+2:], ack.N)
	}
	return PayloadBlock{Type: BlockAck, Data: data}
}

// NewAckRequestBlock creates an Ack Request block with the given flags.
func NewAckRequestBlock(flags byte) PayloadBlock {
	return PayloadBlock{Type: BlockAckRequest, Data: []byte{flags}}
}

// NewGarlicCloveBlock creates a Garlic Clove block containing raw clove data.
// The data includes delivery instructions, I2NP header (type + message ID + expiration),
// and the I2NP message body.
func NewGarlicCloveBlock(cloveData []byte) PayloadBlock {
	return PayloadBlock{Type: BlockGarlicClove, Data: cloveData}
}

// NewPaddingBlock creates a Padding block of the specified size.
// The padding content is zeroed (it will be encrypted before transmission).
func NewPaddingBlock(size int) PayloadBlock {
	if size < 0 {
		size = 0
	}
	return PayloadBlock{Type: BlockPadding, Data: make([]byte, size)}
}

// DateTime parses a DateTime block and returns the timestamp.
// Returns an error if the block type is wrong or data length is not 4.
func (b PayloadBlock) DateTime() (time.Time, error) {
	flog("PayloadBlock.DateTime", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Parsing DateTime block")
	if b.Type != BlockDateTime {
		return time.Time{}, oops.Errorf("block type %d is not DateTime", b.Type)
	}
	if len(b.Data) != 4 {
		return time.Time{}, oops.Errorf("DateTime block data length %d, expected 4", len(b.Data))
	}
	secs := binary.BigEndian.Uint32(b.Data)
	return time.Unix(int64(secs), 0), nil
}

// TerminationInfo parses a Termination block and returns the reason and additional data.
func (b PayloadBlock) TerminationInfo() (TerminationReason, []byte, error) {
	flog("PayloadBlock.TerminationInfo", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Parsing Termination block")
	if b.Type != BlockTermination {
		return 0, nil, oops.Errorf("block type %d is not Termination", b.Type)
	}
	if len(b.Data) < 1 {
		return 0, nil, oops.Errorf("Termination block data is empty")
	}
	return TerminationReason(b.Data[0]), b.Data[1:], nil
}

// MessageNumber parses a Message Number block and returns the PN value.
func (b PayloadBlock) MessageNumber() (uint16, error) {
	flog("PayloadBlock.MessageNumber", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Parsing MessageNumber block")
	if b.Type != BlockMessageNumber {
		return 0, oops.Errorf("block type %d is not MessageNumber", b.Type)
	}
	if len(b.Data) != 2 {
		return 0, oops.Errorf("MessageNumber block data length %d, expected 2", len(b.Data))
	}
	return binary.BigEndian.Uint16(b.Data), nil
}

// NextKeyInfo holds parsed fields from a NextKey block.
type NextKeyInfo struct {
	KeyPresent     bool
	Reverse        bool
	RequestReverse bool
	KeyID          uint16
	PublicKey      [32]byte // only valid if KeyPresent is true
}

// NextKey parses a NextKey block and returns its fields.
func (b PayloadBlock) NextKey() (NextKeyInfo, error) {
	flog("PayloadBlock.NextKey", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Parsing NextKey block")
	if b.Type != BlockNextKey {
		return NextKeyInfo{}, oops.Errorf("block type %d is not NextKey", b.Type)
	}
	if len(b.Data) != 3 && len(b.Data) != 35 {
		return NextKeyInfo{}, oops.Errorf("NextKey block data length %d, expected 3 or 35", len(b.Data))
	}
	info := NextKeyInfo{
		KeyPresent:     b.Data[0]&NextKeyFlagKeyPresent != 0,
		Reverse:        b.Data[0]&NextKeyFlagReverse != 0,
		RequestReverse: b.Data[0]&NextKeyFlagRequestReverse != 0,
		KeyID:          binary.BigEndian.Uint16(b.Data[1:3]),
	}
	if info.KeyPresent {
		if len(b.Data) < 35 {
			return NextKeyInfo{}, oops.Errorf("NextKey block has key-present flag but only %d bytes", len(b.Data))
		}
		readArray32(&info.PublicKey, b.Data[3:35])
	}
	return info, nil
}

// Acks parses an Ack block and returns the list of acknowledgment entries.
func (b PayloadBlock) Acks() ([]AckEntry, error) {
	flog("PayloadBlock.Acks", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Parsing Ack block")
	if b.Type != BlockAck {
		return nil, oops.Errorf("block type %d is not Ack", b.Type)
	}
	if len(b.Data)%4 != 0 || len(b.Data) < 4 {
		return nil, oops.Errorf("Ack block data length %d is not a positive multiple of 4", len(b.Data))
	}
	count := len(b.Data) / 4
	acks := make([]AckEntry, count)
	for i := range acks {
		acks[i].TagSetID = binary.BigEndian.Uint16(b.Data[i*4:])
		acks[i].N = binary.BigEndian.Uint16(b.Data[i*4+2:])
	}
	return acks, nil
}

// SerializeSize returns the total wire size of this block including the 3-byte header.
func (b PayloadBlock) SerializeSize() int {
	return blockHeaderSize + len(b.Data)
}

// Serialize writes the block to a byte slice in wire format: [type(1)] + [size(2)] + [data(N)].
// Returns the number of bytes written.
func (b PayloadBlock) Serialize(dst []byte) (int, error) {
	flog("PayloadBlock.Serialize", logger.Fields{"block_type": b.Type, "data_len": len(b.Data)}).Debug("Serializing payload block")
	needed := b.SerializeSize()
	if len(dst) < needed {
		return 0, oops.Errorf("destination buffer too small: need %d, have %d", needed, len(dst))
	}
	if len(b.Data) > maxBlockDataSize {
		return 0, oops.Errorf("block data size %d exceeds maximum %d", len(b.Data), maxBlockDataSize)
	}
	dst[0] = byte(b.Type)
	binary.BigEndian.PutUint16(dst[1:3], uint16(len(b.Data)))
	copy(dst[3:], b.Data)
	return needed, nil
}
