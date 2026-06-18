package ratchet

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// nowFunc returns the current time. It is a variable so tests can override it.
var nowFunc = time.Now

// PayloadBuilder constructs a spec-compliant payload from a sequence of blocks.
// It enforces ordering rules from ratchet.md §"Block Ordering Rules":
//   - Padding, if present, must be the last block.
//   - Termination, if present, must be last except for padding.
//   - Multiple padding blocks are not allowed.
//
// Use the message-type-specific constructors (NewSessionPayloadBuilder,
// ExistingSessionPayloadBuilder) for full validation.
type PayloadBuilder struct {
	blocks []PayloadBlock
}

// NewPayloadBuilder creates an empty PayloadBuilder.
func NewPayloadBuilder() *PayloadBuilder {
	return &PayloadBuilder{}
}

// AddBlock appends a block to the payload.
func (pb *PayloadBuilder) AddBlock(block PayloadBlock) *PayloadBuilder {
	pb.blocks = append(pb.blocks, block)
	return pb
}

// Build serializes all blocks into a single byte slice.
// Returns an error if the payload exceeds maxPayloadSize or block ordering
// rules are violated.
func (pb *PayloadBuilder) Build() ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "PayloadBuilder.Build", "block_count": len(pb.blocks)}).Debug("Building payload from blocks")
	if err := pb.validate(); err != nil {
		return nil, err
	}

	totalSize := 0
	for _, b := range pb.blocks {
		totalSize += b.SerializeSize()
	}
	if totalSize > maxPayloadSize {
		return nil, oops.Errorf("payload size %d exceeds maximum %d", totalSize, maxPayloadSize)
	}

	buf := make([]byte, totalSize)
	offset := 0
	for _, b := range pb.blocks {
		n, err := b.Serialize(buf[offset:])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize block type %d", b.Type)
		}
		offset += n
	}
	return buf, nil
}

// validate checks block ordering rules per the spec.
// It also rejects BlockOptions (type 5), which is unimplemented in the I2P
// ECIES spec (ratchet.md §"Unencrypted data") and would produce
// non-interoperable messages if transmitted.
func (pb *PayloadBuilder) validate() error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "PayloadBuilder.validate", "block_count": len(pb.blocks)}).Debug("Validating payload block ordering")
	if len(pb.blocks) == 0 {
		return nil // empty payload is allowed
	}

	paddingIdx, terminationIdx, err := pb.collectBlockPositions()
	if err != nil {
		return err
	}

	if err := pb.checkPaddingPosition(paddingIdx); err != nil {
		return err
	}
	return pb.checkTerminationPosition(terminationIdx, paddingIdx)
}

// collectBlockPositions scans the payload blocks and collects the indices of
// padding and termination blocks. It also validates that BlockOptions blocks
// (which are unimplemented in the I2P ECIES spec) and multiple padding blocks
// do not appear.
//
// Returns the padding block index, termination block index (or -1 if not present),
// and an error if validation fails. Indices are -1 if the block type was not found.
func (pb *PayloadBuilder) collectBlockPositions() (int, int, error) {
	paddingCount := 0
	paddingIdx := -1
	terminationIdx := -1

	for i, b := range pb.blocks {
		switch b.Type {
		case BlockOptions:
			return -1, -1, oops.Errorf(
				"BlockOptions (type %d) is unimplemented in the I2P ECIES spec "+
					"and must not appear in outgoing messages (ratchet.md §\"Unencrypted data\")",
				BlockOptions,
			)
		case BlockPadding:
			paddingCount++
			if paddingCount > 1 {
				return -1, -1, oops.Errorf("multiple padding blocks not allowed")
			}
			paddingIdx = i
		case BlockTermination:
			terminationIdx = i
		}
	}

	return paddingIdx, terminationIdx, nil
}

// checkPaddingPosition validates that the padding block, if present, is the
// last block in the payload. Per spec the Padding block must trail all others.
func (pb *PayloadBuilder) checkPaddingPosition(paddingIdx int) error {
	if paddingIdx >= 0 && paddingIdx != len(pb.blocks)-1 {
		return oops.Errorf("padding block must be the last block (found at index %d of %d)",
			paddingIdx, len(pb.blocks)-1)
	}
	return nil
}

// checkTerminationPosition validates that the termination block, if present, is
// the last non-padding block. It must appear immediately before any Padding block.
func (pb *PayloadBuilder) checkTerminationPosition(terminationIdx, paddingIdx int) error {
	if terminationIdx < 0 {
		return nil
	}
	expectedLast := len(pb.blocks) - 1
	if paddingIdx >= 0 {
		expectedLast = len(pb.blocks) - 2
	}
	if terminationIdx != expectedLast {
		return oops.Errorf("termination block must be last non-padding block (found at index %d, expected %d)",
			terminationIdx, expectedLast)
	}
	return nil
}

// NewSessionPayloadBuilder creates a PayloadBuilder pre-populated with a DateTime block
// as required by the New Session format. Additional allowed blocks: GarlicClove, Options, Padding.
// Spec ref: ratchet.md §"Block Ordering Rules" — "In the New Session message,
// the DateTime block is required, and must be the first block."
func NewSessionPayloadBuilder() *PayloadBuilder {
	return NewPayloadBuilder().AddBlock(NewDateTimeBlock(nowFunc()))
}

// ExistingSessionPayloadBuilder creates an empty PayloadBuilder for Existing Session
// messages, which have no required blocks and allow all block types.
func ExistingSessionPayloadBuilder() *PayloadBuilder {
	return NewPayloadBuilder()
}

// ValidateNewSessionPayload checks that payload is a valid New Session body:
// it must be non-empty, parse as a sequence of valid blocks, and have a
// DateTime block as the very first block.
//
// Spec ref: ratchet.md §1b — "Payload must contain a DateTime block and will
// usually contain one or more Garlic Clove blocks."
//
// A caller that omits the DateTime block produces a non-compliant NS message
// that will fail interoperability checks with any conformant I2P router.
// Use NewSessionPayloadBuilder to construct a compliant payload automatically.
func ValidateNewSessionPayload(payload []byte) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "ValidateNewSessionPayload", "payload_len": len(payload)}).Debug("Validating New Session payload")
	if len(payload) == 0 {
		return oops.Errorf("new session payload must not be empty: spec requires a DateTime block as the first block (ratchet.md §1b)")
	}
	blocks, err := ParsePayload(payload)
	if err != nil {
		return oops.Wrapf(err, "new session payload is malformed")
	}
	if len(blocks) == 0 {
		return oops.Errorf("new session payload contains no blocks: spec requires a DateTime block as the first block (ratchet.md §1b)")
	}
	if blocks[0].Type != BlockDateTime {
		return oops.Errorf(
			"new session payload first block is type %d, want BlockDateTime (type 0): spec requires DateTime as first block (ratchet.md §1b)",
			blocks[0].Type,
		)
	}
	return nil
}

// BuildNSPayload is a convenience wrapper that constructs a spec-compliant New
// Session payload containing a fresh DateTime block followed by a single
// GarlicClove block that carries the provided garlic data.
//
// Use this when you have a raw garlic byte slice and need to wrap it in the
// structured NS payload format required by EncryptGarlicMessage.
func BuildNSPayload(garlicData []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "BuildNSPayload", "garlic_data_len": len(garlicData)}).Debug("Building New Session payload")
	return NewSessionPayloadBuilder().
		AddBlock(PayloadBlock{Type: BlockGarlicClove, Data: garlicData}).
		Build()
}

// ParsePayload deserializes a byte slice into a sequence of PayloadBlocks.
// Unknown block types are preserved (the spec requires receivers to ignore them).
// Returns an error for malformed data (truncated headers, length overflows).
//
// A BlockOptions (type 5) block is preserved in the output for completeness
// (so the caller can inspect it), but a warning is logged because the block
// type is unimplemented in the I2P ECIES spec and indicates a non-conformant peer.
func ParsePayload(data []byte) ([]PayloadBlock, error) {
	var blocks []PayloadBlock
	offset := 0

	for offset < len(data) {
		remaining := len(data) - offset
		if remaining < blockHeaderSize {
			return nil, oops.Errorf("truncated block header at offset %d: %d bytes remaining, need %d", offset, remaining, blockHeaderSize)
		}

		blockType := BlockType(data[offset])
		blockLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += blockHeaderSize

		if blockLen > len(data)-offset {
			return nil, oops.Errorf("block type %d at offset %d: data length %d exceeds remaining %d bytes", blockType, offset-blockHeaderSize, blockLen, len(data)-offset)
		}

		blockData := make([]byte, blockLen)
		copy(blockData, data[offset:offset+blockLen])

		if blockType == BlockOptions {
			log.WithFields(logger.Fields{"pkg": "ratchet", "func": "ParsePayload"}).Warn("received BlockOptions (type 5) in payload: " +
				"this block type is unimplemented in the I2P ECIES spec " +
				"and indicates a non-conformant peer (ratchet.md §\"Unencrypted data\")")
		}

		blocks = append(blocks, PayloadBlock{
			Type: blockType,
			Data: blockData,
		})
		offset += blockLen
	}

	return blocks, nil
}

// FindBlock returns the first block of the given type, or nil if not found.
func FindBlock(blocks []PayloadBlock, blockType BlockType) *PayloadBlock {
	for i := range blocks {
		if blocks[i].Type == blockType {
			return &blocks[i]
		}
	}
	return nil
}

// FindBlocks returns all blocks of the given type.
func FindBlocks(blocks []PayloadBlock, blockType BlockType) []PayloadBlock {
	var result []PayloadBlock
	for _, b := range blocks {
		if b.Type == blockType {
			result = append(result, b)
		}
	}
	return result
}
