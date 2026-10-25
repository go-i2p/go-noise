package ratchet

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// nowFunc returns the current time. It is a variable so tests can override it.
var nowFunc = time.Now

// payloadMessageType identifies which ECIES message a payload is being built
// for, so the builder can enforce the spec's per-message-type block allowlist
// (ecies.rst §"Block Ordering Rules").
type payloadMessageType int

const (
	// messageTypeUnspecified is used by the generic [NewPayloadBuilder], which
	// does not enforce a per-message-type allowlist.
	messageTypeUnspecified payloadMessageType = iota
	messageTypeNewSession
	messageTypeNewSessionReply
	messageTypeExistingSession
)

// String returns a human-readable name for the message type, used in error
// messages.
func (mt payloadMessageType) String() string {
	switch mt {
	case messageTypeNewSession:
		return "New Session"
	case messageTypeNewSessionReply:
		return "New Session Reply"
	case messageTypeExistingSession:
		return "Existing Session"
	default:
		return "unspecified"
	}
}

// allowedBlocksForMessageType returns the set of block types the spec permits
// in a payload of the given message type (ecies.rst §"Block Ordering Rules").
//
//   - New Session: DateTime (required, first), GarlicClove, Options, Padding.
//   - New Session Reply: GarlicClove, Options, Padding.
//   - Existing Session: DateTime, Termination, Options, MessageNumber, NextKey,
//     Ack, AckRequest, GarlicClove, Padding.
//
// BlockOptions is listed because the spec allows it, but it is additionally
// rejected on send by [PayloadBuilder.validate] (see R-004: the block is
// unimplemented in the I2P ECIES spec).
func allowedBlocksForMessageType(mt payloadMessageType) map[BlockType]bool {
	switch mt {
	case messageTypeNewSession:
		return map[BlockType]bool{
			BlockDateTime: true, BlockGarlicClove: true,
			BlockOptions: true, BlockPadding: true,
		}
	case messageTypeNewSessionReply:
		return map[BlockType]bool{
			BlockGarlicClove: true, BlockOptions: true, BlockPadding: true,
		}
	case messageTypeExistingSession:
		return map[BlockType]bool{
			BlockDateTime: true, BlockTermination: true, BlockOptions: true,
			BlockMessageNumber: true, BlockNextKey: true, BlockAck: true,
			BlockAckRequest: true, BlockGarlicClove: true, BlockPadding: true,
		}
	default:
		return nil
	}
}

// PayloadBuilder constructs a spec-compliant payload from a sequence of
// [PayloadBlock]s.
//
// A payload is the data that gets encrypted inside a garlic message. It is
// made up of small typed pieces called blocks (a timestamp, a message
// counter, a garlic clove, and so on).
//
// The builder enforces the spec's block ordering rules:
//
//   - Padding, if present, must be the last block.
//   - Termination, if present, must be last except for padding.
//   - Multiple padding blocks are not allowed.
//
// Use the message-type-specific constructors ([NewSessionPayloadBuilder],
// [ExistingSessionPayloadBuilder]) for full validation.
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
type PayloadBuilder struct {
	blocks      []PayloadBlock
	messageType payloadMessageType
	allowlist   map[BlockType]bool
}

// newSessionPayloadBuilder creates a builder for a New Session or Existing
// Session payload. When includeDateTime is true a DateTime block is added
// first (required for New Session).
func newSessionPayloadBuilder(includeDateTime bool, mt payloadMessageType) *PayloadBuilder {
	pb := NewPayloadBuilder()
	pb.messageType = mt
	pb.allowlist = allowedBlocksForMessageType(mt)
	if includeDateTime {
		pb.AddBlock(NewDateTimeBlock(nowFunc()))
	}
	return pb
}

// NewPayloadBuilder creates an empty [PayloadBuilder] that does not enforce a
// per-message-type block allowlist. Use the message-type-specific
// constructors for full validation.
func NewPayloadBuilder() *PayloadBuilder {
	return &PayloadBuilder{}
}

// AddBlock appends a block to the payload. It returns the builder so
// calls can be chained.
func (pb *PayloadBuilder) AddBlock(block PayloadBlock) *PayloadBuilder {
	pb.blocks = append(pb.blocks, block)
	return pb
}

// Build serializes all blocks into a single byte slice.
// Returns an error if the payload exceeds the maximum size or block
// ordering rules are violated.
func (pb *PayloadBuilder) Build() ([]byte, error) {
	flog("PayloadBuilder.Build", logger.Fields{"block_count": len(pb.blocks)}).Debug("Building payload from blocks")
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
// ECIES spec (ecies.rst §"Unencrypted data") and would produce
// non-interoperable messages if transmitted, and enforces the per-message-type
// block allowlist (ecies.rst §"Block Ordering Rules").
func (pb *PayloadBuilder) validate() error {
	flog("PayloadBuilder.validate", logger.Fields{"block_count": len(pb.blocks)}).Debug("Validating payload block ordering")
	if len(pb.blocks) == 0 {
		return nil // empty payload is allowed
	}

	if err := pb.checkBlockAllowlist(); err != nil {
		return err
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

// checkBlockAllowlist enforces the spec's per-message-type block allowlist
// (ecies.rst §"Block Ordering Rules"). It is a no-op for the generic builder
// ([NewPayloadBuilder]), which has no message type.
func (pb *PayloadBuilder) checkBlockAllowlist() error {
	if pb.allowlist == nil {
		return nil
	}
	for _, b := range pb.blocks {
		if !pb.allowlist[b.Type] {
			return oops.Errorf(
				"block type %d is not allowed in a %s payload (ecies.rst §\"Block Ordering Rules\")",
				b.Type, pb.messageType,
			)
		}
	}
	return nil
}

// maxNextKeyBlocks is the maximum number of NextKey blocks allowed in a single
// frame, per the spec's Block Ordering Rules (ecies.rst §"Block Ordering
// Rules": "Up to two Next Key blocks in a single frame").
const maxNextKeyBlocks = 2

// collectBlockPositions scans the payload blocks and collects the indices of
// padding and termination blocks. It also validates that BlockOptions blocks
// (which are unimplemented in the I2P ECIES spec), multiple padding blocks,
// and more than two NextKey blocks do not appear.
//
// Returns the padding block index, termination block index (or -1 if not present),
// and an error if validation fails. Indices are -1 if the block type was not found.
func (pb *PayloadBuilder) collectBlockPositions() (int, int, error) {
	paddingCount := 0
	paddingIdx := -1
	terminationIdx := -1
	nextKeyCount := 0

	for i, b := range pb.blocks {
		switch b.Type {
		case BlockOptions:
			return -1, -1, oops.Errorf(
				"BlockOptions (type %d) is unimplemented in the I2P ECIES spec "+
					"and must not appear in outgoing messages (ecies.rst §\"Unencrypted data\")",
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
		case BlockNextKey:
			nextKeyCount++
			if nextKeyCount > maxNextKeyBlocks {
				return -1, -1, oops.Errorf(
					"more than %d NextKey blocks in a single frame (found %d): spec allows up to two (ecies.rst §\"Block Ordering Rules\")",
					maxNextKeyBlocks, nextKeyCount,
				)
			}
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

// NewSessionPayloadBuilder creates a [PayloadBuilder] pre-populated with a
// DateTime block, as required by the New Session format. The DateTime block
// must be the first block in a New Session payload. Additional allowed
// blocks: GarlicClove and Padding.
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
func NewSessionPayloadBuilder() *PayloadBuilder {
	return newSessionPayloadBuilder(true, messageTypeNewSession)
}

// ExistingSessionPayloadBuilder creates an empty [PayloadBuilder] for
// Existing Session messages, which have no required blocks and allow the
// Existing Session block types (DateTime, Termination, Options,
// MessageNumber, NextKey, Ack, AckRequest, GarlicClove, Padding).
func ExistingSessionPayloadBuilder() *PayloadBuilder {
	return newSessionPayloadBuilder(false, messageTypeExistingSession)
}

// ValidateNewSessionPayload checks that payload is a valid New Session body:
// it must be non-empty, parse as a sequence of valid blocks, and have a
// DateTime block as the very first block.
//
// A New Session payload must contain a DateTime block and will usually
// contain one or more Garlic Clove blocks. A caller that omits the DateTime
// block produces a non-compliant message that will fail interoperability
// checks with any conformant I2P router. Use [NewSessionPayloadBuilder] to
// construct a compliant payload automatically.
//
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for details.
func ValidateNewSessionPayload(payload []byte) error {
	flog("ValidateNewSessionPayload", logger.Fields{"payload_len": len(payload)}).Debug("Validating New Session payload")
	if len(payload) == 0 {
		return oops.Errorf("new session payload must not be empty: spec requires a DateTime block as the first block (ecies.rst §1b)")
	}
	blocks, err := ParsePayload(payload)
	if err != nil {
		return oops.Wrapf(err, "new session payload is malformed")
	}
	if len(blocks) == 0 {
		return oops.Errorf("new session payload contains no blocks: spec requires a DateTime block as the first block (ecies.rst §1b)")
	}
	if blocks[0].Type != BlockDateTime {
		return oops.Errorf(
			"new session payload first block is type %d, want BlockDateTime (type 0): spec requires DateTime as first block (ecies.rst §1b)",
			blocks[0].Type,
		)
	}
	return nil
}

// BuildNSPayload is a convenience wrapper that constructs a spec-compliant
// New Session payload containing a fresh DateTime block followed by a single
// GarlicClove block that carries the provided garlic data.
//
// Use this when you have a raw garlic byte slice and need to wrap it in the
// structured New Session payload format required by
// [Session.EncryptGarlicMessage].
func BuildNSPayload(garlicData []byte) ([]byte, error) {
	flog("BuildNSPayload", logger.Fields{"garlic_data_len": len(garlicData)}).Debug("Building New Session payload")
	return NewSessionPayloadBuilder().
		AddBlock(PayloadBlock{Type: BlockGarlicClove, Data: garlicData}).
		Build()
}

// ParsePayload deserializes a byte slice into a sequence of
// [PayloadBlock]s.
//
// Unknown block types are preserved (the spec requires receivers to ignore
// them). Returns an error for malformed data (truncated headers, length
// overflows, or too many blocks).
//
// A BlockOptions (type 5) block is preserved in the output for completeness
// (so the caller can inspect it), but a warning is logged because the block
// type is unimplemented in the I2P ECIES spec and indicates a non-conformant
// peer.
func ParsePayload(data []byte) ([]PayloadBlock, error) {
	var blocks []PayloadBlock
	offset := 0

	for offset < len(data) {
		if len(blocks) >= maxPayloadBlocks {
			// Defense-in-depth: bounded independent of any upstream
			// AEAD frame-size/maxPayloadSize limit, guarding against a
			// crafted payload packing many zero-length blocks to grow
			// the blocks slice unboundedly.
			return nil, oops.Errorf("payload exceeds maximum block count %d", maxPayloadBlocks)
		}

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
			flog("ParsePayload").Warn("received BlockOptions (type 5) in payload: " +
				"this block type is unimplemented in the I2P ECIES spec " +
				"and indicates a non-conformant peer (ecies.rst §\"Unencrypted data\")")
		}

		blocks = append(blocks, PayloadBlock{
			Type: blockType,
			Data: blockData,
		})
		offset += blockLen
	}

	return blocks, nil
}

// ParsePayloadLenient parses as many leading blocks as it can and stops at the
// first malformed one, returning what was parsed so far.
//
// Used only for control-block extraction from a decrypted ES payload: the
// payload is already AEAD-authenticated, so a framing failure cannot come from
// an unauthenticated attacker — it means the local caller supplied a payload
// that is not itself a block sequence (prependPendingNextKeys puts our control
// blocks in front of whatever the caller handed us). Dropping the whole parse
// would silently discard a peer's NextKey or Ack blocks, which ecies.md
// §"4a) DH Ratchet" requires us to act on ("each do a DH ratchet for every
// NextKey block received").
func ParsePayloadLenient(data []byte) []PayloadBlock {
	blocks, err := ParsePayload(data)
	if err == nil {
		return blocks
	}
	// Re-parse, stopping where the error occurred.
	var out []PayloadBlock
	offset := 0
	for offset < len(data) {
		if len(out) >= maxPayloadBlocks {
			break
		}
		if len(data)-offset < blockHeaderSize {
			break
		}
		blockType := BlockType(data[offset])
		blockLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		if blockLen > len(data)-offset-blockHeaderSize {
			break
		}
		blockData := make([]byte, blockLen)
		copy(blockData, data[offset+blockHeaderSize:offset+blockHeaderSize+blockLen])
		out = append(out, PayloadBlock{Type: blockType, Data: blockData})
		offset += blockHeaderSize + blockLen
	}
	return out
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
