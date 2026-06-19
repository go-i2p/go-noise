package ratchet

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Helpers
// ============================================================================

// mustBuildAndParse builds a payload using the provided build function, parses
// the result, asserts the expected block count, and returns the parsed blocks.
func mustBuildAndParse(t testing.TB, build func() ([]byte, error), expectedBlocks int) []PayloadBlock {
	t.Helper()
	data, err := build()
	require.NoError(t, err, "payload build failed")
	blocks, err := ParsePayload(data)
	require.NoError(t, err, "payload parse failed")
	require.Len(t, blocks, expectedBlocks)
	return blocks
}

// mustSerializeAndParseSingle serializes a PayloadBlock, parses it back, and
// asserts exactly one block was recovered. Returns the parsed block.
func mustSerializeAndParseSingle(t *testing.T, b PayloadBlock) PayloadBlock {
	t.Helper()
	buf := make([]byte, b.SerializeSize())
	_, err := b.Serialize(buf)
	require.NoError(t, err)
	blocks, err := ParsePayload(buf)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	return blocks[0]
}

// ============================================================================
// Block Construction
// ============================================================================

func TestNewDateTimeBlock(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	b := NewDateTimeBlock(ts)

	assert.Equal(t, BlockDateTime, b.Type)
	assert.Len(t, b.Data, 4)

	parsed, err := b.DateTime()
	require.NoError(t, err)
	assert.Equal(t, ts.Unix(), parsed.Unix())
}

func TestNewDateTimeBlock_ZeroTime(t *testing.T) {
	ts := time.Unix(0, 0)
	b := NewDateTimeBlock(ts)
	parsed, err := b.DateTime()
	require.NoError(t, err)
	assert.Equal(t, int64(0), parsed.Unix())
}

func TestNewTerminationBlock(t *testing.T) {
	b := NewTerminationBlock(TerminationNormal, nil)
	assert.Equal(t, BlockTermination, b.Type)
	assert.Len(t, b.Data, 1)

	reason, addl, err := b.TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationNormal, reason)
	assert.Empty(t, addl)
}

func TestNewTerminationBlock_WithData(t *testing.T) {
	extra := []byte("session expired")
	b := NewTerminationBlock(TerminationReceived, extra)

	reason, addl, err := b.TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationReceived, reason)
	assert.Equal(t, extra, addl)
}

func TestNewMessageNumberBlock(t *testing.T) {
	b := NewMessageNumberBlock(12345)
	assert.Equal(t, BlockMessageNumber, b.Type)
	assert.Len(t, b.Data, 2)

	pn, err := b.MessageNumber()
	require.NoError(t, err)
	assert.Equal(t, uint16(12345), pn)
}

func TestNewMessageNumberBlock_MaxValue(t *testing.T) {
	b := NewMessageNumberBlock(65535)
	pn, err := b.MessageNumber()
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), pn)
}

func TestNewNextKeyBlock(t *testing.T) {
	var testKey [32]byte
	for i := range testKey {
		testKey[i] = byte(i)
	}
	tests := []struct {
		name           string
		keyID          uint16
		key            *[32]byte
		reverse        bool
		requestReverse bool
		expectedLen    int
		expectPresent  bool
		expectReverse  bool
		expectReqRev   bool
	}{
		{
			name:           "WithKey",
			keyID:          42,
			key:            &testKey,
			reverse:        false,
			requestReverse: true,
			expectedLen:    35,
			expectPresent:  true,
			expectReverse:  false,
			expectReqRev:   true,
		},
		{
			name:           "WithoutKey",
			keyID:          7,
			key:            nil,
			reverse:        true,
			requestReverse: false,
			expectedLen:    3,
			expectPresent:  false,
			expectReverse:  true,
			expectReqRev:   false,
		},
		{
			name:           "ReverseOverridesRequestReverse",
			keyID:          0,
			key:            nil,
			reverse:        true,
			requestReverse: true,
			expectedLen:    3,
			expectPresent:  false,
			expectReverse:  true,
			expectReqRev:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewNextKeyBlock(tt.keyID, tt.key, tt.reverse, tt.requestReverse)
			assert.Equal(t, BlockNextKey, b.Type)
			assert.Len(t, b.Data, tt.expectedLen)

			info, err := b.NextKey()
			require.NoError(t, err)
			assert.Equal(t, tt.expectPresent, info.KeyPresent)
			assert.Equal(t, tt.expectReverse, info.Reverse)
			assert.Equal(t, tt.expectReqRev, info.RequestReverse)
			assert.Equal(t, tt.keyID, info.KeyID)
			if tt.key != nil {
				assert.Equal(t, *tt.key, info.PublicKey)
			}
		})
	}
}

func TestNewAckBlock(t *testing.T) {
	acks := []AckEntry{
		{TagSetID: 1, N: 100},
		{TagSetID: 2, N: 200},
	}
	b := NewAckBlock(acks)
	assert.Equal(t, BlockAck, b.Type)
	assert.Len(t, b.Data, 8)

	parsed, err := b.Acks()
	require.NoError(t, err)
	assert.Equal(t, acks, parsed)
}

func TestNewAckRequestBlock(t *testing.T) {
	b := NewAckRequestBlock(0)
	assert.Equal(t, BlockAckRequest, b.Type)
	assert.Equal(t, []byte{0}, b.Data)
}

func TestNewGarlicCloveBlock(t *testing.T) {
	cloveData := []byte{0x01, 0x02, 0x03, 0x04}
	b := NewGarlicCloveBlock(cloveData)
	assert.Equal(t, BlockGarlicClove, b.Type)
	assert.Equal(t, cloveData, b.Data)
}

func TestNewPaddingBlock(t *testing.T) {
	b := NewPaddingBlock(16)
	assert.Equal(t, BlockPadding, b.Type)
	assert.Len(t, b.Data, 16)
	// Padding is all zeros
	for _, v := range b.Data {
		assert.Equal(t, byte(0), v)
	}
}

func TestNewPaddingBlock_NegativeSize(t *testing.T) {
	b := NewPaddingBlock(-5)
	assert.Empty(t, b.Data)
}

func TestNewPaddingBlock_Zero(t *testing.T) {
	b := NewPaddingBlock(0)
	assert.Empty(t, b.Data)
}

// ============================================================================
// Block Parsing Errors
// ============================================================================

func TestDateTime_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0, 0}}
	_, err := b.DateTime()
	assert.Error(t, err)
}

func TestDateTime_WrongSize(t *testing.T) {
	b := PayloadBlock{Type: BlockDateTime, Data: []byte{0, 0}}
	_, err := b.DateTime()
	assert.Error(t, err)
}

func TestTerminationInfo_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockDateTime, Data: []byte{0}}
	_, _, err := b.TerminationInfo()
	assert.Error(t, err)
}

func TestTerminationInfo_EmptyData(t *testing.T) {
	b := PayloadBlock{Type: BlockTermination, Data: []byte{}}
	_, _, err := b.TerminationInfo()
	assert.Error(t, err)
}

func TestMessageNumber_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0}}
	_, err := b.MessageNumber()
	assert.Error(t, err)
}

func TestMessageNumber_WrongSize(t *testing.T) {
	b := PayloadBlock{Type: BlockMessageNumber, Data: []byte{0}}
	_, err := b.MessageNumber()
	assert.Error(t, err)
}

func TestNextKey_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0}}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestNextKey_InvalidSize(t *testing.T) {
	// Neither 3 nor 35 bytes
	b := PayloadBlock{Type: BlockNextKey, Data: []byte{0, 0, 0, 0, 0}}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestNextKey_KeyPresentButTooShort(t *testing.T) {
	// Flag says key present but only 3 bytes
	data := []byte{NextKeyFlagKeyPresent, 0, 0}
	b := PayloadBlock{Type: BlockNextKey, Data: data}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestAcks_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0, 0}}
	_, err := b.Acks()
	assert.Error(t, err)
}

func TestAcks_InvalidSize(t *testing.T) {
	b := PayloadBlock{Type: BlockAck, Data: []byte{0, 0, 0}} // not a multiple of 4
	_, err := b.Acks()
	assert.Error(t, err)
}

func TestAcks_EmptyData(t *testing.T) {
	b := PayloadBlock{Type: BlockAck, Data: []byte{}}
	_, err := b.Acks()
	assert.Error(t, err)
}

// ============================================================================
// Serialization
// ============================================================================

func TestSerialize_DateTime(t *testing.T) {
	b := NewDateTimeBlock(time.Unix(1700000000, 0))
	buf := make([]byte, b.SerializeSize())
	n, err := b.Serialize(buf)
	require.NoError(t, err)
	assert.Equal(t, 7, n) // 3 header + 4 data

	// Verify wire format: [type=0] [size=0,4] [timestamp]
	assert.Equal(t, byte(0), buf[0])
	assert.Equal(t, uint16(4), binary.BigEndian.Uint16(buf[1:3]))
}

func TestSerialize_BufferTooSmall(t *testing.T) {
	b := NewDateTimeBlock(time.Unix(0, 0))
	buf := make([]byte, 2) // too small
	_, err := b.Serialize(buf)
	assert.Error(t, err)
}

func TestSerializeSize(t *testing.T) {
	tests := []struct {
		name     string
		block    PayloadBlock
		expected int
	}{
		{"DateTime", NewDateTimeBlock(time.Now()), 7},
		{"Termination_no_data", NewTerminationBlock(TerminationNormal, nil), 4},
		{"MessageNumber", NewMessageNumberBlock(0), 5},
		{"NextKey_no_key", NewNextKeyBlock(0, nil, false, false), 6},
		{"NextKey_with_key", NewNextKeyBlock(0, &[32]byte{}, false, false), 38},
		{"AckRequest", NewAckRequestBlock(0), 4},
		{"Padding_10", NewPaddingBlock(10), 13},
		{"Padding_0", NewPaddingBlock(0), 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.block.SerializeSize())
		})
	}
}

// ============================================================================
// PayloadBuilder
// ============================================================================

func TestPayloadBuilder_Empty(t *testing.T) {
	pb := NewPayloadBuilder()
	data, err := pb.Build()
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestPayloadBuilder_SingleBlock(t *testing.T) {
	pb := NewPayloadBuilder().AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0)))
	data, err := pb.Build()
	require.NoError(t, err)
	assert.Len(t, data, 7)
}

func TestPayloadBuilder_MultipleBlocks(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0))).
		AddBlock(NewGarlicCloveBlock([]byte{1, 2, 3})).
		AddBlock(NewPaddingBlock(5))

	data, err := pb.Build()
	require.NoError(t, err)
	// 7 (datetime) + 6 (garlic: 3 header + 3 data) + 8 (padding: 3 header + 5 data) = 21
	assert.Len(t, data, 21)
}

func TestPayloadBuilder_PaddingMustBeLast(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewPaddingBlock(5)).
		AddBlock(NewDateTimeBlock(time.Now()))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "padding block must be the last block")
}

func TestPayloadBuilder_MultiplePaddingBlocks(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewPaddingBlock(5)).
		AddBlock(NewPaddingBlock(5))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple padding blocks")
}

func TestPayloadBuilder_TerminationBeforePadding(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewTerminationBlock(TerminationNormal, nil)).
		AddBlock(NewPaddingBlock(5))

	data, err := pb.Build()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestPayloadBuilder_TerminationNotLast(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Now())).
		AddBlock(NewTerminationBlock(TerminationNormal, nil)).
		AddBlock(NewGarlicCloveBlock([]byte{1}))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "termination block must be last non-padding block")
}

func TestNewSessionPayloadBuilder(t *testing.T) {
	// Override time for deterministic test
	origNow := nowFunc
	nowFunc = func() time.Time { return time.Unix(1700000000, 0) }
	defer func() { nowFunc = origNow }()

	pb := NewSessionPayloadBuilder().
		AddBlock(NewGarlicCloveBlock([]byte("test clove")))

	// Parse and verify DateTime is first
	blocks := mustBuildAndParse(t, pb.Build, 2)
	assert.Equal(t, BlockDateTime, blocks[0].Type)
	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
}

func TestExistingSessionPayloadBuilder(t *testing.T) {
	pb := ExistingSessionPayloadBuilder().
		AddBlock(NewGarlicCloveBlock([]byte("clove data"))).
		AddBlock(NewNextKeyBlock(1, &[32]byte{1}, false, false)).
		AddBlock(NewPaddingBlock(8))

	data, err := pb.Build()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// ============================================================================
// ParsePayload
// ============================================================================

func TestParsePayload_Empty(t *testing.T) {
	blocks, err := ParsePayload(nil)
	require.NoError(t, err)
	assert.Empty(t, blocks)
}

func TestParsePayload_SingleBlock(t *testing.T) {
	pb := NewPayloadBuilder().AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0)))
	blocks := mustBuildAndParse(t, pb.Build, 1)
	assert.Equal(t, BlockDateTime, blocks[0].Type)

	parsed, err := blocks[0].DateTime()
	require.NoError(t, err)
	assert.Equal(t, int64(1700000000), parsed.Unix())
}

func TestParsePayload_MultipleBlocks(t *testing.T) {
	clove := []byte{0xAA, 0xBB, 0xCC}
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Unix(100, 0))).
		AddBlock(NewGarlicCloveBlock(clove)).
		AddBlock(NewAckRequestBlock(0)).
		AddBlock(NewPaddingBlock(4))
	blocks := mustBuildAndParse(t, pb.Build, 4)
	assert.Equal(t, BlockDateTime, blocks[0].Type)
	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
	assert.Equal(t, clove, blocks[1].Data)
	assert.Equal(t, BlockAckRequest, blocks[2].Type)
	assert.Equal(t, BlockPadding, blocks[3].Type)
}

func TestParsePayload_TruncatedHeader(t *testing.T) {
	// Only 2 bytes, need at least 3 for a header
	_, err := ParsePayload([]byte{0, 0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated block header")
}

func TestParsePayload_DataOverrun(t *testing.T) {
	// Header says 10 bytes of data, but only 2 available
	data := []byte{0, 0, 10, 0xFF, 0xFF}
	_, err := ParsePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds remaining")
}

func TestParsePayload_UnknownBlockType(t *testing.T) {
	// Unknown type 200 with 2 bytes of data
	data := []byte{200, 0, 2, 0xAA, 0xBB}
	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockType(200), blocks[0].Type)
	assert.Equal(t, []byte{0xAA, 0xBB}, blocks[0].Data)
}

func TestParsePayload_ZeroLengthBlock(t *testing.T) {
	// Padding with zero data
	data := []byte{254, 0, 0}
	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockPadding, blocks[0].Type)
	assert.Empty(t, blocks[0].Data)
}

// ============================================================================
// Round-trip: Build → Parse → Verify
// ============================================================================

func TestRoundTrip_ComplexPayload(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 10)
	}

	origBlocks := []PayloadBlock{
		NewDateTimeBlock(time.Unix(1700000000, 0)),
		NewGarlicCloveBlock([]byte("test clove data")),
		NewGarlicCloveBlock([]byte("second clove")),
		NewNextKeyBlock(5, &key, false, true),
		NewAckBlock([]AckEntry{{TagSetID: 1, N: 42}, {TagSetID: 3, N: 99}}),
		NewMessageNumberBlock(500),
		NewPaddingBlock(12),
	}

	pb := NewPayloadBuilder()
	for _, b := range origBlocks {
		pb.AddBlock(b)
	}
	data, err := pb.Build()
	require.NoError(t, err)

	parsed, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, parsed, len(origBlocks))

	for i, b := range parsed {
		assert.Equal(t, origBlocks[i].Type, b.Type, "block %d type mismatch", i)
		assert.Equal(t, origBlocks[i].Data, b.Data, "block %d data mismatch", i)
	}
}

func TestRoundTrip_NextKeyReverseKey(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0xFF - byte(i)
	}
	b := NewNextKeyBlock(100, &key, true, false)

	parsed := mustSerializeAndParseSingle(t, b)

	info, err := parsed.NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.True(t, info.Reverse)
	assert.Equal(t, uint16(100), info.KeyID)
	assert.Equal(t, key, info.PublicKey)
}

func TestRoundTrip_TerminationWithData(t *testing.T) {
	extra := []byte("debug: timeout after 30s")
	b := NewTerminationBlock(TerminationReason(42), extra)

	parsed := mustSerializeAndParseSingle(t, b)

	reason, addl, err := parsed.TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationReason(42), reason)
	assert.Equal(t, extra, addl)
}

// ============================================================================
// FindBlock / FindBlocks
// ============================================================================

func TestFindBlock_Found(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
		NewGarlicCloveBlock([]byte("data")),
		NewPaddingBlock(0),
	}
	b := FindBlock(blocks, BlockGarlicClove)
	require.NotNil(t, b)
	assert.Equal(t, BlockGarlicClove, b.Type)
}

func TestFindBlock_NotFound(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
	}
	b := FindBlock(blocks, BlockTermination)
	assert.Nil(t, b)
}

func TestFindBlocks_Multiple(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
		NewGarlicCloveBlock([]byte("clove1")),
		NewGarlicCloveBlock([]byte("clove2")),
		NewGarlicCloveBlock([]byte("clove3")),
		NewPaddingBlock(0),
	}
	cloves := FindBlocks(blocks, BlockGarlicClove)
	assert.Len(t, cloves, 3)
}

func TestFindBlocks_None(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
	}
	result := FindBlocks(blocks, BlockTermination)
	assert.Empty(t, result)
}

// ============================================================================
// Wire format correctness
// ============================================================================

func TestWireFormat_ManualParse(t *testing.T) {
	// Construct a payload manually and verify parsing matches
	// DateTime(0, size=4, timestamp=0x65B8D800) + Padding(254, size=2, data=0x00,0x00)
	raw := []byte{
		0x00, 0x00, 0x04, 0x65, 0xB8, 0xD8, 0x00, // DateTime
		0xFE, 0x00, 0x02, 0x00, 0x00, // Padding
	}
	blocks, err := ParsePayload(raw)
	require.NoError(t, err)
	require.Len(t, blocks, 2)

	assert.Equal(t, BlockDateTime, blocks[0].Type)
	ts := binary.BigEndian.Uint32(blocks[0].Data)
	assert.Equal(t, uint32(0x65B8D800), ts)

	assert.Equal(t, BlockPadding, blocks[1].Type)
	assert.Len(t, blocks[1].Data, 2)
}

func TestWireFormat_NextKey_FlagEncoding(t *testing.T) {
	// Verify bit-level flag encoding
	b := NewNextKeyBlock(256, nil, false, true)
	assert.Equal(t, byte(NextKeyFlagKeyPresent|NextKeyFlagRequestReverse)&^NextKeyFlagKeyPresent, b.Data[0]&(NextKeyFlagKeyPresent|NextKeyFlagReverse|NextKeyFlagRequestReverse))
	// flags = 0x04 (request reverse, no key present, not reverse)
	assert.Equal(t, byte(0x04), b.Data[0])
	// key ID = 256 big endian
	assert.Equal(t, uint16(256), binary.BigEndian.Uint16(b.Data[1:3]))
}

// ============================================================================
// ValidateNewSessionPayload — spec compliance (ratchet.md §1b)
// ============================================================================

// TestValidateNewSessionPayload_AcceptsValidPayload verifies that a payload
// built with BuildNSPayload passes validation without error.
func TestValidateNewSessionPayload_AcceptsValidPayload(t *testing.T) {
	payload, err := BuildNSPayload([]byte("garlic data"))
	require.NoError(t, err, "BuildNSPayload must succeed")
	assert.NoError(t, ValidateNewSessionPayload(payload),
		"a properly built NS payload must pass ValidateNewSessionPayload")
}

// TestValidateNewSessionPayload_RejectsEmpty verifies that an empty payload
// is rejected with a descriptive error.
func TestValidateNewSessionPayload_RejectsEmpty(t *testing.T) {
	err := ValidateNewSessionPayload([]byte{})
	require.Error(t, err, "empty payload must be rejected")
	assert.Contains(t, err.Error(), "empty")
}

// TestValidateNewSessionPayload_RejectsRawBytes verifies that arbitrary raw
// bytes that do not conform to the block wire format are rejected.
func TestValidateNewSessionPayload_RejectsRawBytes(t *testing.T) {
	err := ValidateNewSessionPayload([]byte("raw garlic data without blocks"))
	require.Error(t, err, "raw bytes must be rejected")
}

// TestValidateNewSessionPayload_RejectsNilPayload verifies that a nil payload
// is treated as empty and rejected.
func TestValidateNewSessionPayload_RejectsNilPayload(t *testing.T) {
	err := ValidateNewSessionPayload(nil)
	require.Error(t, err, "nil payload must be rejected")
}

// TestValidateNewSessionPayload_RejectsNonDateTimeFirstBlock verifies that a
// payload whose first block is not BlockDateTime is rejected.  Per ratchet.md §1b
// the DateTime block MUST be the first block in a New Session payload.
func TestValidateNewSessionPayload_RejectsNonDateTimeFirstBlock(t *testing.T) {
	// Build raw bytes: Padding block (type=0xFE, size=2) then DateTime block.
	// Wire format: [type(1)][len_hi(1)][len_lo(1)][data(N)]
	buf := []byte{
		byte(BlockPadding), 0x00, 0x02, 0x00, 0x00, // Padding block, 2 zero bytes
		byte(BlockDateTime), 0x00, 0x04, 0x65, 0xB8, 0xD8, 0x00, // DateTime second
	}
	err := ValidateNewSessionPayload(buf)
	require.Error(t, err, "payload with non-DateTime first block must be rejected")
	assert.Contains(t, err.Error(), "DateTime")
}

// TestBuildNSPayload_ContainsDateTimeFirstBlock verifies that BuildNSPayload
// always places a BlockDateTime block as the first block in the output.
func TestBuildNSPayload_ContainsDateTimeFirstBlock(t *testing.T) {
	payload, err := BuildNSPayload([]byte("test garlic"))
	require.NoError(t, err)

	blocks, parseErr := ParsePayload(payload)
	require.NoError(t, parseErr, "BuildNSPayload output must be parseable")
	require.NotEmpty(t, blocks, "BuildNSPayload must produce at least one block")
	assert.Equal(t, BlockDateTime, blocks[0].Type,
		"first block must be BlockDateTime per ratchet.md §1b")
}

// TestBuildNSPayload_RoundTrip verifies that a payload created with BuildNSPayload
// can be parsed back and yields the original garlic data in the second block.
func TestBuildNSPayload_RoundTrip(t *testing.T) {
	garlicData := []byte("round-trip garlic payload")
	payload, err := BuildNSPayload(garlicData)
	require.NoError(t, err)

	blocks, parseErr := ParsePayload(payload)
	require.NoError(t, parseErr)
	require.GreaterOrEqual(t, len(blocks), 2, "must have at least DateTime + GarlicClove blocks")

	assert.Equal(t, BlockDateTime, blocks[0].Type)

	// Find a GarlicClove block and verify its data matches.
	found := false
	for _, bl := range blocks[1:] {
		if bl.Type == BlockGarlicClove {
			assert.Equal(t, garlicData, bl.Data,
				"GarlicClove block data must match the original garlic data")
			found = true
			break
		}
	}
	assert.True(t, found, "at least one BlockGarlicClove block must be present")
}

// TestBuildNSPayload_EmptyData verifies that BuildNSPayload accepts empty
// garlic data and produces a valid, parseable payload.
func TestBuildNSPayload_EmptyData(t *testing.T) {
	payload, err := BuildNSPayload([]byte{})
	require.NoError(t, err, "BuildNSPayload must accept empty garlic data")
	assert.NoError(t, ValidateNewSessionPayload(payload),
		"payload built from empty garlic data must still pass validation")
}

// ============================================================================
// BlockOptions Guard
// ============================================================================

// TestPayloadBuilder_BlockOptions_Rejected verifies that PayloadBuilder.Build()
// returns an error when a BlockOptions (type 5) block is included, since the
// spec marks it unimplemented and interoperability-breaking.
func TestPayloadBuilder_BlockOptions_Rejected(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Now())).
		AddBlock(PayloadBlock{Type: BlockOptions, Data: []byte{0x01, 0x02}})

	_, err := pb.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BlockOptions")
	assert.Contains(t, err.Error(), "unimplemented")
}

// TestPayloadBuilder_BlockOptions_RejectedAlone verifies that even a single
// BlockOptions block without any other blocks is rejected.
func TestPayloadBuilder_BlockOptions_RejectedAlone(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(PayloadBlock{Type: BlockOptions, Data: nil})

	_, err := pb.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BlockOptions")
}

// TestPayloadBuilder_BlockOptions_RejectedInNewSession verifies that
// NewSessionPayloadBuilder also rejects BlockOptions.
func TestPayloadBuilder_BlockOptions_RejectedInNewSession(t *testing.T) {
	origNow := nowFunc
	nowFunc = func() time.Time { return time.Unix(1700000000, 0) }
	defer func() { nowFunc = origNow }()

	pb := NewSessionPayloadBuilder().
		AddBlock(PayloadBlock{Type: BlockOptions, Data: []byte{0xFF}}).
		AddBlock(NewGarlicCloveBlock([]byte("clove")))

	_, err := pb.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BlockOptions")
}

// TestPayloadBuilder_BlockOptions_RejectedInExistingSession verifies that
// ExistingSessionPayloadBuilder also rejects BlockOptions.
func TestPayloadBuilder_BlockOptions_RejectedInExistingSession(t *testing.T) {
	pb := ExistingSessionPayloadBuilder().
		AddBlock(NewGarlicCloveBlock([]byte("clove"))).
		AddBlock(PayloadBlock{Type: BlockOptions, Data: []byte{0x01}}).
		AddBlock(NewPaddingBlock(4))

	_, err := pb.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BlockOptions")
}

// TestParsePayload_BlockOptions_PreservedWithWarning verifies that
// ParsePayload preserves BlockOptions blocks in the output (so callers
// can inspect them) rather than rejecting them. The spec says receivers
// should ignore unknown/unimplemented blocks — we log a warning but
// do not fail.
func TestParsePayload_BlockOptions_PreservedWithWarning(t *testing.T) {
	// Manually construct a wire payload containing a BlockOptions block:
	// [type=5] [length=0,2] [data=0xAA,0xBB]
	data := []byte{byte(BlockOptions), 0, 2, 0xAA, 0xBB}

	blocks, err := ParsePayload(data)
	require.NoError(t, err, "ParsePayload must not reject BlockOptions on the receive path")
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockOptions, blocks[0].Type)
	assert.Equal(t, []byte{0xAA, 0xBB}, blocks[0].Data)
}

// TestParsePayload_BlockOptions_AmongOtherBlocks verifies that a
// BlockOptions block embedded among valid blocks is preserved and does
// not corrupt parsing of surrounding blocks.
func TestParsePayload_BlockOptions_AmongOtherBlocks(t *testing.T) {
	// Build a valid DateTime block, then manually append an Options block,
	// then a padding block.
	dtBlock := NewDateTimeBlock(time.Unix(1700000000, 0))
	dtBuf := make([]byte, dtBlock.SerializeSize())
	_, err := dtBlock.Serialize(dtBuf)
	require.NoError(t, err)

	// Options block: type 5, length 1, data 0xFF
	optionsWire := []byte{byte(BlockOptions), 0, 1, 0xFF}

	// Padding block: type 254, length 0
	paddingWire := []byte{byte(BlockPadding), 0, 0}

	var combined []byte
	combined = append(combined, dtBuf...)
	combined = append(combined, optionsWire...)
	combined = append(combined, paddingWire...)

	blocks, err := ParsePayload(combined)
	require.NoError(t, err)
	require.Len(t, blocks, 3)
	assert.Equal(t, BlockDateTime, blocks[0].Type)
	assert.Equal(t, BlockOptions, blocks[1].Type)
	assert.Equal(t, []byte{0xFF}, blocks[1].Data)
	assert.Equal(t, BlockPadding, blocks[2].Type)
}
