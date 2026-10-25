package wire

import (
	"bytes"
	"testing"
)

// TestContainsI2NPBlocks covers the TLV scan used by the data-phase
// immediate-ack heuristic (ssu2.md §"Congestion Control" -> §"Immediate ACK
// Flag"): the flag is only for packets carrying I2NP messages or fragments.
func TestContainsI2NPBlocks(t *testing.T) {
	tests := []struct {
		name   string
		blocks []*SSU2Block
		want   bool
	}{
		{"i2np message", []*SSU2Block{{Type: BlockTypeI2NPMessage, Data: bytes.Repeat([]byte{0xAA}, 8)}}, true},
		{"first fragment", []*SSU2Block{{Type: BlockTypeFirstFragment, Data: bytes.Repeat([]byte{0xAA}, 8)}}, true},
		{"follow-on fragment", []*SSU2Block{{Type: BlockTypeFollowOnFragment, Data: bytes.Repeat([]byte{0xAA}, 8)}}, true},
		{"ack only", []*SSU2Block{{Type: BlockTypeACK, Data: bytes.Repeat([]byte{0xAA}, 8)}}, false},
		{"termination only", []*SSU2Block{{Type: BlockTypeTermination, Data: bytes.Repeat([]byte{0}, 9)}}, false},
		{"padding only", []*SSU2Block{{Type: BlockTypePadding, Data: bytes.Repeat([]byte{0xAA}, 8)}}, false},
		{"mixed ack then i2np", []*SSU2Block{
			{Type: BlockTypeACK, Data: bytes.Repeat([]byte{0xAA}, 8)},
			{Type: BlockTypeI2NPMessage, Data: bytes.Repeat([]byte{0xBB}, 8)},
		}, true},
		{"empty payload", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := SerializeBlocks(tc.blocks)
			if err != nil {
				t.Fatalf("SerializeBlocks: %v", err)
			}
			if got := ContainsI2NPBlocks(payload); got != tc.want {
				t.Errorf("ContainsI2NPBlocks = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestContainsI2NPBlocks_Malformed proves a truncated or self-referential TLV
// stream reports false rather than looping.
func TestContainsI2NPBlocks_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"truncated header": {BlockTypeACK, 0x00},
		"zero length loop": {BlockTypePadding, 0x00, 0x00},
		// Length overruns the buffer on a non-I2NP block: the scan must
		// terminate and report false, not loop on the bogus length.
		"length overruns": {BlockTypePadding, 0xFF, 0xFF},
		"empty":           {},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if ContainsI2NPBlocks(payload) {
				t.Errorf("ContainsI2NPBlocks(%v) = true, want false for malformed input", payload)
			}
		})
	}
}
