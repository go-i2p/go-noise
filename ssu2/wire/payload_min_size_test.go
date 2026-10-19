package wire

import (
	"testing"
)

// ssu2.rst (Messages): "The minimum payload size is 8 bytes. This requirement
// will be met by any ACK, I2NP, First Fragment, or Follow-on Fragment block. If
// the requirement is not met, a Padding block must be included."
func TestPadPayloadToMin(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x07}},
		{"two bytes", []byte{0x07, 0x00}},
		{"deficit smaller than block header", []byte{0x07, 0x00, 0x01, 0xAA, 0xBB, 0xCC}},
		{"seven bytes", []byte{0x07, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}},
		{"already at minimum", []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"already above minimum", make([]byte, 40)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]byte(nil), tc.input...)

			got, err := PadPayloadToMin(in)
			if err != nil {
				t.Fatalf("PadPayloadToMin() error = %v", err)
			}
			if len(got) < MinPayloadSize {
				t.Errorf("padded payload is %d bytes, want at least %d", len(got), MinPayloadSize)
			}

			// Input must not be mutated in a way that loses the original bytes.
			if len(got) < len(in) {
				t.Fatalf("padded payload shrank: %d -> %d", len(in), len(got))
			}
			for i := range in {
				if got[i] != in[i] {
					t.Fatalf("original payload bytes modified at %d", i)
				}
			}

			// A payload already at or above the floor must be untouched.
			if len(in) >= MinPayloadSize && len(got) != len(in) {
				t.Errorf("payload of %d bytes was modified, want it returned unchanged", len(in))
			}

			// Whatever was appended must parse back as blocks, and the only
			// block type appended may be Padding.
			if len(got) > len(in) {
				blocks, err := DeserializeBlocks(got[len(in):])
				if err != nil {
					t.Fatalf("appended bytes do not parse as blocks: %v", err)
				}
				if len(blocks) != 1 {
					t.Fatalf("got %d appended blocks, want exactly 1", len(blocks))
				}
				if blocks[0].Type != BlockTypePadding {
					t.Errorf("appended block type = %d, want Padding (%d)", blocks[0].Type, BlockTypePadding)
				}
			}
		})
	}
}

func TestPadPayloadToMin_ExactFloor(t *testing.T) {
	// The helper should land on the floor exactly whenever a non-empty padding
	// block fits, so senders are not inflated beyond the requirement.
	for size := 0; size <= MinPayloadSize; size++ {
		payload := make([]byte, size)
		got, err := PadPayloadToMin(payload)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		// A 1-byte deficit cannot be expressed exactly (a Padding block costs 3
		// header bytes), so the result may overshoot by up to 2 bytes.
		if gotLen := len(got); gotLen < MinPayloadSize || gotLen > MinPayloadSize+2 {
			t.Errorf("size %d: padded to %d bytes, want %d..%d",
				size, gotLen, MinPayloadSize, MinPayloadSize+2)
		}
	}
}

// A lone DateTime block serializes to 7 bytes, which is below the floor. This is
// the real-world shape that motivated the fix.
func TestPadPayloadToMin_LoneDateTimeBlock(t *testing.T) {
	block := NewSSU2Block(BlockTypeDateTime, []byte{0x65, 0x4C, 0x3D, 0x00})
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		t.Fatalf("SerializeBlocks: %v", err)
	}
	if len(payload) >= MinPayloadSize {
		t.Skipf("lone DateTime block is %d bytes; no longer below the floor", len(payload))
	}

	got, err := PadPayloadToMin(payload)
	if err != nil {
		t.Fatalf("PadPayloadToMin() error = %v", err)
	}
	if len(got) < MinPayloadSize {
		t.Errorf("padded to %d bytes, want at least %d", len(got), MinPayloadSize)
	}

	blocks, err := DeserializeBlocks(got)
	if err != nil {
		t.Fatalf("DeserializeBlocks: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want DateTime + Padding", len(blocks))
	}
	if blocks[0].Type != BlockTypeDateTime || blocks[1].Type != BlockTypePadding {
		t.Errorf("block order = [%d %d], want [DateTime Padding]", blocks[0].Type, blocks[1].Type)
	}
}
