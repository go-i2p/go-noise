package ntcp2

import (
	"encoding/binary"
	"testing"
)

// msg3Block builds a wire block (1-byte type, 2-byte big-endian size, data) for
// the message 3 part 2 block-ordering tests.
func msg3Block(t byte, data []byte) []byte {
	b := make([]byte, BlockHeaderSize+len(data))
	b[0] = t
	binary.BigEndian.PutUint16(b[1:3], uint16(len(data)))
	copy(b[3:], data)
	return b
}

// TestValidateMsg3Part2Blocks covers the SessionConfirmed requirement that
// message 3 part 2 "must contain 1 to 3 blocks in the following order:
// Router Info (required), Options (optional), Padding (optional)" and "must
// never contain any other block type".
func TestValidateMsg3Part2Blocks(t *testing.T) {
	ri := msg3Block(routerInfoBlockType, make([]byte, 4))
	opt := msg3Block(optionsBlockType, make([]byte, 4))
	pad := msg3Block(PaddingBlockType, make([]byte, 4))
	i2np := msg3Block(0x03, make([]byte, 4)) // forbidden type

	tests := []struct {
		name    string
		frame   []byte
		wantErr bool
	}{
		{"ri only", ri, false},
		{"ri+opt", append(append([]byte{}, ri...), opt...), false},
		{"ri+pad", append(append([]byte{}, ri...), pad...), false},
		{"ri+opt+pad", append(append(append([]byte{}, ri...), opt...), pad...), false},

		// RouterInfo is mandatory: a frame with only optional blocks passes the
		// relative-ordering check but must still be rejected.
		{"opt+pad (no RI)", append(append([]byte{}, opt...), pad...), true},
		{"opt only (no RI)", opt, true},
		{"pad only (no RI)", pad, true},
		{"empty frame", nil, true},

		// Ordering: RouterInfo must come first.
		{"pad+ri (wrong order)", append(append([]byte{}, pad...), ri...), true},
		{"opt+ri (wrong order)", append(append([]byte{}, opt...), ri...), true},

		// Whitelist: any other block type is forbidden.
		{"ri+i2np (forbidden type)", append(append([]byte{}, ri...), i2np...), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMsg3Part2Blocks(tc.frame)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateMsg3Part2Blocks() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateMsg3Part2Blocks_TruncatedHeader verifies a frame that ends with a
// partial block header is rejected rather than read past its bounds.
func TestValidateMsg3Part2Blocks_TruncatedHeader(t *testing.T) {
	// A valid RouterInfo block followed by a single stray byte (an incomplete
	// header) must fail.
	frame := append(msg3Block(routerInfoBlockType, make([]byte, 4)), 0xFF)
	if err := validateMsg3Part2Blocks(frame); err == nil {
		t.Error("expected error for truncated block header, got nil")
	}
}

// TestValidateMsg3Part2Blocks_SizeOverrun verifies a block declaring a size
// beyond the end of the frame is rejected.
func TestValidateMsg3Part2Blocks_SizeOverrun(t *testing.T) {
	// RouterInfo header claims 200 bytes but only 4 follow.
	bad := make([]byte, BlockHeaderSize+4)
	bad[0] = routerInfoBlockType
	binary.BigEndian.PutUint16(bad[1:3], 200)
	if err := validateMsg3Part2Blocks(bad); err == nil {
		t.Error("expected error for block size overrun, got nil")
	}
}
