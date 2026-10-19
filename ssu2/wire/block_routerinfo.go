package wire

import "github.com/samber/oops"

// RouterInfo block (type 2) wire format, per ssu2.rst §"RouterInfo":
//
//	blk  :: 1 byte  = 2
//	size :: 2 bytes = 2 + fragment size (the flag and frag bytes are counted)
//	flag :: 1 byte  bit 0 = flood request, bit 1 = gzip, bits 7-2 unused
//	frag :: 1 byte  bits 7-4 = fragment number (always 0),
//	               bits 3-0 = total fragments (always 1)
//	data :: the RouterInfo bytes
//
// The two prefix bytes are mandatory. Building a type-2 block from raw
// RouterInfo bytes (omitting flag/frag) produces a message a spec-conformant
// peer parses as a corrupt RouterInfo, so always go through these helpers.
const (
	// RouterInfoPrefixSize is the flag + frag byte overhead of a RouterInfo block.
	RouterInfoPrefixSize = 2

	// RouterInfoFlagFlood is bit 0: request the receiver to flood/store the RI.
	RouterInfoFlagFlood = 0x01
	// RouterInfoFlagGzip is bit 1: the RouterInfo is gzip compressed.
	RouterInfoFlagGzip = 0x02

	// RouterInfoUnfragmented is the mandatory frag byte value: fragment 0 of 1
	// ("The Router Info block is never fragmented. The frag byte must be set to
	// fragment 0, total fragments 1.").
	RouterInfoUnfragmented = 0x01
)

// RouterInfoBlock is a decoded RouterInfo block.
type RouterInfoBlock struct {
	Flood      bool
	Compressed bool
	Fragment   uint8 // high nibble: fragment number, always 0
	TotalFrags uint8 // low nibble: total fragments, always 1
	Data       []byte
}

// EncodeRouterInfoBlock builds a spec-compliant RouterInfo block, prepending
// the mandatory flag and frag bytes.
func EncodeRouterInfoBlock(routerInfo []byte, flood, compressed bool) (*SSU2Block, error) {
	if len(routerInfo) == 0 {
		return nil, oops.Errorf("RouterInfo block requires non-empty RouterInfo bytes")
	}

	var flag byte
	if flood {
		flag |= RouterInfoFlagFlood
	}
	if compressed {
		flag |= RouterInfoFlagGzip
	}

	data := make([]byte, RouterInfoPrefixSize+len(routerInfo))
	data[0] = flag
	data[1] = RouterInfoUnfragmented
	copy(data[RouterInfoPrefixSize:], routerInfo)

	return NewSSU2Block(BlockTypeRouterInfo, data), nil
}

// DecodeRouterInfoBlock parses the flag/frag prefix from a RouterInfo block
// and returns the RouterInfo bytes.
func DecodeRouterInfoBlock(block *SSU2Block) (*RouterInfoBlock, error) {
	if block == nil {
		return nil, oops.Errorf("nil RouterInfo block")
	}
	if block.Type != BlockTypeRouterInfo {
		return nil, oops.Errorf("expected RouterInfo block (type %d), got type %d",
			BlockTypeRouterInfo, block.Type)
	}
	if len(block.Data) <= RouterInfoPrefixSize {
		return nil, oops.Errorf("RouterInfo block too short: %d bytes (need more than %d for flag+frag)",
			len(block.Data), RouterInfoPrefixSize)
	}

	flag := block.Data[0]
	frag := block.Data[1]

	return &RouterInfoBlock{
		Flood:      flag&RouterInfoFlagFlood != 0,
		Compressed: flag&RouterInfoFlagGzip != 0,
		Fragment:   frag >> 4,
		TotalFrags: frag & 0x0f,
		Data:       block.Data[RouterInfoPrefixSize:],
	}, nil
}
