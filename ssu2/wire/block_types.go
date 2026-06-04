package wire

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/samber/oops"
)

// NewTokenBlock represents a NewToken (Type 17) block.
// Per SSU2 spec, this block contains:
//   - 4 bytes: Token expiration timestamp (seconds since epoch)
//   - 8 bytes: Token (randomly-generated, big-endian)
//
// Total data size: 12 bytes
type NewTokenBlock struct {
	Expiration uint32 // Unix timestamp when token expires
	Token      []byte // Token value (8 bytes per spec)
}

// NewNewTokenBlock creates a NewToken block with the specified expiration and token.
// Per SSU2 spec, the token must be exactly 8 bytes.
func NewNewTokenBlock(expiration time.Time, token []byte) (*SSU2Block, error) {
	if len(token) != TokenSize {
		return nil, oops.Errorf("token must be exactly %d bytes per SSU2 spec, got %d", TokenSize, len(token))
	}

	// Build block data: expiration (4) + token (8)
	data := make([]byte, 4+len(token))
	binary.BigEndian.PutUint32(data[0:4], uint32(expiration.Unix()))
	copy(data[4:], token)

	return NewSSU2Block(BlockTypeNewToken, data), nil
}

// ParseNewTokenBlock extracts the expiration and token from a NewToken block.
func ParseNewTokenBlock(block *SSU2Block) (*NewTokenBlock, error) {
	if block.Type != BlockTypeNewToken {
		return nil, oops.Errorf("expected NewToken block (type %d), got type %d", BlockTypeNewToken, block.Type)
	}

	if len(block.Data) < minNewTokenSize {
		return nil, oops.Errorf("NewToken block data too short: %d bytes (minimum %d)", len(block.Data), minNewTokenSize)
	}

	return &NewTokenBlock{
		Expiration: binary.BigEndian.Uint32(block.Data[0:4]),
		Token:      block.Data[4:],
	}, nil
}

// FindBlockByType searches for a block of the specified type in a slice of blocks.
// Returns the first matching block, or nil if not found.
func FindBlockByType(blocks []*SSU2Block, blockType uint8) *SSU2Block {
	for _, block := range blocks {
		if block.Type == blockType {
			return block
		}
	}
	return nil
}

// AddressBlock represents a decoded Address block (type 13).
// Per spec: port(2) + IP(4 for IPv4, 16 for IPv6).
type AddressBlock struct {
	IP   net.IP
	Port uint16
}

// EncodeAddressBlock creates an Address block from an IP and port.
func EncodeAddressBlock(ip net.IP, port uint16) *SSU2Block {
	ip4 := ip.To4()
	var data []byte
	if ip4 != nil {
		data = make([]byte, 6)
		binary.BigEndian.PutUint16(data[0:2], port)
		copy(data[2:6], ip4)
	} else {
		data = make([]byte, 18)
		binary.BigEndian.PutUint16(data[0:2], port)
		copy(data[2:18], ip.To16())
	}
	return NewSSU2Block(BlockTypeAddress, data)
}

// DecodeAddressBlock parses an Address block into IP and port.
func DecodeAddressBlock(block *SSU2Block) (*AddressBlock, error) {
	if block.Type != BlockTypeAddress {
		return nil, oops.Errorf("expected Address block (type %d), got type %d", BlockTypeAddress, block.Type)
	}
	switch len(block.Data) {
	case minAddressSizeIPv4: // 6 = port(2) + IPv4(4)
		return &AddressBlock{
			Port: binary.BigEndian.Uint16(block.Data[0:2]),
			IP:   net.IP(block.Data[2:6]),
		}, nil
	case minAddressSizeIPv6: // 18 = port(2) + IPv6(16)
		return &AddressBlock{
			Port: binary.BigEndian.Uint16(block.Data[0:2]),
			IP:   net.IP(block.Data[2:18]),
		}, nil
	default:
		return nil, oops.Errorf("Address block unexpected size: %d bytes (expected %d or %d)",
			len(block.Data), minAddressSizeIPv4, minAddressSizeIPv6)
	}
}
