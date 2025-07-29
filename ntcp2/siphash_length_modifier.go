package ntcp2

import (
	"encoding/binary"

	"github.com/dchest/siphash"
	"github.com/go-i2p/go-noise/handshake"
)

// SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation
// for data phase frame lengths. This prevents identification of frame
// lengths in the data stream.
// Moved from: ntcp2/modifier.go
type SipHashLengthModifier struct {
	name       string
	sipKeys    [2]uint64 // SipHash k1, k2 keys
	outboundIV uint64    // Current IV value for outbound
	inboundIV  uint64    // Current IV value for inbound
	outCounter uint64    // Frame counter for outbound
	inCounter  uint64    // Frame counter for inbound
}

// NewSipHashLengthModifier creates a new SipHash length obfuscation modifier.
// sipKeys must contain exactly 2 uint64 values (k1, k2).
// initialIV is the 8-byte IV from the data phase KDF.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return &SipHashLengthModifier{
		name:       name,
		sipKeys:    sipKeys,
		outboundIV: initialIV,
		inboundIV:  initialIV,
		outCounter: 0,
		inCounter:  0,
	}
}

// ModifyOutbound obfuscates 2-byte frame lengths using SipHash.
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to data phase (not handshake messages 1, 2, or 3 part 1)
	if phase != handshake.PhaseFinal || len(data) != 2 {
		return data, nil
	}

	// Get next mask using SipHash for outbound
	mask := slm.getNextOutboundMask()

	// XOR the 2-byte length with the mask
	length := binary.BigEndian.Uint16(data)
	obfuscatedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, obfuscatedLength)

	return result, nil
}

// ModifyInbound removes SipHash obfuscation from frame lengths.
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to data phase (not handshake messages 1, 2, or 3 part 1)
	if phase != handshake.PhaseFinal || len(data) != 2 {
		return data, nil
	}

	// Get next mask using SipHash for inbound
	mask := slm.getNextInboundMask()

	// XOR the 2-byte length with the mask (XOR is symmetric)
	length := binary.BigEndian.Uint16(data)
	deobfuscatedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, deobfuscatedLength)

	return result, nil
}

// getNextOutboundMask generates the next SipHash mask for outbound data.
func (slm *SipHashLengthModifier) getNextOutboundMask() uint16 {
	// Increment counter for next IV
	slm.outCounter++

	// Use proper SipHash-2-4 with the counter as input
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, slm.outCounter)

	// Calculate SipHash with k1, k2 keys
	hash := siphash.Hash(slm.sipKeys[0], slm.sipKeys[1], input)

	// Update IV with the hash result
	slm.outboundIV = hash

	// Return first 2 bytes as mask
	return uint16(hash & 0xFFFF)
}

// getNextInboundMask generates the next SipHash mask for inbound data.
func (slm *SipHashLengthModifier) getNextInboundMask() uint16 {
	// Increment counter for next IV
	slm.inCounter++

	// Use proper SipHash-2-4 with the counter as input
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, slm.inCounter)

	// Calculate SipHash with k1, k2 keys
	hash := siphash.Hash(slm.sipKeys[0], slm.sipKeys[1], input)

	// Update IV with the hash result
	slm.inboundIV = hash

	// Return first 2 bytes as mask
	return uint16(hash & 0xFFFF)
}

// Name returns the modifier name for logging and debugging.
func (slm *SipHashLengthModifier) Name() string {
	return slm.name
}
