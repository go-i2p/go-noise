package ntcp2

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// NTCP2PaddingModifier implements production-grade NTCP2-specific padding strategies.
// Supports I2P NTCP2 specification requirements including:
// - Cleartext padding for messages 1 and 2 (outside AEAD frames)
// - AEAD padding for message 3 and data phase (inside AEAD frames with type 254)
// - Cryptographically secure random padding distribution
// - Configurable padding ratios for traffic analysis resistance
type NTCP2PaddingModifier struct {
	name           string
	minPadding     int
	maxPadding     int
	useAEADPadding bool    // true for message 3+ (AEAD), false for messages 1-2 (cleartext)
	paddingRatio   float64 // padding to data ratio (0.0 to 15.9375 as per I2P spec)
	testMode       bool    // if true, use deterministic padding for testing
}

// NewNTCP2PaddingModifier creates a new production-grade NTCP2 padding modifier.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPadding: minimum padding bytes (0-65516)
//   - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
//   - useAEADPadding: false for messages 1-2 (cleartext), true for message 3+ (AEAD)
//
// The modifier uses cryptographically secure random padding by default.
// Padding sizes follow I2P NTCP2 specification guidelines.
func NewNTCP2PaddingModifier(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error) {
	return NewNTCP2PaddingModifierWithRatio(name, minPadding, maxPadding, useAEADPadding, 0.0)
}

// NewNTCP2PaddingModifierWithRatio creates a new NTCP2 padding modifier with a specific padding ratio.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPadding: minimum padding bytes (0-65516)
//   - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
//   - useAEADPadding: false for messages 1-2 (cleartext), true for message 3+ (AEAD)
//   - paddingRatio: ratio of padding to data (0.0 to 15.9375 as per I2P NTCP2 spec)
//
// A paddingRatio of 0.0 means no ratio-based padding (uses min/max only).
// A paddingRatio of 1.0 means 100% padding (double the message size).
func NewNTCP2PaddingModifierWithRatio(name string, minPadding, maxPadding int, useAEADPadding bool, paddingRatio float64) (*NTCP2PaddingModifier, error) {
	if minPadding < 0 {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	// I2P NTCP2 spec: maximum single block data size is 65516 bytes
	if maxPadding > 65516 {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot exceed 65516 bytes (I2P NTCP2 spec limit)")
	}

	// I2P NTCP2 spec: padding ratio range is 0.0 to 15.9375
	if paddingRatio < 0.0 || paddingRatio > 15.9375 {
		return nil, oops.
			Code("INVALID_PADDING_RATIO").
			In("ntcp2").
			With("padding_ratio", paddingRatio).
			Errorf("padding ratio must be between 0.0 and 15.9375 (I2P NTCP2 spec)")
	}

	return &NTCP2PaddingModifier{
		name:           name,
		minPadding:     minPadding,
		maxPadding:     maxPadding,
		useAEADPadding: useAEADPadding,
		paddingRatio:   paddingRatio,
		testMode:       false,
	}, nil
}

// NewNTCP2PaddingModifierForTesting creates a modifier with deterministic padding for testing.
// This should NEVER be used in production as it compromises security.
func NewNTCP2PaddingModifierForTesting(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error) {
	modifier, err := NewNTCP2PaddingModifier(name, minPadding, maxPadding, useAEADPadding)
	if err != nil {
		return nil, err
	}
	modifier.testMode = true
	return modifier, nil
}

// ModifyOutbound adds NTCP2-specific padding based on message phase.
func (npm *NTCP2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	paddingSize := npm.calculatePaddingSize(len(data))
	if paddingSize == 0 {
		return data, nil
	}

	if npm.useAEADPadding && phase >= handshake.PhaseFinal {
		// AEAD padding: block format with type 254
		return npm.addAEADPadding(data, paddingSize)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		// Cleartext padding: simple append
		return npm.addCleartextPadding(data, paddingSize)
	}

	return data, nil
}

// ModifyInbound removes NTCP2-specific padding.
func (npm *NTCP2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	if npm.useAEADPadding && phase >= handshake.PhaseFinal {
		// Remove AEAD padding (block format)
		return npm.removeAEADPadding(data)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		// Cleartext padding was included in KDF, cannot be removed here
		// This is handled by the protocol itself
		return data, nil
	}

	return data, nil
}

// calculatePaddingSize determines padding size using production-grade strategies.
// Uses cryptographically secure random padding distribution aligned with I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) calculatePaddingSize(dataLen int) int {
	if npm.minPadding == 0 && npm.maxPadding == 0 && npm.paddingRatio == 0.0 {
		return 0
	}

	var paddingSize int

	// Calculate ratio-based padding if specified
	if npm.paddingRatio > 0.0 {
		ratioPadding := int(float64(dataLen) * npm.paddingRatio)
		paddingSize = ratioPadding
	}

	// Ensure minimum padding is met
	if paddingSize < npm.minPadding {
		paddingSize = npm.minPadding
	}

	// Apply random variation within constraints
	paddingRange := npm.maxPadding - npm.minPadding
	if paddingRange > 0 {
		if npm.testMode {
			// Deterministic for testing (INSECURE - for testing only)
			paddingSize = npm.minPadding + (dataLen%paddingRange+paddingRange)%paddingRange
		} else {
			// Cryptographically secure random variation
			randomBytes := make([]byte, 4)
			if _, err := rand.Read(randomBytes); err == nil {
				randomValue := binary.BigEndian.Uint32(randomBytes)
				randomPadding := int(randomValue) % (paddingRange + 1)

				// Choose between base padding size and random size
				if npm.paddingRatio > 0.0 {
					// Use larger of ratio-based or random padding
					if randomPadding > paddingSize-npm.minPadding {
						paddingSize = npm.minPadding + randomPadding
					}
				} else {
					paddingSize = npm.minPadding + randomPadding
				}
			}
		}
	}

	// Ensure we don't exceed maximum
	if paddingSize > npm.maxPadding {
		paddingSize = npm.maxPadding
	}

	return paddingSize
}

// addCleartextPadding adds production-grade cleartext padding for messages 1 and 2.
// Uses cryptographically secure random padding data as required by I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) addCleartextPadding(data []byte, paddingSize int) ([]byte, error) {
	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	// Generate cryptographically secure random padding
	paddingData := result[len(data):]
	if npm.testMode {
		// Deterministic padding for testing (INSECURE - for testing only)
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		// Production: use cryptographically secure random padding
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("PADDING_GENERATION_FAILED").
				In("ntcp2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random padding")
		}
	}

	return result, nil
}

// addAEADPadding adds production-grade AEAD padding in I2P block format (type 254).
// Follows I2P NTCP2 spec: [type:1][size:2][padding_data] inside AEAD frames.
func (npm *NTCP2PaddingModifier) addAEADPadding(data []byte, paddingSize int) ([]byte, error) {
	// Block format: [type:1][size:2][padding_data]
	blockSize := 3 + paddingSize
	result := make([]byte, len(data)+blockSize)
	copy(result, data)

	offset := len(data)
	result[offset] = 254                                               // Padding block type (I2P NTCP2 spec)
	binary.BigEndian.PutUint16(result[offset+1:], uint16(paddingSize)) // Padding size (big-endian)

	// Generate cryptographically secure random padding data
	paddingData := result[offset+3:]
	if npm.testMode {
		// Deterministic padding for testing (INSECURE - for testing only)
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		// Production: use cryptographically secure random padding
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("AEAD_PADDING_GENERATION_FAILED").
				In("ntcp2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random AEAD padding")
		}
	}

	return result, nil
}

// removeAEADPadding removes AEAD padding blocks (type 254) with robust parsing.
// Handles both simple concatenated data+padding and proper I2P block format.
func (npm *NTCP2PaddingModifier) removeAEADPadding(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return data, nil // No room for block header
	}

	// Strategy 1: Look for padding block (type 254) from the end
	// This works for simple cases where we have data + single padding block
	for i := len(data) - 1; i >= 2; i-- {
		if data[i-2] == 254 { // Found potential padding block type
			if i-1 < len(data) {
				paddingSize := binary.BigEndian.Uint16(data[i-1 : i+1])
				expectedEnd := i + 1 + int(paddingSize)
				// Check if this looks like a valid trailing padding block
				if expectedEnd == len(data) && i-2 >= 0 {
					return data[:i-2], nil
				}
			}
		}
	}

	// Strategy 2: Parse as proper I2P block structure if Strategy 1 fails
	offset := 0
	lastDataEnd := 0
	foundValidBlocks := false

	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}

		blockType := data[offset]
		blockSize := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))

		// Validate block size - if invalid, might not be block format
		if offset+3+blockSize > len(data) {
			break
		}

		foundValidBlocks = true

		if blockType == 254 {
			// Found padding block - return data up to this point
			return data[:lastDataEnd], nil
		}

		// Move to next block
		lastDataEnd = offset + 3 + blockSize
		offset = lastDataEnd
	}

	// If we found valid blocks but no padding, return up to last valid block
	if foundValidBlocks && lastDataEnd > 0 && lastDataEnd <= len(data) {
		return data[:lastDataEnd], nil
	}

	// No padding block found or not block format - return original data
	return data, nil
}

// SetPaddingRatio updates the padding ratio for dynamic adjustment during connection.
// This supports I2P NTCP2 options negotiation where padding parameters can be updated.
func (npm *NTCP2PaddingModifier) SetPaddingRatio(ratio float64) error {
	if ratio < 0.0 || ratio > 15.9375 {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ntcp2").
			With("padding_ratio", ratio).
			Errorf("padding ratio must be between 0.0 and 15.9375 (I2P NTCP2 spec)")
	}
	npm.paddingRatio = ratio
	return nil
}

// GetPaddingRatio returns the current padding ratio.
func (npm *NTCP2PaddingModifier) GetPaddingRatio() float64 {
	return npm.paddingRatio
}

// GetPaddingLimits returns the current min/max padding limits.
func (npm *NTCP2PaddingModifier) GetPaddingLimits() (int, int) {
	return npm.minPadding, npm.maxPadding
}

// SetPaddingLimits updates the padding limits for dynamic adjustment.
// Supports I2P NTCP2 options negotiation during data phase.
func (npm *NTCP2PaddingModifier) SetPaddingLimits(minPadding, maxPadding int) error {
	if minPadding < 0 {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	if maxPadding > 65516 {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot exceed 65516 bytes (I2P NTCP2 spec limit)")
	}

	npm.minPadding = minPadding
	npm.maxPadding = maxPadding
	return nil
}

// IsAEADMode returns true if this modifier is configured for AEAD padding (message 3+).
func (npm *NTCP2PaddingModifier) IsAEADMode() bool {
	return npm.useAEADPadding
}

// EstimatePaddingSize estimates the padding size for a given data length.
// Useful for pre-allocating buffers and bandwidth calculations.
func (npm *NTCP2PaddingModifier) EstimatePaddingSize(dataLen int) int {
	if npm.paddingRatio > 0.0 {
		ratioPadding := int(math.Ceil(float64(dataLen) * npm.paddingRatio))
		if ratioPadding < npm.minPadding {
			return npm.minPadding
		}
		if ratioPadding > npm.maxPadding {
			return npm.maxPadding
		}
		return ratioPadding
	}

	// Return average of min/max for estimation
	return (npm.minPadding + npm.maxPadding) / 2
}

// ValidateAEADFrame validates that a frame contains properly formatted AEAD blocks.
// Returns true if the frame structure is valid according to I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) ValidateAEADFrame(data []byte) bool {
	if len(data) == 0 {
		return true // Empty frame is valid
	}

	offset := 0
	hasPadding := false

	for offset < len(data) {
		if offset+3 > len(data) {
			return false // Invalid block header
		}

		blockType := data[offset]
		blockSize := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))

		if offset+3+blockSize > len(data) {
			return false // Block size exceeds data
		}

		// Check I2P NTCP2 block ordering rules
		if blockType == 254 { // Padding block
			if hasPadding {
				return false // Multiple padding blocks not allowed
			}
			hasPadding = true
			// Padding must be last block
			if offset+3+blockSize != len(data) {
				return false
			}
		}

		offset += 3 + blockSize
	}

	return true
}

// Name returns the modifier name for logging and debugging.
func (npm *NTCP2PaddingModifier) Name() string {
	return npm.name
}
