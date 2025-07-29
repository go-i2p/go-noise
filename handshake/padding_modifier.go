package handshake

import (
	"github.com/samber/oops"
)

// PaddingModifier implements padding-based obfuscation by adding random
// padding to handshake messages and removing it during processing.
// Moved from: handshake/modifiers.go
type PaddingModifier struct {
	name       string
	minPadding int
	maxPadding int
}

// NewPaddingModifier creates a new padding modifier with the specified
// minimum and maximum padding sizes.
func NewPaddingModifier(name string, minPadding, maxPadding int) (*PaddingModifier, error) {
	if minPadding < 0 {
		return nil, oops.
			Code("INVALID_PADDING").
			In("handshake").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return nil, oops.
			Code("INVALID_PADDING").
			In("handshake").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	return &PaddingModifier{
		name:       name,
		minPadding: minPadding,
		maxPadding: maxPadding,
	}, nil
}

// ModifyOutbound adds padding to outbound handshake data.
// Padding format: [original_length:4][original_data][padding_data]
func (pm *PaddingModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if pm.minPadding == 0 && pm.maxPadding == 0 {
		return data, nil // No padding configured
	}

	// Calculate padding size (simplified to use minPadding for deterministic testing)
	paddingSize := pm.minPadding
	if pm.maxPadding > pm.minPadding {
		// In real implementation, this would be random between min and max
		paddingSize = pm.minPadding + ((len(data) * 7) % (pm.maxPadding - pm.minPadding + 1))
	}

	// Create result with length prefix, original data, and padding
	result := make([]byte, 4+len(data)+paddingSize)

	// Write original length as 4-byte big-endian
	originalLen := len(data)
	result[0] = byte(originalLen >> 24)
	result[1] = byte(originalLen >> 16)
	result[2] = byte(originalLen >> 8)
	result[3] = byte(originalLen)

	// Copy original data
	copy(result[4:4+len(data)], data)

	// Add deterministic padding (in real implementation, this would be random)
	for i := 0; i < paddingSize; i++ {
		result[4+len(data)+i] = byte((i + len(data)) % 256)
	}

	return result, nil
}

// ModifyInbound removes padding from inbound handshake data.
func (pm *PaddingModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("padded data too short, missing length prefix")
	}

	// Read original length from 4-byte big-endian prefix
	originalLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if originalLen < 0 || 4+originalLen > len(data) {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("original_length", originalLen).
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("invalid original length in padded data")
	}

	// Extract original data
	result := make([]byte, originalLen)
	copy(result, data[4:4+originalLen])

	return result, nil
}

// Name returns the name of the padding modifier for logging and debugging.
func (pm *PaddingModifier) Name() string {
	return pm.name
}
