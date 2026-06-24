package ntcp2

import (
	"encoding/binary"
	"math"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2PaddingModifier implements production-grade NTCP2-specific padding strategies.
// Supports I2P NTCP2 specification requirements including:
// - Cleartext padding for messages 1 and 2 (outside AEAD frames)
// - AEAD padding for message 3 and data phase (inside AEAD frames with type 254)
// - Cryptographically secure random padding distribution
// - Configurable padding ratios for traffic analysis resistance
//
// Padding computation and I2P block wire format operations are provided by
// the shared handshake.PaddingEngine. NTCP2-specific concerns (AEAD removal
// with trailing-block scan, frame validation) remain in this type.
//
// All exported methods are safe for concurrent use.
type NTCP2PaddingModifier struct {
	mu             sync.Mutex
	name           string
	engine         *handshake.PaddingEngine
	useAEADPadding bool // true for message 3+ (AEAD), false for messages 1-2 (cleartext)
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
	flog("NewNTCP2PaddingModifierWithRatio", logger.Fields{"name": name}).Debug("Creating NTCP2 padding modifier")
	engine, err := handshake.NewPaddingEngine(handshake.PaddingEngineConfig{
		MinPadding:   minPadding,
		MaxPadding:   maxPadding,
		PaddingRatio: paddingRatio,
		TestMode:     false,
		Domain:       "ntcp2",
	})
	if err != nil {
		return nil, err
	}

	return &NTCP2PaddingModifier{
		name:           name,
		engine:         engine,
		useAEADPadding: useAEADPadding,
	}, nil
}

// WithTestMode enables deterministic (non-random) padding for this modifier.
// WARNING: For testing only — deterministic padding compromises security.
// Returns the receiver for method chaining.
func (npm *NTCP2PaddingModifier) WithTestMode() *NTCP2PaddingModifier {
	npm.engine.Config.TestMode = true
	return npm
}

// ModifyOutbound adds NTCP2-specific padding based on message phase.
//
// PhaseFinal (message 3) is explicitly skipped because the handshake code
// manages message 3 padding at the plaintext level — it must be included
// in m3p2Len which is committed in message 1 before the modifier runs.
// AEAD padding is only applied during PhaseData (post-handshake frames).
func (npm *NTCP2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	npm.mu.Lock()
	defer npm.mu.Unlock()

	paddingSize := npm.engine.CalculatePaddingSize(len(data))
	if paddingSize == 0 {
		flog("NTCP2PaddingModifier.ModifyOutbound").Debug("No padding needed for outbound data")
		return data, nil
	}

	flog("NTCP2PaddingModifier.ModifyOutbound", logger.Fields{"padding_size": paddingSize}).Debug("Adding NTCP2 outbound padding")

	if npm.useAEADPadding && phase > handshake.PhaseFinal {
		return npm.engine.AddAEADPadding(data, paddingSize)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		return npm.engine.AddCleartextPadding(data, paddingSize)
	}

	return data, nil
}

// ModifyInbound removes NTCP2-specific padding.
//
// PhaseFinal (message 3) is skipped — padding in message 3 is inside the
// encrypted payload and parsed by the block-format layer, not the modifier.
func (npm *NTCP2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	npm.mu.Lock()
	defer npm.mu.Unlock()

	flog("NTCP2PaddingModifier.ModifyInbound").Debug("Removing NTCP2 inbound padding")

	if npm.useAEADPadding && phase > handshake.PhaseFinal {
		return npm.engine.RemoveTrailingAEADPadding(data, npm.engine.Config.MaxPadding)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		return data, nil
	}

	return data, nil
}

// removeAEADPadding removes a trailing AEAD padding block via the shared engine.
func (npm *NTCP2PaddingModifier) removeAEADPadding(data []byte) ([]byte, error) {
	return npm.engine.RemoveTrailingAEADPadding(data, npm.engine.Config.MaxPadding)
}

// parseBlockStructure analyzes data as I2P block format and tracks parsing state.
// Per the I2P NTCP2 spec, padding MUST be the last block. If any valid block
// appears after the first padding block, result.blocksAfterPadding is set to
// true so callers can reject the malformed payload.
func (npm *NTCP2PaddingModifier) parseBlockStructure(data []byte) blockParseResult {
	result := blockParseResult{}
	offset := 0
	foundPadding := false

	for offset < len(data) {
		blockType, blockSize, ok := npm.validateBlockAtOffset(data, offset)
		if !ok {
			break
		}

		result.foundValidBlocks = true

		if blockType == PaddingBlockType {
			foundPadding = true
			// Continue scanning to detect any data blocks that follow the padding block.
			offset += 3 + blockSize
			continue
		}

		if foundPadding {
			// A non-padding block was found after the padding block — spec violation.
			result.blocksAfterPadding = true
			return result
		}

		result.lastDataEnd = offset + 3 + blockSize
		offset = result.lastDataEnd
	}

	return result
}

// blockParseResult holds the state from parsing I2P block structure.
type blockParseResult struct {
	foundValidBlocks bool
	lastDataEnd      int
	// blocksAfterPadding is true when at least one additional valid block was
	// found after the first padding block. Per the I2P NTCP2 spec, padding MUST
	// be the last block; data blocks after padding indicate a malformed payload.
	blocksAfterPadding bool
}

// validateBlockBounds checks if there's enough data for a block header at the given offset.
func (npm *NTCP2PaddingModifier) validateBlockBounds(data []byte, offset int) bool {
	return offset+3 <= len(data)
}

// extractBlockHeader reads the block type and size from the data at the given offset.
func (npm *NTCP2PaddingModifier) extractBlockHeader(data []byte, offset int) (blockType byte, blockSize int) {
	blockType = data[offset]
	blockSize = int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
	return blockType, blockSize
}

// validateBlockSize ensures the block size doesn't exceed the available data.
func (npm *NTCP2PaddingModifier) validateBlockSize(data []byte, offset, blockSize int) bool {
	return offset+3+blockSize <= len(data)
}

// validateBlockAtOffset validates header and size bounds, then returns parsed fields.
func (npm *NTCP2PaddingModifier) validateBlockAtOffset(data []byte, offset int) (blockType byte, blockSize int, ok bool) {
	if !npm.validateBlockBounds(data, offset) {
		return 0, 0, false
	}

	blockType, blockSize = npm.extractBlockHeader(data, offset)
	if !npm.validateBlockSize(data, offset, blockSize) {
		return 0, 0, false
	}

	return blockType, blockSize, true
}

// SetPaddingRatio updates the padding ratio for dynamic adjustment during connection.
// This supports I2P NTCP2 options negotiation where padding parameters can be updated.
func (npm *NTCP2PaddingModifier) SetPaddingRatio(ratio float64) error {
	if ratio < 0.0 || ratio > MaxPaddingRatio {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ntcp2").
			With("padding_ratio", ratio).
			Errorf("padding ratio must be between 0.0 and %.4f (I2P NTCP2 spec)", MaxPaddingRatio)
	}
	npm.mu.Lock()
	npm.engine.Config.PaddingRatio = ratio
	npm.mu.Unlock()
	return nil
}

// GetPaddingRatio returns the current padding ratio.
func (npm *NTCP2PaddingModifier) GetPaddingRatio() float64 {
	npm.mu.Lock()
	defer npm.mu.Unlock()
	return npm.engine.Config.PaddingRatio
}

// GetPaddingLimits returns the current min/max padding limits.
func (npm *NTCP2PaddingModifier) GetPaddingLimits() (int, int) {
	npm.mu.Lock()
	defer npm.mu.Unlock()
	return npm.engine.Config.MinPadding, npm.engine.Config.MaxPadding
}

// SetPaddingLimits updates the padding limits for dynamic adjustment.
// Supports I2P NTCP2 options negotiation during data phase.
func (npm *NTCP2PaddingModifier) SetPaddingLimits(minPadding, maxPadding int) error {
	if err := handshake.ValidatePaddingParams("ntcp2", minPadding, maxPadding, 0.0); err != nil {
		return err
	}

	npm.mu.Lock()
	npm.engine.Config.MinPadding = minPadding
	npm.engine.Config.MaxPadding = maxPadding
	npm.mu.Unlock()
	return nil
}

// IsAEADMode returns true if this modifier is configured for AEAD padding (message 3+).
func (npm *NTCP2PaddingModifier) IsAEADMode() bool {
	return npm.useAEADPadding
}

// EstimatePaddingSize estimates the padding size for a given data length.
// Useful for pre-allocating buffers and bandwidth calculations.
func (npm *NTCP2PaddingModifier) EstimatePaddingSize(dataLen int) int {
	npm.mu.Lock()
	defer npm.mu.Unlock()
	if npm.engine.Config.PaddingRatio > 0.0 {
		ratioPadding := int(math.Ceil(float64(dataLen) * npm.engine.Config.PaddingRatio))
		if ratioPadding < npm.engine.Config.MinPadding {
			return npm.engine.Config.MinPadding
		}
		if ratioPadding > npm.engine.Config.MaxPadding {
			return npm.engine.Config.MaxPadding
		}
		return ratioPadding
	}
	return (npm.engine.Config.MinPadding + npm.engine.Config.MaxPadding) / 2
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
		blockType, blockSize, ok := npm.validateBlockAtOffset(data, offset)
		if !ok {
			return false
		}

		if !npm.validateFramePaddingRules(blockType, blockSize, offset, len(data), &hasPadding) {
			return false
		}

		offset += 3 + blockSize
	}

	return true
}

// validateFramePaddingRules enforces I2P NTCP2 padding block ordering rules
func (npm *NTCP2PaddingModifier) validateFramePaddingRules(blockType byte, blockSize, offset, dataLen int, hasPadding *bool) bool {
	if blockType == PaddingBlockType { // Padding block
		if *hasPadding {
			return false // Multiple padding blocks not allowed
		}
		*hasPadding = true
		// Padding must be last block
		if offset+3+blockSize != dataLen {
			return false
		}
	}
	return true
}

// Name returns the modifier name for logging and debugging.
func (npm *NTCP2PaddingModifier) Name() string {
	return npm.name
}

// Close is a no-op for NTCP2PaddingModifier because it holds no sensitive key
// material. It satisfies the HandshakeModifier lifecycle contract.
func (npm *NTCP2PaddingModifier) Close() error {
	return nil
}

// Clone creates a deep copy of the NTCP2PaddingModifier with independent state.
// This implements handshake.ModifierCloner to support safe Config.Clone() operations.
func (npm *NTCP2PaddingModifier) Clone() handshake.HandshakeModifier {
	npm.mu.Lock()
	defer npm.mu.Unlock()

	// Deep copy the engine config
	engineCopy, err := handshake.NewPaddingEngine(handshake.PaddingEngineConfig{
		MinPadding:   npm.engine.Config.MinPadding,
		MaxPadding:   npm.engine.Config.MaxPadding,
		PaddingRatio: npm.engine.Config.PaddingRatio,
		TestMode:     npm.engine.Config.TestMode,
		Domain:       npm.engine.Config.Domain,
	})
	if err != nil {
		// Should never happen since we're copying a valid config
		flog("NTCP2PaddingModifier.Clone").
			Errorf("Failed to clone padding engine: %v", err)
		// Return the original on error (caller must handle potential shared state)
		return npm
	}

	return &NTCP2PaddingModifier{
		name:           npm.name,
		engine:         engineCopy,
		useAEADPadding: npm.useAEADPadding,
	}
}
