package handshake

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Shared I2P padding constants used by both NTCP2 and SSU2 transports.
const (
	// I2PPaddingBlockType is the I2P block type identifier for padding (type 254).
	I2PPaddingBlockType byte = 254

	// I2PBlockHeaderSize is the size of an I2P block header: [type:1][size:2].
	I2PBlockHeaderSize = 3

	// I2PMaxBlockDataSize is the maximum data size for a single I2P block (65516 bytes).
	I2PMaxBlockDataSize = 65516

	// I2PMaxPaddingRatio is the maximum padding ratio per I2P spec (4.4 fixed-point format).
	I2PMaxPaddingRatio = 15.9375
)

// PaddingEngineConfig holds shared padding parameters for the engine.
// The engine does not manage concurrency — callers must handle locking.
type PaddingEngineConfig struct {
	MinPadding   int
	MaxPadding   int
	PaddingRatio float64
	TestMode     bool
	Domain       string // Error domain for oops messages (e.g., "ntcp2", "ssu2")
}

// PaddingEngine provides shared padding computation and I2P block wire format
// operations for transport protocols. Both NTCP2 and SSU2 padding modifiers
// embed this engine and add protocol-specific constraints.
//
// The engine is NOT thread-safe. The embedding modifier handles locking.
type PaddingEngine struct {
	Config PaddingEngineConfig
}

// NewPaddingEngine creates a validated padding engine.
func NewPaddingEngine(config PaddingEngineConfig) (*PaddingEngine, error) {
	flog("NewPaddingEngine", logger.Fields{"domain": config.Domain, "min": config.MinPadding, "max": config.MaxPadding}).Debug("Creating padding engine")
	if err := ValidatePaddingParams(config.Domain, config.MinPadding, config.MaxPadding, config.PaddingRatio); err != nil {
		return nil, err
	}
	return &PaddingEngine{Config: config}, nil
}

// ValidatePaddingParams validates common I2P padding parameters.
func ValidatePaddingParams(domain string, minPadding, maxPadding int, paddingRatio float64) error {
	flog("ValidatePaddingParams", logger.Fields{"domain": domain, "min": minPadding, "max": maxPadding, "ratio": paddingRatio}).Debug("Validating padding params")
	if minPadding < 0 {
		return oops.
			Code("INVALID_MIN_PADDING").
			In(domain).
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return oops.
			Code("INVALID_PADDING_RANGE").
			In(domain).
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	if maxPadding > I2PMaxBlockDataSize {
		return oops.
			Code("INVALID_PADDING").
			In(domain).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot exceed %d bytes (I2P spec limit)", I2PMaxBlockDataSize)
	}

	if paddingRatio < 0.0 || paddingRatio > I2PMaxPaddingRatio {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In(domain).
			With("padding_ratio", paddingRatio).
			Errorf("padding ratio must be between 0.0 and %.4f (I2P spec)", I2PMaxPaddingRatio)
	}

	return nil
}

// ShouldSkipPadding returns true when no padding is configured.
func (pe *PaddingEngine) ShouldSkipPadding() bool {
	return pe.Config.MinPadding == 0 && pe.Config.MaxPadding == 0 && pe.Config.PaddingRatio == 0.0
}

// CalculatePaddingSize computes the padding size using ratio, random variation,
// and min/max enforcement. The result is clamped to [MinPadding, MaxPadding].
func (pe *PaddingEngine) CalculatePaddingSize(dataLen int) int {
	if pe.ShouldSkipPadding() {
		return 0
	}

	paddingSize := pe.calculateRatioPadding(dataLen)
	paddingSize = pe.enforceMinimumPadding(paddingSize)
	paddingSize = pe.applyRandomVariation(paddingSize, dataLen)
	result := pe.enforceMaximumPadding(paddingSize)
	flog("PaddingEngine.CalculatePaddingSize", logger.Fields{"data_len": dataLen, "padding_size": result}).Debug("Calculated padding size")
	return result
}

// UpdateParams updates the engine's padding parameters after validation.
func (pe *PaddingEngine) UpdateParams(minPad, maxPad int, ratio float64) error {
	flog("PaddingEngine.UpdateParams", logger.Fields{"domain": pe.Config.Domain, "min": minPad, "max": maxPad, "ratio": ratio}).Debug("Updating padding params")
	if err := ValidatePaddingParams(pe.Config.Domain, minPad, maxPad, ratio); err != nil {
		return err
	}
	pe.Config.MinPadding = minPad
	pe.Config.MaxPadding = maxPad
	pe.Config.PaddingRatio = ratio
	return nil
}

// EstimatePaddingSize estimates padding for bandwidth calculations.
func (pe *PaddingEngine) EstimatePaddingSize(dataLen int) int {
	if pe.Config.PaddingRatio > 0.0 {
		ratioPadding := int(float64(dataLen) * pe.Config.PaddingRatio)
		if ratioPadding < pe.Config.MinPadding {
			return pe.Config.MinPadding
		}
		if ratioPadding > pe.Config.MaxPadding {
			return pe.Config.MaxPadding
		}
		return ratioPadding
	}
	return (pe.Config.MinPadding + pe.Config.MaxPadding) / 2
}

// AddCleartextPadding appends cryptographically random bytes after the data.
// addPaddingCore is the shared core logic for adding padding to data.
// header is an optional byte slice prepended to the padding data.
// If header is nil, padding is appended directly. If header is provided,
// it is included before the padding data, and the header must be pre-filled
// by the caller.
func (pe *PaddingEngine) addPaddingCore(data, header []byte, paddingSize int) ([]byte, error) {
	totalSize := len(data) + len(header) + paddingSize
	result := make([]byte, totalSize)
	copy(result, data)
	copy(result[len(data):], header)

	paddingData := result[len(data)+len(header):]
	if pe.Config.TestMode {
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("PADDING_GENERATION_FAILED").
				In(pe.Config.Domain).
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random padding")
		}
	}

	return result, nil
}

// AddCleartextPadding appends random padding directly to the data.
func (pe *PaddingEngine) AddCleartextPadding(data []byte, paddingSize int) ([]byte, error) {
	return pe.addPaddingCore(data, nil, paddingSize)
}

// AddAEADPadding appends a padding block in I2P format: [type:1][size:2][random padding].
func (pe *PaddingEngine) AddAEADPadding(data []byte, paddingSize int) ([]byte, error) {
	// Build I2P block header: [type:1][size:2]
	header := make([]byte, I2PBlockHeaderSize)
	header[0] = I2PPaddingBlockType
	binary.BigEndian.PutUint16(header[1:], uint16(paddingSize))

	return pe.addPaddingCore(data, header, paddingSize)
}

// RemoveTrailingAEADPadding removes a trailing I2P padding block (type 254)
// by scanning from paddingSize=0 upward. maxScanPadding limits the search range.
func (pe *PaddingEngine) RemoveTrailingAEADPadding(data []byte, maxScanPadding int) ([]byte, error) {
	flog("PaddingEngine.RemoveTrailingAEADPadding", logger.Fields{"data_len": len(data), "max_scan": maxScanPadding}).Debug("Removing trailing AEAD padding")
	if len(data) < I2PBlockHeaderSize {
		return data, nil
	}

	maxPadding := len(data) - I2PBlockHeaderSize
	if maxPadding < 0 {
		return data, nil
	}
	if maxScanPadding > 0 && maxPadding > maxScanPadding {
		maxPadding = maxScanPadding
	}
	if maxPadding > I2PMaxBlockDataSize {
		maxPadding = I2PMaxBlockDataSize
	}

	for paddingSize := 0; paddingSize <= maxPadding; paddingSize++ {
		start := len(data) - I2PBlockHeaderSize - paddingSize
		if start < 0 {
			break
		}
		if data[start] != I2PPaddingBlockType {
			continue
		}
		declaredSize := int(binary.BigEndian.Uint16(data[start+1 : start+3]))
		if declaredSize == paddingSize {
			return data[:start], nil
		}
	}
	return data, nil
}

func (pe *PaddingEngine) calculateRatioPadding(dataLen int) int {
	if pe.Config.PaddingRatio > 0.0 {
		return int(float64(dataLen) * pe.Config.PaddingRatio)
	}
	return 0
}

func (pe *PaddingEngine) enforceMinimumPadding(paddingSize int) int {
	if paddingSize < pe.Config.MinPadding {
		return pe.Config.MinPadding
	}
	return paddingSize
}

func (pe *PaddingEngine) enforceMaximumPadding(paddingSize int) int {
	if paddingSize > pe.Config.MaxPadding {
		return pe.Config.MaxPadding
	}
	return paddingSize
}

func (pe *PaddingEngine) applyRandomVariation(paddingSize, dataLen int) int {
	paddingRange := pe.Config.MaxPadding - pe.Config.MinPadding
	if paddingRange <= 0 {
		return paddingSize
	}

	if pe.Config.TestMode {
		return pe.Config.MinPadding + (dataLen%paddingRange+paddingRange)%paddingRange
	}
	return pe.calculateSecureRandomPadding(paddingSize, paddingRange)
}

func (pe *PaddingEngine) calculateSecureRandomPadding(paddingSize, paddingRange int) int {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fail-open on padding *size* jitter only (unlike addPaddingCore's
		// padding *content* generation, which fails closed): falling back to
		// a deterministic size is a traffic-analysis weakness, not a
		// confidentiality/integrity break, since the connection can still
		// proceed securely without randomized padding size. Log at Error so
		// operators can detect degraded entropy, since this fallback would
		// otherwise be entirely silent.
		flog("PaddingEngine.calculateSecureRandomPadding", logger.Fields{"domain": pe.Config.Domain}).WithError(err).Error("crypto/rand failed; falling back to non-randomized padding size")
		return paddingSize
	}

	randomValue := binary.BigEndian.Uint32(randomBytes)
	// Use unsigned modulus before converting to int to avoid negative values on 32-bit platforms.
	randomPadding := int(randomValue % uint32(paddingRange+1))

	if pe.Config.PaddingRatio > 0.0 {
		if randomPadding > paddingSize-pe.Config.MinPadding {
			return pe.Config.MinPadding + randomPadding
		}
		return paddingSize
	}
	return pe.Config.MinPadding + randomPadding
}
