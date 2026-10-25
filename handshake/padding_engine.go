package handshake

import (
	"encoding/binary"
	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Shared I2P padding constants used by both the NTCP2 and SSU2 transports.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
const (
	// I2PPaddingBlockType is the I2P block type identifier for padding
	// (type 254).
	I2PPaddingBlockType byte = 254

	// I2PBlockHeaderSize is the size of an I2P block header:
	// [type:1][size:2].
	I2PBlockHeaderSize = 3

	// I2PMaxBlockDataSize is the maximum data size for a single I2P block
	// (65516 bytes).
	I2PMaxBlockDataSize = 65516

	// I2PMaxPaddingRatio is the maximum padding ratio allowed by the I2P
	// spec (4.4 fixed-point format).
	I2PMaxPaddingRatio = 15.9375
)

// PaddingEngineConfig holds the shared padding parameters for a
// [PaddingEngine]. The engine does not manage concurrency — callers must
// handle locking.
type PaddingEngineConfig struct {
	MinPadding   int
	MaxPadding   int
	PaddingRatio float64
	TestMode     bool
	Domain       string // Error domain for oops messages (e.g., "ntcp2", "ssu2")
}

// PaddingEngine provides the shared padding math and I2P block wire format
// used by the transport protocols. Both the NTCP2 and SSU2 padding modifiers
// embed this engine and add their own protocol-specific constraints.
//
// The engine is NOT thread-safe. The modifier that embeds it handles locking.
type PaddingEngine struct {
	Config PaddingEngineConfig
}

// NewPaddingEngine creates a padding engine after validating its config. It
// returns an error if any parameter is out of the I2P-specified range.
func NewPaddingEngine(config PaddingEngineConfig) (*PaddingEngine, error) {
	flog("NewPaddingEngine", logger.Fields{"domain": config.Domain, "min": config.MinPadding, "max": config.MaxPadding}).Debug("Creating padding engine")
	if err := ValidatePaddingParams(config.Domain, config.MinPadding, config.MaxPadding, config.PaddingRatio); err != nil {
		return nil, err
	}
	return &PaddingEngine{Config: config}, nil
}

// ValidatePaddingParams checks that a set of I2P padding parameters is valid:
// the minimum is not negative, the maximum is at least the minimum, the
// maximum does not exceed [I2PMaxBlockDataSize], and the ratio is between 0.0
// and [I2PMaxPaddingRatio]. It returns an error describing the first problem
// found.
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

// ShouldSkipPadding reports whether no padding is configured (minimum,
// maximum, and ratio are all zero).
func (pe *PaddingEngine) ShouldSkipPadding() bool {
	return pe.Config.MinPadding == 0 && pe.Config.MaxPadding == 0 && pe.Config.PaddingRatio == 0.0
}

// CalculatePaddingSize computes how many bytes of padding to add for a
// message of the given length. It starts from the padding ratio, applies
// random variation, and clamps the result to [MinPadding, MaxPadding].
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

// UpdateParams changes the engine's padding parameters. The new values are
// validated first; if any is out of range, the parameters are left unchanged
// and an error is returned.
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

// EstimatePaddingSize estimates how much padding a message of the given
// length will get, for bandwidth calculations. With a ratio configured it
// uses the ratio (clamped to [MinPadding, MaxPadding]); otherwise it uses the
// midpoint of the min/max range.
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

// addPaddingCore is the shared core logic for adding padding to data.
// header is an optional byte slice placed between the data and the padding.
// If header is nil, padding is appended directly after the data. If header is
// provided, it is included before the padding data, and the caller must
// pre-fill it.
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

// AddCleartextPadding appends cryptographically random padding bytes directly
// after the data, with no block header.
func (pe *PaddingEngine) AddCleartextPadding(data []byte, paddingSize int) ([]byte, error) {
	return pe.addPaddingCore(data, nil, paddingSize)
}

// AddAEADPadding appends a padding block in I2P block format:
// [type:1][size:2][random padding], where type is [I2PPaddingBlockType] and
// size is the padding size as a 2-byte big-endian number.
func (pe *PaddingEngine) AddAEADPadding(data []byte, paddingSize int) ([]byte, error) {
	// Build I2P block header: [type:1][size:2]
	header := make([]byte, I2PBlockHeaderSize)
	header[0] = I2PPaddingBlockType
	binary.BigEndian.PutUint16(header[1:], uint16(paddingSize))

	return pe.addPaddingCore(data, header, paddingSize)
}

// RemoveTrailingAEADPadding removes a trailing I2P padding block
// ([I2PPaddingBlockType]) by scanning candidate padding sizes in
// [MinPadding, maxScanPadding]. maxScanPadding further limits the search
// range (for example, to the sender's configured maximum); a value <= 0
// means "no additional limit".
//
// Because the preceding application payload is opaque (not itself I2P-block
// formatted), a candidate header can in principle appear more than once by
// coincidence. Rather than silently accepting the first match found (which
// could strip the wrong boundary and corrupt data), this function scans the
// entire bounded window and only succeeds when exactly one candidate
// matches. Zero candidates is treated as "no padding present" (the
// legitimate outcome when the sender's configured padding size was 0, so no
// block was ever appended). More than one candidate is treated as an
// unresolvable ambiguity and fails closed with an error, rather than
// guessing — the caller should abort the connection.
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

	minPadding := pe.Config.MinPadding
	if minPadding > maxPadding {
		// The configured minimum padding size cannot be satisfied within the
		// available scan window, so no valid candidate can exist.
		return data, nil
	}

	matchStart := -1
	for paddingSize := minPadding; paddingSize <= maxPadding; paddingSize++ {
		start := len(data) - I2PBlockHeaderSize - paddingSize
		if start < 0 {
			break
		}
		if data[start] != I2PPaddingBlockType {
			continue
		}
		declaredSize := int(binary.BigEndian.Uint16(data[start+1 : start+3]))
		if declaredSize != paddingSize {
			continue
		}
		if matchStart != -1 {
			flog("PaddingEngine.RemoveTrailingAEADPadding", logger.Fields{"domain": pe.Config.Domain, "data_len": len(data), "min_padding": minPadding, "max_padding": maxPadding}).Error("Ambiguous AEAD padding: multiple candidate padding blocks found")
			return nil, oops.
				Code("AMBIGUOUS_AEAD_PADDING").
				In(pe.Config.Domain).
				With("data_len", len(data)).
				With("min_padding", minPadding).
				With("max_padding", maxPadding).
				Errorf("multiple candidate AEAD padding blocks found; refusing to guess to avoid silent data corruption")
		}
		matchStart = start
	}

	if matchStart == -1 {
		return data, nil
	}
	return data[:matchStart], nil
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
