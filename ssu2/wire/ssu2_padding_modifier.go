package wire

import (
	"math"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2PaddingModifier implements MTU-aware padding for SSU2 transport.
// Key differences from NTCP2:
// - MTU awareness: padding must respect UDP packet size limits (1280-1500 bytes)
// - Different overhead calculations for UDP vs TCP
// - Dynamic MTU adjustment during connection
//
// Padding computation and I2P block wire format operations are provided by
// the shared handshake.PaddingEngine. SSU2-specific MTU constraints are
// applied on top of the engine's base computation.
type SSU2PaddingModifier struct {
	name     string
	engine   *handshake.PaddingEngine
	aeadMode bool
	mtu      int
	mutex    sync.RWMutex // Protects dynamic parameter updates
}

const (
	// SSU2 MTU constants
	minMTU      = 1280 // IPv6 minimum MTU
	maxMTU      = 1500 // Typical Ethernet MTU
	defaultMTU  = 1280
	aeadTagSize = 16 // ChaCha20-Poly1305 AEAD tag
)

// NewSSU2PaddingModifier creates a new SSU2 padding modifier with default MTU.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPad: minimum padding bytes (0-65516)
//   - maxPad: maximum padding bytes (>= minPad, 0-65516)
//   - aeadMode: true for AEAD-encrypted padding (message 3+)
func NewSSU2PaddingModifier(name string, minPad, maxPad int, aeadMode bool) (*SSU2PaddingModifier, error) {
	return NewSSU2PaddingModifierWithMTU(name, minPad, maxPad, defaultMTU, aeadMode, 0.0)
}

// NewSSU2PaddingModifierWithRatio creates a modifier with a specific padding ratio.
//
// Parameters:
//   - ratio: ratio of padding to data (0.0 to 15.9375 per I2P spec)
func NewSSU2PaddingModifierWithRatio(name string, minPad, maxPad int, aeadMode bool, ratio float64) (*SSU2PaddingModifier, error) {
	return NewSSU2PaddingModifierWithMTU(name, minPad, maxPad, defaultMTU, aeadMode, ratio)
}

// NewSSU2PaddingModifierWithMTU creates a modifier with custom MTU.
//
// Parameters:
//   - mtu: Maximum Transmission Unit (1280-1500 bytes)
//
// This is the primary constructor - all others delegate to it.
func NewSSU2PaddingModifierWithMTU(name string, minPad, maxPad, mtu int, aeadMode bool, ratio float64) (*SSU2PaddingModifier, error) {
	flog("NewSSU2PaddingModifierWithMTU", logger.Fields{"name": name, "mtu": mtu}).Debug("Creating new SSU2PaddingModifier")
	engine, err := handshake.NewPaddingEngine(handshake.PaddingEngineConfig{
		MinPadding:   minPad,
		MaxPadding:   maxPad,
		PaddingRatio: ratio,
		TestMode:     false,
		Domain:       "ssu2",
	})
	if err != nil {
		return nil, err
	}

	if err := validateMTU(mtu); err != nil {
		return nil, err
	}

	return &SSU2PaddingModifier{
		name:     name,
		engine:   engine,
		aeadMode: aeadMode,
		mtu:      mtu,
	}, nil
}

// WithTestMode enables deterministic (non-random) padding for this modifier.
// WARNING: For testing only — deterministic padding compromises security.
// Returns the receiver for method chaining.
func (spm *SSU2PaddingModifier) WithTestMode() *SSU2PaddingModifier {
	spm.engine.Config.TestMode = true
	return spm
}

// ModifyOutbound adds MTU-aware padding based on message phase.
func (spm *SSU2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifyOutbound", logger.Fields{"phase": phase, "dataLen": len(data)}).Debug("ModifyOutbound: adding MTU-aware padding")
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	paddingSize := spm.calculateMTUAwarePadding(len(data))
	if paddingSize == 0 {
		return data, nil
	}

	if spm.aeadMode && phase >= handshake.PhaseFinal {
		return spm.engine.AddAEADPadding(data, paddingSize)
	} else if !spm.aeadMode && phase < handshake.PhaseFinal {
		return spm.engine.AddCleartextPadding(data, paddingSize)
	}

	return data, nil
}

// ModifyInbound removes SSU2-specific padding.
func (spm *SSU2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifyInbound", logger.Fields{"phase": phase, "dataLen": len(data)}).Debug("ModifyInbound: removing SSU2 padding")
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	if spm.aeadMode && phase >= handshake.PhaseFinal {
		return spm.engine.RemoveTrailingAEADPadding(data, spm.engine.Config.MaxPadding)
	}
	// Cleartext padding included in KDF, cannot be removed
	return data, nil
}

// Name returns the modifier name for logging and debugging.
func (spm *SSU2PaddingModifier) Name() string {
	return spm.name
}

// Close releases resources held by the padding modifier.
// SSU2PaddingModifier holds no sensitive key material, so this is a no-op.
func (spm *SSU2PaddingModifier) Close() error {
	return nil
}

// UpdatePaddingParams dynamically updates padding parameters.
// Thread-safe for concurrent use during connection lifetime.
func (spm *SSU2PaddingModifier) UpdatePaddingParams(minPad, maxPad int, ratio float64) error {
	flog("UpdatePaddingParams", logger.Fields{"minPad": minPad, "maxPad": maxPad, "ratio": ratio}).Debug("UpdatePaddingParams: updating padding parameters")
	if err := handshake.ValidatePaddingParams("ssu2", minPad, maxPad, ratio); err != nil {
		return err
	}

	spm.mutex.Lock()
	defer spm.mutex.Unlock()

	spm.engine.Config.MinPadding = minPad
	spm.engine.Config.MaxPadding = maxPad
	spm.engine.Config.PaddingRatio = ratio
	return nil
}

// SetMTU updates the MTU value for dynamic MTU discovery.
// Thread-safe for concurrent use during connection lifetime.
func (spm *SSU2PaddingModifier) SetMTU(mtu int) error {
	flog("SetMTU", logger.Fields{"mtu": mtu}).Debug("SetMTU: updating MTU value")
	if err := validateMTU(mtu); err != nil {
		return err
	}

	spm.mutex.Lock()
	defer spm.mutex.Unlock()

	spm.mtu = mtu
	return nil
}

// headerOverhead returns the spec-correct SSU2 header size based on mode.
// Per SSU2 spec: short (Data) headers are 16 bytes, long (Handshake) headers are 32 bytes.
func (spm *SSU2PaddingModifier) headerOverhead() int {
	if spm.aeadMode {
		return ShortHeaderSize // 16 bytes for data-phase packets
	}
	return LongHeaderSize // 32 bytes for handshake packets
}

// calculateMTUAwarePadding computes padding size respecting MTU limits.
// Key difference from NTCP2: enforces UDP packet size constraints.
func (spm *SSU2PaddingModifier) calculateMTUAwarePadding(dataLen int) int {
	if spm.engine.ShouldSkipPadding() {
		return 0
	}

	// Calculate available space in MTU using spec-correct header sizes
	overhead := spm.headerOverhead() + aeadTagSize
	if spm.aeadMode {
		overhead += handshake.I2PBlockHeaderSize // Block header for AEAD padding
	}

	availableSpace := spm.mtu - dataLen - overhead
	if availableSpace <= 0 {
		return 0 // No room for padding
	}

	// Use the shared engine for base calculation, then clamp to MTU
	paddingSize := spm.engine.CalculatePaddingSize(dataLen)

	// Enforce MTU constraint (key SSU2 difference)
	if paddingSize > availableSpace {
		paddingSize = availableSpace
	}

	return paddingSize
}

// EstimatePaddingSize estimates padding for bandwidth calculations.
func (spm *SSU2PaddingModifier) EstimatePaddingSize(dataLen int) int {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	if spm.engine.Config.PaddingRatio > 0.0 {
		ratioPadding := int(math.Ceil(float64(dataLen) * spm.engine.Config.PaddingRatio))
		if ratioPadding < spm.engine.Config.MinPadding {
			return spm.engine.Config.MinPadding
		}
		if ratioPadding > spm.engine.Config.MaxPadding {
			return spm.engine.Config.MaxPadding
		}

		// Respect MTU constraint
		overhead := spm.headerOverhead() + aeadTagSize
		availableSpace := spm.mtu - dataLen - overhead
		if availableSpace <= 0 {
			return 0 // No room for padding, matching calculateMTUAwarePadding
		}
		if ratioPadding > availableSpace {
			return availableSpace
		}

		return ratioPadding
	}

	return (spm.engine.Config.MinPadding + spm.engine.Config.MaxPadding) / 2
}

// GetMTU returns the current MTU value.
func (spm *SSU2PaddingModifier) GetMTU() int {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()
	return spm.mtu
}

// GetPaddingParams returns current padding configuration.
func (spm *SSU2PaddingModifier) GetPaddingParams() (minPad, maxPad int, ratio float64) {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()
	return spm.engine.Config.MinPadding, spm.engine.Config.MaxPadding, spm.engine.Config.PaddingRatio
}

// validateMTU validates MTU value.
func validateMTU(mtu int) error {
	if mtu < minMTU || mtu > maxMTU {
		return oops.
			Code("INVALID_MTU").
			In("wire").
			With("mtu", mtu).
			Errorf("MTU must be between %d and %d bytes", minMTU, maxMTU)
	}
	return nil
}
