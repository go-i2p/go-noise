package handshake

import (
	"encoding/binary"
	"math"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GenericPaddingModifier implements padding-based obfuscation by adding random
// padding to handshake messages and removing it during processing.
//
// WARNING: GenericPaddingModifier uses a custom wire format ([4-byte big-endian length][data][padding])
// that is NOT part of any I2P specification. It MUST NOT be used in NTCP2 modifier chains
// or any context that expects fixed-size protocol fields (e.g., NTCP2 Message 1 is exactly
// 64 bytes per spec §3.2). Using GenericPaddingModifier in place of ntcp2.NTCP2PaddingModifier will
// produce non-interoperable messages with no error at the modifier layer.
//
// For I2P NTCP2 transport contexts, use ntcp2.NTCP2PaddingModifier instead.
//
// GenericPaddingModifier is phase-aware: it only applies padding during handshake phases
// (PhaseInitial, PhaseExchange, PhaseFinal). For PhaseData and any unknown phase,
// data is passed through unmodified to prevent silent corruption of post-handshake
// transport messages.
type GenericPaddingModifier struct {
	name       string
	minPadding int
	maxPadding int
}

// Deprecated: Use GenericPaddingModifier instead.
type PaddingModifier = GenericPaddingModifier

// NewGenericPaddingModifier creates a new generic padding modifier with the specified
// minimum and maximum padding sizes.
func NewGenericPaddingModifier(name string, minPadding, maxPadding int) (*GenericPaddingModifier, error) {
	flog("NewGenericPaddingModifier", logger.Fields{"name": name, "min": minPadding, "max": maxPadding}).Debug("Creating generic padding modifier")

	// Validate padding parameters against I2P spec limits (paddingRatio = 0.0 for modifier only).
	if err := ValidatePaddingParams("handshake", minPadding, maxPadding, 0.0); err != nil {
		return nil, err
	}

	return &GenericPaddingModifier{
		name:       name,
		minPadding: minPadding,
		maxPadding: maxPadding,
	}, nil
}

// Deprecated: Use NewGenericPaddingModifier instead.
func NewPaddingModifier(name string, minPadding, maxPadding int) (*GenericPaddingModifier, error) {
	return NewGenericPaddingModifier(name, minPadding, maxPadding)
}

// ModifyOutbound adds padding to outbound handshake data.
// Padding format: [original_length:4][original_data][padding_data]
// Returns an error if data exceeds the 4-byte length prefix capacity (math.MaxUint32).
//
// For PhaseData (and any future phases beyond PhaseFinal), data is returned
// unmodified. This prevents silent corruption of post-handshake transport
// messages that use their own framing (e.g., Noise transport, NTCP2 SipHash).
func (pm *GenericPaddingModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if phase > PhaseFinal {
		return data, nil // Post-handshake: pass through unmodified
	}

	if pm.minPadding == 0 && pm.maxPadding == 0 {
		return data, nil // No padding configured
	}

	flog("GenericPaddingModifier.ModifyOutbound", logger.Fields{"modifier": pm.name, "phase": phase.String(), "data_len": len(data)}).Debug("Padding modifier outbound")

	// Guard: reject data larger than the 4-byte length prefix can encode.
	// This branch is unreachable on 32-bit platforms (where len() <= MaxInt32 < MaxUint32)
	// and practically unreachable on 64-bit platforms (requires >4 GiB allocation).
	// It is retained as a defensive check; allocating >4 GiB in tests is impractical,
	// so this branch is excluded from coverage expectations.
	if len(data) > math.MaxUint32 {
		return nil, oops.
			Code("DATA_TOO_LARGE").
			In("handshake").
			With("data_length", len(data)).
			With("max_length", math.MaxUint32).
			With("modifier_name", pm.name).
			Errorf("data exceeds 4-byte length prefix capacity")
	}

	// Calculate padding size using go-i2p/crypto/rand for traffic analysis resistance
	paddingSize := pm.minPadding
	if pm.maxPadding > pm.minPadding {
		paddingRange := pm.maxPadding - pm.minPadding + 1
		n, err := rand.ReadBigInt(big.NewInt(int64(paddingRange)))
		if err != nil {
			return nil, oops.
				Code("PADDING_RANDOM_ERROR").
				In("handshake").
				With("modifier_name", pm.name).
				Wrapf(err, "failed to generate random padding size")
		}
		paddingSize = pm.minPadding + int(n.Int64())
	}

	// Create result with length prefix, original data, and padding
	result := make([]byte, 4+len(data)+paddingSize)

	// Write original length as 4-byte big-endian
	binary.BigEndian.PutUint32(result[:4], uint32(len(data)))

	// Copy original data
	copy(result[4:4+len(data)], data)

	// Fill padding with cryptographically random bytes
	if paddingSize > 0 {
		if _, err := rand.Read(result[4+len(data):]); err != nil {
			return nil, oops.
				Code("PADDING_RANDOM_ERROR").
				In("handshake").
				With("modifier_name", pm.name).
				Wrapf(err, "failed to generate random padding content")
		}
	}

	return result, nil
}

// ModifyInbound removes padding from inbound handshake data.
//
// For PhaseData (and any future phases beyond PhaseFinal), data is returned
// unmodified. This mirrors ModifyOutbound's phase guard and prevents
// misinterpretation of post-handshake transport frames as padded messages.
func (pm *GenericPaddingModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if phase > PhaseFinal {
		return data, nil // Post-handshake: pass through unmodified
	}

	if pm.minPadding == 0 && pm.maxPadding == 0 {
		return data, nil // No padding configured, return data unchanged
	}

	flog("GenericPaddingModifier.ModifyInbound", logger.Fields{"modifier": pm.name, "phase": phase.String(), "data_len": len(data)}).Debug("Padding modifier inbound")

	if len(data) < 4 {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("padded data too short, missing length prefix")
	}

	// Read original length from 4-byte big-endian prefix.
	// Validate as uint32 before casting to int to prevent integer overflow
	// on 32-bit platforms where int is 32 bits. A uint32 value >= 2^31 would
	// wrap to a negative int, bypassing the subsequent bounds check and
	// causing make() to panic with a negative length.
	rawLen := binary.BigEndian.Uint32(data[:4])
	available := uint32(len(data) - 4)
	if rawLen > available {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("original_length", rawLen).
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("invalid original length in padded data")
	}
	originalLen := int(rawLen)

	// Extract original data
	result := make([]byte, originalLen)
	copy(result, data[4:4+originalLen])

	return result, nil
}

// Name returns the name of the padding modifier for logging and debugging.
func (pm *GenericPaddingModifier) Name() string {
	return pm.name
}

// Close is a no-op for GenericPaddingModifier because it holds no sensitive key material.
// It satisfies the HandshakeModifier lifecycle contract.
func (pm *GenericPaddingModifier) Close() error {
	return nil
}
