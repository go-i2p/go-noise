package handshake

import (
	"encoding/binary"
	"math"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GenericPaddingModifier adds random padding to handshake messages on the way
// out and removes it on the way in. Padding makes messages harder to size,
// which resists traffic analysis.
//
// WARNING: this modifier uses a custom wire format —
// [4-byte big-endian length][data][padding] — that is NOT part of any I2P
// specification. Do not use it in NTCP2 modifier chains or anywhere that
// expects fixed-size protocol fields (for example, NTCP2 Message 1 is exactly
// 64 bytes per spec §3.2). Substituting it for ntcp2.NTCP2PaddingModifier
// produces messages that other I2P peers cannot read, and the modifier layer
// will not report an error.
//
// For I2P NTCP2 transport contexts, use ntcp2.NTCP2PaddingModifier instead.
// See [I2P Spec: NTCP2](https://i2p.net/en/docs/specs/ntcp2/) for details.
//
// The modifier is phase-aware: it only pads during the handshake phases
// ([PhaseInitial], [PhaseExchange], [PhaseFinal]). For [PhaseData] and any
// unknown phase, data passes through unchanged so post-handshake transport
// messages are not corrupted.
type GenericPaddingModifier struct {
	name       string
	minPadding int
	maxPadding int
}

// Deprecated: Use GenericPaddingModifier instead.
type PaddingModifier = GenericPaddingModifier

// NewGenericPaddingModifier creates a new generic padding modifier that adds
// between minPadding and maxPadding bytes of random padding. The values are
// validated against I2P limits before the modifier is returned.
func NewGenericPaddingModifier(name string, minPadding, maxPadding int) (*GenericPaddingModifier, error) {
	flog("NewGenericPaddingModifier", logger.Fields{"name": name, "min": minPadding, "max": maxPadding}).Debug("Creating generic padding modifier")

	// Validate the padding parameters (paddingRatio = 0.0 for this modifier).
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

// ModifyOutbound adds random padding to outbound handshake data. The result
// has the form [original_length:4][original_data][padding_data], where the
// length prefix is the original data length as a 4-byte big-endian number.
// It returns an error if the data is too large for the 4-byte length prefix
// (math.MaxUint32).
//
// For [PhaseData] (and any future phase beyond [PhaseFinal]), data is
// returned unmodified. This prevents silent corruption of post-handshake
// transport messages that use their own framing (for example, Noise
// transport or NTCP2 SipHash).
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

// ModifyInbound removes the padding that ModifyOutbound added, recovering the
// original data from the [original_length:4][original_data][padding_data]
// format.
//
// For [PhaseData] (and any future phase beyond [PhaseFinal]), data is
// returned unmodified. This mirrors ModifyOutbound's phase guard and prevents
// post-handshake transport frames from being misread as padded messages.
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
