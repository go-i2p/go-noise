package handshake

import (
	"github.com/go-i2p/logger"
)

// ValidatePaddingRange checks that min and max padding sizes form a valid range.
// It returns a contextual oops error scoped to the given subsystem name.
//
// This delegates to ValidatePaddingParams (with paddingRatio=0.0, since
// callers of this function validate padding ratio separately, if at all)
// so that the config-time min/max bound check can never diverge from the
// stricter bound enforced later at padding-engine construction time
// (NewPaddingEngine/NewNTCP2PaddingModifier/NewSSU2PaddingModifier). Prior to
// this, ValidatePaddingRange only checked min>=0 and max>=min, allowing a
// MaxPaddingSize above the I2P spec limit (I2PMaxBlockDataSize) to pass
// config validation and fail later at connection-establishment time with a
// different, confusing error code (see AUDIT.md).
func ValidatePaddingRange(subsystem string, minPadding, maxPadding int) error {
	flog("ValidatePaddingRange", logger.Fields{"subsystem": subsystem, "min": minPadding, "max": maxPadding}).Debug("Validating padding range")
	return ValidatePaddingParams(subsystem, minPadding, maxPadding, 0.0)
}
