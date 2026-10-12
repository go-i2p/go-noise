package handshake

import (
	"github.com/go-i2p/logger"
)

// ValidatePaddingRange checks that min and max padding sizes form a valid
// range. It returns an error scoped to the given subsystem name.
//
// It delegates to [ValidatePaddingParams] (with paddingRatio=0.0, since
// callers of this function validate the padding ratio separately, if at all)
// so that the config-time min/max check can never diverge from the stricter
// bound enforced later when a padding engine is constructed
// (NewPaddingEngine/NewNTCP2PaddingModifier/NewSSU2PaddingModifier). This
// keeps a MaxPaddingSize above the I2P spec limit ([I2PMaxBlockDataSize])
// from passing config validation and only failing later at
// connection-establishment time with a different, confusing error code.
func ValidatePaddingRange(subsystem string, minPadding, maxPadding int) error {
	flog("ValidatePaddingRange", logger.Fields{"subsystem": subsystem, "min": minPadding, "max": maxPadding}).Debug("Validating padding range")
	return ValidatePaddingParams(subsystem, minPadding, maxPadding, 0.0)
}
