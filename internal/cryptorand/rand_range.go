package cryptorand

import (
	"errors"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

// RandInRange returns a cryptographically secure, uniformly distributed random
// int64 in the inclusive range [lower, upper].
//
// Uses crypto/rand-backed rejection sampling (via rand.CryptoInt) so there is
// no modulo bias, regardless of whether (max-min+1) is a power of two.
//
// Returns an error only if the CSPRNG is unavailable or lower > upper.
func RandInRange(lower, upper int64) (int64, error) {
	if lower > upper {
		flog("RandInRange", logger.Fields{"min": lower, "max": upper}).Error("min > max")
		return 0, errors.New("internal: RandInRange: min must be <= max")
	}
	if lower == upper {
		return lower, nil
	}

	// spread = upper - lower + 1 (number of values in [lower, upper])
	spread := big.NewInt(upper - lower + 1)
	n, err := rand.CryptoInt(rand.Reader, spread)
	if err != nil {
		flog("RandInRange").WithError(err).Error("Failed to read from CSPRNG")
		return 0, err
	}
	return lower + n.Int64(), nil
}
