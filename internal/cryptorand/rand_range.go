package cryptorand

import (
	"errors"
	"math/big"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

// RandInRange returns a cryptographically secure, uniformly distributed random
// int64 in the inclusive range [min, max].
//
// Uses crypto/rand-backed rejection sampling (via rand.CryptoInt) so there is
// no modulo bias, regardless of whether (max-min+1) is a power of two.
//
// Returns an error only if the CSPRNG is unavailable or min > max.
func RandInRange(min, max int64) (int64, error) {
	if min > max {
		flog("RandInRange", logger.Fields{"min": min, "max": max}).Error("min > max")
		return 0, errors.New("internal: RandInRange: min must be <= max")
	}
	if min == max {
		return min, nil
	}

	// spread = max - min + 1 (number of values in [min, max])
	spread := big.NewInt(max - min + 1)
	n, err := rand.CryptoInt(rand.Reader, spread)
	if err != nil {
		flog("RandInRange").WithError(err).Error("Failed to read from CSPRNG")
		return 0, err
	}
	return min + n.Int64(), nil
}
