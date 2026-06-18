// Package cryptorand provides a thin wrapper around the system CSPRNG,
// returning cryptographically secure random bytes. It is intentionally
// internal so that only packages within this module can import it.

package cryptorand

import (
	"errors"
	"io"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

// RandomBytes generates cryptographically secure random bytes.
// Returns an error if n is negative. If n is zero, returns an empty slice.
func RandomBytes(n int) ([]byte, error) {
	flog("RandomBytes", logger.Fields{"n": n}).Debug("Generating random bytes")
	if n < 0 {
		flog("RandomBytes", logger.Fields{"n": n}).Error("Negative byte count")
		return nil, errors.New("internal: negative byte count")
	}
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		flog("RandomBytes").WithError(err).Error("Failed to read from crypto/rand")
		return nil, err
	}
	return b, nil
}
