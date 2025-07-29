package internal

import (
	"crypto/rand"
	"io"
)

// SecureZero securely zeroes out the given byte slice
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ValidateKeySize validates that a key has the expected size
func ValidateKeySize(key []byte, expectedSize int) bool {
	return len(key) == expectedSize
}
