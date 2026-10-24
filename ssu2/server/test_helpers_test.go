package server

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
)

// generateRandomHash creates a random data.Hash for testing.
func generateRandomHash() data.Hash {
	var h data.Hash
	_, _ = rand.Read(h[:])
	return h
}

// hashPtr returns a pointer to the given data.Hash, useful for struct literals.
func hashPtr(h data.Hash) *data.Hash {
	return &h
}

// testStaticKey returns a valid, non-zero 32-byte Curve25519 private key for
// testing. go-i2p's NewCurve25519PrivateKey rejects all-zero keys, so tests
// must not pass make([]byte, 32) as a local static key.
func testStaticKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}
