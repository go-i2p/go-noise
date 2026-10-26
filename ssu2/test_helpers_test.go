package ssu2

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

// generateIntroKey creates a random 32-byte intro key, the size ssu2.md
// requires for header protection and ephemeral-key obfuscation.
func generateIntroKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

// hashPtr returns a pointer to the given data.Hash, useful for struct literals.
func hashPtr(h data.Hash) *data.Hash {
	return &h
}
