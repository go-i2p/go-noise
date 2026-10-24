package handshake

import (
	"github.com/go-i2p/crypto/rand"

	"github.com/samber/oops"
)

func GenerateNewStaticKey() ([]byte, error) {
	key := make([]byte, StaticKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, oops.Wrapf(err, "failed to generate static key")
	}
	return key, nil
}

// GenerateNewIntroKey generates a new random 32-byte introduction key.
// This is a helper for creating keys outside the manager.
func GenerateNewIntroKey() ([]byte, error) {
	key := make([]byte, IntroKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, oops.Wrapf(err, "failed to generate intro key")
	}
	return key, nil
}
