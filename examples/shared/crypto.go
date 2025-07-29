// Package shared provides common utilities for go-noise examples
package shared

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/samber/oops"
)

// GenerateRandomKey generates a random 32-byte Curve25519 private key for testing
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, oops.
			Code("KEYGEN_FAILED").
			In("examples").
			Wrapf(err, "failed to generate random key")
	}
	return key, nil
}

// ParseKeyFromHex parses a hexadecimal string into a 32-byte key
func ParseKeyFromHex(keyStr string) ([]byte, error) {
	if keyStr == "" {
		return GenerateRandomKey()
	}

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, oops.
			Code("INVALID_KEY_FORMAT").
			In("examples").
			With("key", keyStr).
			Wrapf(err, "invalid hex key format")
	}

	if len(key) != 32 {
		return nil, oops.
			Code("INVALID_KEY_LENGTH").
			In("examples").
			With("length", len(key)).
			Errorf("key must be exactly 32 bytes")
	}

	return key, nil
}

// KeyToHex converts a 32-byte key to a hex string for display/storage
func KeyToHex(key []byte) string {
	if len(key) != 32 {
		return ""
	}
	return hex.EncodeToString(key)
}

// GenerateKeyPair generates a pair of keys for testing (static key and remote key)
func GenerateKeyPair() (localKey, remoteKey []byte, err error) {
	localKey, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, oops.
			Code("KEYGEN_FAILED").
			In("examples").
			Wrapf(err, "failed to generate local key")
	}

	remoteKey, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, oops.
			Code("KEYGEN_FAILED").
			In("examples").
			Wrapf(err, "failed to generate remote key")
	}

	return localKey, remoteKey, nil
}

// PrintKeys displays keys in a user-friendly format
func PrintKeys(localKey, remoteKey []byte) {
	fmt.Printf("🔑 Cryptographic Material:\n")
	if localKey != nil {
		fmt.Printf("  Local Static Key:  %s\n", KeyToHex(localKey))
	}
	if remoteKey != nil {
		fmt.Printf("  Remote Static Key: %s\n", KeyToHex(remoteKey))
	}
	fmt.Println()
}

// ParseKeys parses cryptographic keys based on pattern requirements for general Noise examples
func ParseKeys(args *CommonArgs) (staticKey, remoteKey []byte, err error) {
	needsLocal, needsRemote := GetPatternRequirements(args.Pattern)

	// Parse or generate static key if needed
	if needsLocal {
		staticKey, err = ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, nil, oops.
				Code("INVALID_STATIC_KEY").
				In("examples").
				With("pattern", args.Pattern).
				Wrapf(err, "invalid static key")
		}
	}

	// Parse or generate remote key if needed
	if needsRemote {
		remoteKey, err = ParseKeyFromHex(args.RemoteKey)
		if err != nil {
			return nil, nil, oops.
				Code("INVALID_REMOTE_KEY").
				In("examples").
				With("pattern", args.Pattern).
				Wrapf(err, "invalid remote key")
		}
	}

	return staticKey, remoteKey, nil
}
