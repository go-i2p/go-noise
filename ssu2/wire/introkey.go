package wire

import (
	"github.com/go-i2p/logger"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/samber/oops"
)

// keyFromRouterAddress extracts a 32-byte key from a RouterAddress options map
// by parameter name. The value must be a 44-byte I2P Base64-encoded string
// representing 32 bytes.
func keyFromRouterAddress(options map[string]string, param, label string) ([]byte, error) {
	flog("keyFromRouterAddress", logger.Fields{"param": param, "label": label}).Debug("Extracting key from RouterAddress")
	val, ok := options[param]
	if !ok || val == "" {
		return nil, oops.Errorf("RouterAddress missing required '%s' (%s) parameter", param, label)
	}

	key, err := i2pbase64.I2PEncoding.DecodeString(val)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid Base64 in '%s' parameter", param)
	}

	if len(key) != 32 {
		return nil, oops.Errorf("%s must be 32 bytes, got %d", label, len(key))
	}

	return key, nil
}

// IntroKeyFromRouterAddress extracts the 32-byte introduction key from
// a RouterAddress options map. The "i" parameter is a 44-byte I2P
// Base64-encoded string representing the 32-byte ChaCha20 key used
// for header encryption.
//
// Per SSU2 spec §Published Router Address: "i=(Base64 key) — The current
// introduction key for encrypting the headers for this RouterAddress.
// Base 64 encoded using the standard I2P Base 64 alphabet. 32 bytes in
// binary, 44 bytes as Base 64 encoded, big-endian ChaCha20 key."
func IntroKeyFromRouterAddress(options map[string]string) ([]byte, error) {
	flog("IntroKeyFromRouterAddress").Debug("Extracting introduction key")
	return keyFromRouterAddress(options, "i", "introduction key")
}

// StaticKeyFromRouterAddress extracts the 32-byte static public key from
// a RouterAddress options map. The "s" parameter is a 44-byte I2P
// Base64-encoded string representing the X25519 public key.
func StaticKeyFromRouterAddress(options map[string]string) ([]byte, error) {
	flog("StaticKeyFromRouterAddress").Debug("Extracting static public key")
	return keyFromRouterAddress(options, "s", "static key")
}
