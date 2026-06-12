// Package validation provides shared validation helpers for go-noise sub-packages.
// These functions validate Noise protocol configuration values such as patterns,
// key lengths, timeouts, and retry parameters.
//
// Callers may use this package directly or use the forwarding shims in the
// parent mod package (mod.ValidatePattern, mod.ValidateHandshakeTimeout, …)
// which maintain backward compatibility.
package validation

import (
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ValidatePattern checks that a Noise protocol pattern is non-empty.
func ValidatePattern(pattern, pkg string) error {
	log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "ValidatePattern", "pattern": pattern, "calling_pkg": pkg}).Debug("Validating pattern")
	if pattern == "" {
		return oops.
			Code("INVALID_PATTERN").
			In(pkg).
			Errorf("noise pattern is required")
	}
	return nil
}

// ValidateHandshakeTimeout checks that the handshake timeout is positive.
func ValidateHandshakeTimeout(timeout time.Duration, pkg string) error {
	log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "ValidateHandshakeTimeout", "timeout": timeout, "calling_pkg": pkg}).Debug("Validating handshake timeout")
	if timeout <= 0 {
		return oops.
			Code("INVALID_TIMEOUT").
			In(pkg).
			With("timeout", timeout).
			Errorf("handshake timeout must be positive")
	}
	return nil
}

// ValidateKeySize validates that a key has the expected size.
func ValidateKeySize(key []byte, expectedSize int) bool {
	valid := len(key) == expectedSize
	if !valid {
		log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "ValidateKeySize", "expected": expectedSize, "actual": len(key)}).Warn("Key size mismatch")
	}
	return valid
}

// ValidateKeyLength checks that a key is either empty or exactly 32 bytes.
func ValidateKeyLength(key []byte, name, pkg string) error {
	log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "ValidateKeyLength", "key_name": name, "key_len": len(key), "calling_pkg": pkg}).Debug("Validating key length")
	if len(key) > 0 && len(key) != 32 {
		return oops.
			Code("INVALID_KEY_LENGTH").
			In(pkg).
			With("key_length", len(key)).
			Errorf("%s must be 32 bytes for Curve25519", name)
	}
	return nil
}

// RunValidators executes a sequence of validation functions, returning the
// first error encountered or nil if all pass.
func RunValidators(validators ...func() error) error {
	log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "RunValidators", "validator_count": len(validators)}).Debug("Running validators")
	for _, v := range validators {
		if err := v(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRetryConfig checks that retry parameters are within valid ranges.
func ValidateRetryConfig(retries int, backoff time.Duration, pkg string) error {
	log.WithFields(logger.Fields{"pkg": "mod/validation", "func": "ValidateRetryConfig", "retries": retries, "backoff": backoff, "calling_pkg": pkg}).Debug("Validating retry config")
	if retries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In(pkg).
			With("retries", retries).
			Errorf("handshake retries must be >= -1 (-1 = infinite, 0 = no retries)")
	}
	if backoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In(pkg).
			With("backoff", backoff).
			Errorf("retry backoff must be non-negative")
	}
	return nil
}

// ValidateTransportConfig validates the combination of handshake timeout and
// retry configuration that is common to all transport protocol configs.
// It is equivalent to calling ValidateHandshakeTimeout followed by ValidateRetryConfig.
func ValidateTransportConfig(timeout time.Duration, retries int, backoff time.Duration, pkg string) error {
	if err := ValidateHandshakeTimeout(timeout, pkg); err != nil {
		return err
	}
	return ValidateRetryConfig(retries, backoff, pkg)
}

// ValidateNetworkAddr checks that the network and address strings are non-empty.
// This is the canonical check shared by the root noise package, ntcp2, and ssu2.
func ValidateNetworkAddr(network, addr, pkg string) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			In(pkg).
			Errorf("network cannot be empty")
	}
	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			In(pkg).
			Errorf("address cannot be empty")
	}
	return nil
}
