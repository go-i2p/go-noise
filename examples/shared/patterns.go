// Package shared provides common utilities for go-noise examples
package shared

import (
	"strings"

	"github.com/samber/oops"
)

// SupportedPatterns lists all standard Noise Protocol patterns
var SupportedPatterns = []string{
	// One-way patterns
	"N", "K", "X",
	// Interactive patterns
	"NN", "NK", "NX",
	"XN", "XK", "XX",
	"KN", "KK", "KX",
	"IN", "IK", "IX",
}

// PatternsRequiringLocalKey returns patterns that require a static key for the local party
var PatternsRequiringLocalKey = map[string]bool{
	"K": true, "X": true,
	"XK": true, "XX": true,
	"KN": true, "KK": true, "KX": true,
	"IK": true, "IX": true,
}

// PatternsRequiringRemoteKey returns patterns that require a remote static key
var PatternsRequiringRemoteKey = map[string]bool{
	"K": true, "NK": true,
	"XK": true, "KN": true, "KK": true, "KX": true,
	"IK": true, "IN": true,
}

// ValidatePattern checks if a pattern is supported
func ValidatePattern(pattern string) error {
	// Handle full pattern names like "Noise_XX_25519_AESGCM_SHA256"
	if strings.HasPrefix(pattern, "Noise_") {
		parts := strings.Split(pattern, "_")
		if len(parts) >= 2 {
			pattern = parts[1] // Extract the pattern part
		}
	}

	for _, supported := range SupportedPatterns {
		if pattern == supported {
			return nil
		}
	}

	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("examples").
		With("pattern", pattern).
		With("supported", SupportedPatterns).
		Errorf("unsupported Noise pattern")
}

// RequiresLocalStaticKey returns true if the pattern requires a local static key
func RequiresLocalStaticKey(pattern string) bool {
	// Handle full pattern names
	if strings.HasPrefix(pattern, "Noise_") {
		parts := strings.Split(pattern, "_")
		if len(parts) >= 2 {
			pattern = parts[1]
		}
	}
	return PatternsRequiringLocalKey[pattern]
}

// RequiresRemoteStaticKey returns true if the pattern requires a remote static key
func RequiresRemoteStaticKey(pattern string) bool {
	// Handle full pattern names
	if strings.HasPrefix(pattern, "Noise_") {
		parts := strings.Split(pattern, "_")
		if len(parts) >= 2 {
			pattern = parts[1]
		}
	}
	return PatternsRequiringRemoteKey[pattern]
}

// GetPatternRequirements returns the key requirements for a pattern
func GetPatternRequirements(pattern string) (needsLocal, needsRemote bool) {
	return RequiresLocalStaticKey(pattern), RequiresRemoteStaticKey(pattern)
}
