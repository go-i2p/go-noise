// Package shared provides common utilities for go-noise examples
package shared

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-i2p/go-noise"
)

// RunDemo executes demonstration mode showing supported patterns and configurations
func RunDemo() {
	fmt.Println("=== go-noise Library Demonstration ===")

	demonstratePatterns()
	demonstrateConfigurations()
	demonstrateKeyRequirements()
}

// RunGenerate generates and displays cryptographic keys for testing
func RunGenerate() {
	fmt.Println("=== Cryptographic Key Generation ===")

	fmt.Println("Generating key pairs for testing...")

	// Generate individual keys
	staticKey, err := GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate static key: %v\n", err)
		return
	}

	remoteKey, err := GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate remote key: %v\n", err)
		return
	}

	fmt.Println("✅ Keys generated successfully!")

	// Display keys
	PrintKeys(staticKey, remoteKey)

	// Show usage examples
	fmt.Println("Usage in commands:")
	fmt.Printf("  -static-key %s\n", KeyToHex(staticKey))
	fmt.Printf("  -remote-key %s\n", KeyToHex(remoteKey))
	fmt.Println("\nExample server command:")
	fmt.Printf("  go run main.go -server localhost:8080 -pattern XX -static-key %s\n", KeyToHex(staticKey))
	fmt.Println("\nExample client command:")
	fmt.Printf("  go run main.go -client localhost:8080 -pattern XX -static-key %s -remote-key %s\n",
		KeyToHex(staticKey), KeyToHex(remoteKey))
}

// demonstratePatterns shows all supported patterns and their validation
func demonstratePatterns() {
	fmt.Println("🔐 Supported Noise Protocol Patterns:")
	fmt.Println("=====================================")

	for _, pattern := range SupportedPatterns {
		config := noise.NewConnConfig(pattern, true)
		needsLocal, needsRemote := GetPatternRequirements(pattern)

		status := "✅"
		if err := config.Validate(); err != nil {
			status = "❌"
		}

		keyReq := "None"
		if needsLocal && needsRemote {
			keyReq = "Local + Remote"
		} else if needsLocal {
			keyReq = "Local only"
		} else if needsRemote {
			keyReq = "Remote only"
		}

		fmt.Printf("  %s %-4s - %s\n", status, pattern, keyReq)
	}
	fmt.Println()
}

// demonstrateConfigurations shows example configurations for different patterns
func demonstrateConfigurations() {
	fmt.Println("⚙️  Example Configurations:")
	fmt.Println("============================")

	examples := []struct {
		pattern     string
		description string
		showKeys    bool
	}{
		{"NN", "No authentication (testing only)", false},
		{"XX", "Mutual authentication (most common)", true},
		{"IK", "Server identity known to client", true},
		{"NK", "Client anonymous, server authenticated", true},
	}

	for _, example := range examples {
		fmt.Printf("\n📋 Pattern %s - %s:\n", example.pattern, example.description)

		config := noise.NewConnConfig(example.pattern, true).
			WithHandshakeTimeout(defaultHandshakeTimeout).
			WithReadTimeout(defaultReadTimeout).
			WithWriteTimeout(defaultWriteTimeout)

		fmt.Printf("   Pattern: %s\n", config.Pattern)
		fmt.Printf("   Initiator: %t\n", config.Initiator)
		fmt.Printf("   Timeouts: handshake=%v, read=%v, write=%v\n",
			config.HandshakeTimeout, config.ReadTimeout, config.WriteTimeout)

		if example.showKeys {
			needsLocal, needsRemote := GetPatternRequirements(example.pattern)
			if needsLocal {
				fmt.Println("   ⚠️  Requires local static key")
			}
			if needsRemote {
				fmt.Println("   ⚠️  Requires remote static key")
			}
		}
	}
	fmt.Println()
}

// demonstrateKeyRequirements shows which patterns require which keys
func demonstrateKeyRequirements() {
	fmt.Println("🔑 Key Requirements by Pattern:")
	fmt.Println("===============================")

	fmt.Printf("%-8s %-12s %-12s %s\n", "Pattern", "Local Key", "Remote Key", "Use Case")
	fmt.Println(strings.Repeat("-", 60))

	for _, pattern := range SupportedPatterns {
		needsLocal, needsRemote := GetPatternRequirements(pattern)

		localReq := "❌"
		if needsLocal {
			localReq = "✅"
		}

		remoteReq := "❌"
		if needsRemote {
			remoteReq = "✅"
		}

		useCase := getPatternUseCase(pattern)
		fmt.Printf("%-8s %-12s %-12s %s\n", pattern, localReq, remoteReq, useCase)
	}
	fmt.Println()
}

// getPatternUseCase returns a description of the pattern's typical use case
func getPatternUseCase(pattern string) string {
	useCases := map[string]string{
		"NN": "Testing/development only",
		"NK": "Anonymous client to known server",
		"NX": "Anonymous client, server proves identity",
		"XN": "Client proves identity to anonymous server",
		"XK": "Client proves identity to known server",
		"XX": "Mutual authentication (recommended)",
		"KN": "Known client to anonymous server",
		"KK": "Both parties pre-authenticated",
		"KX": "Known client, server proves identity",
		"IN": "Client has server's identity",
		"IK": "Client knows server, both authenticate",
		"IX": "Client knows server, mutual auth",
		"N":  "One-way, no authentication",
		"K":  "One-way to known server",
		"X":  "One-way with server authentication",
	}

	if desc, ok := useCases[pattern]; ok {
		return desc
	}
	return "Unknown"
}

// Default timeout values for demonstrations
const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultReadTimeout      = 60 * time.Second
	defaultWriteTimeout     = 60 * time.Second
)
