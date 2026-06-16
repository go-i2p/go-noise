// Example: NTCP2Config builder pattern demonstration for I2P transport configuration
// This example shows how to create and configure NTCP2Config objects using the
// builder pattern with proper argument handling and validation.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/go-i2p/common/data"
	ntcp2shared "github.com/go-i2p/go-noise/examples/exampleutil"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	ntcp2shared.RunNTCP2Example(
		"ntcp2-config",
		"NTCP2Config builder pattern demonstration",
		"",
		runNTCP2ConfigDemo,
		func(args *ntcp2shared.NTCP2Args, routerHash, remoteRouterHash, destHash, staticKey []byte) {
			runNTCP2ConfigurationDemo(routerHash, remoteRouterHash, destHash, staticKey, args)
		},
	)
}

// runNTCP2ConfigDemo demonstrates NTCP2 configuration with demo mode
func runNTCP2ConfigDemo(args *ntcp2shared.NTCP2Args) {
	fmt.Println("🎭 NTCP2Config Demo Mode")
	fmt.Println("========================")

	// Run the standard NTCP2 demo first
	ntcp2shared.RunNTCP2Demo()

	// Generate demo materials for configuration examples
	routerHash, err := generateDemoMaterial()
	if err != nil {
		log.Fatalf("Failed to generate demo material: %v", err)
	}

	fmt.Printf("\n🔧 NTCP2Config Builder Pattern Examples:\n")
	demonstrateBasicConfigurations(routerHash)
	demonstrateAdvancedConfigurations(routerHash)

	fmt.Println("\n✅ Demo completed - run without -demo for interactive configuration")
}

// generateDemoMaterial creates sample cryptographic material for demo
func generateDemoMaterial() ([]byte, error) {
	// Use the shared utility for consistency
	return []byte("example_demo_router_hash_32_byte"), nil
}

// runNTCP2ConfigurationDemo shows configuration examples with real material
func runNTCP2ConfigurationDemo(routerHash, remoteRouterHash, destHash, staticKey []byte, args *ntcp2shared.NTCP2Args) {
	fmt.Println("=== NTCP2Config Builder Pattern Example ===")
	fmt.Printf("Router Hash: %x...\n", routerHash[:8])
	if remoteRouterHash != nil {
		fmt.Printf("Remote Router Hash: %x...\n", remoteRouterHash[:8])
	}

	// Demonstrate configuration patterns based on command line arguments
	if args.ServerAddr != "" {
		demonstrateResponderConfiguration(routerHash, staticKey, args)
	} else if args.ClientAddr != "" {
		demonstrateInitiatorConfiguration(routerHash, remoteRouterHash, staticKey, args)
	} else {
		// Show both configurations if no specific mode
		demonstrateResponderConfiguration(routerHash, staticKey, args)
		demonstrateInitiatorConfiguration(routerHash, remoteRouterHash, staticKey, args)
	}
}

// createAndDisplayBasicConfig creates an NTCP2Config for the given role and
// prints its common properties (pattern and role name), consolidating the
// repeated create-and-display pattern used for responder and initiator configs.
func createAndDisplayBasicConfig(routerHash []byte, isInitiator bool, roleName string) *ntcp2.Config {
	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, isInitiator)
	if err != nil {
		fmt.Printf("❌ Failed to create %s config: %v\n", roleName, err)
		return nil
	}
	fmt.Printf("%s Config:\n", roleName)
	fmt.Printf("  Pattern: %s\n", config.Pattern)
	fmt.Printf("  Role: %s\n", roleName)
	return config
}

// demonstrateBasicConfigurations shows basic NTCP2 configuration examples
func demonstrateBasicConfigurations(routerHash []byte) {
	fmt.Println("\n1. Basic Configuration Examples:")
	fmt.Println("===============================")

	responder := createAndDisplayBasicConfig(routerHash, false, "Responder")
	if responder == nil {
		return
	}
	fmt.Printf("  AES Obfuscation: %t\n", responder.EnableAESObfuscation)
	fmt.Printf("  SipHash Length: %t\n", responder.EnableSipHashLength)

	fmt.Println()
	initiator := createAndDisplayBasicConfig(routerHash, true, "Initiator")
	if initiator == nil {
		return
	}
	fmt.Printf("  Max Frame Size: %d bytes\n", initiator.MaxFrameSize)
}

// demonstrateAdvancedConfigurations shows advanced builder pattern usage
func demonstrateAdvancedConfigurations(routerHash []byte) {
	fmt.Println("\n2. Advanced Builder Pattern:")
	fmt.Println("============================")

	// Create custom handshake modifiers
	xorMod, err := handshake.NewXORModifier("demo-xor", []byte{0xAA, 0xBB, 0xCC, 0xDD})
	if err != nil {
		fmt.Printf("❌ Failed to create XOR modifier: %v\n", err)
		return
	}
	paddingMod, err := handshake.NewGenericPaddingModifier("demo-padding", 8, 32)
	if err != nil {
		fmt.Printf("❌ Failed to create generic padding modifier: %v\n", err)
		return
	}

	// Advanced configuration with chained builder methods
	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, true) // true = initiator
	if err != nil {
		fmt.Printf("❌ Failed to create config: %v\n", err)
		return
	}

	config = config.
		WithHandshakeTimeout(60*time.Second).
		WithReadTimeout(45*time.Second).
		WithWriteTimeout(45*time.Second).
		WithHandshakeRetries(3).
		WithRetryBackoff(2*time.Second).
		WithModifiers(xorMod, paddingMod).
		WithFrameSettings(32768, true, 16, 128) // 32KB frames, padding 16-128 bytes

	fmt.Printf("Advanced Config:\n")
	fmt.Printf("  Handshake Timeout: %v\n", config.HandshakeTimeout)
	fmt.Printf("  Retry Settings: %d attempts, %v backoff\n",
		config.HandshakeRetries, config.RetryBackoff)
	fmt.Printf("  Custom Modifiers: %d\n", len(config.Modifiers))
	fmt.Printf("  Frame Padding: %t\n", config.FramePaddingEnabled)
}

// applyResponderFeatures applies NTCP2-specific features to the responder config
func applyResponderFeatures(config *ntcp2.Config, args *ntcp2shared.NTCP2Args) (*ntcp2.Config, error) {
	if args.EnableAESObfuscation {
		config = config.WithAESObfuscation(args.EnableAESObfuscation, nil)
	}
	if args.EnableSipHashLength {
		config = config.WithSipHashLength(args.EnableSipHashLength, 0, 0)
	}
	if args.MaxFrameSize > 0 {
		config = config.WithFrameSettings(args.MaxFrameSize, false, 0, 0)
	}
	return config, nil
}

// displayResponderConfig prints the responder configuration details
func displayResponderConfig(config *ntcp2.Config) {
	fmt.Printf("  Pattern: %s\n", config.Pattern)
	fmt.Printf("  Role: Responder\n")
	fmt.Printf("  Timeouts: handshake=%v, read=%v, write=%v\n",
		config.HandshakeTimeout, config.ReadTimeout, config.WriteTimeout)
	fmt.Printf("  AES Obfuscation: %t\n", config.EnableAESObfuscation)
	fmt.Printf("  SipHash Length: %t\n", config.EnableSipHashLength)
	fmt.Printf("  Max Frame Size: %d bytes\n", config.MaxFrameSize)
	fmt.Println("✅ Responder configuration valid")
}

// demonstrateResponderConfiguration shows responder (server) configuration
func demonstrateResponderConfiguration(routerHash, staticKey []byte, args *ntcp2shared.NTCP2Args) {
	fmt.Println("\n🔧 Responder (Server) Configuration:")
	fmt.Println("====================================")

	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create responder config: %v", err)
	}

	config = config.WithStaticKey(staticKey).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	config, err = applyResponderFeatures(config, args)
	if err != nil {
		fmt.Printf("❌ Failed to apply responder features: %v\n", err)
		return
	}

	if err := config.Validate(); err != nil {
		fmt.Printf("❌ Invalid configuration: %v\n", err)
		return
	}

	displayResponderConfig(config)
}

// demonstrateInitiatorConfiguration shows initiator (client) configuration
func demonstrateInitiatorConfiguration(routerHash, remoteRouterHash, staticKey []byte, args *ntcp2shared.NTCP2Args) {
	fmt.Println("\n🔧 Initiator (Client) Configuration:")
	fmt.Println("====================================")

	configBuilder := createBaseInitiatorConfig(routerHash, staticKey, args)
	configBuilder = applyNTCP2Features(configBuilder, remoteRouterHash, args)
	configBuilder = addCustomModifiers(configBuilder, args)
	finalConfig := configBuilder

	validateAndDisplayConfig(finalConfig, remoteRouterHash)
}

// createBaseInitiatorConfig creates the basic NTCP2 configuration with core settings
func createBaseInitiatorConfig(routerHash, staticKey []byte, args *ntcp2shared.NTCP2Args) *ntcp2.Config {
	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, true) // true = initiator
	if err != nil {
		log.Fatalf("Failed to create initiator config: %v", err)
	}

	return config.
		WithStaticKey(staticKey).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)
}

// applyNTCP2Features applies NTCP2-specific features and remote router configuration
func applyNTCP2Features(configBuilder *ntcp2.Config, remoteRouterHash []byte, args *ntcp2shared.NTCP2Args) *ntcp2.Config {
	// Add remote router hash if available
	if remoteRouterHash != nil {
		var rrh data.Hash
		copy(rrh[:], remoteRouterHash)
		configBuilder = configBuilder.WithRemoteRouterHash(rrh)
	}

	// Apply NTCP2-specific features
	if args.EnableAESObfuscation {
		configBuilder = configBuilder.WithAESObfuscation(args.EnableAESObfuscation, nil)
	}
	if args.EnableSipHashLength {
		configBuilder = configBuilder.WithSipHashLength(args.EnableSipHashLength, 0, 0)
	}

	if args.MaxFrameSize > 0 {
		configBuilder = configBuilder.WithFrameSettings(args.MaxFrameSize, false, 0, 0)
	}

	return configBuilder
}

// addCustomModifiers creates and adds demonstration modifiers to the configuration
func addCustomModifiers(configBuilder *ntcp2.Config, args *ntcp2shared.NTCP2Args) *ntcp2.Config {
	if args.Verbose {
		xorMod, err := handshake.NewXORModifier("demo-xor", []byte{0xAA, 0xBB, 0xCC, 0xDD})
		if err == nil {
			paddingMod, err := handshake.NewGenericPaddingModifier("demo-padding", 8, 32)
			if err == nil {
				configBuilder = configBuilder.WithModifiers(xorMod, paddingMod)
			}
		}
	}
	return configBuilder
}

// validateAndDisplayConfig validates the configuration and displays its details
func validateAndDisplayConfig(finalConfig *ntcp2.Config, remoteRouterHash []byte) {
	if err := finalConfig.Validate(); err != nil {
		fmt.Printf("❌ Invalid configuration: %v\n", err)
		return
	}

	fmt.Printf("  Pattern: %s\n", finalConfig.Pattern)
	fmt.Printf("  Role: Initiator\n")
	if remoteRouterHash != nil {
		fmt.Printf("  Remote Router: %x...\n", finalConfig.RemoteRouterHash[:8])
	}
	fmt.Printf("  Timeouts: handshake=%v, read=%v, write=%v\n",
		finalConfig.HandshakeTimeout, finalConfig.ReadTimeout, finalConfig.WriteTimeout)
	if len(finalConfig.Modifiers) > 0 {
		fmt.Printf("  Custom Modifiers: %d\n", len(finalConfig.Modifiers))
	}
	fmt.Println("✅ Initiator configuration valid")
}
