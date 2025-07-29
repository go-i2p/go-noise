// Example: NTCP2Config builder pattern demonstration for I2P transport configuration
// This example shows how to create and configure NTCP2Config objects using the
// builder pattern with proper argument handling and validation.
package main

import (
	"fmt"
	"log"
	"time"

	ntcp2shared "github.com/go-i2p/go-noise/examples/ntcp2-shared"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	// Parse NTCP2-specific command line arguments
	args, err := ntcp2shared.ParseNTCP2Args("ntcp2-config")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		ntcp2shared.PrintNTCP2Usage("ntcp2-config", "NTCP2Config builder pattern demonstration")
		return
	}

	// Handle special modes
	if args.Demo {
		runNTCP2ConfigDemo(args)
		return
	}

	if args.Generate {
		ntcp2shared.RunNTCP2Generate()
		return
	}

	// Parse NTCP2 keys and material
	routerHash, remoteRouterHash, destHash, staticKey, err := ntcp2shared.ParseNTCP2Keys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run NTCP2 configuration demonstration
	runNTCP2ConfigurationDemo(routerHash, remoteRouterHash, destHash, staticKey, args)
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

// demonstrateBasicConfigurations shows basic NTCP2 configuration examples
func demonstrateBasicConfigurations(routerHash []byte) {
	fmt.Println("\n1. Basic Configuration Examples:")
	fmt.Println("===============================")

	// Basic responder configuration
	responderConfig, err := ntcp2.NewNTCP2Config(routerHash, false) // false = responder
	if err != nil {
		fmt.Printf("❌ Failed to create responder config: %v\n", err)
		return
	}

	fmt.Printf("Responder Config:\n")
	fmt.Printf("  Pattern: %s\n", responderConfig.Pattern)
	fmt.Printf("  Role: Responder\n")
	fmt.Printf("  AES Obfuscation: %t\n", responderConfig.EnableAESObfuscation)
	fmt.Printf("  SipHash Length: %t\n", responderConfig.EnableSipHashLength)

	// Basic initiator configuration
	initiatorConfig, err := ntcp2.NewNTCP2Config(routerHash, true) // true = initiator
	if err != nil {
		fmt.Printf("❌ Failed to create initiator config: %v\n", err)
		return
	}

	fmt.Printf("\nInitiator Config:\n")
	fmt.Printf("  Pattern: %s\n", initiatorConfig.Pattern)
	fmt.Printf("  Role: Initiator\n")
	fmt.Printf("  Max Frame Size: %d bytes\n", initiatorConfig.MaxFrameSize)
}

// demonstrateAdvancedConfigurations shows advanced builder pattern usage
func demonstrateAdvancedConfigurations(routerHash []byte) {
	fmt.Println("\n2. Advanced Builder Pattern:")
	fmt.Println("============================")

	// Create custom handshake modifiers
	xorMod := handshake.NewXORModifier("demo-xor", []byte{0xAA, 0xBB, 0xCC, 0xDD})
	paddingMod, err := handshake.NewPaddingModifier("demo-padding", 8, 32)
	if err != nil {
		fmt.Printf("❌ Failed to create padding modifier: %v\n", err)
		return
	}

	// Advanced configuration with chained builder methods
	config, err := ntcp2.NewNTCP2Config(routerHash, true) // true = initiator
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

// demonstrateResponderConfiguration shows responder (server) configuration
func demonstrateResponderConfiguration(routerHash, staticKey []byte, args *ntcp2shared.NTCP2Args) {
	fmt.Println("\n🔧 Responder (Server) Configuration:")
	fmt.Println("====================================")

	config, err := ntcp2.NewNTCP2Config(routerHash, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create responder config: %v", err)
	}

	config = config.
		WithStaticKey(staticKey).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Apply NTCP2-specific features based on arguments
	if args.EnableAESObfuscation {
		config = config.WithAESObfuscation(args.EnableAESObfuscation, nil)
	}

	if args.EnableSipHashLength {
		config = config.WithSipHashLength(args.EnableSipHashLength, 0, 0)
	}

	if args.MaxFrameSize > 0 {
		config = config.WithFrameSettings(args.MaxFrameSize, false, 0, 0)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Printf("❌ Invalid configuration: %v\n", err)
		return
	}

	fmt.Printf("  Pattern: %s\n", config.Pattern)
	fmt.Printf("  Role: Responder\n")
	fmt.Printf("  Timeouts: handshake=%v, read=%v, write=%v\n",
		config.HandshakeTimeout, config.ReadTimeout, config.WriteTimeout)
	fmt.Printf("  AES Obfuscation: %t\n", config.EnableAESObfuscation)
	fmt.Printf("  SipHash Length: %t\n", config.EnableSipHashLength)
	fmt.Printf("  Max Frame Size: %d bytes\n", config.MaxFrameSize)
	fmt.Println("✅ Responder configuration valid")
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
func createBaseInitiatorConfig(routerHash, staticKey []byte, args *ntcp2shared.NTCP2Args) *ntcp2.NTCP2Config {
	config, err := ntcp2.NewNTCP2Config(routerHash, true) // true = initiator
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
func applyNTCP2Features(configBuilder *ntcp2.NTCP2Config, remoteRouterHash []byte, args *ntcp2shared.NTCP2Args) *ntcp2.NTCP2Config {
	// Add remote router hash if available
	if remoteRouterHash != nil {
		configBuilder = configBuilder.WithRemoteRouterHash(remoteRouterHash)
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
func addCustomModifiers(configBuilder *ntcp2.NTCP2Config, args *ntcp2shared.NTCP2Args) *ntcp2.NTCP2Config {
	if args.Verbose {
		xorMod := handshake.NewXORModifier("demo-xor", []byte{0xAA, 0xBB, 0xCC, 0xDD})
		paddingMod, err := handshake.NewPaddingModifier("demo-padding", 8, 32)
		if err == nil {
			configBuilder = configBuilder.WithModifiers(xorMod, paddingMod)
		}
	}
	return configBuilder
}

// validateAndDisplayConfig validates the configuration and displays its details
func validateAndDisplayConfig(finalConfig *ntcp2.NTCP2Config, remoteRouterHash []byte) {
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
