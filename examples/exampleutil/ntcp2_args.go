// Package exampleutil provides NTCP2-specific utilities for go-noise examples
package exampleutil

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/samber/oops"
)

// NTCP2Args holds NTCP2-specific command-line arguments
type NTCP2Args struct {
	// Network configuration
	ServerAddr string
	ClientAddr string

	// NTCP2-specific material
	RouterHash       string
	RemoteRouterHash string
	DestinationHash  string

	// Cryptographic keys (Curve25519)
	StaticKey string

	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// NTCP2 features
	EnableAESObfuscation bool
	EnableSipHashLength  bool
	MaxFrameSize         int

	// Operation modes
	Demo     bool
	Generate bool
	Verbose  bool
}

// ParseNTCP2Args parses NTCP2-specific command-line arguments
func ParseNTCP2Args(appName string) (*NTCP2Args, error) {
	args := &NTCP2Args{}

	// Network configuration
	RegisterNetworkFlags(&args.ServerAddr, &args.ClientAddr, "localhost:7654")

	// NTCP2-specific material (all 64-character hex strings for 32-byte values)
	flag.StringVar(&args.RouterHash, "router-hash", "", "Local router hash as 64-character hex string (generated if empty)")
	flag.StringVar(&args.RemoteRouterHash, "remote-router-hash", "", "Remote router hash as 64-character hex string (generated if empty)")
	flag.StringVar(&args.DestinationHash, "destination-hash", "", "Destination hash for tunnel connections (optional)")

	// Cryptographic keys
	flag.StringVar(&args.StaticKey, "static-key", "", "Static private key as 64-character hex string (generated if empty)")

	// Timeouts
	RegisterTimeoutFlags(&args.HandshakeTimeout, &args.ReadTimeout, &args.WriteTimeout, 45*time.Second, "NTCP2 handshake timeout")

	// NTCP2 features
	flag.BoolVar(&args.EnableAESObfuscation, "aes-obfuscation", true, "Enable AES obfuscation modifier")
	flag.BoolVar(&args.EnableSipHashLength, "siphash-length", true, "Enable SipHash length modifier")
	flag.IntVar(&args.MaxFrameSize, "max-frame-size", 16384, "Maximum frame size in bytes")

	// Operation modes
	RegisterModeFlags(&args.Demo, &args.Generate, &args.Verbose,
		"Run demonstration mode showing NTCP2 configurations",
		"Generate and display NTCP2 cryptographic material")

	flag.Parse()

	return args, nil
}

// PrintNTCP2Usage displays usage information for an NTCP2 example
func PrintNTCP2Usage(appName, description string) {
	PrintUsageHeader(appName, description)
	PrintUsageExample(appName, "Generate NTCP2 material for testing", "-generate")
	PrintUsageExample(appName, "Run demo mode", "-demo")
	PrintUsageExample(appName, "Run NTCP2 server", "-server localhost:7654 -router-hash <64-char-hex>")
	PrintUsageExample(appName, "Run NTCP2 client", "-client localhost:7654 -router-hash <64-char-hex> -remote-router-hash <64-char-hex>")
	fmt.Println("Note: NTCP2 uses Noise_XK_25519_AESGCM_SHA256 pattern exclusively")
}

// HandleNTCP2DefaultAddress sets the default server address for an NTCP2 example
// when no address is provided. This consolidates the common default-address
// pattern used across NTCP2 example programs.
func HandleNTCP2DefaultAddress(args *NTCP2Args, defaultAddr string) {
	if defaultAddr != "" && args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = defaultAddr
	}
}

// RunNTCP2Example runs a standard NTCP2 example program with common argument
// parsing, validation, and mode dispatch. This consolidates the main()
// boilerplate duplicated across ntcp2, ntcp2-config, and ntcp2-listener examples.
func RunNTCP2Example(appName, description, defaultAddr string,
	demoFunc func(*NTCP2Args),
	runFunc func(*NTCP2Args, []byte, []byte, []byte, []byte),
) {
	args, err := ParseNTCP2Args(appName)
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	HandleNTCP2DefaultAddress(args, defaultAddr)

	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		PrintNTCP2Usage(appName, description)
		return
	}

	if args.Demo {
		demoFunc(args)
		return
	}

	if args.Generate {
		RunNTCP2Generate()
		return
	}

	routerHash, remoteRouterHash, destHash, staticKey, err := ParseNTCP2Keys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	runFunc(args, routerHash, remoteRouterHash, destHash, staticKey)
}

// ValidateArgs performs validation on parsed NTCP2 arguments
func (args *NTCP2Args) ValidateArgs() error {
	modeCount := args.countOperationModes()

	if err := args.validateModeSelection(modeCount); err != nil {
		return err
	}

	if err := args.validateRouterHashRequirements(); err != nil {
		return err
	}

	if err := args.validateClientRequirements(); err != nil {
		return err
	}

	return nil
}

// countOperationModes counts the number of operation modes specified
func (args *NTCP2Args) countOperationModes() int {
	count := 0
	if args.ServerAddr != "" {
		count++
	}
	if args.ClientAddr != "" {
		count++
	}
	if args.Demo {
		count++
	}
	if args.Generate {
		count++
	}
	return count
}

// validateModeSelection ensures exactly one operation mode is selected
func (args *NTCP2Args) validateModeSelection(modeCount int) error {
	if modeCount == 0 {
		return oops.
			Code("INVALID_ARGS").
			In("ntcp2-examples").
			Errorf("must specify one of: -server, -client, -demo, or -generate")
	}

	if modeCount > 1 {
		return oops.
			Code("INVALID_ARGS").
			In("ntcp2-examples").
			Errorf("cannot specify multiple modes simultaneously")
	}

	return nil
}

// validateRouterHashRequirements checks router hash requirements for network modes
func (args *NTCP2Args) validateRouterHashRequirements() error {
	if (args.ServerAddr != "" || args.ClientAddr != "") && args.RouterHash == "" {
		return oops.
			Code("MISSING_ROUTER_HASH").
			In("ntcp2-examples").
			Errorf("NTCP2 requires a router hash (-router-hash)")
	}
	return nil
}

// validateClientRequirements checks client-specific requirements
func (args *NTCP2Args) validateClientRequirements() error {
	if args.ClientAddr != "" && args.RemoteRouterHash == "" {
		return oops.
			Code("MISSING_REMOTE_ROUTER_HASH").
			In("ntcp2-examples").
			Errorf("NTCP2 client requires remote router hash (-remote-router-hash)")
	}
	return nil
}

// parseRouterHash handles parsing or generation of router hash
func parseRouterHash(args *NTCP2Args) ([]byte, error) {
	if args.RouterHash != "" {
		routerHash, err := ParseKeyFromHex(args.RouterHash)
		if err != nil {
			return nil, oops.
				Code("INVALID_ROUTER_HASH").
				In("ntcp2-examples").
				Wrapf(err, "invalid router hash")
		}
		return routerHash, nil
	} else if !args.Demo && !args.Generate {
		return GenerateRandomKey()
	}
	return nil, nil
}

// parseRemoteRouterHash handles parsing or generation of remote router hash
func parseRemoteRouterHash(args *NTCP2Args) ([]byte, error) {
	if args.RemoteRouterHash != "" {
		remoteRouterHash, err := ParseKeyFromHex(args.RemoteRouterHash)
		if err != nil {
			return nil, oops.
				Code("INVALID_REMOTE_ROUTER_HASH").
				In("ntcp2-examples").
				Wrapf(err, "invalid remote router hash")
		}
		return remoteRouterHash, nil
	} else if args.ClientAddr != "" && !args.Demo && !args.Generate {
		return GenerateRandomKey()
	}
	return nil, nil
}

// parseDestinationHash handles parsing of destination hash if provided
func parseDestinationHash(args *NTCP2Args) ([]byte, error) {
	if args.DestinationHash != "" {
		destHash, err := ParseKeyFromHex(args.DestinationHash)
		if err != nil {
			return nil, oops.
				Code("INVALID_DESTINATION_HASH").
				In("ntcp2-examples").
				Wrapf(err, "invalid destination hash")
		}
		return destHash, nil
	}
	return nil, nil
}

// parseStaticKey handles parsing or generation of static key
func parseStaticKey(args *NTCP2Args) ([]byte, error) {
	if args.StaticKey != "" {
		staticKey, err := ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, oops.
				Code("INVALID_STATIC_KEY").
				In("ntcp2-examples").
				Wrapf(err, "invalid static key")
		}
		return staticKey, nil
	} else if !args.Demo && !args.Generate {
		return GenerateRandomKey()
	}
	return nil, nil
}

// ParseNTCP2Keys handles parsing of NTCP2-specific cryptographic material
func ParseNTCP2Keys(args *NTCP2Args) (routerHash, remoteRouterHash, destHash, staticKey []byte, err error) {
	routerHash, err = parseRouterHash(args)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	remoteRouterHash, err = parseRemoteRouterHash(args)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	destHash, err = parseDestinationHash(args)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	staticKey, err = parseStaticKey(args)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return routerHash, remoteRouterHash, destHash, staticKey, nil
}

// RunNTCP2Demo executes demonstration mode for NTCP2
func RunNTCP2Demo() {
	fmt.Println("=== NTCP2 (Noise over I2P) Demonstration ===")
	fmt.Println()

	demonstrateNTCP2Pattern()
	demonstrateNTCP2Addressing()
	demonstrateNTCP2Configuration()
}

// generateNTCP2Material generates all 4 pieces of NTCP2 crypto material
func generateNTCP2Material() (routerHash, remoteRouterHash, staticKey, destinationHash []byte, err error) {
	routerHash, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate router hash: %w", err)
	}
	remoteRouterHash, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate remote router hash: %w", err)
	}
	staticKey, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate static key: %w", err)
	}
	destinationHash, err = GenerateRandomKey()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate destination hash: %w", err)
	}
	return routerHash, remoteRouterHash, staticKey, destinationHash, nil
}

// displayNTCP2Material prints the generated material and usage examples
func displayNTCP2Material(routerHash, remoteRouterHash, staticKey, destinationHash []byte) {
	fmt.Printf("🔑 NTCP2 Cryptographic Material:\n")
	fmt.Printf("  Router Hash:        %s\n", KeyToHex(routerHash))
	fmt.Printf("  Remote Router Hash: %s\n", KeyToHex(remoteRouterHash))
	fmt.Printf("  Static Key:         %s\n", KeyToHex(staticKey))
	fmt.Printf("  Destination Hash:   %s\n", KeyToHex(destinationHash))
	fmt.Println()

	fmt.Println("Usage in commands:")
	fmt.Printf("  -router-hash %s\n", KeyToHex(routerHash))
	fmt.Printf("  -remote-router-hash %s\n", KeyToHex(remoteRouterHash))
	fmt.Printf("  -static-key %s\n", KeyToHex(staticKey))
	fmt.Printf("  -destination-hash %s\n", KeyToHex(destinationHash))
	fmt.Println("\nExample server command:")
	fmt.Printf("  go run main.go -server localhost:7654 -router-hash %s -static-key %s\n",
		KeyToHex(routerHash), KeyToHex(staticKey))
	fmt.Println("\nExample client command:")
	fmt.Printf("  go run main.go -client localhost:7654 -router-hash %s -remote-router-hash %s -static-key %s\n",
		KeyToHex(routerHash), KeyToHex(remoteRouterHash), KeyToHex(staticKey))
}

// RunNTCP2Generate generates and displays NTCP2 cryptographic material
func RunNTCP2Generate() {
	fmt.Println("=== NTCP2 Cryptographic Material Generation ===")
	fmt.Println()

	fmt.Println("Generating NTCP2 material for testing...")

	routerHash, remoteRouterHash, staticKey, destinationHash, err := generateNTCP2Material()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	fmt.Println("✅ NTCP2 material generated successfully!")
	fmt.Println()

	displayNTCP2Material(routerHash, remoteRouterHash, staticKey, destinationHash)
}

// demonstrateNTCP2Pattern shows NTCP2's use of the IK pattern
func demonstrateNTCP2Pattern() {
	PrintLines(
		"🔐 NTCP2 Noise Protocol Pattern:",
		"=================================",
		"NTCP2 exclusively uses: Noise_XK_25519_AESGCM_SHA256",
		"  • XK Pattern: Initiator sends static key, knows responder's static key",
		"  • Curve25519: Elliptic curve for key exchange",
		"  • AESGCM: Authenticated encryption",
		"  • SHA256: Hash function",
		"  • Requirements: Local static key + Remote router hash",
		"",
	)
}

// demonstrateNTCP2Addressing shows NTCP2 addressing capabilities
func demonstrateNTCP2Addressing() {
	fmt.Println("📍 NTCP2 Addressing System:")
	fmt.Println("===========================")

	// Generate sample data for demonstration
	sampleRouterHash := make([]byte, 32)
	copy(sampleRouterHash, "sample_router_hash_32_bytes.....")

	fmt.Printf("Router-to-Router Connection:\n")
	fmt.Printf("  • Uses router hash for identification\n")
	fmt.Printf("  • Example: ntcp2://127.0.0.1:7654 (role=initiator, router=%x...)\n", sampleRouterHash[:8])
	fmt.Println()

	fmt.Printf("Tunnel Connection:\n")
	fmt.Printf("  • Uses router hash + destination hash\n")
	fmt.Printf("  • Example: ntcp2://127.0.0.1:7654 (role=initiator, router=%x..., dest=%x...)\n",
		sampleRouterHash[:8], sampleRouterHash[:8])
	fmt.Println()
}

// demonstrateNTCP2Configuration shows NTCP2 configuration options
func demonstrateNTCP2Configuration() {
	PrintLines(
		"⚙️  NTCP2 Configuration Options:",
		"===============================",
		"",
		"Core Configuration:",
		"  • Router Hash: 32-byte identifier for local I2P router",
		"  • Static Key: 32-byte Curve25519 private key",
		"  • Remote Router Hash: 32-byte identifier for remote router",
		"",
		"NTCP2-Specific Features:",
		"  • AES Obfuscation: Additional encryption layer",
		"  • SipHash Length: Length field obfuscation",
		"  • Frame Padding: Variable-size frame padding",
		"  • Max Frame Size: Configurable frame size limit",
		"",
		"Timeouts:",
		"  • Handshake: 45 seconds (I2P standard)",
		"  • Read/Write: 60 seconds",
		"",
	)
}
