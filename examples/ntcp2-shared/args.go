// Package shared provides NTCP2-specific utilities for go-noise examples
package shared

import (
	"flag"
	"fmt"
	"time"

	"github.com/go-i2p/go-noise/examples/shared"
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
	flag.StringVar(&args.ServerAddr, "server", "", "Run as server on specified address (e.g., localhost:7654)")
	flag.StringVar(&args.ClientAddr, "client", "", "Run as client connecting to specified address")

	// NTCP2-specific material (all 64-character hex strings for 32-byte values)
	flag.StringVar(&args.RouterHash, "router-hash", "", "Local router hash as 64-character hex string (generated if empty)")
	flag.StringVar(&args.RemoteRouterHash, "remote-router-hash", "", "Remote router hash as 64-character hex string (generated if empty)")
	flag.StringVar(&args.DestinationHash, "destination-hash", "", "Destination hash for tunnel connections (optional)")

	// Cryptographic keys
	flag.StringVar(&args.StaticKey, "static-key", "", "Static private key as 64-character hex string (generated if empty)")

	// Timeouts
	flag.DurationVar(&args.HandshakeTimeout, "handshake-timeout", 45*time.Second, "NTCP2 handshake timeout")
	flag.DurationVar(&args.ReadTimeout, "read-timeout", 60*time.Second, "Read operation timeout")
	flag.DurationVar(&args.WriteTimeout, "write-timeout", 60*time.Second, "Write operation timeout")

	// NTCP2 features
	flag.BoolVar(&args.EnableAESObfuscation, "aes-obfuscation", true, "Enable AES obfuscation modifier")
	flag.BoolVar(&args.EnableSipHashLength, "siphash-length", true, "Enable SipHash length modifier")
	flag.IntVar(&args.MaxFrameSize, "max-frame-size", 16384, "Maximum frame size in bytes")

	// Operation modes
	flag.BoolVar(&args.Demo, "demo", false, "Run demonstration mode showing NTCP2 configurations")
	flag.BoolVar(&args.Generate, "generate", false, "Generate and display NTCP2 cryptographic material")
	flag.BoolVar(&args.Verbose, "verbose", false, "Enable verbose logging")

	flag.Parse()

	return args, nil
}

// PrintNTCP2Usage displays usage information for an NTCP2 example
func PrintNTCP2Usage(appName, description string) {
	fmt.Printf("%s - %s\n\n", appName, description)
	fmt.Println("Usage:")
	fmt.Printf("  %s [options]\n\n", appName)
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Printf("  # Generate NTCP2 material for testing:\n")
	fmt.Printf("  %s -generate\n\n", appName)
	fmt.Printf("  # Run demo mode:\n")
	fmt.Printf("  %s -demo\n\n", appName)
	fmt.Printf("  # Run NTCP2 server:\n")
	fmt.Printf("  %s -server localhost:7654 -router-hash <64-char-hex>\n\n", appName)
	fmt.Printf("  # Run NTCP2 client:\n")
	fmt.Printf("  %s -client localhost:7654 -router-hash <64-char-hex> -remote-router-hash <64-char-hex>\n\n", appName)
	fmt.Println("Note: NTCP2 uses Noise_IK_25519_AESGCM_SHA256 pattern exclusively")
}

// ValidateNTCP2Args performs validation on parsed NTCP2 arguments
func (args *NTCP2Args) ValidateArgs() error {
	// Check that we have either server, client, demo, or generate mode
	modeCount := 0
	if args.ServerAddr != "" {
		modeCount++
	}
	if args.ClientAddr != "" {
		modeCount++
	}
	if args.Demo {
		modeCount++
	}
	if args.Generate {
		modeCount++
	}

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

	// For non-demo/generate modes, require router hash
	if (args.ServerAddr != "" || args.ClientAddr != "") && args.RouterHash == "" {
		return oops.
			Code("MISSING_ROUTER_HASH").
			In("ntcp2-examples").
			Errorf("NTCP2 requires a router hash (-router-hash)")
	}

	// For client mode, require remote router hash
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
		routerHash, err := shared.ParseKeyFromHex(args.RouterHash)
		if err != nil {
			return nil, oops.
				Code("INVALID_ROUTER_HASH").
				In("ntcp2-examples").
				Wrapf(err, "invalid router hash")
		}
		return routerHash, nil
	} else if !args.Demo && !args.Generate {
		return shared.GenerateRandomKey()
	}
	return nil, nil
}

// parseRemoteRouterHash handles parsing or generation of remote router hash
func parseRemoteRouterHash(args *NTCP2Args) ([]byte, error) {
	if args.RemoteRouterHash != "" {
		remoteRouterHash, err := shared.ParseKeyFromHex(args.RemoteRouterHash)
		if err != nil {
			return nil, oops.
				Code("INVALID_REMOTE_ROUTER_HASH").
				In("ntcp2-examples").
				Wrapf(err, "invalid remote router hash")
		}
		return remoteRouterHash, nil
	} else if args.ClientAddr != "" && !args.Demo && !args.Generate {
		return shared.GenerateRandomKey()
	}
	return nil, nil
}

// parseDestinationHash handles parsing of destination hash if provided
func parseDestinationHash(args *NTCP2Args) ([]byte, error) {
	if args.DestinationHash != "" {
		destHash, err := shared.ParseKeyFromHex(args.DestinationHash)
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
		staticKey, err := shared.ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, oops.
				Code("INVALID_STATIC_KEY").
				In("ntcp2-examples").
				Wrapf(err, "invalid static key")
		}
		return staticKey, nil
	} else if !args.Demo && !args.Generate {
		return shared.GenerateRandomKey()
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

// RunNTCP2Generate generates and displays NTCP2 cryptographic material
func RunNTCP2Generate() {
	fmt.Println("=== NTCP2 Cryptographic Material Generation ===")
	fmt.Println()

	fmt.Println("Generating NTCP2 material for testing...")

	// Generate router hashes and keys
	routerHash, err := shared.GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate router hash: %v\n", err)
		return
	}

	remoteRouterHash, err := shared.GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate remote router hash: %v\n", err)
		return
	}

	staticKey, err := shared.GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate static key: %v\n", err)
		return
	}

	destinationHash, err := shared.GenerateRandomKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate destination hash: %v\n", err)
		return
	}

	fmt.Println("✅ NTCP2 material generated successfully!")
	fmt.Println()

	// Display material
	fmt.Printf("🔑 NTCP2 Cryptographic Material:\n")
	fmt.Printf("  Router Hash:        %s\n", shared.KeyToHex(routerHash))
	fmt.Printf("  Remote Router Hash: %s\n", shared.KeyToHex(remoteRouterHash))
	fmt.Printf("  Static Key:         %s\n", shared.KeyToHex(staticKey))
	fmt.Printf("  Destination Hash:   %s\n", shared.KeyToHex(destinationHash))
	fmt.Println()

	// Show usage examples
	fmt.Println("Usage in commands:")
	fmt.Printf("  -router-hash %s\n", shared.KeyToHex(routerHash))
	fmt.Printf("  -remote-router-hash %s\n", shared.KeyToHex(remoteRouterHash))
	fmt.Printf("  -static-key %s\n", shared.KeyToHex(staticKey))
	fmt.Printf("  -destination-hash %s\n", shared.KeyToHex(destinationHash))
	fmt.Println("\nExample server command:")
	fmt.Printf("  go run main.go -server localhost:7654 -router-hash %s -static-key %s\n",
		shared.KeyToHex(routerHash), shared.KeyToHex(staticKey))
	fmt.Println("\nExample client command:")
	fmt.Printf("  go run main.go -client localhost:7654 -router-hash %s -remote-router-hash %s -static-key %s\n",
		shared.KeyToHex(routerHash), shared.KeyToHex(remoteRouterHash), shared.KeyToHex(staticKey))
}

// demonstrateNTCP2Pattern shows NTCP2's use of the IK pattern
func demonstrateNTCP2Pattern() {
	fmt.Println("🔐 NTCP2 Noise Protocol Pattern:")
	fmt.Println("=================================")
	fmt.Println("NTCP2 exclusively uses: Noise_IK_25519_AESGCM_SHA256")
	fmt.Println("  • IK Pattern: Initiator knows responder's static key")
	fmt.Println("  • Curve25519: Elliptic curve for key exchange")
	fmt.Println("  • AESGCM: Authenticated encryption")
	fmt.Println("  • SHA256: Hash function")
	fmt.Println("  • Requirements: Local static key + Remote router hash")
	fmt.Println()
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
	fmt.Println("⚙️  NTCP2 Configuration Options:")
	fmt.Println("===============================")

	fmt.Println("Core Configuration:")
	fmt.Println("  • Router Hash: 32-byte identifier for local I2P router")
	fmt.Println("  • Static Key: 32-byte Curve25519 private key")
	fmt.Println("  • Remote Router Hash: 32-byte identifier for remote router")
	fmt.Println()

	fmt.Println("NTCP2-Specific Features:")
	fmt.Println("  • AES Obfuscation: Additional encryption layer")
	fmt.Println("  • SipHash Length: Length field obfuscation")
	fmt.Println("  • Frame Padding: Variable-size frame padding")
	fmt.Println("  • Max Frame Size: Configurable frame size limit")
	fmt.Println()

	fmt.Println("Timeouts:")
	fmt.Println("  • Handshake: 45 seconds (I2P standard)")
	fmt.Println("  • Read/Write: 60 seconds")
	fmt.Println()
}
