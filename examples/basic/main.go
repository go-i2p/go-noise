// Example: Basic usage of the go-noise library with configurable patterns and complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("basic-noise")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("basic-noise", "Basic Noise Protocol example with all pattern support")
		return
	}

	// Handle special modes
	if args.Demo {
		shared.RunDemo()
		return
	}

	if args.Generate {
		shared.RunGenerate()
		return
	}

	// Parse and validate keys for the selected pattern
	staticKey, remoteKey, err := parseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run client or server based on arguments
	if args.ServerAddr != "" {
		runBasicServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runBasicClient(args, staticKey, remoteKey)
	}
}

// parseKeys handles key parsing and generation for the selected pattern
func parseKeys(args *shared.CommonArgs) (staticKey, remoteKey []byte, err error) {
	needsLocal, needsRemote := shared.GetPatternRequirements(args.Pattern)

	// Parse or generate static key if needed
	if needsLocal {
		staticKey, err = shared.ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, nil, err
		}

		if args.Verbose {
			fmt.Printf("🔑 Using static key: %s\n", shared.KeyToHex(staticKey))
		}
	}

	// Parse or generate remote key if needed
	if needsRemote {
		remoteKey, err = shared.ParseKeyFromHex(args.RemoteKey)
		if err != nil {
			return nil, nil, err
		}

		if args.Verbose {
			fmt.Printf("🔑 Using remote key: %s\n", shared.KeyToHex(remoteKey))
		}
	}

	return staticKey, remoteKey, nil
}

// demonstrateBasicConfigurations shows examples of creating and validating Noise configurations.
func demonstrateBasicConfigurations() {
	// 1. Create configuration for XX pattern (most common)
	configXX := noise.NewConnConfig("XX", true).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	fmt.Printf("XX Pattern Config: %s\n", configXX.Pattern)

	// 2. Create configuration with full pattern name
	configFull := noise.NewConnConfig("Noise_IK_25519_AESGCM_SHA256", false).
		WithHandshakeTimeout(15 * time.Second)

	fmt.Printf("Full Pattern Config: %s\n", configFull.Pattern)

	// 3. Validate configurations
	validateConfiguration("XX", configXX)
	validateConfiguration("Full", configFull)
}

// validateConfiguration validates a Noise configuration and prints the result.
func validateConfiguration(name string, config *noise.ConnConfig) {
	if err := config.Validate(); err != nil {
		fmt.Printf("%s config validation failed: %v\n", name, err)
	} else {
		fmt.Printf("%s config is valid\n", name)
	}
}

// demonstrateSupportedPatterns shows all supported Noise patterns and their validation status.
func demonstrateSupportedPatterns() {
	supportedPatterns := []string{
		"NN", "NK", "NX",
		"XN", "XK", "XX",
		"KN", "KK", "KX",
		"IN", "IK", "IX",
		"N", "K", "X",
	}

	fmt.Println("\nSupported Noise patterns:")
	for _, pattern := range supportedPatterns {
		config := noise.NewConnConfig(pattern, true)
		if err := config.Validate(); err == nil {
			fmt.Printf("✓ %s\n", pattern)
		} else {
			fmt.Printf("✗ %s: %v\n", pattern, err)
		}
	}
}

// demonstrateNoiseAddressing shows examples of NoiseAddr usage and formatting.
func demonstrateNoiseAddressing() {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "localhost:8080")
	noiseAddr := noise.NewNoiseAddr(tcpAddr, "XX", "initiator")

	fmt.Printf("\nNoise Address Examples:\n")
	fmt.Printf("Network: %s\n", noiseAddr.Network())
	fmt.Printf("String: %s\n", noiseAddr.String())
	fmt.Printf("Pattern: %s\n", noiseAddr.Pattern())
	fmt.Printf("Role: %s\n", noiseAddr.Role())

	printConnectionExample()
}

// printConnectionExample prints a commented example of NoiseConn usage.
func printConnectionExample() {
	fmt.Println("\n// Note: Actual connection creation would require a real net.Conn")
	fmt.Println("// and proper logger setup, which is commented out due to logger issues")
	fmt.Println("//")
	fmt.Println("// Example of creating a NoiseConn (requires working logger):")
	fmt.Println("// tcpConn, err := net.Dial(\"tcp\", \"localhost:8080\")")
	fmt.Println("// noiseConn, err := noise.NewNoiseConn(tcpConn, configXX)")
	fmt.Println("// err := noiseConn.Handshake(ctx)")
}

// runBasicServer starts a basic Noise server with complete handshake
func runBasicServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting basic Noise server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

	// Create server configuration (responder)
	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Add static key if required
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
		if args.Verbose {
			fmt.Printf("🔑 Server using static key: %s\n", shared.KeyToHex(staticKey))
		}
	}

	// Start the server
	listener, err := noise.ListenNoise("tcp", args.ServerAddr, config)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Server listening on: %s\n", listener.Addr())
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}

		go handleBasicConnection(conn, args)
	}
}

// runBasicClient connects to a basic Noise server with complete handshake
func runBasicClient(args *shared.CommonArgs, staticKey, remoteKey []byte) {
	fmt.Printf("🔌 Connecting to server at %s with pattern %s\n", args.ClientAddr, args.Pattern)

	// Create client configuration (initiator)
	config := noise.NewConnConfig(args.Pattern, true).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Add static key if required
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
		if args.Verbose {
			fmt.Printf("🔑 Client using static key: %s\n", shared.KeyToHex(staticKey))
		}
	}

	// Add remote key if required
	if remoteKey != nil {
		config = config.WithRemoteKey(remoteKey)
		if args.Verbose {
			fmt.Printf("🔑 Client using remote key: %s\n", shared.KeyToHex(remoteKey))
		}
	}

	// Connect to server
	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to: %s\n", conn.RemoteAddr())

	// Perform handshake
	fmt.Println("🔐 Starting handshake...")
	ctx, cancel := context.WithTimeout(context.Background(), args.HandshakeTimeout)
	defer cancel()

	err = conn.Handshake(ctx)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}
	fmt.Println("✅ Handshake completed - secure channel established!")

	// Send test message
	message := "Hello from basic client!"
	fmt.Printf("📤 Sending: %s\n", message)
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	response := string(buffer[:n])
	fmt.Printf("📨 Received: %s\n", response)
	fmt.Println("✓ Basic Noise communication completed successfully!")
}

// handleBasicConnection handles a server connection with handshake
func handleBasicConnection(conn net.Conn, args *shared.CommonArgs) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New client connected: %s\n", clientAddr)

	// Perform handshake
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
		ctx, cancel := context.WithTimeout(context.Background(), args.HandshakeTimeout)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return
		}
		fmt.Printf("✅ Handshake completed with %s\n", clientAddr)
	}

	// Simple echo loop
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Read error from %s: %v", clientAddr, err)
		return
	}

	message := string(buffer[:n])
	fmt.Printf("📨 Received from %s: %s\n", clientAddr, message)

	response := fmt.Sprintf("Echo: %s", message)
	_, err = conn.Write([]byte(response))
	if err != nil {
		log.Printf("Write error to %s: %v", clientAddr, err)
		return
	}

	fmt.Printf("📤 Sent to %s: %s\n", clientAddr, response)
	fmt.Printf("🔌 Connection with %s completed\n", clientAddr)
}
