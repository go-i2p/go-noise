// Example: Handshake retry mechanisms with complete connections
package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/exampleutil"
)

func main() {
	run()
}

func run() {
	// Parse command line arguments
	args, err := exampleutil.ParseCommonArgs("retry-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "127.0.0.1:8080" // Default retry test address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		exampleutil.PrintUsage("retry-example", "Handshake retry mechanisms supporting all Noise patterns")
		return
	}

	// Handle special modes
	if args.Demo {
		demonstrateRetryConfigurations()
		return
	}

	if args.Generate {
		exampleutil.RunGenerate()
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := exampleutil.ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run retry demonstration
	runRetryExample(args, staticKey)
}

// runRetryExample demonstrates retry mechanisms with real connections
func runRetryExample(args *exampleutil.CommonArgs, staticKey []byte) {
	retries := 3                      // Default retry count
	backoff := 500 * time.Millisecond // Default backoff

	fmt.Printf("🔄 Testing retry mechanisms with %s pattern\n", args.Pattern)
	fmt.Printf("Server: %s, Retries: %d, Backoff: %v\n", args.ServerAddr, retries, backoff)

	// Start echo server for testing
	go startRetryTestServer(args.ServerAddr, args.Pattern, staticKey)
	time.Sleep(200 * time.Millisecond) // Wait for server to start

	// Create client configuration with retry settings
	config := noise.NewConnConfig(args.Pattern, true). // initiator = true
								WithHandshakeRetries(retries).
								WithRetryBackoff(backoff).
								WithHandshakeTimeout(args.HandshakeTimeout)

	// Add static key if provided
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	fmt.Printf("📋 Configuration: retries=%d, backoff=%v, timeout=%v\n",
		config.HandshakeRetries, config.RetryBackoff, config.HandshakeTimeout)

	// Test 1: Successful connection with retry capability
	fmt.Println("\n🧪 Test 1: Successful connection")
	testSuccessfulConnection(args.ServerAddr, config)

	// Test 2: Using high-level transport functions with retry
	fmt.Println("\n🧪 Test 2: High-level transport functions")
	testTransportFunctions(args.ServerAddr, config)

	// Test 3: Context cancellation during retry
	fmt.Println("\n🧪 Test 3: Context cancellation")
	testContextCancellation(args.ServerAddr, config)

	fmt.Println("\n✅ Retry example completed!")
}

// testSuccessfulConnection tests a successful connection with retry capability
func testSuccessfulConnection(serverAddr string, config *noise.ConnConfig) {
	conn, err := noise.DialNoise("tcp", serverAddr, config)
	if err != nil {
		log.Printf("❌ Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to: %s\n", conn.RemoteAddr())

	// Perform handshake with retry
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = conn.HandshakeWithRetry(ctx)
	if err != nil {
		log.Printf("❌ Handshake with retry failed: %v", err)
		return
	}

	fmt.Println("✅ Handshake with retry completed successfully!")

	sendAndReceive(conn, "Hello with retry!", "Received")
}

// sendAndReceive sends a test message on the connection and logs the response.
// This is a thin wrapper around exampleutil.SendAndReceive for local use.
func sendAndReceive(conn *noise.NoiseConn, message, responseLabel string) {
	exampleutil.SendAndReceive(conn, message, responseLabel)
}

// testTransportFunctions tests high-level transport functions with retry
func testTransportFunctions(serverAddr string, config *noise.ConnConfig) {
	fmt.Println("Testing DialNoiseWithHandshake...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := noise.DialNoiseWithHandshakeContext(ctx, "tcp", serverAddr, config)
	if err != nil {
		log.Printf("❌ DialNoiseWithHandshake failed: %v", err)
		return
	}
	defer conn.Close()

	fmt.Println("✅ DialNoiseWithHandshake completed successfully!")

	sendAndReceive(conn, "Hello from transport function!", "Transport function response")
}

// testContextCancellation tests context cancellation during retry
func testContextCancellation(serverAddr string, config *noise.ConnConfig) {
	// Create a context that will timeout quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	fmt.Println("Testing context cancellation (should timeout quickly)...")

	// Try to connect to a non-existent server to trigger retries
	badAddr := "127.0.0.1:9999" // Assume this port is not listening

	start := time.Now()
	conn, err := noise.DialNoiseWithHandshakeContext(ctx, "tcp", badAddr, config)
	duration := time.Since(start)

	if conn != nil {
		conn.Close()
	}

	if err != nil {
		fmt.Printf("✅ Context cancellation worked: %v (took %v)\n", err, duration)
	} else {
		fmt.Println("❌ Expected context cancellation but connection succeeded")
	}
}

// showBasicRetryConfig displays basic retry configuration examples
func showBasicRetryConfig() {
	fmt.Println("\n1. Basic Retry Configuration:")
	config := noise.NewConnConfig("XX", true).
		WithHandshakeRetries(3).
		WithRetryBackoff(500 * time.Millisecond).
		WithHandshakeTimeout(5 * time.Second)

	fmt.Printf("   - Pattern: %s\n", config.Pattern)
	fmt.Printf("   - Handshake Retries: %d\n", config.HandshakeRetries)
	fmt.Printf("   - Retry Backoff: %v\n", config.RetryBackoff)
	fmt.Printf("   - Handshake Timeout: %v\n", config.HandshakeTimeout)

	fmt.Println("\n2. No Retry Configuration (single attempt):")
	noRetryConfig := noise.NewConnConfig("NN", true).
		WithHandshakeRetries(0)

	fmt.Printf("   - Handshake Retries: %d\n", noRetryConfig.HandshakeRetries)

	fmt.Println("\n3. Infinite Retry Configuration:")
	infiniteConfig := noise.NewConnConfig("NN", true).
		WithHandshakeRetries(-1).
		WithRetryBackoff(100 * time.Millisecond)

	fmt.Printf("   - Handshake Retries: %d (infinite)\n", infiniteConfig.HandshakeRetries)
	fmt.Printf("   - Retry Backoff: %v\n", infiniteConfig.RetryBackoff)
}

// showBackoffCalculation displays exponential backoff calculations
func showBackoffCalculation() {
	fmt.Println("\n4. Backoff Calculation (exponential):")
	baseBackoff := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		backoff := time.Duration(float64(baseBackoff) * math.Pow(2, float64(attempt)))
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		fmt.Printf("   Attempt %d: %v\n", attempt+1, backoff)
	}
}

// showConfigValidation displays configuration validation examples
func showConfigValidation() {
	fmt.Println("\n5. Configuration Validation:")

	configs := map[string]*noise.ConnConfig{
		"Valid":           noise.NewConnConfig("NN", true).WithHandshakeRetries(3),
		"Invalid (< -1)":  noise.NewConnConfig("NN", true).WithHandshakeRetries(-5),
		"Invalid backoff": noise.NewConnConfig("NN", true).WithRetryBackoff(-time.Second),
	}

	for name, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			fmt.Printf("   ❌ %s: %v\n", name, err)
		} else {
			fmt.Printf("   ✅ %s: OK\n", name)
		}
	}

	fmt.Println("\n6. Available Transport Functions with Retry:")
	fmt.Println("   - DialNoiseWithHandshake(network, addr, config)")
	fmt.Println("   - DialNoiseWithHandshakeContext(ctx, network, addr, config)")
	fmt.Println("   - DialNoiseWithPoolAndHandshake(network, addr, config)")
	fmt.Println("   - DialNoiseWithPoolAndHandshakeContext(ctx, network, addr, config)")
}

// demonstrateRetryConfigurations shows various retry configuration examples
func demonstrateRetryConfigurations() {
	fmt.Println("=== Handshake Retry Configuration Examples ===")

	showBasicRetryConfig()
	showBackoffCalculation()
	showConfigValidation()
}

// startRetryTestServer starts a simple server for retry testing
func startRetryTestServer(addr, pattern string, staticKey []byte) {
	fmt.Printf("🚀 Starting retry test server on %s\n", addr)

	config := noise.NewListenerConfig(pattern).
		WithHandshakeTimeout(30 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	listener, err := noise.ListenNoise("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to start retry test server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Retry test server listening on: %s\n", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handleRetryTestConnection(conn)
	}
}

// handleRetryTestConnection handles connections for retry testing
func handleRetryTestConnection(conn net.Conn) {
	defer conn.Close()

	// Perform handshake
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			return
		}
	}

	// Simple echo
	exampleutil.EchoOnce(conn)
}
