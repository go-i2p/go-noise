// Example: NoiseListener demonstration with complete handshake
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("noise-listener")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "127.0.0.1:0" // Default listener address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("noise-listener", "NoiseListener demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if args.Demo {
		runListenerDemo(args)
		return
	}

	if args.Generate {
		shared.RunGenerate()
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := parseListenerKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run listener server
	runListenerServer(args, staticKey)
}

// runListenerServer starts a persistent listener server
func runListenerServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting NoiseListener server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

	// Create server configuration
	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Add static key for patterns that require it
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Create underlying TCP listener
	tcpListener, err := net.Listen("tcp", args.ServerAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	fmt.Printf("✓ TCP listener created on: %s\n", tcpListener.Addr().String())

	// Create the NoiseListener
	noiseListener, err := noise.NewNoiseListener(tcpListener, config)
	if err != nil {
		log.Fatalf("Failed to create NoiseListener: %v", err)
	}
	defer noiseListener.Close()

	fmt.Printf("✓ NoiseListener created: %s\n", noiseListener.Addr().String())
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")

	// Accept connections in a loop
	for {
		conn, err := noiseListener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		// Handle each connection in a separate goroutine
		go handleListenerConnection(conn)
	}
}

// runListenerDemo demonstrates NoiseListener with a simulated client
func runListenerDemo(args *shared.CommonArgs) {
	fmt.Printf("🎭 Running NoiseListener demonstration with pattern %s\n", args.Pattern)

	// Use demo address if not specified
	demoAddr := "127.0.0.1:0"
	if args.ServerAddr != "" {
		demoAddr = args.ServerAddr
	}

	// Parse keys for demo
	staticKey, _, err := parseListenerKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp", demoAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	fmt.Printf("✓ TCP listener created on: %s\n", tcpListener.Addr().String())

	// Create NoiseListener configuration
	listenerConfig := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		listenerConfig = listenerConfig.WithStaticKey(staticKey)
	}

	// Create the NoiseListener
	noiseListener, err := noise.NewNoiseListener(tcpListener, listenerConfig)
	if err != nil {
		log.Fatalf("Failed to create NoiseListener: %v", err)
	}
	defer noiseListener.Close()

	fmt.Printf("✓ NoiseListener created: %s\n", noiseListener.Addr().String())

	// Start the server in a goroutine
	go func() {
		fmt.Println("📡 Echo server starting, waiting for connections...")
		for {
			conn, err := noiseListener.Accept()
			if err != nil {
				fmt.Printf("Accept error (likely due to shutdown): %v\n", err)
				return
			}
			go handleListenerConnection(conn)
		}
	}()

	// Simulate a client connection
	time.Sleep(100 * time.Millisecond) // Give server time to start
	simulateClient(tcpListener.Addr().String(), args.Pattern, staticKey)

	// Keep the server running briefly
	time.Sleep(2 * time.Second)
	fmt.Println("🛑 Shutting down listener demo...")
}

// handleListenerConnection handles a single connection with complete handshake
func handleListenerConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

	// Perform the Noise handshake
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return
		}
		fmt.Printf("✅ Handshake completed with %s\n", clientAddr)
	}

	// Echo loop - read data and echo it back
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("Client %s disconnected\n", clientAddr)
			} else {
				fmt.Printf("Read error from %s: %v\n", clientAddr, err)
			}
			return
		}

		message := string(buffer[:n])
		fmt.Printf("📨 Received from %s: %s\n", clientAddr, message)

		// Echo the message back
		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			fmt.Printf("Write error to %s: %v\n", clientAddr, err)
			return
		}

		fmt.Printf("📤 Echoed to %s: %s\n", clientAddr, response)
	}
}

// simulateClient simulates a client connecting to the echo server
func simulateClient(serverAddr, pattern string, serverKey []byte) {
	fmt.Printf("🤖 Simulating client connection to: %s\n", serverAddr)

	// Create client configuration (initiator = true)
	clientConfig := noise.NewConnConfig(pattern, true).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(30 * time.Second).
		WithWriteTimeout(30 * time.Second)

	// Add static key if needed (same as server key for this demo)
	if shared.RequiresLocalStaticKey(pattern) && serverKey != nil {
		clientConfig = clientConfig.WithStaticKey(serverKey)
	}

	// Connect using DialNoise for complete setup
	conn, err := noise.DialNoise("tcp", serverAddr, clientConfig)
	if err != nil {
		fmt.Printf("Failed to connect to server: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())

	// Perform the handshake
	fmt.Println("🔐 Client performing handshake...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = conn.Handshake(ctx)
	if err != nil {
		fmt.Printf("Client handshake failed: %v\n", err)
		return
	}
	fmt.Println("✅ Client handshake completed!")

	// Send test message
	testMessage := "Hello from simulated client!"
	fmt.Printf("📤 Sending: %s\n", testMessage)
	_, err = conn.Write([]byte(testMessage))
	if err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		return
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return
	}

	response := string(buffer[:n])
	fmt.Printf("📨 Received response: %s\n", response)
	fmt.Println("✅ Client simulation completed successfully!")
}

// parseListenerKeys handles key parsing for the listener
func parseListenerKeys(args *shared.CommonArgs) ([]byte, []byte, error) {
	// For patterns that require local static key
	needsLocal, needsRemote := shared.GetPatternRequirements(args.Pattern)

	var staticKey, remoteKey []byte
	var err error

	if needsLocal {
		if args.StaticKey != "" {
			staticKey, err = shared.ParseKeyFromHex(args.StaticKey)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid static key: %w", err)
			}
		} else {
			// Generate a key for the demo
			staticKey, err = shared.GenerateRandomKey()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate static key: %w", err)
			}
		}
	}

	if needsRemote && args.RemoteKey != "" {
		remoteKey, err = shared.ParseKeyFromHex(args.RemoteKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid remote key: %w", err)
		}
	}

	return staticKey, remoteKey, nil
}
