// Example: Echo Server using Noise Protocol with complete handshake
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("echoserver")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Override some defaults for server mode
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "localhost:8080" // Default server address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("echoserver", "Noise Protocol echo server supporting all patterns")
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

	// Parse keys for the selected pattern
	staticKey, _, err := parseServerKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run server
	if args.ServerAddr != "" {
		runEchoServer(args, staticKey)
	} else {
		fmt.Println("❌ Echo server requires -server address")
		shared.PrintUsage("echoserver", "Noise Protocol echo server supporting all patterns")
	}
}

// parseServerKeys handles key parsing for server configuration
func parseServerKeys(args *shared.CommonArgs) (staticKey, _ []byte, err error) {
	needsLocal, _ := shared.GetPatternRequirements(args.Pattern)

	// Parse or generate static key if needed
	if needsLocal {
		staticKey, err = shared.ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, nil, err
		}

		if args.Verbose {
			fmt.Printf("🔑 Server using static key: %s\n", shared.KeyToHex(staticKey))
		}
	}

	return staticKey, nil, nil
}

// runEchoServer starts an echo server with complete Noise handshake
func runEchoServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting Noise echo server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

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

	// Start the server using ListenNoise for automatic transport wrapping
	listener, err := noise.ListenNoise("tcp", args.ServerAddr, config)
	if err != nil {
		log.Fatalf("Failed to start echo server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Echo server listening on: %s\n", listener.Addr())
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")

	// Accept connections in a loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}

		// Handle each connection in its own goroutine
		go handleEchoConnection(conn, args)
	}
}

// handleEchoConnection handles a single echo connection with handshake
func handleEchoConnection(conn net.Conn, args *shared.CommonArgs) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New client connected: %s\n", clientAddr)

	// Perform the Noise handshake
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

	// Echo loop - read messages and echo them back
	buffer := make([]byte, 1024)
	for {
		// Read message from client
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error from %s: %v", clientAddr, err)
			}
			break
		}

		message := strings.TrimSpace(string(buffer[:n]))
		fmt.Printf("📨 Received from %s: %q\n", clientAddr, message)

		// Check for quit command
		if message == "quit" {
			fmt.Printf("👋 Client %s requested disconnect\n", clientAddr)
			break
		}

		// Echo the message back
		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("Write error to %s: %v", clientAddr, err)
			break
		}
		fmt.Printf("📤 Sent to %s: %q\n", clientAddr, response)
	}

	fmt.Printf("🔌 Client %s disconnected\n", clientAddr)
}
