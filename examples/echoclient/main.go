// Example: Echo Client using Noise Protocol with complete handshake
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("echoclient")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Override some defaults for client mode
	if args.ClientAddr == "" && args.ServerAddr == "" && !args.Demo && !args.Generate {
		args.ClientAddr = "localhost:8080" // Default client address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("echoclient", "Noise Protocol echo client supporting all patterns")
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
	staticKey, remoteKey, err := parseClientKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run client
	if args.ClientAddr != "" {
		runEchoClient(args, staticKey, remoteKey)
	} else {
		fmt.Println("❌ Echo client requires -client address")
		shared.PrintUsage("echoclient", "Noise Protocol echo client supporting all patterns")
	}
}

// parseClientKeys handles key parsing for client configuration
func parseClientKeys(args *shared.CommonArgs) (staticKey, remoteKey []byte, err error) {
	needsLocal, needsRemote := shared.GetPatternRequirements(args.Pattern)

	// Parse or generate static key if needed
	if needsLocal {
		staticKey, err = shared.ParseKeyFromHex(args.StaticKey)
		if err != nil {
			return nil, nil, err
		}

		if args.Verbose {
			fmt.Printf("🔑 Client using static key: %s\n", shared.KeyToHex(staticKey))
		}
	}

	// Parse or generate remote key if needed
	if needsRemote {
		remoteKey, err = shared.ParseKeyFromHex(args.RemoteKey)
		if err != nil {
			return nil, nil, err
		}

		if args.Verbose {
			fmt.Printf("🔑 Client using remote key: %s\n", shared.KeyToHex(remoteKey))
		}
	}

	return staticKey, remoteKey, nil
}

// runEchoClient connects to echo server and performs interactive communication
func runEchoClient(args *shared.CommonArgs, staticKey, remoteKey []byte) {
	fmt.Printf("🔌 Connecting to echo server at %s with pattern %s\n", args.ClientAddr, args.Pattern)

	// Create client configuration
	config := createClientConfig(args, staticKey, remoteKey)

	// Establish connection
	conn := establishConnection(args.ClientAddr, config)
	defer conn.Close()

	// Perform handshake
	performHandshake(conn, args.HandshakeTimeout)

	// Start interactive communication
	fmt.Println("\n💬 You can now send messages to the echo server.")
	fmt.Println("Type 'quit' to exit, or any message to echo it back.")

	// Start response reader and handle messages
	var wg sync.WaitGroup
	startResponseReader(conn, &wg)
	handleMessageLoop(conn)

	// Cleanup and shutdown
	cleanupConnection(conn, &wg)
}

// createClientConfig builds the noise connection configuration for the client
func createClientConfig(args *shared.CommonArgs, staticKey, remoteKey []byte) *noise.ConnConfig {
	config := noise.NewConnConfig(args.Pattern, true).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	// Add static key if required
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Add remote key if required
	if remoteKey != nil {
		config = config.WithRemoteKey(remoteKey)
	}

	return config
}

// establishConnection creates and returns a connection to the server
func establishConnection(serverAddr string, config *noise.ConnConfig) *noise.NoiseConn {
	conn, err := noise.DialNoise("tcp", serverAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())
	return conn
}

// performHandshake executes the noise handshake with the server
func performHandshake(conn *noise.NoiseConn, timeout time.Duration) {
	fmt.Println("🔐 Starting handshake...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := conn.Handshake(ctx)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}
	fmt.Println("✅ Handshake completed - secure channel established!")
}

// startResponseReader launches a goroutine to read responses from the server
func startResponseReader(conn *noise.NoiseConn, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %v", err)
				}
				return
			}
			response := string(buffer[:n])
			fmt.Printf("🔊 Server: %s\n", response)
		}
	}()
}

// handleMessageLoop processes user input and sends messages to the server
func handleMessageLoop(conn *noise.NoiseConn) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := strings.TrimSpace(scanner.Text())
		if message == "" {
			continue
		}

		// Send message to server
		_, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("Write error: %v", err)
			break
		}

		// Exit if quit command
		if message == "quit" {
			fmt.Println("👋 Goodbye!")
			break
		}

		// Brief pause for response
		time.Sleep(10 * time.Millisecond)
	}
}

// cleanupConnection closes the connection and waits for goroutines to finish
func cleanupConnection(conn *noise.NoiseConn, wg *sync.WaitGroup) {
	conn.Close()
	wg.Wait()
}
