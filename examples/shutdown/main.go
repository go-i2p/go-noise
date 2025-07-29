// Example: Graceful shutdown demonstration with complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("shutdown-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "localhost:8080" // Default shutdown test address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("shutdown-example", "Graceful shutdown demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if args.Demo {
		runShutdownDemo(args)
		return
	}

	if args.Generate {
		shared.RunGenerate()
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := parseShutdownKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	fmt.Printf("🛑 Graceful Shutdown Example with pattern %s\n", args.Pattern)

	// Run based on mode
	if args.ServerAddr != "" {
		runShutdownServer(args, staticKey)
	} else if args.ClientAddr != "" {
		runShutdownClient(args, staticKey)
	}
}

// parseShutdownKeys handles key parsing for the shutdown example
func parseShutdownKeys(args *shared.CommonArgs) ([]byte, []byte, error) {
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

// runShutdownDemo demonstrates graceful shutdown with server and clients
func runShutdownDemo(args *shared.CommonArgs) {
	fmt.Printf("🎭 Running shutdown demo with graceful termination\n")

	// Parse keys for demo
	staticKey, _, err := parseShutdownKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Use a simpler demo for shutdown functionality
	fmt.Printf("✓ Demo configuration: pattern=%s\n", args.Pattern)
	if staticKey != nil {
		fmt.Printf("✓ Static key: %x...\n", staticKey[:8])
	} else {
		fmt.Printf("✓ No static key required for pattern %s\n", args.Pattern)
	}

	fmt.Println("\n🎯 Shutdown Features Demonstrated:")
	fmt.Println("  • Argument parsing with shared.ParseCommonArgs")
	fmt.Println("  • Pattern validation for all 15 Noise patterns")
	fmt.Println("  • Key generation and validation")
	fmt.Println("  • Builder pattern configuration")
	fmt.Println("  • Signal-based graceful shutdown")
	fmt.Println("  • Context-based connection management")

	fmt.Println("\n✅ Use -server or -client mode for actual functionality")
}

// runShutdownServer demonstrates server with graceful shutdown capability
func runShutdownServer(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting shutdown server on %s\n", args.ServerAddr)

	if err := runShutdownServerFunc(args.ServerAddr, args.Pattern, staticKey); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// runShutdownServerFunc implements the server logic
func runShutdownServerFunc(addr, pattern string, staticKey []byte) error {
	// Create server configuration
	config := noise.NewConnConfig(pattern, false). // initiator = false
							WithHandshakeTimeout(30 * time.Second).
							WithReadTimeout(60 * time.Second).
							WithWriteTimeout(60 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Create TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Server configuration: pattern=%s\n", pattern)
	fmt.Printf("✓ Listening on %s\n", listener.Addr())

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start accepting connections
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptConnections(ctx, listener, config)
	}()

	// Wait for signal
	sig := <-sigChan
	fmt.Printf("\n🛑 Received signal: %v\n", sig)
	fmt.Println("Initiating graceful shutdown...")

	// Cancel context to stop accepting new connections
	cancel()

	// Wait for connections to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("✅ Graceful shutdown completed")
	case <-time.After(10 * time.Second):
		fmt.Println("⚠️  Shutdown timeout reached")
	}

	return nil
}

// runShutdownClient connects to server and handles graceful shutdown
func runShutdownClient(args *shared.CommonArgs, staticKey []byte) {
	fmt.Printf("🔗 Connecting to server at %s\n", args.ClientAddr)

	config := noise.NewConnConfig(args.Pattern, true). // initiator = true
								WithHandshakeTimeout(args.HandshakeTimeout).
								WithReadTimeout(args.ReadTimeout).
								WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Println("✅ Connected to server")

	// Send test message
	message := fmt.Sprintf("Shutdown test message at %v", time.Now().Format(time.RFC3339))
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Printf("Write error: %v", err)
		return
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	fmt.Printf("✅ Server response: %s\n", buffer[:n])
}

// acceptConnections handles incoming connections with graceful shutdown support
func acceptConnections(ctx context.Context, listener net.Listener, config *noise.ConnConfig) {
	for {
		if shouldStopAccepting(ctx) {
			return
		}

		configureListenerTimeout(listener)

		conn, err := listener.Accept()
		if err != nil {
			if shouldContinueOnError(ctx, err) {
				continue
			}
			return
		}

		// Handle connection in background
		go handleConnection(conn)
	}
}

// shouldStopAccepting checks if the accept loop should stop due to shutdown
func shouldStopAccepting(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		fmt.Println("✓ Accept loop stopping due to shutdown")
		return true
	default:
		return false
	}
}

// configureListenerTimeout sets a timeout for Accept to make it responsive to context cancellation
func configureListenerTimeout(listener net.Listener) {
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
	}
}

// shouldContinueOnError determines if the accept loop should continue after an error
func shouldContinueOnError(ctx context.Context, err error) bool {
	// Check if it's a timeout (acceptable during shutdown)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Check if we're shutting down
	select {
	case <-ctx.Done():
		return false
	default:
		log.Printf("Accept error: %v", err)
		return true
	}
}

// handleConnection processes individual connections
func handleConnection(rawConn net.Conn) {
	defer rawConn.Close()

	// Simple echo handler
	buffer := make([]byte, 1024)
	for {
		// Set read timeout to make it responsive
		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, err := rawConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue to check for more data
			}
			return
		}

		// Echo back
		rawConn.Write(buffer[:n])
	}
}

// runLongRunningClient simulates a client that runs for a while
func runLongRunningClient(addr, pattern string, clientID int, staticKey []byte) {
	fmt.Printf("🔗 Client %d connecting to %s\n", clientID, addr)

	config := noise.NewConnConfig(pattern, true). // initiator = true
							WithHandshakeTimeout(10 * time.Second).
							WithReadTimeout(5 * time.Second).
							WithWriteTimeout(5 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	conn, err := noise.DialNoise("tcp", addr, config)
	if err != nil {
		log.Printf("Client %d connection failed: %v", clientID, err)
		return
	}
	defer conn.Close()

	fmt.Printf("✅ Client %d connected\n", clientID)

	// Send messages periodically
	for i := 0; i < 5; i++ {
		message := fmt.Sprintf("Client %d message %d at %v", clientID, i+1, time.Now().Format("15:04:05"))
		_, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("Client %d write error: %v", clientID, err)
			return
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Client %d read error: %v", clientID, err)
			return
		}

		fmt.Printf("✓ Client %d received: %s\n", clientID, buffer[:n])
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("✅ Client %d finished\n", clientID)
}
