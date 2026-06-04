// Example: Graceful shutdown demonstration with complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/exampleutil"
)

func main() {
	exampleutil.RunExample(
		"shutdown-example",
		"Graceful shutdown demonstration supporting all Noise patterns",
		"localhost:8080",
		"🛑 Graceful Shutdown Example with pattern %s",
		runShutdownDemo,
		runShutdownServer,
		runShutdownClient,
	)
}

// runShutdownDemo demonstrates graceful shutdown with server and clients
func runShutdownDemo(args *exampleutil.CommonArgs) {
	fmt.Printf("🎭 Running shutdown demo with graceful termination\n")

	// Parse keys for demo
	staticKey, _, err := exampleutil.ParseKeys(args)
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

	exampleutil.PrintLines(
		"\n🎯 Shutdown Features Demonstrated:",
		"  • Argument parsing with exampleutil.ParseCommonArgs",
		"  • Pattern validation for all 15 Noise patterns",
		"  • Key generation and validation",
		"  • Builder pattern configuration",
		"  • Signal-based graceful shutdown",
		"  • Context-based connection management",
		"\n✅ Use -server or -client mode for actual functionality",
	)
}

// runShutdownServer demonstrates server with graceful shutdown capability
func runShutdownServer(args *exampleutil.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting shutdown server on %s\n", args.ServerAddr)

	if err := runShutdownServerFunc(args.ServerAddr, args.Pattern, staticKey); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// createShutdownListener creates the server config and TCP listener
func createShutdownListener(addr, pattern string, staticKey []byte) (net.Listener, *noise.ConnConfig, error) {
	config := noise.NewConnConfig(pattern, false).
		WithHandshakeTimeout(30 * time.Second).
		WithReadTimeout(60 * time.Second).
		WithWriteTimeout(60 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create listener: %w", err)
	}
	return listener, config, nil
}

// awaitShutdownSignal is a thin wrapper around exampleutil.AwaitShutdownSignal.
func awaitShutdownSignal(cancel context.CancelFunc, wg *sync.WaitGroup) {
	exampleutil.AwaitShutdownSignal(cancel, wg)
}

func runShutdownServerFunc(addr, pattern string, staticKey []byte) error {
	listener, config, err := createShutdownListener(addr, pattern, staticKey)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("✓ Server configuration: pattern=%s\n", pattern)
	fmt.Printf("✓ Listening on %s\n", listener.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptConnections(ctx, listener, config)
	}()

	awaitShutdownSignal(cancel, &wg)

	return nil
}

// runShutdownClient connects to server and handles graceful shutdown
func runShutdownClient(args *exampleutil.CommonArgs, staticKey []byte) {
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

// acceptConnections is a thin wrapper around exampleutil.AcceptConnections.
func acceptConnections(ctx context.Context, listener net.Listener, config *noise.ConnConfig) {
	exampleutil.AcceptConnections(ctx, listener, config)
}

// handleConnection is a thin wrapper around exampleutil.HandleEchoConnection.
func handleConnection(rawConn net.Conn) {
	exampleutil.HandleEchoConnection(rawConn)
}

// sendPeriodicMessages is a thin wrapper around exampleutil.SendPeriodicMessages.
func sendPeriodicMessages(conn net.Conn, clientID, count int) {
	exampleutil.SendPeriodicMessages(conn, clientID, count)
}

// runLongRunningClient is a thin wrapper around exampleutil.RunLongRunningClient.
func runLongRunningClient(addr, pattern string, clientID int, staticKey []byte) {
	exampleutil.RunLongRunningClient(addr, pattern, clientID, staticKey)
}
