// Example: NTCP2Listener demonstration for I2P transport
// This example shows how to create and use an NTCP2Listener for accepting
// I2P NTCP2 transport connections with router identity management.
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	ntcp2shared "github.com/go-i2p/go-noise/examples/ntcp2-shared"
	"github.com/go-i2p/go-noise/examples/shared"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	// Parse NTCP2-specific command line arguments
	args, err := ntcp2shared.ParseNTCP2Args("ntcp2-listener")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "127.0.0.1:0" // Default NTCP2 listener address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		ntcp2shared.PrintNTCP2Usage("ntcp2-listener", "NTCP2Listener demonstration for I2P transport")
		return
	}

	// Handle special modes
	if args.Demo {
		runNTCP2ListenerDemo(args)
		return
	}

	if args.Generate {
		ntcp2shared.RunNTCP2Generate()
		return
	}

	// Parse NTCP2 keys and material
	routerHash, _, _, staticKey, err := ntcp2shared.ParseNTCP2Keys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run NTCP2 listener demonstration
	runNTCP2Listener(args, routerHash, staticKey)
}

// runNTCP2ListenerDemo demonstrates NTCP2 listener functionality with demo mode
func runNTCP2ListenerDemo(args *ntcp2shared.NTCP2Args) {
	fmt.Println("🎭 NTCP2 Listener Demo Mode")
	fmt.Println("===========================")

	// Run the standard NTCP2 demo
	ntcp2shared.RunNTCP2Demo()

	// Generate demo materials
	routerHash, err := shared.GenerateRandomKey()
	if err != nil {
		log.Fatalf("Failed to generate demo router hash: %v", err)
	}

	staticKey, err := shared.GenerateRandomKey()
	if err != nil {
		log.Fatalf("Failed to generate demo static key: %v", err)
	}

	fmt.Printf("\n🎯 NTCP2 Listener Configuration Demo:\n")
	fmt.Printf("Router Hash: %x...\n", routerHash[:8])
	fmt.Printf("Pattern: IK (NTCP2 standard)\n")
	fmt.Printf("Role: Responder (listener)\n")

	// Create and display configuration
	config, err := ntcp2.NewNTCP2Config(routerHash, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create NTCP2 config: %v", err)
	}

	config = config.
		WithStaticKey(staticKey).
		WithHandshakeTimeout(45 * time.Second).
		WithReadTimeout(60 * time.Second).
		WithWriteTimeout(60 * time.Second)

	fmt.Printf("\n📋 Configuration Details:\n")
	fmt.Printf("  Handshake Timeout: %v\n", config.HandshakeTimeout)
	fmt.Printf("  Read Timeout: %v\n", config.ReadTimeout)
	fmt.Printf("  Write Timeout: %v\n", config.WriteTimeout)
	fmt.Printf("  AES Obfuscation: %v\n", args.EnableAESObfuscation)
	fmt.Printf("  SipHash Length: %v\n", args.EnableSipHashLength)
	fmt.Printf("  Max Frame Size: %d bytes\n", args.MaxFrameSize)

	fmt.Println("\n✅ Demo completed - use -server mode for actual listener")
}

// runNTCP2Listener starts an NTCP2 listener with the provided configuration
func runNTCP2Listener(args *ntcp2shared.NTCP2Args, routerHash, staticKey []byte) {
	fmt.Printf("🚀 Starting NTCP2 Listener on %s\n", args.ServerAddr)
	fmt.Printf("Router Hash: %x...\n", routerHash[:8])

	// Setup TCP listener
	tcpListener, err := net.Listen("tcp", args.ServerAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	// Create NTCP2 configuration
	config, err := ntcp2.NewNTCP2Config(routerHash, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create NTCP2 config: %v", err)
	}

	config = config.
		WithStaticKey(staticKey).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if err := config.Validate(); err != nil {
		log.Fatalf("Invalid NTCP2 config: %v", err)
	}

	// Create NTCP2 listener
	listener, err := ntcp2.NewNTCP2Listener(tcpListener, config)
	if err != nil {
		log.Fatalf("Failed to create NTCP2 listener: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ NTCP2 Listener started\n")
	fmt.Printf("  Address: %s\n", listener.Addr().String())
	fmt.Printf("  Network: %s\n", listener.Addr().Network())
	fmt.Printf("  Noise pattern: IK\n")
	fmt.Println("\n📡 Waiting for connections... (Press Ctrl+C to stop)")

	// Accept connections in a loop
	acceptConnections(listener)
}

// acceptConnections handles incoming NTCP2 connections
func acceptConnections(listener *ntcp2.NTCP2Listener) {
	connCount := 0

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		connCount++
		fmt.Printf("📞 Connection %d accepted from %s\n", connCount, conn.RemoteAddr())

		// Handle connection in a goroutine
		go handleNTCP2Connection(conn, connCount)
	}
}

// handleNTCP2Connection processes an individual NTCP2 connection
func handleNTCP2Connection(conn net.Conn, connID int) {
	defer conn.Close()

	fmt.Printf("🔗 [Conn %d] Processing connection from %s\n", connID, conn.RemoteAddr())

	// Cast to NTCP2Conn to access I2P-specific methods
	if ntcp2Conn, ok := conn.(*ntcp2.NTCP2Conn); ok {
		fmt.Printf("🔗 [Conn %d] Router hash: %x...\n", connID, ntcp2Conn.RouterHash()[:8])
		fmt.Printf("🔗 [Conn %d] Role: %s\n", connID, ntcp2Conn.Role())

		if destHash := ntcp2Conn.DestinationHash(); destHash != nil {
			fmt.Printf("🔗 [Conn %d] Destination: %x...\n", connID, destHash[:8])
		} else {
			fmt.Printf("🔗 [Conn %d] Type: Router-to-router connection\n", connID)
		}
	}

	// Read data from the connection
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("🔗 [Conn %d] Read error: %v\n", connID, err)
			break
		}

		if n > 0 {
			fmt.Printf("🔗 [Conn %d] Received %d bytes: %s\n", connID, n, string(buffer[:n]))

			// Echo the data back
			_, err = conn.Write(buffer[:n])
			if err != nil {
				fmt.Printf("🔗 [Conn %d] Write error: %v\n", connID, err)
				break
			}
		}
	}

	fmt.Printf("🔗 [Conn %d] Connection closed\n", connID)
}
