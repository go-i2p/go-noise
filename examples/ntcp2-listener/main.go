// Example: NTCP2Listener demonstration for I2P transport
// This example shows how to create and use an NTCP2Listener for accepting
// I2P NTCP2 transport connections with router identity management.
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/common/data"

	"github.com/go-i2p/go-noise/examples/exampleutil"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	exampleutil.RunNTCP2Example(
		"ntcp2-listener",
		"NTCP2Listener demonstration for I2P transport",
		"127.0.0.1:0",
		runNTCP2ListenerDemo,
		func(args *exampleutil.NTCP2Args, routerHash, _, _, staticKey []byte) {
			runNTCP2Listener(args, routerHash, staticKey)
		},
	)
}

// createDemoConfig creates and displays an NTCP2 config for demo purposes
func createDemoConfig(routerHash, staticKey []byte, args *exampleutil.NTCP2Args) {
	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create NTCP2 config: %v", err)
	}

	config = config.WithStaticKey(staticKey)

	config = config.
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
}

// runNTCP2ListenerDemo demonstrates NTCP2 listener functionality with demo mode
func runNTCP2ListenerDemo(args *exampleutil.NTCP2Args) {
	fmt.Println("🎭 NTCP2 Listener Demo Mode")
	fmt.Println("===========================")

	exampleutil.RunNTCP2Demo()

	routerHash, err := exampleutil.GenerateRandomKey()
	if err != nil {
		log.Fatalf("Failed to generate demo router hash: %v", err)
	}

	staticKey, err := exampleutil.GenerateRandomKey()
	if err != nil {
		log.Fatalf("Failed to generate demo static key: %v", err)
	}

	fmt.Printf("\n🎯 NTCP2 Listener Configuration Demo:\n")
	fmt.Printf("Router Hash: %x...\n", routerHash[:8])
	fmt.Printf("Pattern: IK (NTCP2 standard)\n")
	fmt.Printf("Role: Responder (listener)\n")

	createDemoConfig(routerHash, staticKey, args)

	fmt.Println("\n✅ Demo completed - use -server mode for actual listener")
}

// createNTCP2ListenerConfig creates and validates NTCP2 configuration for the listener
func createNTCP2ListenerConfig(args *exampleutil.NTCP2Args, routerHash, staticKey []byte) *ntcp2.Config {
	var rh data.Hash
	copy(rh[:], routerHash)
	config, err := ntcp2.NewNTCP2Config(rh, false) // false = responder
	if err != nil {
		log.Fatalf("Failed to create NTCP2 config: %v", err)
	}

	config = config.WithStaticKey(staticKey)
	config = config.
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if err := config.Validate(); err != nil {
		log.Fatalf("Invalid NTCP2 config: %v", err)
	}
	return config
}

// runNTCP2Listener starts an NTCP2 listener with the provided configuration
func runNTCP2Listener(args *exampleutil.NTCP2Args, routerHash, staticKey []byte) {
	fmt.Printf("🚀 Starting NTCP2 Listener on %s\n", args.ServerAddr)
	fmt.Printf("Router Hash: %x...\n", routerHash[:8])

	tcpListener, err := net.Listen("tcp", args.ServerAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	config := createNTCP2ListenerConfig(args, routerHash, staticKey)

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

	acceptConnections(listener)
}

// acceptConnections handles incoming NTCP2 connections
func acceptConnections(listener *ntcp2.Listener) {
	runAcceptLoop(listener, 0)
}

func runAcceptLoop(listener *ntcp2.Listener, connCount int) {
	for {
		connCount = acceptNextConnection(listener, connCount)
	}
}

func acceptNextConnection(listener *ntcp2.Listener, connCount int) int {
	conn, err := listener.Accept()
	if err != nil {
		log.Printf("Accept error: %v", err)
		return connCount
	}

	connCount++
	fmt.Printf("📞 Connection %d accepted from %s\n", connCount, conn.RemoteAddr())

	// Handle connection in a goroutine
	go handleNTCP2Connection(conn, connCount)
	return connCount
}

// handleNTCP2Connection processes an individual NTCP2 connection
func handleNTCP2Connection(conn net.Conn, connID int) {
	defer conn.Close()

	fmt.Printf("🔗 [Conn %d] Processing connection from %s\n", connID, conn.RemoteAddr())

	// Cast to NTCP2Conn to access I2P-specific methods
	if ntcp2Conn, ok := conn.(*ntcp2.Conn); ok {
		rHash := ntcp2Conn.RouterHash()
		fmt.Printf("🔗 [Conn %d] Router hash: %x...\n", connID, rHash[:8])
		fmt.Printf("🔗 [Conn %d] Role: %s\n", connID, ntcp2Conn.Role())
		fmt.Printf("🔗 [Conn %d] IdentHash: %x\n", connID, ntcp2Conn.RemoteAddr().(*ntcp2.Addr).IdentHash())
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
