// Example: NTCP2 addressing and connection demonstration for I2P router addressing
package main

import (
	"fmt"
	"log"
	"net"

	shared "github.com/go-i2p/go-noise/examples/ntcp2-shared"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	// Parse NTCP2-specific command line arguments
	args, err := shared.ParseNTCP2Args("ntcp2-demo")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintNTCP2Usage("ntcp2-demo", "NTCP2 addressing and connection demonstration")
		return
	}

	// Handle special modes
	if args.Demo {
		shared.RunNTCP2Demo()
		demonstrateNTCP2Addressing()
		return
	}

	if args.Generate {
		shared.RunNTCP2Generate()
		return
	}

	// Parse NTCP2 keys and material
	routerHash, remoteRouterHash, destHash, staticKey, err := shared.ParseNTCP2Keys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run NTCP2 demonstration
	if args.ServerAddr != "" || args.ClientAddr != "" {
		fmt.Println("🚧 NTCP2 server/client functionality coming in future examples")
		fmt.Println("This example demonstrates NTCP2 addressing only")
		fmt.Println()
	}

	// Demonstrate NTCP2 addressing with parsed material
	demonstrateNTCP2AddressingWithKeys(routerHash, remoteRouterHash, destHash, staticKey)
}

// demonstrateNTCP2Addressing shows basic NTCP2 addressing examples
func demonstrateNTCP2Addressing() {
	fmt.Println("📍 NTCP2 Addressing Examples:")
	fmt.Println("============================")

	// Create a TCP address for the underlying connection
	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 7654,
	}

	// Create a sample router hash (32 bytes)
	routerHash := make([]byte, 32)
	copy(routerHash, []byte("example_router_hash_32_bytes...."))

	// Create an NTCP2 address for an initiator
	ntcpAddr, err := ntcp2.NewNTCP2Addr(tcpAddr, routerHash, "initiator")
	if err != nil {
		log.Fatalf("Failed to create NTCP2 address: %v", err)
	}

	fmt.Printf("Basic NTCP2 Address:\n")
	fmt.Printf("  Network: %s\n", ntcpAddr.Network())
	fmt.Printf("  String:  %s\n", ntcpAddr.String())
	fmt.Printf("  Role:    %s\n", ntcpAddr.Role())
	fmt.Printf("  Router-to-Router: %v\n", ntcpAddr.IsRouterToRouter())
	fmt.Println()

	// Add a destination hash for tunnel connections
	destHash := make([]byte, 32)
	copy(destHash, []byte("example_destination_hash_32_byte."))

	tunnelAddr, err := ntcpAddr.WithDestinationHash(destHash)
	if err != nil {
		log.Fatalf("Failed to add destination hash: %v", err)
	}

	fmt.Printf("Tunnel NTCP2 Address:\n")
	fmt.Printf("  String: %s\n", tunnelAddr.String())
	fmt.Printf("  Is Tunnel Connection: %v\n", tunnelAddr.IsTunnelConnection())
	fmt.Printf("  Router-to-Router: %v\n", tunnelAddr.IsRouterToRouter())
	fmt.Println()

	// Add a session tag
	sessionTag := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	sessionAddr, err := tunnelAddr.WithSessionTag(sessionTag)
	if err != nil {
		log.Fatalf("Failed to add session tag: %v", err)
	}

	fmt.Printf("NTCP2 Address with Session Tag:\n")
	fmt.Printf("  String: %s\n", sessionAddr.String())
	fmt.Println()

	// Demonstrate net.Addr interface compliance
	var netAddr net.Addr = sessionAddr
	fmt.Printf("net.Addr Interface Compliance:\n")
	fmt.Printf("  Network(): %s\n", netAddr.Network())
	fmt.Printf("  String():  %s\n", netAddr.String())
	fmt.Println()
}

// demonstrateNTCP2AddressingWithKeys shows NTCP2 addressing with user-provided keys
func demonstrateNTCP2AddressingWithKeys(routerHash, remoteRouterHash, destHash, staticKey []byte) {
	fmt.Println("📍 NTCP2 Addressing with User Keys:")
	fmt.Println("===================================")

	if routerHash == nil {
		fmt.Println("⚠️  No router hash provided - using demo mode")
		demonstrateNTCP2Addressing()
		return
	}

	// Create a TCP address for the underlying connection
	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 7654,
	}

	// Create NTCP2 address with user-provided router hash
	ntcpAddr, err := ntcp2.NewNTCP2Addr(tcpAddr, routerHash, "initiator")
	if err != nil {
		log.Fatalf("Failed to create NTCP2 address: %v", err)
	}

	fmt.Printf("NTCP2 Address with User Router Hash:\n")
	fmt.Printf("  Network: %s\n", ntcpAddr.Network())
	fmt.Printf("  String:  %s\n", ntcpAddr.String())
	fmt.Printf("  Role:    %s\n", ntcpAddr.Role())
	fmt.Printf("  Router Hash: %x...\n", routerHash[:8])
	fmt.Println()

	// Show remote router hash if provided
	if remoteRouterHash != nil {
		fmt.Printf("Remote Router Information:\n")
		fmt.Printf("  Remote Router Hash: %x...\n", remoteRouterHash[:8])
		fmt.Println()
	}

	// Show static key information if provided
	if staticKey != nil {
		fmt.Printf("Static Key Information:\n")
		fmt.Printf("  Static Key: %x...\n", staticKey[:8])
		fmt.Println()
	}

	// Add destination hash for tunnel connections if provided
	if destHash != nil {
		tunnelAddr, err := ntcpAddr.WithDestinationHash(destHash)
		if err != nil {
			log.Printf("Failed to add destination hash: %v", err)
			return
		}

		fmt.Printf("Tunnel NTCP2 Address:\n")
		fmt.Printf("  String: %s\n", tunnelAddr.String())
		fmt.Printf("  Is Tunnel Connection: %v\n", tunnelAddr.IsTunnelConnection())
		fmt.Printf("  Destination Hash: %x...\n", destHash[:8])
		fmt.Println()
	}

	fmt.Println("✅ NTCP2 addressing demonstration completed!")
	fmt.Println("🔗 Use NTCP2 listener/client examples for full connection functionality")
}
