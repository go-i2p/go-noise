// Example: Basic usage of the go-noise library with configurable patterns and complete handshakes
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/exampleutil"
)

func main() {
	// Parse command line arguments
	args, err := exampleutil.ParseCommonArgs("basic-noise")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		exampleutil.PrintUsage("basic-noise", "Basic Noise Protocol example with all pattern support")
		return
	}

	// Handle special modes
	if exampleutil.HandleSpecialModes(args, func(_ *exampleutil.CommonArgs) { exampleutil.RunDemo() }) {
		return
	}

	// Parse and validate keys for the selected pattern
	staticKey, remoteKey, err := exampleutil.ParseKeys(args)
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

// runBasicServer starts a basic Noise server with complete handshake
func runBasicServer(args *exampleutil.CommonArgs, staticKey []byte) {
	exampleutil.RunServer(args, staticKey, "basic", func(conn net.Conn) {
		exampleutil.HandleConnection(conn, "Basic", nil)
	})
}

// runBasicClient connects to a basic Noise server with complete handshake
func runBasicClient(args *exampleutil.CommonArgs, staticKey, remoteKey []byte) {
	exampleutil.RunClient(args, staticKey, remoteKey, "basic", func(conn *noise.NoiseConn) {
		fmt.Printf("📤 Sending: Hello from basic client!\n")
		_, err := conn.Write([]byte("Hello from basic client!"))
		if err != nil {
			log.Fatalf("Write failed: %v", err)
		}
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Fatalf("Read failed: %v", err)
		}
		fmt.Printf("📨 Received: %s\n", string(buffer[:n]))
		fmt.Println("✓ Basic Noise communication completed successfully!")
	})
}
