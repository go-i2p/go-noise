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
	"github.com/go-i2p/go-noise/examples/exampleutil"
)

func main() {
	exampleutil.RunExample(
		"noise-listener",
		"NoiseListener demonstration supporting all Noise patterns",
		"127.0.0.1:0",
		"",
		runListenerDemo,
		runListenerServer,
		nil,
	)
}

// createListenerConfig builds a NoiseListener config from args and an optional static key
func createListenerConfig(args *exampleutil.CommonArgs, staticKey []byte) *noise.ListenerConfig {
	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}
	return config
}

// runListenerServer starts a persistent listener server
func runListenerServer(args *exampleutil.CommonArgs, staticKey []byte) {
	fmt.Printf("🚀 Starting NoiseListener server on %s with pattern %s\n", args.ServerAddr, args.Pattern)

	config := createListenerConfig(args, staticKey)

	tcpListener, err := net.Listen("tcp", args.ServerAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()

	fmt.Printf("✓ TCP listener created on: %s\n", tcpListener.Addr().String())

	noiseListener, err := noise.NewNoiseListener(tcpListener, config)
	if err != nil {
		log.Fatalf("Failed to create NoiseListener: %v", err)
	}
	defer noiseListener.Close()

	fmt.Printf("✓ NoiseListener created: %s\n", noiseListener.Addr().String())
	fmt.Println("Waiting for connections... (Press Ctrl+C to stop)")

	for {
		conn, err := noiseListener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleListenerConnection(conn)
	}
}

// createDemoNoiseListener creates the TCP and Noise listeners for the demo
func createDemoNoiseListener(demoAddr string, args *exampleutil.CommonArgs, staticKey []byte) (net.Listener, *noise.NoiseListener) {
	tcpListener, err := net.Listen("tcp", demoAddr)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}

	fmt.Printf("✓ TCP listener created on: %s\n", tcpListener.Addr().String())

	listenerConfig := createListenerConfig(args, staticKey)

	noiseListener, err := noise.NewNoiseListener(tcpListener, listenerConfig)
	if err != nil {
		tcpListener.Close()
		log.Fatalf("Failed to create NoiseListener: %v", err)
	}

	fmt.Printf("✓ NoiseListener created: %s\n", noiseListener.Addr().String())
	return tcpListener, noiseListener
}

// startDemoEchoServer starts the echo server goroutine
func startDemoEchoServer(noiseListener *noise.NoiseListener) {
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
}

// runListenerDemo demonstrates NoiseListener with a simulated client
func runListenerDemo(args *exampleutil.CommonArgs) {
	fmt.Printf("🎭 Running NoiseListener demonstration with pattern %s\n", args.Pattern)

	demoAddr := "127.0.0.1:0"
	if args.ServerAddr != "" {
		demoAddr = args.ServerAddr
	}

	staticKey, _, err := exampleutil.ParseKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	tcpListener, noiseListener := createDemoNoiseListener(demoAddr, args, staticKey)
	defer tcpListener.Close()
	defer noiseListener.Close()

	startDemoEchoServer(noiseListener)

	time.Sleep(100 * time.Millisecond)
	simulateClient(tcpListener.Addr().String(), args.Pattern, staticKey)

	time.Sleep(2 * time.Second)
	fmt.Println("🛑 Shutting down listener demo...")
}

// performListenerHandshake performs the Noise handshake for a listener connection
func performListenerHandshake(conn net.Conn, clientAddr string) bool {
	noiseConn, ok := conn.(*noise.NoiseConn)
	if !ok {
		return true
	}
	fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := noiseConn.Handshake(ctx)
	if err != nil {
		log.Printf("Handshake failed with %s: %v", clientAddr, err)
		return false
	}
	fmt.Printf("✅ Handshake completed with %s\n", clientAddr)
	return true
}

// runListenerEchoLoop reads data and echoes it back
func runListenerEchoLoop(conn net.Conn, clientAddr string) {
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

		response := fmt.Sprintf("Echo: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			fmt.Printf("Write error to %s: %v\n", clientAddr, err)
			return
		}

		fmt.Printf("📤 Echoed to %s: %s\n", clientAddr, response)
	}
}

// handleListenerConnection handles a single connection with complete handshake
func handleListenerConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

	if !performListenerHandshake(conn, clientAddr) {
		return
	}

	runListenerEchoLoop(conn, clientAddr)
}

// connectSimulatedClient connects and handshakes the simulated client
func connectSimulatedClient(serverAddr, pattern string, serverKey []byte) (*noise.NoiseConn, error) {
	clientConfig := noise.NewConnConfig(pattern, true).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(30 * time.Second).
		WithWriteTimeout(30 * time.Second)

	if exampleutil.RequiresLocalStaticKey(pattern) && serverKey != nil {
		clientConfig = clientConfig.WithStaticKey(serverKey)
	}

	transport := exampleutil.NewExampleTransport()
	defer transport.GracefulShutdown()

	// The handshake is performed below on the returned conn, so dial only.
	conn, err := exampleutil.Dial(transport, serverAddr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())

	fmt.Println("🔐 Client performing handshake...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = conn.Handshake(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("client handshake failed: %w", err)
	}
	fmt.Println("✅ Client handshake completed!")

	return conn, nil
}

// testSimulatedClientEcho sends a test message and reads the response
func testSimulatedClientEcho(conn *noise.NoiseConn) {
	testMessage := "Hello from simulated client!"
	fmt.Printf("📤 Sending: %s\n", testMessage)
	exampleutil.SendAndReceive(conn, testMessage, "Received response")
	fmt.Println("✅ Client simulation completed successfully!")
}

// simulateClient simulates a client connecting to the echo server
func simulateClient(serverAddr, pattern string, serverKey []byte) {
	fmt.Printf("🤖 Simulating client connection to: %s\n", serverAddr)

	conn, err := connectSimulatedClient(serverAddr, pattern, serverKey)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer conn.Close()

	testSimulatedClientEcho(conn)
}
