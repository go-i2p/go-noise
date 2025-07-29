// Example: Connection pooling demonstration with complete handshakes
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/shared"
	"github.com/go-i2p/go-noise/pool"
)

func main() {
	// Parse command line arguments
	args, err := shared.ParseCommonArgs("pool-example")
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	// Set default server address if none provided
	if args.ServerAddr == "" && args.ClientAddr == "" && !args.Demo && !args.Generate {
		args.ServerAddr = "127.0.0.1:8080" // Default pool test address
	}

	// Validate arguments
	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		shared.PrintUsage("pool-example", "Connection pooling demonstration supporting all Noise patterns")
		return
	}

	// Handle special modes
	if args.Demo {
		runPoolDemo(args)
		return
	}

	if args.Generate {
		shared.RunGenerate()
		return
	}

	// Parse keys for the selected pattern
	staticKey, _, err := parsePoolKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	// Run pool demonstration
	runPoolExample(args, staticKey)
}

// runPoolExample demonstrates connection pooling with handshakes
func runPoolExample(args *shared.CommonArgs, staticKey []byte) {
	poolSize := 5       // Default pool size
	numConnections := 3 // Default number of test connections

	fmt.Printf("🏊‍♂️ Connection Pool Example with pattern %s\n", args.Pattern)
	fmt.Printf("Server: %s, Pool size: %d, Test connections: %d\n", args.ServerAddr, poolSize, numConnections)

	customPool := setupConnectionPool(poolSize)
	defer customPool.Close()

	startTestServer(args.ServerAddr, args.Pattern, staticKey)
	config := createClientConfig(args.Pattern, staticKey)

	fmt.Printf("📊 Pool statistics before connections: %+v\n", customPool.Stats())

	connections := createPooledConnections(args.ServerAddr, config, numConnections)
	fmt.Printf("\n📊 Pool statistics after creating connections: %+v\n", customPool.Stats())

	testConnectionCommunication(connections)
	closeConnections(connections)

	fmt.Printf("\n📊 Final pool statistics: %+v\n", customPool.Stats())
	fmt.Println("✅ Pool example completed!")
}

// setupConnectionPool creates and configures the connection pool
func setupConnectionPool(poolSize int) *pool.ConnPool {
	customPool := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: poolSize,         // Maximum connections per remote address
		MaxAge:  30 * time.Minute, // Connections expire after 30 minutes
		MaxIdle: 5 * time.Minute,  // Close idle connections after 5 minutes
	})

	noise.SetGlobalConnPool(customPool)
	fmt.Printf("✓ Created connection pool (MaxSize: %d)\n", poolSize)

	return customPool
}

// startTestServer initializes the echo server for testing
func startTestServer(serverAddr, pattern string, staticKey []byte) {
	go startEchoServer(serverAddr, pattern, staticKey)
	time.Sleep(200 * time.Millisecond) // Wait for server to start
}

// createClientConfig builds the client configuration with appropriate settings
func createClientConfig(pattern string, staticKey []byte) *noise.ConnConfig {
	config := noise.NewConnConfig(pattern, true). // initiator = true
							WithHandshakeTimeout(10 * time.Second).
							WithReadTimeout(30 * time.Second).
							WithWriteTimeout(30 * time.Second)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	return config
}

// createPooledConnections establishes multiple connections using the pool
func createPooledConnections(serverAddr string, config *noise.ConnConfig, numConnections int) []*noise.NoiseConn {
	connections := make([]*noise.NoiseConn, numConnections)

	for i := 0; i < numConnections; i++ {
		conn := createSingleConnection(serverAddr, config, i+1)
		connections[i] = conn
	}

	return connections
}

// createSingleConnection creates and handshakes a single connection
func createSingleConnection(serverAddr string, config *noise.ConnConfig, connectionNum int) *noise.NoiseConn {
	fmt.Printf("\n🔌 Creating connection %d...\n", connectionNum)

	conn, err := noise.DialNoiseWithPool("tcp", serverAddr, config)
	if err != nil {
		log.Printf("Failed to create connection %d: %v", connectionNum, err)
		return nil
	}

	if !performHandshake(conn, connectionNum) {
		conn.Close()
		return nil
	}

	fmt.Printf("✅ Connection %d ready (handshake completed)\n", connectionNum)
	return conn
}

// performHandshake executes the handshake process for a connection
func performHandshake(conn *noise.NoiseConn, connectionNum int) bool {
	fmt.Printf("🔐 Performing handshake for connection %d...\n", connectionNum)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := conn.Handshake(ctx)
	if err != nil {
		log.Printf("Handshake failed for connection %d: %v", connectionNum, err)
		return false
	}

	return true
}

// testConnectionCommunication sends test messages through all connections
func testConnectionCommunication(connections []*noise.NoiseConn) {
	fmt.Println("\n💬 Testing connections...")

	for i, conn := range connections {
		if conn == nil {
			continue
		}
		testSingleConnection(conn, i+1)
	}
}

// testSingleConnection performs communication test on a single connection
func testSingleConnection(conn *noise.NoiseConn, connectionNum int) {
	testMessage := fmt.Sprintf("Hello from connection %d", connectionNum)
	fmt.Printf("📤 Sending via connection %d: %s\n", connectionNum, testMessage)

	_, err := conn.Write([]byte(testMessage))
	if err != nil {
		log.Printf("Failed to write to connection %d: %v", connectionNum, err)
		return
	}

	readConnectionResponse(conn, connectionNum)
}

// readConnectionResponse reads and displays the response from a connection
func readConnectionResponse(conn *noise.NoiseConn, connectionNum int) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read from connection %d: %v", connectionNum, err)
	} else {
		response := string(buffer[:n])
		fmt.Printf("📨 Connection %d received: %s\n", connectionNum, response)
	}
}

// closeConnections properly closes all connections
func closeConnections(connections []*noise.NoiseConn) {
	fmt.Println("\n🔄 Closing connections...")

	for i, conn := range connections {
		if conn != nil {
			conn.Close()
			fmt.Printf("🔌 Closed connection %d\n", i+1)
		}
	}
}

// startEchoServer starts a simple echo server for pool testing
func startEchoServer(addr, pattern string, staticKey []byte) {
	fmt.Printf("🚀 Starting echo server on %s with pattern %s\n", addr, pattern)

	// Create server configuration
	config := noise.NewListenerConfig(pattern).
		WithHandshakeTimeout(30 * time.Second).
		WithReadTimeout(60 * time.Second).
		WithWriteTimeout(60 * time.Second)

	// Add static key if provided
	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	// Start server
	listener, err := noise.ListenNoise("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to start echo server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("✓ Echo server listening on: %s\n", listener.Addr())

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handlePoolEchoConnection(conn)
	}
}

// handlePoolEchoConnection handles echo connections for pool testing
func handlePoolEchoConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()

	// Perform handshake
	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return
		}
	}

	// Simple echo
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	message := string(buffer[:n])
	response := fmt.Sprintf("Echo: %s", message)
	conn.Write([]byte(response))
}

// runPoolDemo demonstrates the connection pool functionality
func runPoolDemo(args *shared.CommonArgs) {
	fmt.Println("🏊‍♂️ Connection Pool Demonstration")
	fmt.Println("===================================")

	// Parse keys for demo
	staticKey, _, err := parsePoolKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	// Use default configuration for demo
	demoArgs := *args
	if demoArgs.ServerAddr == "" {
		demoArgs.ServerAddr = "127.0.0.1:0"
	}

	// Run the pool example
	runPoolExample(&demoArgs, staticKey)
}

// parsePoolKeys handles key parsing for the pool example
func parsePoolKeys(args *shared.CommonArgs) ([]byte, []byte, error) {
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
