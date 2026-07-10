// Package shared provides common utilities for go-noise examples
package exampleutil

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-i2p/go-noise"
)

// RunServer creates a Noise listener and runs an accept loop, dispatching
// connections to the provided handler function. This consolidates the common
// server setup pattern duplicated across state, transport, and other examples.
func RunServer(args *CommonArgs, staticKey []byte, label string, handler func(net.Conn)) {
	fmt.Printf("🚀 Starting %s server on %s with pattern %s\n", label, args.ServerAddr, args.Pattern)

	config := noise.NewListenerConfig(args.Pattern).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	listener, err := noise.ListenNoise("tcp", args.ServerAddr, config)
	if err != nil {
		log.Fatalf("Failed to start %s server: %v", label, err)
	}
	defer listener.Close()

	fmt.Printf("✓ %s server listening on: %s\n", capitalize(label), listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Back off on persistent Accept errors instead of busy-spinning
			// (AUDIT.md Level 9 examples/exampleutil Finding 1) — mirrors the
			// bounded-backoff pattern integrators should copy from the
			// production listener package rather than the naive tight loop
			// this example previously demonstrated.
			log.Printf("Accept failed: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handler(conn)
	}
}

// RunClient creates a Noise connection and invokes the provided callback
// with the established connection. This consolidates the common client
// setup pattern duplicated across state, transport, and other examples.
// Pass nil for remoteKey when the pattern does not require one.
func RunClient(args *CommonArgs, staticKey, remoteKey []byte, label string, postConnect func(*noise.NoiseConn)) {
	fmt.Printf("📱 Starting %s client connecting to %s\n", label, args.ClientAddr)

	config := noise.NewConnConfig(args.Pattern, true).
		WithHandshakeTimeout(args.HandshakeTimeout).
		WithReadTimeout(args.ReadTimeout).
		WithWriteTimeout(args.WriteTimeout)

	if staticKey != nil {
		config = config.WithStaticKey(staticKey)
	}

	if remoteKey != nil {
		config = config.WithRemoteKey(remoteKey)
	}

	conn, err := noise.DialNoise("tcp", args.ClientAddr, config)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("✓ Connected to server: %s\n", conn.RemoteAddr())

	postConnect(conn)
}

// HandleConnection handles a Noise connection with handshake, optional
// post-handshake callback, and echo loop. This consolidates the common
// connection handler pattern duplicated across state, transport, and other examples.
func HandleConnection(conn net.Conn, echoPrefix string, postHandshake func(*noise.NoiseConn)) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📝 New connection from: %s\n", clientAddr)

	if noiseConn, ok := conn.(*noise.NoiseConn); ok {
		fmt.Printf("🔐 Starting handshake with %s...\n", clientAddr)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := noiseConn.Handshake(ctx)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", clientAddr, err)
			return
		}
		fmt.Printf("✅ Handshake completed with %s\n", clientAddr)

		if postHandshake != nil {
			postHandshake(noiseConn)
		}
	}

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Client %s disconnected\n", clientAddr)
			return
		}

		message := string(buffer[:n])
		fmt.Printf("📨 Received from %s: %s\n", clientAddr, message)

		response := fmt.Sprintf("%s echo: %s", echoPrefix, message)
		conn.Write([]byte(response))
	}
}

// RunDemo2 starts a server in the background, waits briefly, then runs a client.
// This consolidates the common demo pattern duplicated across state, transport,
// and other examples.
func RunDemo2(args *CommonArgs, label string, serverFunc, clientFunc func(*CommonArgs, []byte)) {
	fmt.Printf("🎭 Running %s demo with server and client\n", label)

	staticKey, _, err := ParseKeys(args)
	if err != nil {
		log.Fatalf("Failed to parse keys for demo: %v", err)
	}

	go serverFunc(args, staticKey)
	time.Sleep(200 * time.Millisecond)

	clientArgs := *args
	clientArgs.ClientAddr = args.ServerAddr
	clientArgs.ServerAddr = ""
	clientFunc(&clientArgs, staticKey)
}

// RunExample runs a standard example program with common argument parsing,
// validation, and mode dispatch. This consolidates the main() boilerplate
// duplicated across listener, shutdown, state, and transport examples.
// Pass an empty banner to skip the startup message. Pass nil for clientFunc
// if the example only runs in server mode.
func RunExample(appName, description, defaultAddr, banner string,
	demoFunc func(*CommonArgs),
	serverFunc func(*CommonArgs, []byte),
	clientFunc func(*CommonArgs, []byte),
) {
	args, err := ParseCommonArgs(appName)
	if err != nil {
		log.Fatalf("❌ Failed to parse arguments: %v", err)
	}

	HandleDefaultAddress(args, defaultAddr)

	if err := args.ValidateArgs(); err != nil {
		fmt.Printf("❌ Invalid arguments: %v\n\n", err)
		PrintUsage(appName, description)
		return
	}

	if HandleSpecialModes(args, demoFunc) {
		return
	}

	staticKey, _, err := ParseKeys(args)
	if err != nil {
		log.Fatalf("❌ Key parsing failed: %v", err)
	}

	if banner != "" {
		fmt.Printf(banner+"\n", args.Pattern)
	}

	dispatchMode(args, staticKey, serverFunc, clientFunc)
}

// dispatchMode runs the server or client function based on parsed arguments.
func dispatchMode(args *CommonArgs, staticKey []byte,
	serverFunc func(*CommonArgs, []byte),
	clientFunc func(*CommonArgs, []byte),
) {
	if args.ServerAddr != "" {
		serverFunc(args, staticKey)
	} else if clientFunc != nil && args.ClientAddr != "" {
		clientFunc(args, staticKey)
	}
}

// SendAndDisplay sends a series of messages on a NoiseConn and displays
// responses with a pause between each. This consolidates the common
// send-receive loop duplicated across the state and transport examples.
func SendAndDisplay(conn *noise.NoiseConn, messages []string) {
	for i, msg := range messages {
		fmt.Printf("\n📤 Sending message %d: %s\n", i+1, msg)

		_, err := conn.Write([]byte(msg))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			continue
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			continue
		}

		response := string(buffer[:n])
		fmt.Printf("📨 Received response: %s\n", response)

		time.Sleep(500 * time.Millisecond)
	}
}

// SendAndReceive sends a message on a NoiseConn and prints the response.
// This consolidates the common send-and-echo pattern duplicated across
// the listener and retry examples.
func SendAndReceive(conn *noise.NoiseConn, message, responseLabel string) {
	_, err := conn.Write([]byte(message))
	if err != nil {
		log.Printf("Write failed: %v", err)
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Read failed: %v", err)
		return
	}

	response := string(buffer[:n])
	fmt.Printf("📨 %s: %s\n", responseLabel, response)
}

// EchoOnce reads one message from a net.Conn and writes back an echo response.
// This consolidates the simple echo handler duplicated across pool and retry
// server examples.
func EchoOnce(conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	message := string(buffer[:n])
	response := fmt.Sprintf("Echo: %s", message)
	conn.Write([]byte(response))
}

// capitalize returns the string with the first letter uppercased.
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
