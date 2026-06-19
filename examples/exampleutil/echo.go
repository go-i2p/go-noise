package exampleutil

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-noise"
)

// AcceptConnections accepts incoming connections in a loop, dispatching each to
// HandleEchoConnection, until ctx is cancelled. It configures a 1-second
// Accept deadline so the loop remains responsive to context cancellation.
func AcceptConnections(ctx context.Context, listener net.Listener, config *noise.ConnConfig) {
	for {
		if acceptShouldStop(ctx) {
			return
		}
		setAcceptDeadline(listener)
		conn, err := listener.Accept()
		if err != nil {
			if acceptShouldContinue(ctx, err) {
				continue
			}
			return
		}
		go HandleEchoConnection(conn)
	}
}

// HandleEchoConnection echoes bytes from rawConn back to the sender until EOF
// or a non-timeout error.
func HandleEchoConnection(rawConn net.Conn) {
	defer rawConn.Close()
	buf := make([]byte, 1024)
	for {
		// The deadline is advisory for responsiveness; a failure still leaves
		// the read loop in a valid state, so we intentionally ignore it here.
		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		n, err := rawConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		// Echo best-effort: if the write fails, the connection is already being
		// torn down by the read loop's error handling.
		rawConn.Write(buf[:n]) //nolint:errcheck
	}
}

// SendPeriodicMessages sends count messages on conn, printing echoed responses.
func SendPeriodicMessages(conn net.Conn, clientID, count int) {
	for i := 0; i < count; i++ {
		message := fmt.Sprintf("Client %d message %d at %v", clientID, i+1, time.Now().Format("15:04:05"))
		if _, err := conn.Write([]byte(message)); err != nil {
			log.Printf("Client %d write error: %v", clientID, err)
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Client %d read error: %v", clientID, err)
			return
		}
		fmt.Printf("✓ Client %d received: %s\n", clientID, buf[:n])
		time.Sleep(500 * time.Millisecond)
	}
}

// RunLongRunningClient connects to addr using pattern and staticKey, then calls
// SendPeriodicMessages with count=5.
func RunLongRunningClient(addr, pattern string, clientID int, staticKey []byte) {
	fmt.Printf("🔗 Client %d connecting to %s\n", clientID, addr)
	config := noise.NewConnConfig(pattern, true).
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
	SendPeriodicMessages(conn, clientID, 5)
	fmt.Printf("✅ Client %d finished\n", clientID)
}

// acceptShouldStop returns true when ctx is already Done.
func acceptShouldStop(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		fmt.Println("✓ Accept loop stopping due to shutdown")
		return true
	default:
		return false
	}
}

// setAcceptDeadline sets a 1-second deadline on the listener so Accept
// unblocks periodically and the loop can check context cancellation.
func setAcceptDeadline(listener net.Listener) {
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		// Deadline refresh is a responsiveness hint; failure just means the
		// accept loop will wait until the next iteration.
		tcpListener.SetDeadline(time.Now().Add(1 * time.Second)) //nolint:errcheck
	}
}

// acceptShouldContinue returns true for transient Accept errors (timeouts).
func acceptShouldContinue(ctx context.Context, err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	default:
		log.Printf("Accept error: %v", err)
		return true
	}
}
