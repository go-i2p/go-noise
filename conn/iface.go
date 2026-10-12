package conn

import (
	"context"
	"net"
	"time"
)

// ConnIface defines the public interface for Noise protocol connections.
// It embeds net.Conn and adds handshake and state management methods.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// This interface lets consumers substitute test doubles or alternative
// implementations without depending on the concrete *Conn type.
type ConnIface interface {
	net.Conn

	// Handshake performs the Noise protocol handshake with the remote peer.
	// It must be called before Read or Write operations on the connection.
	Handshake(ctx context.Context) error

	// HandshakeWithRetry performs the Noise protocol handshake with automatic
	// retry logic based on the connection configuration.
	HandshakeWithRetry(ctx context.Context) error

	// GetConnectionState returns the current connection state (Init,
	// Handshaking, Established, or Closed).
	GetConnectionState() ConnState

	// GetConnectionMetrics returns connection performance metrics: bytes
	// read, bytes written, and handshake duration.
	GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration)
}

// Compile-time assertion that *Conn implements ConnIface.
var _ ConnIface = (*Conn)(nil)
