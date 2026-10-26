// Package noise provides an easy-to-use wrapper around the Noise Protocol
// Framework for the I2P network.
//
// # What this library does
//
// I2P is a private overlay network. Routers in I2P talk to each other over
// encrypted connections. This library builds those connections for you. It
// wraps a regular network connection (a net.Conn) in an encrypted layer, so
// you can read and write I2P messages as if the connection were already
// secure.
//
// The encryption follows the Noise Protocol Framework, a set of rules for
// building secure connections.
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// # The protocols
//
// This library supports the two modern I2P router-to-router transport
// protocols:
//
//   - NTCP2: Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256, used for
//     TCP-based connections.
//     See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
//   - SSU2: Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256, used for
//     UDP-based connections.
//     See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
//
// Both protocols use the XK base pattern, X25519 key exchange,
// ChaCha20-Poly1305 encryption, and SHA-256 hashing. They carry I2NP
// messages between two routers; they are not general-purpose data pipes.
//
// # How to use it
//
// The main type is [Transport]. A Transport owns a connection pool and a
// shutdown manager, and it has methods to open connections (Dial) and accept
// them (Listen).
//
// To connect to a peer:
//
//	transport := noise.NewTransport(pool, noise.NewShutdownManager(30*time.Second))
//	defer transport.GracefulShutdown()
//	conn, err := transport.Dial("tcp", "127.0.0.1:7001", config)
//
// To accept connections:
//
//	listener, err := transport.Listen("tcp", "0.0.0.0:7001", config)
//
// Build your own Transport and call its methods. The package does not keep a
// shared, package-level Transport: pool and shutdown state belong to whoever
// constructs them.
//
// # Package layout
//
// This root package re-exports the public API from the noise/conn,
// noise/listener, and noise/shutdown sub-packages, so callers can keep using
// the root import path unchanged.
package noise

import (
	"net"
	"time"

	"github.com/go-i2p/go-noise/conn"
	"github.com/go-i2p/go-noise/listener"
	"github.com/go-i2p/go-noise/shutdown"
)

// ─── Type aliases (zero-cost: no wrapping, full method set preserved) ────────

// NoiseConn is an encrypted connection. It is an alias for conn.Conn, so it
// has the same methods as a regular net.Conn plus Noise-specific ones such as
// Handshake.
type NoiseConn = conn.Conn

// NoiseConnIface is an interface version of NoiseConn. Use it instead of
// *NoiseConn when you need to swap in a test double or another
// implementation.
type NoiseConnIface = conn.ConnIface

// NoiseAddr is an alias for conn.Addr. It describes the address of a Noise
// connection, including the Noise pattern and role in use.
type NoiseAddr = conn.Addr

// ConnConfig holds the settings for a Noise connection, such as the Noise
// handshake pattern and the key material.
type ConnConfig = conn.ConnConfig

// ConnState is an alias for conn.ConnState. It describes the current state
// of a Noise connection (for example, handshaking or established).
type ConnState = conn.ConnState

// NoiseListener is an alias for listener.Listener. It accepts incoming
// connections and wraps each one in a NoiseConn.
type NoiseListener = listener.Listener

// NoiseListenerIface is an interface version of NoiseListener. Use it
// instead of *NoiseListener when you need to swap in a test double or another
// implementation.
type NoiseListenerIface = listener.ListenerIface

// ListenerConfig holds the settings for a NoiseListener, such as the Noise
// handshake pattern.
type ListenerConfig = listener.ListenerConfig

// ShutdownManager coordinates a graceful shutdown: it tracks the connections
// and listeners created by a Transport and closes them in order when the
// application is stopping.
type ShutdownManager = shutdown.ShutdownManager

// ShutdownConn is an alias for shutdown.ShutdownConn. It marks a connection
// that can be shut down gracefully.
type ShutdownConn = shutdown.ShutdownConn

// ShutdownListener is an alias for shutdown.ShutdownListener. It marks a
// listener that can be shut down gracefully.
type ShutdownListener = shutdown.ShutdownListener

// Shutdowner is an alias for shutdown.Shutdowner. Accept this interface
// instead of *ShutdownManager when you want to allow test doubles or other
// shutdown coordinators.
type Shutdowner = shutdown.Shutdowner

// ─── Constant re-exports ─────────────────────────────────────────────────────

// Connection state constants, forwarded from noise/conn. They describe the
// lifecycle of a Noise connection:
//
//   - StateInit: the connection was created but has not started yet.
//   - StateHandshaking: the Noise handshake is in progress.
//   - StateEstablished: the handshake finished and data can flow.
//   - StateClosed: the connection is closed.
//
// These four are the only states a conn.Conn (root NoiseConn) can be in.
// The shared conn.ConnState type (mod.ConnState) defines a fifth value,
// StateClosing (a transient graceful-teardown state), but it is used only by
// SSU2, which re-exports it as ssu2.StateClosing; conn.Conn never sets it.
const (
	StateInit        = conn.StateInit
	StateHandshaking = conn.StateHandshaking
	StateEstablished = conn.StateEstablished
	StateClosed      = conn.StateClosed
)

// ─── Constructor wrappers ─────────────────────────────────────────────────────

// NewNoiseConn wraps an existing net.Conn in a NoiseConn using the given
// config. The returned connection is not yet encrypted: call its Handshake
// method to finish setting up the secure channel.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*NoiseConn, error) {
	return conn.NewNoiseConn(underlying, config)
}

// NewNoiseAddr creates a NoiseAddr from an underlying net.Addr, recording
// the Noise pattern (for example "XK") and the role ("initiator" or
// "responder").
func NewNoiseAddr(underlying net.Addr, pattern, role string) *NoiseAddr {
	return conn.NewNoiseAddr(underlying, pattern, role)
}

// NewConnConfig creates a ConnConfig with sensible defaults for the given
// Noise pattern and role. The initiator flag should be true for the side
// that starts the connection and false for the side that accepts it.
func NewConnConfig(pattern string, initiator bool) *ConnConfig {
	return conn.NewConnConfig(pattern, initiator)
}

// NewNoiseListener wraps an existing net.Listener so that every accepted
// connection is wrapped in a NoiseConn.
func NewNoiseListener(underlying net.Listener, config *ListenerConfig) (*NoiseListener, error) {
	return listener.NewNoiseListener(underlying, config)
}

// NewListenerConfig creates a ListenerConfig with sensible defaults for the
// given Noise pattern.
func NewListenerConfig(pattern string) *ListenerConfig {
	return listener.NewListenerConfig(pattern)
}

// NewShutdownManager creates a ShutdownManager that waits up to timeout for
// in-flight work to finish during a graceful shutdown.
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	return shutdown.NewShutdownManager(timeout)
}

// ValidateHandshakePattern reports whether pattern is a known Noise
// handshake pattern name. It accepts short names (such as "XK") and the
// standard full protocol names built from those short names with a plain
// cipher suite (such as "Noise_XK_25519_ChaChaPoly_SHA256" or
// "Noise_XK_25519_AESGCM_SHA256"). It does NOT accept the I2P transport
// protocol names with handshake modifiers (such as
// "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"); those are set via
// ConnConfig.ProtocolName, which bypasses pattern parsing.
func ValidateHandshakePattern(pattern string) error {
	return conn.ValidateHandshakePattern(pattern)
}
