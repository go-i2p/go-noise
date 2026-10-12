package noise

import (
	"context"
)

// DialNoise opens a new TCP connection to addr and wraps it in a NoiseConn.
// It does not perform the Noise handshake. This is a convenience function
// that delegates to the Default Transport.
//
// # Choosing a Dial function
//
// The package exposes six DialNoise variants. They differ along two axes:
//
//   - Pool: does the call reuse an idle TCP connection from the Default
//     Transport's pool?
//   - Handshake: does the call perform the Noise handshake (with retry) for
//     you?
//
// Use this table to pick the right entry point:
//
//	                          │ No handshake │ Handshake (with retry) │
//	──────────────────────────┼──────────────┼────────────────────────┤
//	No pool (fresh TCP)       │ DialNoise    │ DialNoiseWithHandshake
//	                          │              │ DialNoiseWithHandshakeContext
//	──────────────────────────┼──────────────┼────────────────────────┤
//	Pool (reuse TCP)          │ DialNoiseWithPool │ DialNoiseWithPoolAndHandshake
//	                          │              │ DialNoiseWithPoolAndHandshakeContext
//
// Guidance:
//
//   - For most applications, use [DialNoiseWithHandshakeContext] (fresh TCP +
//     handshake + context). It supports cancellation and retry.
//   - Use the *WithPool* variants only if you share long-lived TCP
//     connections and have already configured the Default Transport's pool.
//   - Use the bare [DialNoise] only when you will perform the handshake
//     yourself on the returned *NoiseConn.
//   - For production workloads, prefer building your own [Transport] instead
//     of relying on the package-level Default singleton.
//
// See examples/transport/main.go for a complete example.
//
// Deprecated: Use Transport.Dial on a dedicated Transport instance instead of
// depending on package-level global state. For example:
//
//	pool := pool.NewConnPool(&pool.PoolConfig{MaxSize: 10})
//	transport := noise.NewTransport(pool, noise.NewShutdownManager(30*time.Second))
//	defer transport.GracefulShutdown()
//	conn, err := transport.Dial("tcp", "example.com:8080", config)
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().Dial(network, addr, config)
}

// DialNoiseWithPool creates a connection to addr, checking the Default
// Transport's pool first. If the pool has an idle connection to addr, it is
// reused; otherwise a new one is created. When the NoiseConn is closed, the
// underlying TCP connection goes back to the pool for reuse.
//
// Deprecated: Use Transport.DialWithPool on a dedicated Transport instance
// instead of depending on package-level global state. See DialNoise for a
// migration example.
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPool(network, addr, config)
}

// DialNoiseWithHandshake creates a connection to addr, wraps it in a
// NoiseConn, and performs the Noise handshake, retrying if it fails. This is
// the recommended high-level function for establishing Noise connections
// with automatic retry.
//
// Deprecated: Use Transport.DialWithHandshake on a dedicated Transport
// instance instead of depending on package-level global state. See DialNoise
// for a migration example.
func DialNoiseWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshake(network, addr, config)
}

// DialNoiseWithHandshakeContext is like DialNoiseWithHandshake but takes a
// context. Cancelling the context (or letting its deadline pass) stops the
// dial and handshake.
//
// Deprecated: Use Transport.DialWithHandshakeContext on a dedicated Transport
// instance instead of depending on package-level global state. See DialNoise
// for a migration example.
func DialNoiseWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshakeContext(ctx, network, addr, config)
}

// DialNoiseWithPoolAndHandshake combines connection pooling with the Noise
// handshake: it checks the Default Transport's pool first, creates a new
// connection if needed, and performs the handshake with retry.
//
// Deprecated: Use Transport.DialWithPoolAndHandshake on a dedicated Transport
// instance instead of depending on package-level global state. See DialNoise
// for a migration example.
func DialNoiseWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshake(network, addr, config)
}

// DialNoiseWithPoolAndHandshakeContext is like DialNoiseWithPoolAndHandshake
// but takes a context for cancellation. It reuses a pooled TCP connection
// when one is available (the pool keys connections by their remote address,
// which equals addr), wraps it in a new NoiseConn, and performs the Noise
// handshake. If the pool is empty, or a pooled connection fails the
// handshake, it falls back to a fresh dial.
//
// Deprecated: Use Transport.DialWithPoolAndHandshakeContext on a dedicated
// Transport instance instead of depending on package-level global state. See
// DialNoise for a migration example.
func DialNoiseWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshakeContext(ctx, network, addr, config)
}
