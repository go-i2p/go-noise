package noise

import (
	"context"
)

// # Dial function selection matrix
//
// The package exposes six DialNoise variants that differ along two axes:
//
//   - Pool: reuse idle TCP connections from the Default Transport pool?
//   - Handshake: perform the Noise handshake (with retry) as part of the call?
//
// Use this matrix to pick the right entry-point:
//
//	                        │ No handshake │ Handshake (retry) │
//	────────────────────────┼──────────────┼───────────────────┤
//	No pool (fresh TCP)     │ DialNoise    │ DialNoiseWithHandshake
//	                        │              │ DialNoiseWithHandshakeContext
//	────────────────────────┼──────────────┼───────────────────┤
//	Pool (reuse TCP)        │ DialNoiseWithPool │ DialNoiseWithPoolAndHandshake
//	                        │              │ DialNoiseWithPoolAndHandshakeContext
//
// Guidance:
//   - For most applications, use [DialNoiseWithHandshakeContext] (fresh TCP +
//     handshake + context) — it provides cancellation and retry support.
//   - Use the *WithPool* variants only if you share long-lived TCP connections
//     and have already configured the Default Transport pool.
//   - Use the bare [DialNoise] only when you will perform the handshake yourself
//     on the returned *NoiseConn.
//   - Prefer constructing a [Transport] directly for production workloads to
//     avoid coupling to the package-level Default singleton.

// DialNoise creates a connection to the given address and wraps it with NoiseConn.
// This is a convenience function that delegates to the Default Transport.
//
// Deprecated: Use Transport.Dial on a dedicated Transport instance instead of
// depending on package-level global state. For example:
//
//	pool := pool.NewConnPool(&pool.PoolConfig{MaxSize: 10})
//	transport := noise.NewTransport(pool, noise.NewShutdownManager(30*time.Second))
//	defer transport.GracefulShutdown()
//	conn, err := transport.Dial("tcp", "example.com:8080", config)
//
// See examples/transport/main.go for a complete example.
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().Dial(network, addr, config)
}

// DialNoiseWithPool creates a connection to the given address, checking the pool first.
// If a suitable connection is available in the pool, it will be reused.
// Otherwise, a new connection is created. The connection will be automatically
// returned to the pool when the NoiseConn is closed.
//
// Deprecated: Use Transport.DialWithPool on a dedicated Transport instance instead of
// depending on package-level global state. See DialNoise for a migration example.
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPool(network, addr, config)
}

// DialNoiseWithHandshake creates a connection to the given address, wraps it with NoiseConn,
// and performs the handshake with retry logic. This is the recommended high-level function
// for establishing Noise connections with automatic retry capabilities.
//
// Deprecated: Use Transport.DialWithHandshake on a dedicated Transport instance instead of
// depending on package-level global state. See DialNoise for a migration example.
func DialNoiseWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshake(network, addr, config)
}

// DialNoiseWithHandshakeContext creates a connection with context support for cancellation.
// It combines dialing, NoiseConn creation, and handshake with retry in a single operation.
//
// Deprecated: Use Transport.DialWithHandshakeContext on a dedicated Transport instance instead of
// depending on package-level global state. See DialNoise for a migration example.
func DialNoiseWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshakeContext(ctx, network, addr, config)
}

// DialNoiseWithPoolAndHandshake creates a connection with pool support and handshake retry.
// It checks the pool first, creates new if needed, and performs handshake with retry logic.
//
// Deprecated: Use Transport.DialWithPoolAndHandshake on a dedicated Transport instance instead of
// depending on package-level global state. See DialNoise for a migration example.
func DialNoiseWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshake(network, addr, config)
}

// DialNoiseWithPoolAndHandshakeContext combines pool checking, dialing, and handshake with context.
// It reuses a pooled raw TCP connection when available (the pool keys by
// conn.RemoteAddr().String(), which equals addr), wraps it in a new NoiseConn,
// and performs the Noise handshake. Falls back to a fresh dial if the pool is
// empty or the pooled connection fails the handshake.
//
// Deprecated: Use Transport.DialWithPoolAndHandshakeContext on a dedicated Transport instance instead of
// depending on package-level global state. See DialNoise for a migration example.
func DialNoiseWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshakeContext(ctx, network, addr, config)
}
