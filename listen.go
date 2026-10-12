package noise

import (
	"net"
)

// ListenNoise creates a listener on addr and wraps it in a NoiseListener, so
// every accepted connection is wrapped in a NoiseConn. This is a convenience
// function that delegates to the Default Transport.
//
// See examples/transport/main.go for a complete example.
//
// Deprecated: Use Transport.Listen on a dedicated Transport instance instead
// of depending on package-level global state. For example:
//
//	pool := pool.NewConnPool(&pool.PoolConfig{MaxSize: 10})
//	transport := noise.NewTransport(pool, noise.NewShutdownManager(30*time.Second))
//	defer transport.GracefulShutdown()
//	listener, err := transport.Listen("tcp", "0.0.0.0:8080", config)
func ListenNoise(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	return getDefault().Listen(network, addr, config)
}

// WrapConn wraps an existing net.Conn in a NoiseConn. It is an alias for
// NewNoiseConn, provided for consistency with the transport API.
func WrapConn(conn net.Conn, config *ConnConfig) (*NoiseConn, error) {
	return NewNoiseConn(conn, config)
}

// WrapListener wraps an existing net.Listener in a NoiseListener, so every
// accepted connection is wrapped in a NoiseConn. It is an alias for
// NewNoiseListener, provided for consistency with the transport API.
func WrapListener(listener net.Listener, config *ListenerConfig) (*NoiseListener, error) {
	return NewNoiseListener(listener, config)
}
