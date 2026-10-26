package noise

import (
	"net"
)

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
