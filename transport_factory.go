package noise

import (
	"context"
	"io"
	"net"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// shutdownRegisterer is implemented by types that support global shutdown management.
type shutdownRegisterer interface {
	SetShutdownManager(Shutdowner)
}

// wrapTransportError creates a contextual error with transport metadata.
// This consolidates the repeated oops error wrapping pattern used by
// Transport.Dial and Transport.Listen.
func wrapTransportError(code, network, addr, msg string, err error, args ...interface{}) error {
	return oops.
		Code(code).
		In("transport").
		With("network", network).
		With("address", addr).
		Wrapf(err, msg, args...)
}

// openAndWrapTransport validates parameters, opens a network resource, wraps it
// in a Noise layer, and optionally registers it with a shutdown manager. It
// consolidates the shared validate-open-wrap-cleanup-register pattern used by
// Transport.Dial and Transport.Listen, eliminating the structural duplication
// between them.
func openAndWrapTransport[R shutdownRegisterer](
	sm Shutdowner,
	validate func() error,
	open func() (io.Closer, error),
	wrap func(io.Closer) (R, error),
) (R, error) {
	var zero R
	if err := validate(); err != nil {
		return zero, err
	}
	resource, err := open()
	if err != nil {
		return zero, err
	}
	result, err := wrap(resource)
	if err != nil {
		if closeErr := resource.Close(); closeErr != nil {
			flog("openAndWrapTransport", logger.Fields{"error": closeErr.Error()}).Warn("resource.Close failed after wrap error")
		}
		return zero, err
	}
	if sm != nil {
		result.SetShutdownManager(sm)
	}
	return result, nil
}

// createNewConn establishes a new network connection to the specified
// address using net.Dial. It returns an error with detailed context if the
// connection fails.
//
// Note: net.Dial has no timeout. A caller using the non-context variants
// (Dial, DialWithPool) that route through this
// function can block indefinitely if the peer never responds to the TCP
// handshake (for example, a firewall silently drops SYN packets). Callers
// that need a bounded connect time should use the *Context variants
// (DialWithHandshakeContext, DialWithPoolAndHandshakeContext), which honor
// context cancellation and deadlines.
func createNewConn(network, addr string) (net.Conn, error) {
	flog("createNewConn", logger.Fields{"network": network, "address": addr}).Debug("Dialing new connection")
	conn, err := net.Dial(network, addr)
	if err != nil {
		flog("createNewConn", logger.Fields{"network": network, "address": addr}).WithError(err).Error("Dial failed")
		return nil, wrapTransportError("DIAL_FAILED", network, addr,
			"failed to dial %s://%s", err, network, addr)
	}
	return conn, nil
}

// createNewConnContext establishes a new network connection with context
// support, so the dial can be cancelled or stopped by a deadline. It returns
// an error with detailed context if the connection fails.
func createNewConnContext(ctx context.Context, network, addr string) (net.Conn, error) {
	flog("createNewConnContext", logger.Fields{"network": network, "address": addr}).Debug("Dialing new connection with context")
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		flog("createNewConnContext", logger.Fields{"network": network, "address": addr}).WithError(err).Error("Dial failed")
		return nil, wrapTransportError("DIAL_FAILED", network, addr,
			"failed to dial %s://%s", err, network, addr)
	}
	return conn, nil
}

// createNoiseConn wraps a network connection in a NoiseConn using the given
// config. It returns an error with detailed context if creation fails.
func createNoiseConn(conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	flog("createNoiseConn", logger.Fields{"network": network, "address": addr}).Debug("Creating NoiseConn wrapper")
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		flog("createNoiseConn").WithError(err).Error("Failed to create NoiseConn")
		return nil, wrapTransportError("NOISE_CONN_FAILED", network, addr,
			"failed to create noise connection", err)
	}
	return noiseConn, nil
}

// createNewListener establishes a new network listener on the specified
// address. It returns an error with detailed context if the listen call
// fails.
func createNewListener(network, addr string) (net.Listener, error) {
	flog("createNewListener", logger.Fields{"network": network, "address": addr}).Debug("Creating new listener")
	listener, err := net.Listen(network, addr)
	if err != nil {
		flog("createNewListener", logger.Fields{"network": network, "address": addr}).WithError(err).Error("Listen failed")
		return nil, wrapTransportError("LISTEN_FAILED", network, addr,
			"failed to listen on %s://%s", err, network, addr)
	}
	return listener, nil
}

// createNoiseListener wraps a network listener in a NoiseListener using the
// given config. It returns an error with detailed context if creation fails.
func createNoiseListener(listener net.Listener, config *ListenerConfig, network, addr string) (*NoiseListener, error) {
	noiseListener, err := NewNoiseListener(listener, config)
	if err != nil {
		return nil, wrapTransportError("NOISE_LISTENER_FAILED", network, addr,
			"failed to create noise listener", err)
	}
	return noiseListener, nil
}
