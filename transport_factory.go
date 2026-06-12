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
// DialNoise and ListenNoise.
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
			log.WithFields(logger.Fields{"pkg": "transport", "func": "openAndWrapTransport", "error": closeErr.Error()}).Warn("resource.Close failed after wrap error")
		}
		return zero, err
	}
	if sm != nil {
		result.SetShutdownManager(sm)
	}
	return result, nil
}

// createNewConn establishes a new network connection to the specified address.
// Returns an error with detailed context if the connection fails.
func createNewConn(network, addr string) (net.Conn, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewConn", "network": network, "address": addr}).Debug("Dialing new connection")
	conn, err := net.Dial(network, addr)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewConn", "network": network, "address": addr}).WithError(err).Error("Dial failed")
		return nil, oops.
			Code("DIAL_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to dial %s://%s", network, addr)
	}
	return conn, nil
}

// createNoiseConn wraps a network connection with NoiseConn configuration.
// Returns an error with detailed context if NoiseConn creation fails.
func createNoiseConn(conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNoiseConn", "network": network, "address": addr}).Debug("Creating NoiseConn wrapper")
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNoiseConn"}).WithError(err).Error("Failed to create NoiseConn")
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}
	return noiseConn, nil
}

// createNewListener establishes a new network listener on the specified address.
// Returns an error with detailed context if the listen call fails.
func createNewListener(network, addr string) (net.Listener, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewListener", "network": network, "address": addr}).Debug("Creating new listener")
	listener, err := net.Listen(network, addr)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewListener", "network": network, "address": addr}).WithError(err).Error("Listen failed")
		return nil, wrapTransportError("LISTEN_FAILED", network, addr,
			"failed to listen on %s://%s", err, network, addr)
	}
	return listener, nil
}

// createNoiseListener wraps a network listener with NoiseListener configuration.
// Returns an error with detailed context if NoiseListener creation fails.
func createNoiseListener(listener net.Listener, config *ListenerConfig, network, addr string) (*NoiseListener, error) {
	noiseListener, err := NewNoiseListener(listener, config)
	if err != nil {
		return nil, wrapTransportError("NOISE_LISTENER_FAILED", network, addr,
			"failed to create noise listener", err)
	}
	return noiseListener, nil
}

// tryGetPooledConn attempts to retrieve a connection from the Default Transport's pool.
// Returns the connection and a boolean indicating if it came from the pool.
func tryGetPooledConn(addr string) (net.Conn, bool) {
	dt := getDefault()
	dt.mu.RLock()
	p := dt.pool
	dt.mu.RUnlock()
	if p != nil {
		conn := p.Get(addr)
		if conn != nil {
			return conn, true
		}
	}
	return nil, false
}

// createAndHandshakeConn creates a NoiseConn and performs handshake with retry logic.
// On error, the function closes conn (directly or via noiseConn.Close) so the
// caller must NOT close conn when an error is returned.
//
// This function delegates to the Default Transport's createAndHandshakeConnTransport
// to avoid duplicating the wrap-then-handshake logic.
func createAndHandshakeConn(ctx context.Context, conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	sm := GetGlobalShutdownManager()
	return getDefault().createAndHandshakeConnTransport(ctx, conn, config, network, addr, sm)
}
