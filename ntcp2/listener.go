package ntcp2

import (
	"fmt"
	"net"
	"sync"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Listener implements net.Listener for accepting NTCP2 transport connections.
// It wraps a NoiseListener and provides NTCP2-specific addressing and connection handling
// with I2P router identity management and session establishment.
// Moved from: ntcp2/listener.go
type NTCP2Listener struct {
	// noiseListener is the underlying Noise protocol listener
	noiseListener *noise.NoiseListener

	// config contains the NTCP2-specific configuration
	config *NTCP2Config

	// addr is the NTCP2 address for this listener
	addr *NTCP2Addr

	// logger for listener events
	logger logger.Logger

	// closed indicates if the listener has been closed
	closed bool

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// acceptMutex protects accept operations
	acceptMutex sync.Mutex
}

// NewNTCP2Listener creates a new NTCP2Listener that wraps the underlying TCP listener.
// The listener will accept connections and wrap them in NTCP2Conn instances
// configured as responders with NTCP2-specific addressing and protocol handling.
func NewNTCP2Listener(underlying net.Listener, config *NTCP2Config) (*NTCP2Listener, error) {
	if err := validateListenerInput(underlying, config); err != nil {
		return nil, err
	}

	noiseListener, err := createNoiseListener(underlying, config)
	if err != nil {
		return nil, err
	}

	ntcp2Addr, err := createNTCP2Address(underlying, config)
	if err != nil {
		noiseListener.Close() // Clean up noise listener
		return nil, err
	}

	return initializeListener(noiseListener, config, ntcp2Addr, underlying), nil
}

// validateListenerInput checks if the underlying listener and config parameters are valid
func validateListenerInput(underlying net.Listener, config *NTCP2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_UNDERLYING_LISTENER").
			In("ntcp2").
			Errorf("underlying listener cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("ntcp2 config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "invalid ntcp2 listener configuration")
	}

	return nil
}

// createNoiseListener constructs and configures the underlying Noise protocol listener
func createNoiseListener(underlying net.Listener, config *NTCP2Config) (*noise.NoiseListener, error) {
	// Create underlying Noise listener configuration
	noiseConfig := noise.NewListenerConfig(config.Pattern).
		WithStaticKey(config.StaticKey).
		WithHandshakeTimeout(config.HandshakeTimeout).
		WithReadTimeout(config.ReadTimeout).
		WithWriteTimeout(config.WriteTimeout)

	// Create underlying Noise listener
	noiseListener, err := noise.NewNoiseListener(underlying, noiseConfig)
	if err != nil {
		return nil, oops.
			Code("NOISE_LISTENER_FAILED").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "failed to create underlying noise listener")
	}

	return noiseListener, nil
}

// createNTCP2Address creates the NTCP2 address for the listener from the underlying address and config
func createNTCP2Address(underlying net.Listener, config *NTCP2Config) (*NTCP2Addr, error) {
	ntcp2Addr, err := NewNTCP2Addr(underlying.Addr(), config.RouterHash, "responder")
	if err != nil {
		return nil, oops.
			Code("ADDR_CREATION_FAILED").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "failed to create ntcp2 address")
	}

	return ntcp2Addr, nil
}

// initializeListener creates and configures the final NTCP2Listener with logging
func initializeListener(noiseListener *noise.NoiseListener, config *NTCP2Config, ntcp2Addr *NTCP2Addr, underlying net.Listener) *NTCP2Listener {
	nl := &NTCP2Listener{
		noiseListener: noiseListener,
		config:        config,
		addr:          ntcp2Addr,
		logger:        *log,
		closed:        false,
	}

	nl.logger.Info("NTCP2 listener created",
		"pattern", config.Pattern,
		"listener_address", underlying.Addr().String(),
		"router_hash", formatRouterHash(config.RouterHash))

	return nl
}

// acceptFromNoiseListener accepts a connection from the underlying noise listener.
func (nl *NTCP2Listener) acceptFromNoiseListener() (net.Conn, error) {
	noiseConn, err := nl.noiseListener.Accept()
	if err != nil {
		return nil, oops.
			Code("ACCEPT_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to accept from underlying noise listener")
	}
	return noiseConn, nil
}

// validateAndCastNoiseConn validates the connection type and casts to NoiseConn.
func (nl *NTCP2Listener) validateAndCastNoiseConn(conn net.Conn) (*noise.NoiseConn, error) {
	actualNoiseConn, ok := conn.(*noise.NoiseConn)
	if !ok {
		conn.Close() // Clean up the connection
		return nil, oops.
			Code("INVALID_CONN_TYPE").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Errorf("expected *noise.NoiseConn from noise listener")
	}
	return actualNoiseConn, nil
}

// createRemoteNTCP2Addr creates the remote NTCP2 address for the accepted connection.
func (nl *NTCP2Listener) createRemoteNTCP2Addr(noiseConn *noise.NoiseConn) (*NTCP2Addr, error) {
	// Create remote NTCP2 address (we'll use placeholder router hash for now)
	// In a real implementation, this would be extracted from the handshake
	remoteRouterHash := make([]byte, 32) // Placeholder - would be from handshake
	remoteAddr, err := NewNTCP2Addr(noiseConn.RemoteAddr(), remoteRouterHash, "initiator")
	if err != nil {
		return nil, oops.
			Code("REMOTE_ADDR_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create remote ntcp2 address")
	}
	return remoteAddr, nil
}

// wrapInNTCP2Conn wraps the noise connection in an NTCP2Conn.
func (nl *NTCP2Listener) wrapInNTCP2Conn(noiseConn *noise.NoiseConn, remoteAddr *NTCP2Addr) (*NTCP2Conn, error) {
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, nl.addr, remoteAddr)
	if err != nil {
		return nil, oops.
			Code("NTCP2_WRAP_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create ntcp2 connection")
	}
	return ntcp2Conn, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection is wrapped in an NTCP2Conn configured as a responder.
func (nl *NTCP2Listener) Accept() (net.Conn, error) {
	nl.acceptMutex.Lock()
	defer nl.acceptMutex.Unlock()

	if err := nl.validateAcceptState(); err != nil {
		return nil, err
	}

	noiseConn, err := nl.acceptFromNoiseListener()
	if err != nil {
		return nil, err
	}

	ntcp2Conn, err := nl.processAcceptedConnection(noiseConn)
	if err != nil {
		return nil, err
	}

	nl.logAcceptedConnection(ntcp2Conn)
	return ntcp2Conn, nil
}

// validateAcceptState checks if the listener is in a valid state for accepting connections.
func (nl *NTCP2Listener) validateAcceptState() error {
	if nl.isClosed() {
		return oops.
			Code("LISTENER_CLOSED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Errorf("ntcp2 listener is closed")
	}
	return nil
}

// processAcceptedConnection converts the accepted connection to NTCP2Conn.
func (nl *NTCP2Listener) processAcceptedConnection(noiseConn net.Conn) (*NTCP2Conn, error) {
	actualNoiseConn, err := nl.validateAndCastNoiseConn(noiseConn)
	if err != nil {
		return nil, err
	}

	remoteAddr, err := nl.createRemoteNTCP2Addr(actualNoiseConn)
	if err != nil {
		return nil, err
	}

	return nl.wrapInNTCP2Conn(actualNoiseConn, remoteAddr)
}

// logAcceptedConnection logs details about the newly accepted connection.
func (nl *NTCP2Listener) logAcceptedConnection(ntcp2Conn *NTCP2Conn) {
	nl.logger.Debug("accepted new NTCP2 connection",
		"listener_addr", nl.addr.String(),
		"remote_addr", ntcp2Conn.RemoteAddr().String())
}

// Close closes the listener and prevents new connections from being accepted.
// Any blocked Accept operations will be unblocked and return errors.
func (nl *NTCP2Listener) Close() error {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()

	if nl.closed {
		return nil // Already closed
	}

	nl.closed = true

	err := nl.noiseListener.Close()
	if err != nil {
		nl.logger.Error("error closing underlying noise listener",
			"listener_addr", nl.addr.String(),
			"error", err.Error())

		return oops.
			Code("CLOSE_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to close underlying noise listener")
	}

	nl.logger.Info("NTCP2 listener closed",
		"listener_addr", nl.addr.String())

	return nil
}

// Addr returns the listener's network address.
// This is an NTCP2Addr that wraps the underlying listener's address.
func (nl *NTCP2Listener) Addr() net.Addr {
	return nl.addr
}

// isClosed returns true if the listener has been closed.
// This method is not thread-safe and should only be called while holding closeMutex.
func (nl *NTCP2Listener) isClosed() bool {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()
	return nl.closed
}

// formatRouterHash formats a router hash for logging (first 8 bytes as hex).
func formatRouterHash(hash []byte) string {
	if len(hash) < 8 {
		return "invalid"
	}
	return fmt.Sprintf("%x...", hash[:8])
}
