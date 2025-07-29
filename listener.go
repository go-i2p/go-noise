package noise

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// NoiseListener implements net.Listener for accepting Noise Protocol connections.
// It wraps an underlying net.Listener and provides encrypted connections
// following the Noise Protocol Framework specification.
type NoiseListener struct {
	// underlying is the wrapped network listener
	underlying net.Listener

	// config contains the Noise protocol configuration for accepted connections
	config *ListenerConfig

	// addr is the Noise address for this listener
	addr *NoiseAddr

	// logger for listener events
	logger *logger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager *ShutdownManager

	// closed indicates if the listener has been closed
	closed bool

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// acceptMutex protects accept operations
	acceptMutex sync.Mutex
}

// ListenerConfig contains configuration for creating a NoiseListener.
// It follows the builder pattern for optional configuration and validation.
type ListenerConfig struct {
	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// StaticKey is the long-term static key for this listener (32 bytes for Curve25519)
	StaticKey []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration
}

// NewListenerConfig creates a new ListenerConfig with sensible defaults.
func NewListenerConfig(pattern string) *ListenerConfig {
	return &ListenerConfig{
		Pattern:          pattern,
		HandshakeTimeout: 30 * time.Second,
		ReadTimeout:      0, // No timeout by default
		WriteTimeout:     0, // No timeout by default
	}
}

// WithStaticKey sets the static key for this listener.
// key must be 32 bytes for Curve25519.
func (lc *ListenerConfig) WithStaticKey(key []byte) *ListenerConfig {
	lc.StaticKey = key
	return lc
}

// WithHandshakeTimeout sets the handshake timeout.
func (lc *ListenerConfig) WithHandshakeTimeout(timeout time.Duration) *ListenerConfig {
	lc.HandshakeTimeout = timeout
	return lc
}

// WithReadTimeout sets the read timeout for accepted connections.
func (lc *ListenerConfig) WithReadTimeout(timeout time.Duration) *ListenerConfig {
	lc.ReadTimeout = timeout
	return lc
}

// WithWriteTimeout sets the write timeout for accepted connections.
func (lc *ListenerConfig) WithWriteTimeout(timeout time.Duration) *ListenerConfig {
	lc.WriteTimeout = timeout
	return lc
}

// Validate checks if the configuration is valid.
func (lc *ListenerConfig) Validate() error {
	if lc.Pattern == "" {
		return oops.
			Code("INVALID_PATTERN").
			In("noise").
			Errorf("noise pattern is required")
	}

	if _, err := parseHandshakePattern(lc.Pattern); err != nil {
		return oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", lc.Pattern).
			Wrapf(err, "invalid noise pattern")
	}

	if len(lc.StaticKey) > 0 && len(lc.StaticKey) != 32 {
		return oops.
			Code("INVALID_KEY_LENGTH").
			In("noise").
			With("key_length", len(lc.StaticKey)).
			With("pattern", lc.Pattern).
			Errorf("static key must be 32 bytes")
	}

	if lc.HandshakeTimeout <= 0 {
		return oops.
			Code("INVALID_TIMEOUT").
			In("noise").
			With("timeout", lc.HandshakeTimeout).
			With("pattern", lc.Pattern).
			Errorf("handshake timeout must be positive")
	}

	return nil
}

// NewNoiseListener creates a new NoiseListener that wraps the underlying listener.
// The listener will accept connections and wrap them in NoiseConn instances
// configured as responders (non-initiators) using the provided configuration.
func NewNoiseListener(underlying net.Listener, config *ListenerConfig) (*NoiseListener, error) {
	if underlying == nil {
		return nil, oops.Errorf("underlying listener cannot be nil")
	}

	if config == nil {
		return nil, oops.Errorf("listener config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("noise").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "invalid listener configuration")
	}

	// Create Noise address for this listener
	addr := NewNoiseAddr(underlying.Addr(), config.Pattern, "responder")

	nl := &NoiseListener{
		underlying: underlying,
		config:     config,
		addr:       addr,
		logger:     log,
		closed:     false,
	}

	log.WithFields(logrus.Fields{
		"pattern":           config.Pattern,
		"listener_address":  underlying.Addr().String(),
		"handshake_timeout": config.HandshakeTimeout,
	}).Info("noise listener created")

	return nl, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection is wrapped in a NoiseConn configured as a responder.
func (nl *NoiseListener) Accept() (net.Conn, error) {
	nl.acceptMutex.Lock()
	defer nl.acceptMutex.Unlock()

	if nl.isClosed() {
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			Errorf("listener is closed")
	}

	// Accept the underlying connection
	underlying, err := nl.underlying.Accept()
	if err != nil {
		return nil, oops.
			Code("ACCEPT_FAILED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to accept underlying connection")
	}

	// Create connection config for the accepted connection (as responder)
	connConfig := NewConnConfig(nl.config.Pattern, false). // false = responder
								WithStaticKey(nl.config.StaticKey).
								WithHandshakeTimeout(nl.config.HandshakeTimeout).
								WithReadTimeout(nl.config.ReadTimeout).
								WithWriteTimeout(nl.config.WriteTimeout)

	// Wrap in NoiseConn
	noiseConn, err := NewNoiseConn(underlying, connConfig)
	if err != nil {
		underlying.Close() // Clean up the underlying connection
		return nil, oops.
			Code("WRAP_FAILED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", underlying.RemoteAddr().String()).
			Wrapf(err, "failed to create noise connection")
	}

	nl.logger.WithFields(logrus.Fields{
		"listener_addr": nl.addr.String(),
		"remote_addr":   underlying.RemoteAddr().String(),
	}).Debug("accepted new noise connection")

	return noiseConn, nil
}

// Close closes the listener and prevents new connections from being accepted.
// Any blocked Accept operations will be unblocked and return errors.
func (nl *NoiseListener) Close() error {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()

	if nl.closed {
		return nil // Already closed
	}

	nl.closed = true

	// Unregister from shutdown manager if set
	if nl.shutdownManager != nil {
		nl.shutdownManager.UnregisterListener(nl)
	}

	err := nl.underlying.Close()
	if err != nil {
		nl.logger.WithFields(logrus.Fields{
			"listener_addr": nl.addr.String(),
			"error":         err.Error(),
		}).Error("error closing underlying listener")

		return oops.
			Code("CLOSE_FAILED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to close underlying listener")
	}

	nl.logger.WithFields(logrus.Fields{
		"listener_addr": nl.addr.String(),
	}).Info("noise listener closed")

	return nil
}

// SetShutdownManager sets the shutdown manager for this listener.
// If a shutdown manager is set, the listener will be automatically
// registered for graceful shutdown coordination.
func (nl *NoiseListener) SetShutdownManager(sm *ShutdownManager) {
	nl.shutdownManager = sm
	if sm != nil {
		sm.RegisterListener(nl)
	}
}

// Addr returns the listener's network address.
// This is a NoiseAddr that wraps the underlying listener's address.
func (nl *NoiseListener) Addr() net.Addr {
	return nl.addr
}

// isClosed returns true if the listener has been closed.
// This method is not thread-safe and should only be called while holding closeMutex.
func (nl *NoiseListener) isClosed() bool {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()
	return nl.closed
}
