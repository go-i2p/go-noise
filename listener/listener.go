package listener

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/conn"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	shutdown "github.com/go-i2p/go-noise/shutdown"
	"github.com/go-i2p/logger"
	i2plogger "github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Listener implements net.Listener for accepting Noise Protocol connections.
// It wraps an underlying net.Listener and provides encrypted connections
// following the Noise Protocol Framework specification.
//
// IMPORTANT: The Listener does not internally retry on transient Accept errors
// (such as EMFILE, ECONNABORTED, or temporary resource exhaustion). Callers MUST
// implement retry logic with exponential backoff to recover from transient failures.
// Failure to do so allows attackers to kill the accept loop by repeatedly opening
// and resetting connections, causing a Denial of Service on the listener.
type Listener struct {
	// underlying is the wrapped network listener
	underlying net.Listener

	// config contains the Noise protocol configuration for accepted connections
	config *ListenerConfig

	// addr is the Noise address for this listener
	addr *conn.Addr

	// logger for listener events
	logger *logger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager shutdown.Shutdowner

	// closed indicates if the listener has been closed
	closed bool

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// consecutiveTransientErrors tracks the count of consecutive transient accept errors
	// for implementing exponential backoff retry logic (see Accept method).
	consecutiveTransientErrors int

	// transientErrorMutex protects updates to consecutiveTransientErrors
	transientErrorMutex sync.Mutex

	// maxConnSemaphore limits concurrent connections to prevent resource exhaustion DoS (M-6)
	// Nil if MaxConnections is 0 (unlimited). Non-nil if configured.
	maxConnSemaphore chan struct{}
}

// ListenerConfig contains configuration for creating a NoiseListener.
// It follows the builder pattern for optional configuration and validation.
type ListenerConfig struct {
	// BaseHandshakeConfig embeds the shared timeout, retry, and modifier fields
	// common to all Noise config types in this module.
	baseconfig.BaseHandshakeConfig

	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// StaticKey is the long-term static key for this listener (32 bytes for Curve25519)
	StaticKey []byte

	// MaxAcceptErrors sets the maximum number of consecutive transient accept errors
	// (such as EMFILE or ECONNABORTED) that the listener will automatically retry
	// before returning the error to the caller. Defaults to 3 if not set.
	// Set to 0 to disable automatic retry (all errors returned immediately).
	MaxAcceptErrors int

	// MaxConnections limits the number of concurrent connections accepted by this
	// listener, providing backpressure to prevent resource exhaustion DoS attacks (M-6).
	// Defaults to 0 (unlimited). Set to > 0 to enforce a limit.
	// When the limit is reached, Accept() blocks until a connection closes.
	MaxConnections int

	// PostHandshakeHook is an optional callback invoked after the Noise
	// handshake completes successfully but before the connection transitions
	// to the Established state. This allows protocol layers (e.g., NTCP2)
	// to derive additional key material from the handshake hash, set up
	// data-phase obfuscators, or perform post-handshake validation.
	//
	// If the hook returns an error, the handshake is considered failed and
	// the connection reverts to the Init state.
	PostHandshakeHook func(*conn.Conn) error

	// AdditionalSymmetricKeyLabels specifies labels for Additional Symmetric
	// Key (ASK) derivation at Split() time, per Noise spec §10.3. Each label
	// produces a 32-byte key derived from the chaining key. The derived keys
	// are available via NoiseConn.AdditionalSymmetricKeys() after the
	// handshake completes.
	//
	// For NTCP2, this should be set to [][]byte{[]byte("ask")} to derive
	// the ask_master used for SipHash key derivation.
	AdditionalSymmetricKeyLabels [][]byte
}

// NewListenerConfig creates a new ListenerConfig with sensible defaults.
func NewListenerConfig(pattern string) *ListenerConfig {
	return &ListenerConfig{
		Pattern:         pattern,
		MaxAcceptErrors: 3, // Default to retrying up to 3 transient errors
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: baseconfig.DefaultHandshakeTimeout,
			ReadTimeout:      0,
			WriteTimeout:     0,
			HandshakeRetries: 0,
			RetryBackoff:     1 * time.Second,
		},
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

// WithModifiers sets the handshake modifiers for accepted connections.
// Modifiers are applied in the order provided for outbound data and in
// reverse order for inbound data. Required for NTCP2 server-side connections.
func (lc *ListenerConfig) WithModifiers(modifiers ...handshake.HandshakeModifier) *ListenerConfig {
	lc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(lc.Modifiers, modifiers)
	return lc
}

// WithPostHandshakeHook sets a callback invoked after the Noise handshake completes
// but before the connection transitions to the Established state.
func (lc *ListenerConfig) WithPostHandshakeHook(hook func(*conn.Conn) error) *ListenerConfig {
	lc.PostHandshakeHook = hook
	return lc
}

// WithAdditionalSymmetricKeyLabels sets labels for ASK derivation at Split() time.
// For NTCP2, use [][]byte{[]byte("ask")}.
func (lc *ListenerConfig) WithAdditionalSymmetricKeyLabels(labels [][]byte) *ListenerConfig {
	lc.AdditionalSymmetricKeyLabels = labels
	return lc
}

// WithHandshakeRetries sets the number of handshake retry attempts for
// accepted connections. 0 means no retries.
func (lc *ListenerConfig) WithHandshakeRetries(retries int) *ListenerConfig {
	lc.HandshakeRetries = retries
	return lc
}

// WithRetryBackoff sets the base delay between retry attempts for accepted
// connections. Actual delay uses exponential backoff.
func (lc *ListenerConfig) WithRetryBackoff(backoff time.Duration) *ListenerConfig {
	lc.RetryBackoff = backoff
	return lc
}

// WithMaxAcceptErrors sets the maximum number of consecutive transient accept errors
// that the listener will retry before returning an error to the caller. Transient
// errors include EMFILE, ECONNABORTED, and other temporary system errors.
// Defaults to 3. Set to 0 to disable automatic retry.
func (lc *ListenerConfig) WithMaxAcceptErrors(maxErrors int) *ListenerConfig {
	lc.MaxAcceptErrors = maxErrors
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

	if err := conn.ValidateHandshakePattern(lc.Pattern); err != nil {
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
func NewNoiseListener(underlying net.Listener, config *ListenerConfig) (*Listener, error) {
	if underlying == nil {
		return nil, oops.
			Code("INVALID_LISTENER").
			In("noise").
			Errorf("underlying listener cannot be nil")
	}

	if config == nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("noise").
			Errorf("listener config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("noise").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "invalid listener configuration")
	}

	// Create Noise address for this listener
	addr := conn.NewNoiseAddr(underlying.Addr(), config.Pattern, "responder")

	// Initialize semaphore for connection limiting (M-6)
	var maxConnSem chan struct{}
	if config.MaxConnections > 0 {
		maxConnSem = make(chan struct{}, config.MaxConnections)
	}

	nl := &Listener{
		underlying:       underlying,
		config:           config,
		addr:             addr,
		logger:           log,
		closed:           false,
		maxConnSemaphore: maxConnSem,
	}

	log.WithFields(i2plogger.Fields{
		"pkg":               "noise",
		"func":              "NewNoiseListener",
		"pattern":           config.Pattern,
		"listener_address":  underlying.Addr().String(),
		"handshake_timeout": config.HandshakeTimeout,
	}).Info("noise listener created")

	return nl, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection is wrapped in a NoiseConn configured as a responder.
// This method is safe for concurrent use by multiple goroutines.
//
// Accept automatically retries on transient errors (EMFILE, ECONNABORTED, etc.)
// using exponential backoff, up to the configured MaxAcceptErrors threshold.
// This prevents transient system errors (e.g., temporary file descriptor exhaustion)
// from killing the accept loop. If MaxAcceptErrors consecutive transient errors
// occur, the error is returned to the caller.
//
// Connection Limiting (M-6): If MaxConnections is configured, Accept blocks
// until a connection slot becomes available. This provides backpressure against
// resource exhaustion DoS attacks.
func (nl *Listener) Accept() (net.Conn, error) {
	if nl.isClosed() {
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			Errorf("listener is closed")
	}

	// Acquire semaphore slot if MaxConnections is configured (M-6)
	// This blocks if the limit is reached, providing backpressure.
	if nl.maxConnSemaphore != nil {
		nl.maxConnSemaphore <- struct{}{}
	}

	// Flag to track if we successfully acquired a semaphore slot
	// If we acquired it but then fail before returning, we need to release it
	slotAcquired := nl.maxConnSemaphore != nil

	// Retry loop for handling transient accept errors with exponential backoff
	for {
		// Accept the underlying connection — net.TCPListener.Accept() is
		// concurrency-safe, so no mutex is needed here.
		underlying, err := nl.underlying.Accept()
		if err == nil {
			// Success: reset consecutive transient error counter
			nl.transientErrorMutex.Lock()
			nl.consecutiveTransientErrors = 0
			nl.transientErrorMutex.Unlock()

			// M-8: Set a handshake deadline on the underlying connection to prevent
			// a slow or silent peer from holding a goroutine indefinitely.
			// Use the configured HandshakeTimeout as the deadline duration.
			if nl.config.HandshakeTimeout > 0 {
				if err := underlying.SetDeadline(time.Now().Add(nl.config.HandshakeTimeout)); err != nil {
					if slotAcquired {
						<-nl.maxConnSemaphore // Release semaphore on deadline failure (M-6)
						slotAcquired = false
					}
					underlying.Close() // Clean up the underlying connection
					return nil, oops.
						Code("SET_DEADLINE_FAILED").
						In("noise").
						With("listener_addr", nl.addr.String()).
						With("remote_addr", underlying.RemoteAddr().String()).
						Wrapf(err, "failed to set handshake deadline")
				}
			}

			// Create connection config for the accepted connection (as responder),
			// propagating modifiers, post-handshake hook, and ASK labels from
			// the listener config.
			connConfig := nl.createAcceptConnConfig()

			// Wrap in NoiseConn
			noiseConn, err := conn.NewNoiseConn(underlying, connConfig)
			if err != nil {
				if slotAcquired {
					<-nl.maxConnSemaphore // Release semaphore on wrap failure (M-6)
					slotAcquired = false
				}
				underlying.Close() // Clean up the underlying connection
				return nil, oops.
					Code("WRAP_FAILED").
					In("noise").
					With("listener_addr", nl.addr.String()).
					With("remote_addr", underlying.RemoteAddr().String()).
					Wrapf(err, "failed to create noise connection")
			}

			nl.logger.WithFields(i2plogger.Fields{
				"pkg":           "noise",
				"func":          "NoiseListener.Accept",
				"listener_addr": nl.addr.String(),
				"remote_addr":   underlying.RemoteAddr().String(),
			}).Debug("accepted new noise connection")

			// If we acquired a semaphore slot, wrap the connection to release it on Close() (M-6)
			if slotAcquired {
				return newSemaphoreReleaseWrapper(noiseConn, nl.maxConnSemaphore), nil
			}
			return noiseConn, nil
		}

		// Accept error: check if it's a transient error and if we should retry
		isTransient := false
		if netErr, ok := err.(net.Error); ok {
			isTransient = netErr.Temporary()
		}

		// If it's not a transient error, release semaphore if acquired and return error (M-6)
		if !isTransient {
			if slotAcquired {
				<-nl.maxConnSemaphore
				slotAcquired = false
			}
			return nil, oops.
				Code("ACCEPT_FAILED").
				In("noise").
				With("listener_addr", nl.addr.String()).
				Wrapf(err, "failed to accept underlying connection")
		}

		// Handle transient error: update counter and check if we should retry
		nl.transientErrorMutex.Lock()
		nl.consecutiveTransientErrors++
		errorCount := nl.consecutiveTransientErrors
		nl.transientErrorMutex.Unlock()

		// If we've exceeded max transient errors, release semaphore and return error (M-6)
		if nl.config.MaxAcceptErrors > 0 && errorCount > nl.config.MaxAcceptErrors {
			if slotAcquired {
				<-nl.maxConnSemaphore
				slotAcquired = false
			}
			return nil, oops.
				Code("ACCEPT_FAILED_MAX_TRANSIENT").
				In("noise").
				With("listener_addr", nl.addr.String()).
				With("consecutive_errors", errorCount).
				With("max_errors", nl.config.MaxAcceptErrors).
				Wrapf(err, "exceeded maximum consecutive transient accept errors")
		}

		// If max errors is 0 (disabled), release semaphore and return immediately (M-6)
		if nl.config.MaxAcceptErrors == 0 {
			if slotAcquired {
				<-nl.maxConnSemaphore
				slotAcquired = false
			}
			return nil, oops.
				Code("ACCEPT_FAILED").
				In("noise").
				With("listener_addr", nl.addr.String()).
				Wrapf(err, "failed to accept underlying connection (transient error, retries disabled)")
		}

		// Calculate exponential backoff: base^count, capped at 10 seconds
		backoffDuration := nl.config.RetryBackoff
		for i := 1; i < errorCount; i++ {
			backoffDuration *= 2
			if backoffDuration > 10*time.Second {
				backoffDuration = 10 * time.Second
				break
			}
		}

		nl.logger.WithFields(i2plogger.Fields{
			"pkg":                "noise",
			"func":               "NoiseListener.Accept",
			"listener_addr":      nl.addr.String(),
			"consecutive_errors": errorCount,
			"max_errors":         nl.config.MaxAcceptErrors,
			"backoff_duration":   backoffDuration.String(),
			"transient_error":    err.Error(),
		}).Debug("transient accept error, retrying with backoff")

		// Sleep before retrying
		time.Sleep(backoffDuration)
	}
}

// createAcceptConnConfig builds a ConnConfig for an accepted (responder)
// connection, propagating all relevant fields from the ListenerConfig
// including modifiers, post-handshake hook, and ASK labels.
func (nl *Listener) createAcceptConnConfig() *conn.ConnConfig {
	connConfig := conn.NewConnConfig(nl.config.Pattern, false). // false = responder
									WithStaticKey(nl.config.StaticKey).
									WithHandshakeTimeout(nl.config.HandshakeTimeout).
									WithReadTimeout(nl.config.ReadTimeout).
									WithWriteTimeout(nl.config.WriteTimeout)

	if len(nl.config.Modifiers) > 0 {
		connConfig = connConfig.WithModifiers(nl.cloneModifiers()...)
	}
	if nl.config.PostHandshakeHook != nil {
		connConfig.PostHandshakeHook = nl.config.PostHandshakeHook
	}
	if len(nl.config.AdditionalSymmetricKeyLabels) > 0 {
		connConfig.AdditionalSymmetricKeyLabels = nl.config.AdditionalSymmetricKeyLabels
	}
	if nl.config.HandshakeRetries > 0 {
		connConfig = connConfig.WithHandshakeRetries(nl.config.HandshakeRetries)
	}
	if nl.config.RetryBackoff > 0 {
		connConfig = connConfig.WithRetryBackoff(nl.config.RetryBackoff)
	}

	return connConfig
}

// cloneModifiers returns a per-connection copy of the listener's configured
// modifiers. Stateful modifiers (e.g. NTCP2 AES-CBC ephemeral obfuscation, which
// carries chaining state from message 1 into message 2, or SipHash length
// obfuscation, which advances an IV chain) MUST NOT be shared across concurrently
// accepted connections: sharing one instance lets connection B overwrite
// connection A's per-handshake state, silently corrupting A's handshake.
//
// Modifiers implementing handshake.ModifierCloner are deep-copied so each
// connection gets an independent instance. Modifiers that do not implement
// ModifierCloner are assumed to be stateless (or internally immutable) and are
// shared by reference, matching Config.Clone() semantics in the ntcp2 package.
// See M-1 audit finding.
func (nl *Listener) cloneModifiers() []handshake.HandshakeModifier {
	out := make([]handshake.HandshakeModifier, len(nl.config.Modifiers))
	for i, m := range nl.config.Modifiers {
		if cloner, ok := m.(handshake.ModifierCloner); ok {
			out[i] = cloner.Clone()
		} else {
			out[i] = m
		}
	}
	return out
}

// Close closes the listener and prevents new connections from being accepted.
// Any blocked Accept operations will be unblocked and return errors.
func (nl *Listener) Close() error {
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
		nl.logger.WithFields(i2plogger.Fields{
			"pkg":           "noise",
			"func":          "NoiseListener.Close",
			"listener_addr": nl.addr.String(),
			"error":         err.Error(),
		}).Error("error closing underlying listener")

		return oops.
			Code("CLOSE_FAILED").
			In("noise").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to close underlying listener")
	}

	nl.logger.WithFields(i2plogger.Fields{
		"pkg":           "noise",
		"func":          "NoiseListener.Close",
		"listener_addr": nl.addr.String(),
	}).Info("noise listener closed")

	return nil
}

// SetShutdownManager sets the shutdown manager for this listener.
// If a shutdown manager is set, the listener will be automatically
// registered for graceful shutdown coordination.
func (nl *Listener) SetShutdownManager(sm shutdown.Shutdowner) {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()

	// Don't register if the listener is already closed
	if nl.closed {
		return
	}

	nl.shutdownManager = sm
	if sm != nil {
		sm.RegisterListener(nl)
	}
}

// Addr returns the listener's network address.
// This is a NoiseAddr that wraps the underlying listener's address.
func (nl *Listener) Addr() net.Addr {
	return nl.addr
}

// isClosed returns true if the listener has been closed.
// This method is thread-safe and acquires closeMutex internally;
// do not call it while holding closeMutex.
func (nl *Listener) isClosed() bool {
	nl.closeMutex.Lock()
	defer nl.closeMutex.Unlock()
	return nl.closed
}

// semaphoreReleaseWrapper wraps a *conn.Conn so that its Close() call releases
// a connection limit semaphore. Used by Accept() when MaxConnections is configured (M-6).
// It embeds the concrete *conn.Conn type, not the net.Conn interface, so that all
// Noise-specific methods (Handshake, GetConnectionState, etc.) are promoted and accessible
// to callers that type-assert to *conn.Conn.
type semaphoreReleaseWrapper struct {
	*conn.Conn
	semaphore chan struct{}
	mu        sync.Mutex
	released  bool
}

// newSemaphoreReleaseWrapper creates a wrapper that releases a semaphore slot on Close().
// It embeds the concrete *conn.Conn so all Noise-specific methods are promoted and accessible.
func newSemaphoreReleaseWrapper(noiseConn *conn.Conn, semaphore chan struct{}) net.Conn {
	return &semaphoreReleaseWrapper{Conn: noiseConn, semaphore: semaphore}
}

// Close closes the underlying connection and releases the semaphore slot (M-6).
func (w *semaphoreReleaseWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.released {
		// Already released, but still close the underlying connection
		return w.Conn.Close()
	}
	w.released = true
	// Close the underlying connection first
	err := w.Conn.Close()
	// Always release the semaphore, even if Close failed
	<-w.semaphore
	return err
}
