package shutdown

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Shutdowner is implemented by any type that can coordinate graceful shutdown
// of noise connections and listeners. *ShutdownManager satisfies this interface.
// Accepting Shutdowner instead of *ShutdownManager allows callers to substitute
// test doubles or alternative shutdown coordinators without wrapping them inside
// a *ShutdownManager.
type Shutdowner interface {
	Shutdown() error
	RegisterConnection(ShutdownConn)
	UnregisterConnection(ShutdownConn)
	RegisterListener(ShutdownListener)
	UnregisterListener(ShutdownListener)
}

// ShutdownConn is implemented by any connection that can be managed by ShutdownManager.
// *NoiseConn satisfies this interface, as do *ntcp2.NTCP2Conn and *ssu2.SSU2Conn.
type ShutdownConn interface {
	io.Closer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// ShutdownListener is implemented by any listener that can be managed by ShutdownManager.
// *NoiseListener satisfies this interface, as do *ntcp2.NTCP2Listener and *ssu2.SSU2Listener.
type ShutdownListener interface {
	io.Closer
	Addr() net.Addr
}

// ShutdownManager coordinates graceful shutdown of noise components.
// It provides context-based cancellation and ensures proper resource cleanup
// with configurable timeouts for graceful vs forceful shutdown.
type ShutdownManager struct {
	// ctx is the context for shutdown signaling
	ctx context.Context

	// cancel cancels the shutdown context
	cancel context.CancelFunc

	// connections tracks active connections for graceful shutdown
	connections map[ShutdownConn]struct{}

	// listeners tracks active listeners for shutdown coordination
	listeners map[ShutdownListener]struct{}

	// mu protects the connection and listener maps
	mu sync.RWMutex

	// shutdownTimeout is the maximum time to wait for graceful shutdown
	shutdownTimeout time.Duration

	// logger for shutdown events
	logger *logger.Logger

	// done signals when shutdown is complete
	done chan struct{}

	// once ensures shutdown only happens once
	once sync.Once

	// shutdownErr stores the error from the shutdown sequence.
	// Protected by mu to ensure concurrent callers can read it.
	// See LOW-1 audit finding.
	shutdownErr error
}

// NewShutdownManager creates a new shutdown manager with the given timeout.
// If timeout is 0, a default of 30 seconds is used.
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	if timeout == 0 {
		timeout = baseconfig.DefaultHandshakeTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ShutdownManager{
		ctx:             ctx,
		cancel:          cancel,
		connections:     make(map[ShutdownConn]struct{}),
		listeners:       make(map[ShutdownListener]struct{}),
		shutdownTimeout: timeout,
		logger:          logger.GetGoI2PLogger(),
		done:            make(chan struct{}),
	}
}

// RegisterConnection adds a connection to be managed during shutdown.
// The connection will be gracefully closed during shutdown.
// conn may be any type satisfying ShutdownConn, including *NoiseConn,
// *ntcp2.NTCP2Conn, and *ssu2.SSU2Conn.
func (sm *ShutdownManager) RegisterConnection(conn ShutdownConn) {
	sm.registerConnection(conn, true)
}

// registerConnection is a helper to register or unregister a connection.
func (sm *ShutdownManager) registerConnection(conn ShutdownConn, register bool) {
	if conn == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	var op, action string
	if register {
		sm.connections[conn] = struct{}{}
		op = "RegisterConnection"
		action = "registered"
	} else {
		delete(sm.connections, conn)
		op = "UnregisterConnection"
		action = "unregistered"
	}

	sm.logger.WithFields(logger.Fields{
		"pkg":         "noise",
		"func":        "ShutdownManager." + op,
		"local_addr":  conn.LocalAddr().String(),
		"remote_addr": conn.RemoteAddr().String(),
		"total_conns": len(sm.connections),
	}).Debug(action + " connection for shutdown management")
}

// UnregisterConnection removes a connection from shutdown management.
// This should be called when a connection is closed normally.
func (sm *ShutdownManager) UnregisterConnection(conn ShutdownConn) {
	sm.registerConnection(conn, false)
}

// RegisterListener adds a listener to be managed during shutdown.
// The listener will be gracefully closed during shutdown.
// listener may be any type satisfying ShutdownListener, including *NoiseListener,
// *ntcp2.NTCP2Listener, and *ssu2.SSU2Listener.
func (sm *ShutdownManager) RegisterListener(listener ShutdownListener) {
	sm.registerListener(listener, true)
}

// UnregisterListener removes a listener from shutdown management.
// This should be called when a listener is closed normally.
func (sm *ShutdownManager) UnregisterListener(listener ShutdownListener) {
	sm.registerListener(listener, false)
}

// registerListener is a helper to register or unregister a listener.
func (sm *ShutdownManager) registerListener(listener ShutdownListener, register bool) {
	if listener == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	var op, action string
	if register {
		sm.listeners[listener] = struct{}{}
		op = "RegisterListener"
		action = "registered"
	} else {
		delete(sm.listeners, listener)
		op = "UnregisterListener"
		action = "unregistered"
	}

	sm.logger.WithFields(logger.Fields{
		"pkg":             "noise",
		"func":            "ShutdownManager." + op,
		"listener_addr":   listener.Addr().String(),
		"total_listeners": len(sm.listeners),
	}).Debug(action + " listener from shutdown management")
}

// Context returns the shutdown context for monitoring shutdown signals.
// Components can use this context to detect when shutdown has been initiated.
func (sm *ShutdownManager) Context() context.Context {
	return sm.ctx
}

// Shutdown initiates graceful shutdown of all managed components.
// It closes listeners first, waits for connections to drain, then forcefully
// closes remaining connections after the timeout period.
func (sm *ShutdownManager) Shutdown() error {
	var shutdownErr error

	sm.once.Do(func() {
		defer close(sm.done)

		sm.logShutdownInitiation()
		sm.cancel()

		shutdownErr = sm.executeShutdownSequence()
		sm.logger.WithFields(logger.Fields{"pkg": "noise", "func": "ShutdownManager.Shutdown"}).Info("graceful shutdown complete")

		// Store the error in the struct so subsequent callers can retrieve it.
		// See LOW-1 audit finding: all callers should see the same result.
		sm.mu.Lock()
		sm.shutdownErr = shutdownErr
		sm.mu.Unlock()
	})

	// Wait for the closure to complete if this is a concurrent caller.
	<-sm.done

	// Retrieve the stored shutdown error for all callers (including this one).
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.shutdownErr
}

// logShutdownInitiation logs the start of the shutdown process with current state.
// L-3: Acquire RLock before reading map lengths to prevent data race
func (sm *ShutdownManager) logShutdownInitiation() {
	connCount := sm.connectedCount()
	listCount := sm.listenerCount()

	sm.logger.WithFields(logger.Fields{
		"pkg":            "noise",
		"func":           "ShutdownManager.logShutdownInitiation",
		"timeout":        sm.shutdownTimeout.String(),
		"connections":    connCount,
		"listeners":      listCount,
		"shutdown_phase": "initiation",
		"timestamp":      time.Now().Format(time.RFC3339),
	}).Info("initiating graceful shutdown")
}

// executeShutdownSequence performs the main shutdown operations in order.
func (sm *ShutdownManager) executeShutdownSequence() error {
	var shutdownErr error

	// Close listeners first to stop accepting new connections
	shutdownErr = sm.closeListeners()
	if shutdownErr != nil {
		sm.logger.WithFields(logger.Fields{"pkg": "noise", "func": "ShutdownManager.executeShutdownSequence"}).WithError(shutdownErr).Error("error closing listeners during shutdown")
	}

	if err := sm.waitForConnectionsDrain(); err != nil {
		sm.logger.WithFields(logger.Fields{"pkg": "noise", "func": "ShutdownManager.executeShutdownSequence"}).WithError(err).Warn("timeout waiting for connections to drain, forcing close")
		if forceErr := sm.forceCloseConnections(); forceErr != nil {
			sm.logger.WithFields(logger.Fields{"pkg": "noise", "func": "ShutdownManager.executeShutdownSequence"}).WithError(forceErr).Error("error force closing connections")
			if shutdownErr == nil {
				shutdownErr = forceErr
			}
		}
	}

	return shutdownErr
}

// Wait blocks until shutdown is complete.
// This can be used to wait for shutdown to finish after calling Shutdown().
func (sm *ShutdownManager) Wait() {
	<-sm.done
}

// Timeout returns the configured graceful shutdown timeout duration.
func (sm *ShutdownManager) Timeout() time.Duration {
	return sm.shutdownTimeout
}

// connectedCount returns the number of registered connections.
// Thread-safe; acquires read lock.
func (sm *ShutdownManager) connectedCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.connections)
}

// listenerCount returns the number of registered listeners.
// Thread-safe; acquires read lock.
func (sm *ShutdownManager) listenerCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.listeners)
}

// ConnectionRegistered reports whether conn is currently tracked by this ShutdownManager.
func (sm *ShutdownManager) ConnectionRegistered(conn ShutdownConn) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.connections[conn]
	return ok
}

// ListenerRegistered reports whether listener is currently tracked by this ShutdownManager.
func (sm *ShutdownManager) ListenerRegistered(listener ShutdownListener) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.listeners[listener]
	return ok
}

// closeAll closes all items in a slice and returns the first error encountered.
// itemType is used for logging purposes (e.g., "listener" or "connection").
// logFn is called for each error to produce item-specific log messages.
func (sm *ShutdownManager) closeAll(items []io.Closer, itemType string, logFn func(io.Closer, error)) error {
	var firstError error
	for _, item := range items {
		if err := item.Close(); err != nil {
			logFn(item, err)
			if firstError == nil {
				firstError = err
			}
		}
	}
	return firstError
}

// closeListeners closes all registered listeners.
func (sm *ShutdownManager) closeListeners() error {
	sm.mu.RLock()
	listeners := make([]io.Closer, 0, len(sm.listeners))
	for listener := range sm.listeners {
		listeners = append(listeners, listener)
	}
	sm.mu.RUnlock()

	return sm.closeAll(listeners, "listener", func(item io.Closer, err error) {
		listener := item.(ShutdownListener)
		sm.logger.WithFields(logger.Fields{
			"pkg":            "noise",
			"func":           "ShutdownManager.closeListeners",
			"listener_addr":  listener.Addr().String(),
			"shutdown_phase": "listener_close",
		}).WithError(err).Error("error closing listener during shutdown")
	})
}

// waitForConnectionsDrain waits for all connections to close gracefully within timeout.
func (sm *ShutdownManager) waitForConnectionsDrain() error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.NewTimer(sm.shutdownTimeout)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			remaining := sm.connectedCount()

			return oops.
				Code("SHUTDOWN_TIMEOUT").
				In("shutdown").
				With("remaining_connections", remaining).
				With("timeout", sm.shutdownTimeout.String()).
				With("shutdown_phase", "drain_timeout").
				Errorf("timeout waiting for connections to drain")

		case <-ticker.C:
			connectionCount := sm.connectedCount()

			if connectionCount == 0 {
				return nil
			}

			sm.logger.WithFields(logger.Fields{"pkg": "noise", "func": "ShutdownManager.waitForConnectionsDrain", "remaining_connections": connectionCount}).
				WithField("shutdown_phase", "draining").
				Debug("waiting for connections to drain")
		}
	}
}

// forceCloseConnections forcefully closes all remaining connections.
func (sm *ShutdownManager) forceCloseConnections() error {
	sm.mu.RLock()
	connections := make([]io.Closer, 0, len(sm.connections))
	for conn := range sm.connections {
		connections = append(connections, conn)
	}
	sm.mu.RUnlock()

	return sm.closeAll(connections, "connection", func(item io.Closer, err error) {
		conn := item.(ShutdownConn)
		sm.logger.WithFields(logger.Fields{
			"pkg":            "noise",
			"func":           "ShutdownManager.forceCloseConnections",
			"local_addr":     conn.LocalAddr().String(),
			"remote_addr":    conn.RemoteAddr().String(),
			"shutdown_phase": "force_close",
		}).WithError(err).Error("error force closing connection during shutdown")
	})
}
