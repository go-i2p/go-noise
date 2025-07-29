package noise

import (
	"context"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// ShutdownManager coordinates graceful shutdown of noise components.
// It provides context-based cancellation and ensures proper resource cleanup
// with configurable timeouts for graceful vs forceful shutdown.
type ShutdownManager struct {
	// ctx is the context for shutdown signaling
	ctx context.Context

	// cancel cancels the shutdown context
	cancel context.CancelFunc

	// connections tracks active connections for graceful shutdown
	connections map[*NoiseConn]struct{}

	// listeners tracks active listeners for shutdown coordination
	listeners map[*NoiseListener]struct{}

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
}

// NewShutdownManager creates a new shutdown manager with the given timeout.
// If timeout is 0, a default of 30 seconds is used.
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ShutdownManager{
		ctx:             ctx,
		cancel:          cancel,
		connections:     make(map[*NoiseConn]struct{}),
		listeners:       make(map[*NoiseListener]struct{}),
		shutdownTimeout: timeout,
		logger:          logger.GetGoI2PLogger(),
		done:            make(chan struct{}),
	}
}

// RegisterConnection adds a connection to be managed during shutdown.
// The connection will be gracefully closed during shutdown.
func (sm *ShutdownManager) RegisterConnection(conn *NoiseConn) {
	if conn == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.connections[conn] = struct{}{}
	sm.logger.WithFields(logrus.Fields{
		"local_addr":  conn.LocalAddr().String(),
		"remote_addr": conn.RemoteAddr().String(),
		"total_conns": len(sm.connections),
	}).Debug("registered connection for shutdown management")
}

// UnregisterConnection removes a connection from shutdown management.
// This should be called when a connection is closed normally.
func (sm *ShutdownManager) UnregisterConnection(conn *NoiseConn) {
	if conn == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.connections, conn)
	sm.logger.WithFields(logrus.Fields{
		"local_addr":  conn.LocalAddr().String(),
		"remote_addr": conn.RemoteAddr().String(),
		"total_conns": len(sm.connections),
	}).Debug("unregistered connection from shutdown management")
}

// RegisterListener adds a listener to be managed during shutdown.
// The listener will be gracefully closed during shutdown.
func (sm *ShutdownManager) RegisterListener(listener *NoiseListener) {
	if listener == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.listeners[listener] = struct{}{}
	sm.logger.WithFields(logrus.Fields{
		"listener_addr":   listener.Addr().String(),
		"total_listeners": len(sm.listeners),
	}).Debug("registered listener for shutdown management")
}

// UnregisterListener removes a listener from shutdown management.
// This should be called when a listener is closed normally.
func (sm *ShutdownManager) UnregisterListener(listener *NoiseListener) {
	if listener == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.listeners, listener)
	sm.logger.WithFields(logrus.Fields{
		"listener_addr":   listener.Addr().String(),
		"total_listeners": len(sm.listeners),
	}).Debug("unregistered listener from shutdown management")
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
		sm.logger.Info("graceful shutdown complete")
	})

	return shutdownErr
}

// logShutdownInitiation logs the start of the shutdown process with current state.
func (sm *ShutdownManager) logShutdownInitiation() {
	sm.logger.WithFields(logrus.Fields{
		"timeout":     sm.shutdownTimeout.String(),
		"connections": len(sm.connections),
		"listeners":   len(sm.listeners),
	}).Info("initiating graceful shutdown")
}

// executeShutdownSequence performs the main shutdown operations in order.
func (sm *ShutdownManager) executeShutdownSequence() error {
	var shutdownErr error

	// Close listeners first to stop accepting new connections
	shutdownErr = sm.closeListeners()
	if shutdownErr != nil {
		sm.logger.WithError(shutdownErr).Error("error closing listeners during shutdown")
	}

	// Handle connection draining with timeout and force close if needed
	if err := sm.handleConnectionDraining(); err != nil {
		if shutdownErr == nil {
			shutdownErr = err
		}
	}

	// Close global connection pool
	if err := sm.closeGlobalConnectionPool(); err != nil {
		if shutdownErr == nil {
			shutdownErr = err
		}
	}

	return shutdownErr
}

// handleConnectionDraining waits for connections to drain or forces closure on timeout.
func (sm *ShutdownManager) handleConnectionDraining() error {
	if err := sm.waitForConnectionsDrain(); err != nil {
		sm.logger.WithError(err).Warn("timeout waiting for connections to drain, forcing close")
		if forceErr := sm.forceCloseConnections(); forceErr != nil {
			sm.logger.WithError(forceErr).Error("error force closing connections")
			return forceErr
		}
	}
	return nil
}

// closeGlobalConnectionPool closes the global connection pool if it exists.
func (sm *ShutdownManager) closeGlobalConnectionPool() error {
	if globalConnPool != nil {
		if err := globalConnPool.Close(); err != nil {
			sm.logger.WithError(err).Error("error closing global connection pool")
			return err
		}
	}
	return nil
}

// Wait blocks until shutdown is complete.
// This can be used to wait for shutdown to finish after calling Shutdown().
func (sm *ShutdownManager) Wait() {
	<-sm.done
}

// closeListeners closes all registered listeners.
func (sm *ShutdownManager) closeListeners() error {
	sm.mu.RLock()
	listeners := make([]*NoiseListener, 0, len(sm.listeners))
	for listener := range sm.listeners {
		listeners = append(listeners, listener)
	}
	sm.mu.RUnlock()

	var firstError error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			sm.logger.WithError(err).WithField("listener_addr", listener.Addr().String()).
				Error("error closing listener during shutdown")
			if firstError == nil {
				firstError = err
			}
		}
	}

	return firstError
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
			sm.mu.RLock()
			remaining := len(sm.connections)
			sm.mu.RUnlock()

			return oops.
				Code("SHUTDOWN_TIMEOUT").
				In("shutdown").
				With("remaining_connections", remaining).
				With("timeout", sm.shutdownTimeout.String()).
				Errorf("timeout waiting for connections to drain")

		case <-ticker.C:
			sm.mu.RLock()
			connectionCount := len(sm.connections)
			sm.mu.RUnlock()

			if connectionCount == 0 {
				return nil
			}

			sm.logger.WithField("remaining_connections", connectionCount).
				Debug("waiting for connections to drain")
		}
	}
}

// forceCloseConnections forcefully closes all remaining connections.
func (sm *ShutdownManager) forceCloseConnections() error {
	sm.mu.RLock()
	connections := make([]*NoiseConn, 0, len(sm.connections))
	for conn := range sm.connections {
		connections = append(connections, conn)
	}
	sm.mu.RUnlock()

	var firstError error
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			sm.logger.WithError(err).WithFields(logrus.Fields{
				"local_addr":  conn.LocalAddr().String(),
				"remote_addr": conn.RemoteAddr().String(),
			}).Error("error force closing connection during shutdown")
			if firstError == nil {
				firstError = err
			}
		}
	}

	return firstError
}
