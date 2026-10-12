package noise

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/go-i2p/pool"
)

var (
	defaultOnce sync.Once
	defaultInst *Transport
	defaultMu   sync.Mutex // protects concurrent ResetDefault() + getDefault() calls
)

// Default is the package-level Transport used by the convenience functions
// such as DialNoise and ListenNoise. It is created on first use.
//
// See examples/transport/main.go for a complete example.
//
// Deprecated: Package-level convenience only. Callers that share the Default
// instance across goroutines or tests affect shared state (the pool and the
// shutdown manager). Prefer constructing a Transport directly for production
// use:
//
//	newTransport := noise.NewTransport(myPool, myShutdown)
//
// For test isolation, call ResetDefault() in your TestMain or test teardown.
var Default *Transport

// ResetDefault resets the package-level Default Transport so that the next
// use creates a fresh instance.
//
// It is intended for test isolation only. Do not call it in production code:
// callers that still hold a reference to the previous Default will see a
// stale pointer.
//
// If a Default Transport exists, ResetDefault calls GracefulShutdown on it
// first, to clean up pool resources and shutdown manager goroutines. This
// prevents goroutine leaks in test suites that call ResetDefault multiple
// times.
//
// ResetDefault is safe to call from multiple goroutines at once.
func ResetDefault() {
	defaultMu.Lock()
	defer defaultMu.Unlock()

	if defaultInst != nil {
		if err := defaultInst.GracefulShutdown(); err != nil {
			flog("ResetDefault", logger.Fields{"error": err}).Warn("GracefulShutdown of previous Default Transport failed")
		}
	}
	defaultOnce = sync.Once{}
	defaultInst = nil
	Default = nil
}

// getDefault lazily creates the singleton Transport and exposes it as Default.
// Thread-safe: uses a mutex to protect against concurrent calls to ResetDefault().
func getDefault() *Transport {
	defaultMu.Lock()
	defer defaultMu.Unlock()

	// If already initialized, return existing instance
	if defaultInst != nil {
		return defaultInst
	}

	// Perform the one-time initialization using sync.Once
	// (mutex is still held, so ResetDefault won't race here)
	defaultOnce.Do(func() {
		defaultInst = NewTransport(
			pool.NewConnPool(&pool.PoolConfig{
				MaxSize: 10,
				MaxAge:  30 * time.Minute,
				MaxIdle: 5 * time.Minute,
			}),
			NewShutdownManager(30*time.Second),
		)
		Default = defaultInst
	})
	return defaultInst
}

// withLock executes fn while holding the Default Transport's mutex.
// If write is true, uses Write lock; otherwise uses Read lock.
func withLock(write bool, fn func()) {
	dt := getDefault()
	if write {
		dt.mu.Lock()
		defer dt.mu.Unlock()
	} else {
		dt.mu.RLock()
		defer dt.mu.RUnlock()
	}
	fn()
}

// withLockResult executes fn while holding the Default Transport's mutex and returns its result.
// If write is true, uses Write lock; otherwise uses Read lock.
func withLockResult[T any](write bool, fn func() T) T {
	dt := getDefault()
	if write {
		dt.mu.Lock()
		defer dt.mu.Unlock()
	} else {
		dt.mu.RLock()
		defer dt.mu.RUnlock()
	}
	return fn()
}

// SetGlobalConnPool sets a custom connection pool on the Default Transport.
// p may be any implementation of pool.Pool, including *pool.ConnPool. The
// previous pool, if any, is closed first.
//
// Deprecated: Use Transport.DialWithPool or Transport.DialWithPoolAndHandshake
// on a dedicated Transport instance instead of mutating global state.
func SetGlobalConnPool(p pool.Pool) {
	withLock(true, func() {
		dt := getDefault()
		if dt.pool != nil {
			if err := dt.pool.Close(); err != nil {
				flog("SetGlobalConnPool", logger.Fields{"error": err}).Warn("Close of previous global connection pool failed")
			}
		}
		dt.pool = p
	})
}

// GetGlobalConnPool returns the Default Transport's connection pool.
//
// Deprecated: Use a dedicated Transport instance instead of accessing global
// state.
func GetGlobalConnPool() pool.Pool {
	return withLockResult(false, func() pool.Pool {
		dt := getDefault()
		return dt.pool
	})
}

// SetGlobalShutdownManager sets a custom shutdown manager on the Default
// Transport. The previous shutdown manager, if any, is shut down gracefully
// before being replaced.
//
// Deprecated: Use a dedicated Transport instance instead of mutating global
// state.
func SetGlobalShutdownManager(sm Shutdowner) {
	withLock(true, func() {
		dt := getDefault()
		if dt.sm != nil {
			if err := dt.sm.Shutdown(); err != nil {
				flog("SetGlobalShutdownManager", logger.Fields{"error": err}).Warn("Shutdown of previous global shutdown manager failed")
			}
		}
		dt.sm = sm
	})
}

// GetGlobalShutdownManager returns the Default Transport's shutdown manager.
//
// Deprecated: Use a dedicated Transport instance instead of accessing global
// state.
func GetGlobalShutdownManager() Shutdowner {
	return withLockResult(false, func() Shutdowner {
		dt := getDefault()
		return dt.sm
	})
}

// GracefulShutdown shuts down all components of the Default Transport: its
// shutdown manager and its connection pool.
//
// Deprecated: Use Transport.GracefulShutdown on a dedicated Transport
// instance instead.
func GracefulShutdown() error {
	flog("GracefulShutdown").Debug("Initiating graceful shutdown of global components")
	return getDefault().GracefulShutdown()
}
