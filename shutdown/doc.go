// Package shutdown coordinates graceful shutdown of Noise connections and
// listeners.
//
// # What this package is for
//
// When a process is stopping, it wants to close its connections and listeners
// in an orderly way: give in-flight work a bounded amount of time to finish,
// then force-close anything that is still open. This package provides a single
// coordinator (ShutdownManager) that tracks every registered connection and
// listener and closes them together under a configurable timeout.
//
// # How it works
//
// Components register themselves with a ShutdownManager when they start and
// unregister when they close on their own. When Shutdown() is called, the
// manager cancels its context (so components that watch the context can stop
// accepting new work) and then closes all registered connections and
// listeners, waiting up to the configured timeout before giving up.
//
// The interfaces (ShutdownConn, ShutdownListener) are deliberately small so
// that any connection or listener can participate without depending on this
// package's concrete types.
package shutdown
