// Package listener provides a generic Noise Protocol listener.
//
// # What this package is for
//
// A listener accepts incoming connections and runs the Noise handshake as the
// responder (the side that already has a long-term key and is waiting for
// peers to connect). This package is transport-agnostic: it wraps any
// net.Listener (TCP, UDP-over-TCP, etc.) and returns encrypted Noise
// connections, without caring how the underlying bytes travel.
//
// The protocol-specific listeners (ntcp2.NTCP2Listener and ssu2.SSU2Listener)
// build on top of this package, so the retry, connection-limiting, and
// shutdown behavior described here applies to them too.
//
// # Transient error retry
//
// Accept() automatically retries on transient errors (such as EMFILE or
// ECONNABORTED) using exponential backoff, up to the configured
// MaxAcceptErrors threshold (default 3). This keeps a temporary resource
// problem from killing the accept loop. If the threshold is exceeded, the
// error is returned to the caller. Set MaxAcceptErrors to 0 to disable
// automatic retry.
//
// # Connection limiting
//
// If MaxConnections is set to a positive value, Accept() blocks until a
// connection slot is free. This provides backpressure so a burst of
// connections cannot exhaust system resources.
//
// # Shutdown
//
// A listener can be wired to a shutdown.ShutdownManager so that Close()
// participates in a coordinated, timed graceful shutdown of all connections
// and listeners in the process.
package listener
