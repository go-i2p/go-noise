package noise

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/go-i2p/pool"
	"github.com/samber/oops"
)

// Transport is the main entry point of this package. It owns a connection
// pool (which reuses idle TCP connections) and a shutdown manager (which
// closes everything in order on the way out), and it provides Dial and
// Listen methods for opening and accepting Noise connections.
//
// Build one with NewTransport. The package-level Default variable is a
// shared Transport for convenience, but it is deprecated; build your own
// Transport so each part of your program controls its own connections.
type Transport struct {
	mu   sync.RWMutex
	pool pool.Pool
	sm   Shutdowner
}

// NewTransport creates a Transport backed by the given pool and shutdown
// manager. Either argument may be nil: a nil pool disables connection
// reuse, and a nil shutdown manager disables shutdown registration.
func NewTransport(p pool.Pool, sm Shutdowner) *Transport {
	return &Transport{pool: p, sm: sm}
}

// GracefulShutdown shuts down this Transport's shutdown manager and closes
// its connection pool. Call it (often via defer) when your application is
// stopping so that connections are closed in an orderly way.
func (t *Transport) GracefulShutdown() error {
	t.mu.RLock()
	sm := t.sm
	cp := t.pool
	t.mu.RUnlock()
	var shutdownErr error
	if sm != nil {
		shutdownErr = sm.Shutdown()
	}
	if cp != nil {
		if err := cp.Close(); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

func (t *Transport) logAndGetShutdownManager(network, addr, op string) Shutdowner {
	flog(op, logger.Fields{"network": network, "address": addr}).Debug("starting")
	t.mu.RLock()
	sm := t.sm
	t.mu.RUnlock()
	return sm
}

// getPoolAndShutdown snapshots Transport resources under one read lock.
func (t *Transport) getPoolAndShutdown() (pool.Pool, Shutdowner) {
	t.mu.RLock()
	p := t.pool
	sm := t.sm
	t.mu.RUnlock()
	return p, sm
}

// dialFreshAndHandshake dials a new raw connection and then performs the
// standard NoiseConn wrap+handshake flow.
func (t *Transport) dialFreshAndHandshake(ctx context.Context, network, addr string, config *ConnConfig, sm Shutdowner) (*NoiseConn, error) {
	conn, err := createNewConnContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// createAndHandshakeConnTransport takes ownership of conn on error (closes it
	// and zeros key material), so we must not close conn here.
	return t.createAndHandshakeConnTransport(ctx, conn, config, network, addr, sm)
}

// Dial opens a new TCP connection to addr and wraps it in a NoiseConn. It
// does not perform the Noise handshake; call the returned connection's
// Handshake method to finish setup. The connection is registered with this
// Transport's shutdown manager.
func (t *Transport) Dial(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	sm := t.logAndGetShutdownManager(network, addr, "Transport.Dial")
	return openAndWrapTransport(
		sm,
		func() error { return validateDialParams(network, addr, config) },
		func() (io.Closer, error) { return createNewConn(network, addr) },
		func(c io.Closer) (*NoiseConn, error) {
			return createNoiseConn(c.(net.Conn), config, network, addr)
		},
	)
}

// Listen creates a NoiseListener on addr. Every connection the listener
// accepts is wrapped in a NoiseConn. The listener is registered with this
// Transport's shutdown manager.
func (t *Transport) Listen(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	sm := t.logAndGetShutdownManager(network, addr, "Transport.Listen")
	return openAndWrapTransport(
		sm,
		func() error { return validateListenParams(network, addr, config) },
		func() (io.Closer, error) { return createNewListener(network, addr) },
		func(c io.Closer) (*NoiseListener, error) {
			return createNoiseListener(c.(net.Listener), config, network, addr)
		},
	)
}

// DialWithPool creates a connection to addr, checking this Transport's
// connection pool first. If the pool has an idle connection to addr, it is
// reused; otherwise a new one is created. When the NoiseConn is closed, the
// underlying TCP connection goes back to the pool for reuse instead of being
// closed.
func (t *Transport) DialWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	flog("Transport.DialWithPool", logger.Fields{"network": network, "address": addr}).Debug("starting")
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	p, sm := t.getPoolAndShutdown()

	var conn net.Conn
	var fromPool bool
	if p != nil {
		conn = p.Get(addr)
		fromPool = conn != nil
	}

	if conn == nil {
		var err error
		conn, err = createNewConn(network, addr)
		if err != nil {
			return nil, err
		}
		// Wrap the freshly-dialed conn so that NoiseConn.Close() returns it to
		// the pool instead of closing it to the OS. Pool-retrieved conns are
		// already wrapped in PoolConnWrapper by ConnPool.Get(), which handles
		// the release path; this wrapper covers only the new-connection case.
		if p != nil {
			conn = newPutOnCloseWrapper(conn, p)
		}
	}
	_ = fromPool // pool-retrieved path is handled by PoolConnWrapper

	noiseConn, err := createNoiseConn(conn, config, network, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if sm != nil {
		noiseConn.SetShutdownManager(sm)
	}

	return noiseConn, nil
}

// DialWithHandshake creates a connection to addr, wraps it in a NoiseConn,
// and performs the Noise handshake, retrying if it fails. The returned
// connection is ready to send and receive data.
func (t *Transport) DialWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return t.DialWithHandshakeContext(context.Background(), network, addr, config)
}

// DialWithHandshakeContext is like DialWithHandshake but takes a context.
// Cancelling the context (or letting its deadline pass) stops the dial and
// handshake. This is the recommended way to open a connection.
func (t *Transport) DialWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	_, sm := t.getPoolAndShutdown()
	return t.dialFreshAndHandshake(ctx, network, addr, config, sm)
}

// DialWithPoolAndHandshake combines connection pooling with the Noise
// handshake: it reuses a pooled TCP connection when one is available,
// otherwise dials a new one, and then performs the handshake with retry.
func (t *Transport) DialWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return t.DialWithPoolAndHandshakeContext(context.Background(), network, addr, config)
}

// DialWithPoolAndHandshakeContext is like DialWithPoolAndHandshake but
// takes a context for cancellation. It reuses a pooled TCP connection when
// one is available (the pool keys connections by their remote address, which
// equals addr), wraps it in a new NoiseConn, and performs the Noise
// handshake. If the pool is empty, or a pooled connection fails the
// handshake, it falls back to a fresh dial.
func (t *Transport) DialWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	// pool.Put stores entries under conn.RemoteAddr().String(), which is the
	// plain "host:port" string — use addr directly so the keys match.
	p, sm := t.getPoolAndShutdown()

	if p != nil {
		if rawConn := p.Get(addr); rawConn != nil {
			noiseConn, err := t.createAndHandshakeConnTransport(ctx, rawConn, config, network, addr, sm)
			if err == nil {
				return noiseConn, nil
			}
			// createAndHandshakeConnTransport takes ownership of rawConn on error
			// (closes it to release the PoolConnWrapper and zero keys).
			// Fall through to fresh dial.
		}
	}

	// Create new connection with handshake.
	return t.dialFreshAndHandshake(ctx, network, addr, config, sm)
}

// createAndHandshakeConnTransport creates a NoiseConn and performs the
// handshake with retry logic. On error, the function closes conn (directly
// or via noiseConn.Close), so the caller must NOT close conn when an error
// is returned.
//
// If conn implements pool.PooledConnection (that is, it was retrieved from a
// connection pool via DialWithPoolAndHandshake*), a failure here calls
// Discard() instead of Close(). This permanently removes the broken or
// out-of-sync connection from the pool, so it is not handed out again and
// does not keep failing future Dial calls to the same address.
func (t *Transport) createAndHandshakeConnTransport(ctx context.Context, conn net.Conn, config *ConnConfig, network, addr string, sm Shutdowner) (*NoiseConn, error) {
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		discardOrClose(conn)
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	// Register with Transport's shutdown manager
	if sm != nil {
		noiseConn.SetShutdownManager(sm)
	}

	// Perform handshake with retry logic
	if err := noiseConn.HandshakeWithRetry(ctx); err != nil {
		// Discard the raw pool-tracked connection first (if applicable) so it
		// is permanently evicted rather than recycled; PoolConnWrapper.Discard
		// is idempotent with its own Close(), so noiseConn.Close() below
		// (which will call the now-already-discarded underlying's Close())
		// remains safe and still performs its own key-zeroization regardless
		// of the underlying close/discard outcome.
		discardOrClose(conn)
		// Close noiseConn to zero key material and close underlying conn
		noiseConn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "handshake failed")
	}

	return noiseConn, nil
}

// discardOrClose evicts conn from its connection pool via Discard() if conn
// implements pool.PooledConnection, or otherwise falls back to a plain
// Close(). Errors from either are logged at Debug (not caller-remediable, the
// connection is being torn down regardless).
func discardOrClose(conn net.Conn) {
	if pooled, ok := conn.(pool.PooledConnection); ok {
		if err := pooled.Discard(); err != nil {
			flog("discardOrClose").WithError(err).Debug("failed to discard broken pool connection")
		}
		return
	}
	if err := conn.Close(); err != nil {
		flog("discardOrClose").WithError(err).Debug("failed to close connection")
	}
}
