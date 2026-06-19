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

// Transport owns a Pool and ShutdownManager and provides Dial/Listen methods.
// Construct one with NewTransport; use the package-level Default for the
// conventional singleton.
type Transport struct {
	mu   sync.RWMutex
	pool pool.Pool
	sm   Shutdowner
}

// NewTransport creates a Transport backed by the given pool and shutdown
// manager. Either may be nil: a nil pool disables connection reuse; a nil
// ShutdownManager disables shutdown registration.
func NewTransport(p pool.Pool, sm Shutdowner) *Transport {
	return &Transport{pool: p, sm: sm}
}

// GracefulShutdown shuts down this Transport's ShutdownManager and Pool.
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

func (t *Transport) withShutdownManager(network, addr, op string) Shutdowner {
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

// Dial creates a Noise-wrapped connection to the given address using this Transport's
// ShutdownManager and Pool. It is the Transport-scoped equivalent of DialNoise.
func (t *Transport) Dial(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	sm := t.withShutdownManager(network, addr, "Transport.Dial")
	return openAndWrapTransport(
		sm,
		func() error { return validateDialParams(network, addr, config) },
		func() (io.Closer, error) { return createNewConn(network, addr) },
		func(c io.Closer) (*NoiseConn, error) {
			return createNoiseConn(c.(net.Conn), config, network, addr)
		},
	)
}

// Listen creates a Noise-wrapped listener on the given address using this Transport's
// ShutdownManager. It is the Transport-scoped equivalent of ListenNoise.
func (t *Transport) Listen(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	sm := t.withShutdownManager(network, addr, "Transport.Listen")
	return openAndWrapTransport(
		sm,
		func() error { return validateListenParams(network, addr, config) },
		func() (io.Closer, error) { return createNewListener(network, addr) },
		func(c io.Closer) (*NoiseListener, error) {
			return createNoiseListener(c.(net.Listener), config, network, addr)
		},
	)
}

// DialWithPool creates a connection to the given address, checking this Transport's pool first.
// If a suitable connection is available in the pool, it will be reused.
// Otherwise, a new connection is created. The connection will be automatically
// returned to the pool when the NoiseConn is closed.
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

// DialWithHandshake creates a connection to the given address, wraps it with NoiseConn,
// and performs the handshake with retry logic.
func (t *Transport) DialWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return t.DialWithHandshakeContext(context.Background(), network, addr, config)
}

// DialWithHandshakeContext creates a connection with context support for cancellation.
// It combines dialing, NoiseConn creation, and handshake with retry in a single operation.
func (t *Transport) DialWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	_, sm := t.getPoolAndShutdown()
	return t.dialFreshAndHandshake(ctx, network, addr, config, sm)
}

// DialWithPoolAndHandshake creates a connection with pool support and handshake retry.
// It checks the pool first, creates new if needed, and performs handshake with retry logic.
func (t *Transport) DialWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return t.DialWithPoolAndHandshakeContext(context.Background(), network, addr, config)
}

// DialWithPoolAndHandshakeContext combines pool checking, dialing, and handshake with context.
// It reuses a pooled raw TCP connection when available (the pool keys by
// conn.RemoteAddr().String(), which equals addr), wraps it in a new NoiseConn,
// and performs the Noise handshake. Falls back to a fresh dial if the pool is
// empty or the pooled connection fails the handshake.
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

// createAndHandshakeConnTransport creates a NoiseConn and performs handshake with retry logic.
// On error, the function closes conn (directly or via noiseConn.Close) so the
// caller must NOT close conn when an error is returned.
func (t *Transport) createAndHandshakeConnTransport(ctx context.Context, conn net.Conn, config *ConnConfig, network, addr string, sm Shutdowner) (*NoiseConn, error) {
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		conn.Close()
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
