package noise

import (
	"net"
	"sync"

	"github.com/go-i2p/pool"
)

// putOnCloseWrapper wraps a freshly-dialed net.Conn so that its Close() call
// returns the connection to the pool for reuse rather than closing it to the OS.
// This is used by DialNoiseWithPool for new (non-pool-retrieved) connections.
type putOnCloseWrapper struct {
	net.Conn
	p    pool.Pool
	mu   sync.Mutex
	done bool
}

// newPutOnCloseWrapper creates a putOnCloseWrapper for the given connection.
func newPutOnCloseWrapper(conn net.Conn, p pool.Pool) net.Conn {
	return &putOnCloseWrapper{Conn: conn, p: p}
}

// Close puts the underlying connection back into the pool instead of closing it.
// The pool will close the connection itself if it is over capacity or already closed.
func (w *putOnCloseWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	// pool.Put unwraps any PoolConnWrapper nesting and keys by RemoteAddr.
	// Pool management errors are not caller-remediable; log at Debug and return nil
	// so callers (defer conn.Close(), io.Copy cleanup) are not burdened.
	if err := w.p.Put(w.Conn); err != nil {
		flog("putOnCloseWrapper.Close").WithError(err).Debug("pool Put failed on connection close")
	}
	return nil
}
