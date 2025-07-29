package pool

import (
	"net"
)

// PoolConnWrapper wraps a pooled connection to handle automatic release
// Moved from: pool/buffer.go
type PoolConnWrapper struct {
	net.Conn
	pool *ConnPool
	addr string
}

// Close returns the connection to the pool instead of closing it
func (w *PoolConnWrapper) Close() error {
	w.pool.Release(w.addr, w.Conn)
	return nil
}
