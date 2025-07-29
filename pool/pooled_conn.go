package pool

import (
	"net"
	"time"
)

// PooledConn represents a connection in the pool with metadata
// Moved from: pool/buffer.go
type PooledConn struct {
	Conn       net.Conn
	Created    time.Time
	LastUsed   time.Time
	InUse      bool
	RemoteAddr string
}
