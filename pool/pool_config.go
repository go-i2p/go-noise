package pool

import (
	"time"
)

// PoolConfig configures a connection pool
// Moved from: pool/buffer.go
type PoolConfig struct {
	MaxSize int           // Maximum number of connections per remote address
	MaxAge  time.Duration // Maximum age of a connection before it's closed
	MaxIdle time.Duration // Maximum idle time before a connection is closed
}
