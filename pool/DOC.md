# pool
--
    import "github.com/go-i2p/go-noise/pool"

![pool.svg](pool.svg)



## Usage

#### type ConnPool

```go
type ConnPool struct {
}
```

ConnPool manages a pool of reusable connections for performance optimization. It
only uses interface types (net.Conn, net.Addr) for maximum compatibility. Moved
from: pool/buffer.go

#### func  NewConnPool

```go
func NewConnPool(config *PoolConfig) *ConnPool
```
NewConnPool creates a new connection pool with the given configuration

#### func (*ConnPool) Close

```go
func (p *ConnPool) Close() error
```
Close closes all connections in the pool and prevents new connections from being
added

#### func (*ConnPool) Get

```go
func (p *ConnPool) Get(remoteAddr string) net.Conn
```
Get retrieves a connection from the pool for the given remote address. Returns
nil if no suitable connection is available.

#### func (*ConnPool) Put

```go
func (p *ConnPool) Put(conn net.Conn) error
```
Put adds a connection to the pool for reuse

#### func (*ConnPool) Release

```go
func (p *ConnPool) Release(remoteAddr string, conn net.Conn)
```
Release marks a connection as no longer in use, making it available for reuse

#### func (*ConnPool) Stats

```go
func (p *ConnPool) Stats() map[string]int
```
Stats returns pool statistics

#### type PoolConfig

```go
type PoolConfig struct {
	MaxSize int           // Maximum number of connections per remote address
	MaxAge  time.Duration // Maximum age of a connection before it's closed
	MaxIdle time.Duration // Maximum idle time before a connection is closed
}
```

PoolConfig configures a connection pool Moved from: pool/buffer.go

#### type PoolConnWrapper

```go
type PoolConnWrapper struct {
	net.Conn
}
```

PoolConnWrapper wraps a pooled connection to handle automatic release Moved
from: pool/buffer.go

#### func (*PoolConnWrapper) Close

```go
func (w *PoolConnWrapper) Close() error
```
Close returns the connection to the pool instead of closing it

#### type PooledConn

```go
type PooledConn struct {
	Conn       net.Conn
	Created    time.Time
	LastUsed   time.Time
	InUse      bool
	RemoteAddr string
}
```

PooledConn represents a connection in the pool with metadata Moved from:
pool/buffer.go



pool 

github.com/go-i2p/go-noise/pool

[go-i2p template file](/template.md)
