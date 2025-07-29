package pool

import (
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// ConnPool manages a pool of reusable connections for performance optimization.
// It only uses interface types (net.Conn, net.Addr) for maximum compatibility.
// Moved from: pool/buffer.go
type ConnPool struct {
	mu      sync.RWMutex
	conns   map[string][]*PooledConn // keyed by remote address
	maxSize int
	maxAge  time.Duration
	maxIdle time.Duration
	closed  bool
}

// NewConnPool creates a new connection pool with the given configuration
func NewConnPool(config *PoolConfig) *ConnPool {
	if config == nil {
		config = &PoolConfig{
			MaxSize: 10,
			MaxAge:  30 * time.Minute,
			MaxIdle: 5 * time.Minute,
		}
	}

	pool := &ConnPool{
		conns:   make(map[string][]*PooledConn),
		maxSize: config.MaxSize,
		maxAge:  config.MaxAge,
		maxIdle: config.MaxIdle,
	}

	// Start cleanup goroutine
	go pool.cleanup()

	return pool
}

// Get retrieves a connection from the pool for the given remote address.
// Returns nil if no suitable connection is available.
func (p *ConnPool) Get(remoteAddr string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	connList, exists := p.conns[remoteAddr]
	if !exists || len(connList) == 0 {
		return nil
	}

	// Find an available connection
	for _, pooledConn := range connList {
		if !pooledConn.InUse && p.isValid(pooledConn) {
			pooledConn.InUse = true
			pooledConn.LastUsed = time.Now()
			return &PoolConnWrapper{
				Conn: pooledConn.Conn,
				pool: p,
				addr: remoteAddr,
			}
		}
	}

	return nil
}

// Put adds a connection to the pool for reuse
func (p *ConnPool) Put(conn net.Conn) error {
	if conn == nil {
		return oops.Errorf("cannot put nil connection in pool")
	}

	remoteAddr := conn.RemoteAddr().String()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return conn.Close()
	}

	connList := p.conns[remoteAddr]

	// Check if we've reached the maximum pool size for this address
	if len(connList) >= p.maxSize {
		return conn.Close()
	}

	pooledConn := &PooledConn{
		Conn:       conn,
		Created:    time.Now(),
		LastUsed:   time.Now(),
		InUse:      false,
		RemoteAddr: remoteAddr,
	}

	p.conns[remoteAddr] = append(connList, pooledConn)
	return nil
}

// Release marks a connection as no longer in use, making it available for reuse
func (p *ConnPool) Release(remoteAddr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	connList, exists := p.conns[remoteAddr]
	if !exists {
		return
	}

	for _, pooledConn := range connList {
		if pooledConn.Conn == conn {
			pooledConn.InUse = false
			pooledConn.LastUsed = time.Now()
			return
		}
	}
}

// Close closes all connections in the pool and prevents new connections from being added
func (p *ConnPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Close all connections
	for _, connList := range p.conns {
		for _, pooledConn := range connList {
			pooledConn.Conn.Close()
		}
	}

	// Clear the pool
	p.conns = make(map[string][]*PooledConn)

	return nil
}

// Stats returns pool statistics
func (p *ConnPool) Stats() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := 0
	inUse := 0

	for _, connList := range p.conns {
		total += len(connList)
		for _, pooledConn := range connList {
			if pooledConn.InUse {
				inUse++
			}
		}
	}

	return map[string]int{
		"total":     total,
		"in_use":    inUse,
		"available": total - inUse,
		"addresses": len(p.conns),
	}
}

// isValid checks if a pooled connection is still valid for use
func (p *ConnPool) isValid(pooledConn *PooledConn) bool {
	now := time.Now()

	// Check age limit
	if p.maxAge > 0 && now.Sub(pooledConn.Created) > p.maxAge {
		return false
	}

	// Check idle time limit
	if p.maxIdle > 0 && now.Sub(pooledConn.LastUsed) > p.maxIdle {
		return false
	}

	return true
}

// cleanup runs periodically to remove expired connections
func (p *ConnPool) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if p.shouldStopCleanup() {
			return
		}
		p.performCleanupCycle()
	}
}

// shouldStopCleanup checks if the cleanup process should be terminated
func (p *ConnPool) shouldStopCleanup() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// performCleanupCycle executes a single cleanup cycle for all connections
func (p *ConnPool) performCleanupCycle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, connList := range p.conns {
		validConns := p.filterValidConnections(connList)
		p.updateConnectionMap(addr, validConns)
	}
}

// filterValidConnections separates valid connections from expired ones
func (p *ConnPool) filterValidConnections(connList []*PooledConn) []*PooledConn {
	validConns := make([]*PooledConn, 0, len(connList))

	for _, pooledConn := range connList {
		if p.shouldKeepConnection(pooledConn) {
			validConns = append(validConns, pooledConn)
		} else {
			p.closeExpiredConnection(pooledConn)
		}
	}

	return validConns
}

// shouldKeepConnection determines if a connection should be retained
func (p *ConnPool) shouldKeepConnection(pooledConn *PooledConn) bool {
	return pooledConn.InUse || p.isValid(pooledConn)
}

// closeExpiredConnection properly closes an expired connection
func (p *ConnPool) closeExpiredConnection(pooledConn *PooledConn) {
	pooledConn.Conn.Close()
}

// updateConnectionMap updates the pool map with valid connections
func (p *ConnPool) updateConnectionMap(addr string, validConns []*PooledConn) {
	if len(validConns) == 0 {
		delete(p.conns, addr)
	} else {
		p.conns[addr] = validConns
	}
}
