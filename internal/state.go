package internal

import (
	"sync"
	"time"
)

// ConnState represents the internal state of a NoiseConn
type ConnState int

const (
	// StateInit represents a newly created connection
	StateInit ConnState = iota
	// StateHandshaking represents a connection performing handshake
	StateHandshaking
	// StateEstablished represents a connection with completed handshake
	StateEstablished
	// StateClosed represents a closed connection
	StateClosed
)

// String returns the string representation of the connection state
func (s ConnState) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateHandshaking:
		return "handshaking"
	case StateEstablished:
		return "established"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// ConnectionMetrics holds connection performance metrics
type ConnectionMetrics struct {
	mu               sync.RWMutex
	HandshakeStarted time.Time
	HandshakeEnded   time.Time
	BytesRead        int64
	BytesWritten     int64
	Created          time.Time
}

// NewConnectionMetrics creates a new ConnectionMetrics instance
func NewConnectionMetrics() *ConnectionMetrics {
	return &ConnectionMetrics{
		Created: time.Now(),
	}
}

// HandshakeDuration returns the duration of the handshake process
func (m *ConnectionMetrics) HandshakeDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.HandshakeStarted.IsZero() || m.HandshakeEnded.IsZero() {
		return 0
	}
	return m.HandshakeEnded.Sub(m.HandshakeStarted)
}

// SetHandshakeStart records the handshake start time
func (m *ConnectionMetrics) SetHandshakeStart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.HandshakeStarted = time.Now()
}

// SetHandshakeEnd records the handshake completion time
func (m *ConnectionMetrics) SetHandshakeEnd() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.HandshakeEnded = time.Now()
}

// AddBytesRead increments the bytes read counter
func (m *ConnectionMetrics) AddBytesRead(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BytesRead += n
}

// AddBytesWritten increments the bytes written counter
func (m *ConnectionMetrics) AddBytesWritten(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BytesWritten += n
}

// GetStats returns current connection statistics
func (m *ConnectionMetrics) GetStats() (bytesRead, bytesWritten int64, duration time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.BytesRead, m.BytesWritten, m.HandshakeDuration()
}
