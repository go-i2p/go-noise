// Package mod provides shared helpers and secure utilities used across
// go-noise sub-packages, including state management and cryptographic zeroing.
package mod

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
	// StateClosing represents a connection in graceful shutdown (teardown
	// initiated but not yet fully closed). Transports that require a
	// protocol-level goodbye exchange (e.g. SSU2 Termination block) may
	// use this state during that wait period.
	StateClosing
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
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// ConnectionMetrics holds connection performance metrics.
// Mutable fields are unexported and accessed only through thread-safe methods.
// Created is exported because it is immutable after construction.
type ConnectionMetrics struct {
	mu               sync.RWMutex
	handshakeStarted time.Time
	handshakeEnded   time.Time
	bytesRead        int64
	bytesWritten     int64
	Created          time.Time
}

// NewConnectionMetrics creates a new ConnectionMetrics instance
func NewConnectionMetrics() *ConnectionMetrics {
	flog("NewConnectionMetrics").Debug("Creating new connection metrics")
	return &ConnectionMetrics{
		Created: time.Now(),
	}
}

// HandshakeDuration returns the duration of the handshake process
func (m *ConnectionMetrics) HandshakeDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.handshakeStarted.IsZero() || m.handshakeEnded.IsZero() {
		return 0
	}
	return m.handshakeEnded.Sub(m.handshakeStarted)
}

// SetHandshakeStart records the handshake start time
func (m *ConnectionMetrics) SetHandshakeStart() {
	flog("ConnectionMetrics.SetHandshakeStart").Debug("Recording handshake start time")
	updateTime(&m.mu, &m.handshakeStarted, time.Now())
}

// updateTime stores t in *field under mu. Extracted to avoid the
// lock/defer/assign triple appearing in every single-field setter.
func updateTime(mu *sync.RWMutex, field *time.Time, t time.Time) {
	mu.Lock()
	defer mu.Unlock()
	*field = t
}

// SetHandshakeEnd records the handshake completion time
func (m *ConnectionMetrics) SetHandshakeEnd() {
	flog("ConnectionMetrics.SetHandshakeEnd").Debug("Recording handshake end time")
	updateTime(&m.mu, &m.handshakeEnded, time.Now())
}

// AddBytesRead increments the bytes read counter
func (m *ConnectionMetrics) AddBytesRead(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesRead += n
}

// AddBytesWritten increments the bytes written counter
func (m *ConnectionMetrics) AddBytesWritten(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesWritten += n
}

// GetStats returns current connection statistics.
// All fields are read within a single lock acquisition to avoid
// nested RLock calls on the same goroutine, which can deadlock
// under write contention due to Go's RWMutex write-priority fairness.
func (m *ConnectionMetrics) GetStats() (bytesRead, bytesWritten int64, duration time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bytesRead = m.bytesRead
	bytesWritten = m.bytesWritten
	if !m.handshakeStarted.IsZero() && !m.handshakeEnded.IsZero() {
		duration = m.handshakeEnded.Sub(m.handshakeStarted)
	}
	return bytesRead, bytesWritten, duration
}
