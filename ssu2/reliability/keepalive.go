// Package reliability provides SSU2 connection reliability components.
package reliability

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SendReceiver defines the interface for sending keepalive messages.
// This interface is implemented by SSU2Conn to allow testing with mocks.
type SendReceiver interface {
	// SendKeepalive sends an ACK-only packet as keepalive
	SendKeepalive() error
}

// KeepaliveManager manages periodic keepalive messages to maintain UDP connection state.
//
// The keepalive mechanism serves multiple purposes:
//  1. Prevents NAT/firewall timeout by keeping UDP mapping active
//  2. Detects dead connections through lack of peer response
//  3. Maintains minimal overhead by piggybacking on data packets when possible
//
// Per ssu2.rst specification, the default keepalive interval is 15 seconds.
// Dead connection detection occurs after 3x the keepalive interval with no response.
type KeepaliveManager struct {
	// conn is the SSU2 connection this manager belongs to
	conn SendReceiver

	// interval is the time between keepalive checks
	interval time.Duration

	// timeout is the duration after which a connection is considered dead
	// (typically 3x the interval)
	timeout time.Duration

	// ticker drives periodic keepalive checks
	ticker *time.Ticker

	// stopChan signals the keepalive goroutine to stop
	stopChan chan struct{}

	// done signals that the keepalive goroutine has exited
	done chan struct{}

	// lastSent is the timestamp of last packet sent (any packet)
	lastSent time.Time

	// lastRecv is the timestamp of last packet received (any packet)
	lastRecv time.Time

	// mutex protects timestamp fields
	mutex sync.RWMutex

	// started indicates if the manager is currently running
	started bool
}

// NewKeepaliveManager creates a new keepalive manager.
//
// Parameters:
//   - conn: The connection to manage keepalive for
//   - interval: Time between keepalive checks (use 15*time.Second per ssu2.rst)
//   - timeout: Dead connection timeout (use 3*interval, typically 45 seconds)
//
// Returns an initialized but not yet started manager.
func NewKeepaliveManager(conn SendReceiver, interval, timeout time.Duration) *KeepaliveManager {
	flog("NewKeepaliveManager", logger.Fields{"interval": interval, "timeout": timeout}).Debug("Creating new KeepaliveManager")
	if interval <= 0 {
		interval = 15 * time.Second // ssu2.rst default
	}
	if timeout <= 0 {
		timeout = 3 * interval // Standard 3x interval
	}

	now := time.Now()
	return &KeepaliveManager{
		conn:     conn,
		interval: interval,
		timeout:  timeout,
		lastSent: now,
		lastRecv: now,
		started:  false,
	}
}

// Start begins the keepalive management goroutine.
//
// The goroutine will:
//  1. Check activity every interval period
//  2. Send keepalive if no activity since last check
//  3. Detect dead connections if no received packets within timeout
//
// This method is idempotent - calling Start() multiple times has no effect.
func (km *KeepaliveManager) Start() {
	flog("Start").Debug("Starting keepalive manager")
	km.mutex.Lock()
	defer km.mutex.Unlock()

	if km.started {
		return
	}

	km.stopChan = make(chan struct{})
	km.done = make(chan struct{})
	km.ticker = time.NewTicker(km.interval)
	km.started = true

	go km.keepaliveLoop()
}

// Stop terminates the keepalive management goroutine.
//
// This method blocks until the goroutine has fully stopped.
// It is idempotent and safe to call multiple times.
func (km *KeepaliveManager) Stop() {
	flog("Stop").Debug("Stopping keepalive manager")
	km.mutex.Lock()
	if !km.started {
		km.mutex.Unlock()
		return
	}

	km.started = false
	if km.ticker != nil {
		km.ticker.Stop()
	}
	close(km.stopChan)
	km.mutex.Unlock()

	// Wait for goroutine to exit before returning
	<-km.done
}

// IsStarted returns whether the keepalive manager is currently running.
func (km *KeepaliveManager) IsStarted() bool {
	return withRLock(&km.mutex, func() bool { return km.started })
}

// UpdateLastSent records that a packet was just sent.
//
// This should be called after any packet transmission, not just keepalive.
// The manager uses this to avoid sending unnecessary keepalive packets.
func (km *KeepaliveManager) UpdateLastSent() {
	km.mutex.Lock()
	defer km.mutex.Unlock()
	km.lastSent = time.Now()
}

// UpdateLastRecv records that a packet was just received.
//
// This should be called after any packet reception.
// The manager uses this to detect dead connections.
func (km *KeepaliveManager) UpdateLastRecv() {
	km.mutex.Lock()
	defer km.mutex.Unlock()
	km.lastRecv = time.Now()
}

// IsAlive returns true if the connection is responsive.
//
// A connection is considered dead if no packets have been received
// within the timeout period (typically 45 seconds for default settings).
func (km *KeepaliveManager) IsAlive() bool {
	return withRLock(&km.mutex, func() bool {
		return time.Since(km.lastRecv) < km.timeout
	})
}

// GetIdleTime returns the duration since last received packet.
//
// This can be used to monitor connection health or implement
// custom timeout logic.
func (km *KeepaliveManager) GetIdleTime() time.Duration {
	return withRLock(&km.mutex, func() time.Duration {
		return time.Since(km.lastRecv)
	})
}

// GetTimeSinceLastSent returns the duration since last sent packet.
func (km *KeepaliveManager) GetTimeSinceLastSent() time.Duration {
	return withRLock(&km.mutex, func() time.Duration {
		return time.Since(km.lastSent)
	})
}

// keepaliveLoop is the main goroutine that manages keepalive timing.
//
// Strategy:
//  1. Every interval, check time since last sent packet
//  2. If >= interval with no sent packets, send keepalive (DateTime block)
//  3. If >= timeout with no received packets, connection is dead (caller must close)
//
// The keepalive packet is sent via SendKeepalive() which should send a minimal
// DateTime block to maintain the UDP state without excessive overhead.
func (km *KeepaliveManager) keepaliveLoop() {
	flog("keepaliveLoop").Debug("keepaliveLoop: starting keepalive loop")
	defer close(km.done)
	tickC := km.ticker.C
	for {
		select {
		case <-tickC:
			km.mutex.RLock()
			timeSinceSent := time.Since(km.lastSent)
			timeSinceRecv := time.Since(km.lastRecv)
			km.mutex.RUnlock()

			// Send keepalive if we haven't sent anything recently
			if timeSinceSent >= km.interval {
				if err := km.conn.SendKeepalive(); err != nil {
					// Log error but continue - connection may recover
					_ = oops.Wrapf(err, "failed to send keepalive")
				} else {
					// Update lastSent timestamp after successful send
					km.UpdateLastSent()
				}
			}

			// Note: Dead connection detection (timeSinceRecv >= timeout)
			// is handled by the caller via IsAlive() checks.
			// We don't close the connection here to maintain separation of concerns.
			_ = timeSinceRecv // Used implicitly via IsAlive()

		case <-km.stopChan:
			return
		}
	}
}
