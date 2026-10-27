package ntcp2

import (
	"net"
	"sync"
	"time"
)

// Repeated-failure blacklisting.
//
// ntcp2.md §"AEAD Error Handling": "Bob should maintain a blacklist of IPs with
// repeated failures", and §"1) SessionRequest" -> DoS Mitigation: "Limit repeated
// or simultaneous connections from the same source. Maintain blacklists for sources
// that repeatedly fail. Do not respond to AEAD failure."
//
// The spec's probing resistance (a random timeout, a random junk read, then an RST)
// makes one failure cheap for the peer and expensive for us: we hold a socket and a
// goroutine for the whole probe window. Repeated failures from one source are the
// exhaustion vector, so the source gets dropped at accept time instead of being
// given another window.
//
// Policy is deliberately not hard-coded. The spec names neither a failure threshold
// nor a ban duration (both are "TBD"-adjacent "should" guidance), and a wrong guess
// bans real peers behind a shared NAT. So the tracking interface is exported, the
// default implementation's thresholds are configurable, and no tracker is installed
// unless a caller asks for one.

// FailureTracker records handshake and AEAD failures per source and reports when a
// source should no longer be served.
//
// Implementations must be safe for concurrent use.
type FailureTracker interface {
	// RecordFailure notes that the connection from addr failed a handshake or an
	// AEAD check.
	RecordFailure(addr net.Addr)

	// IsBlacklisted reports whether addr's source has failed enough recently to be
	// refused at accept time.
	IsBlacklisted(addr net.Addr) bool
}

// DefaultFailureThreshold is how many failures from one source within
// DefaultFailureWindow cause it to be refused. Three is the point at which a peer is
// no longer plausibly hitting a transient problem: a single clock-skewed or
// replayed message 1 is normal churn, three is a probe.
const DefaultFailureThreshold = 3

// DefaultFailureWindow is how long a recorded failure counts. It is short so a
// temporary glitch does not follow a peer around, and long enough that a scripted
// flood is still inside the window when it is refused.
const DefaultFailureWindow = 5 * time.Minute

// DefaultFailureTrackerCap bounds the number of tracked sources, so the tracker
// cannot itself become the exhaustion vector for a router being flooded from many
// addresses. When full, the oldest-recorded source is evicted.
const DefaultFailureTrackerCap = 4096

// FailureTrackerConfig tunes the built-in tracker.
type FailureTrackerConfig struct {
	// Threshold is the failure count that causes a refusal. Zero selects
	// DefaultFailureThreshold.
	Threshold int
	// Window is how long failures count. Zero selects DefaultFailureWindow.
	Window time.Duration
	// MaxSources bounds tracked sources. Zero selects DefaultFailureTrackerCap.
	MaxSources int
	// Now is a clock seam for tests. Nil selects time.Now.
	Now func() time.Time
}

// inMemoryFailureTracker is the default [FailureTracker]: a bounded map from
// network-or-IP to the timestamps of its recent failures.
type inMemoryFailureTracker struct {
	mutex     sync.Mutex
	threshold int
	window    time.Duration
	max       int
	now       func() time.Time
	failures  map[string][]time.Time
}

// NewFailureTracker builds the built-in tracker. It is not installed by default:
// pass it to a listener with [Config.WithFailureTracker].
func NewFailureTracker(cfg FailureTrackerConfig) *inMemoryFailureTracker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultFailureThreshold
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultFailureWindow
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultFailureTrackerCap
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &inMemoryFailureTracker{
		threshold: cfg.Threshold,
		window:    cfg.Window,
		max:       cfg.MaxSources,
		now:       cfg.Now,
		failures:  make(map[string][]time.Time),
	}
}

// RecordFailure appends a failure for addr's source.
func (t *inMemoryFailureTracker) RecordFailure(addr net.Addr) {
	key := sourceKey(addr)
	if key == "" {
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	now := t.now()
	recent := t.prune(t.failures[key], now)
	recent = append(recent, now)
	t.failures[key] = recent

	if len(t.failures) > t.max {
		t.evictOldestLocked()
	}
}

// IsBlacklisted reports whether addr's source has reached the threshold.
func (t *inMemoryFailureTracker) IsBlacklisted(addr net.Addr) bool {
	key := sourceKey(addr)
	if key == "" {
		return false
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	recent := t.prune(t.failures[key], t.now())
	if len(recent) == 0 {
		delete(t.failures, key)
		return false
	}
	t.failures[key] = recent
	return len(recent) >= t.threshold
}

// prune drops failures older than the window.
func (t *inMemoryFailureTracker) prune(entries []time.Time, now time.Time) []time.Time {
	kept := entries[:0]
	for _, when := range entries {
		if now.Sub(when) <= t.window {
			kept = append(kept, when)
		}
	}
	return kept
}

// evictOldestLocked removes the source whose most recent failure is oldest, so the
// map stays bounded. Must be called with t.mutex held.
func (t *inMemoryFailureTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, entries := range t.failures {
		if len(entries) == 0 {
			delete(t.failures, key)
			continue
		}
		latest := entries[len(entries)-1]
		if first || latest.Before(oldest) {
			oldestKey, oldest, first = key, latest, false
		}
	}
	if oldestKey != "" {
		delete(t.failures, oldestKey)
		flog("FailureTracker").Debug("evicted the oldest tracked source to stay within the cap")
	}
}

// sourceKey reduces an address to the identity the blacklist keys on: the IP, not
// the port. A peer that retries from a new ephemeral port is still the same source,
// and keying on host:port would let a scripted flood outrun the tracker by
// incrementing its port.
func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	tcpAddr, err := net.ResolveTCPAddr(addr.Network(), addr.String())
	if err != nil || tcpAddr.IP == nil {
		// A transport without IP addresses (a pipe in tests, a custom listener):
		// fall back to the whole address so failures are still attributed to
		// something stable.
		return addr.String()
	}
	return tcpAddr.IP.String()
}
