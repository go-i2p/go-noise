package ntcp2

import (
	"time"

	"github.com/go-i2p/go-noise/mod/replaycache"
)

// ClockSkewTolerance is the maximum allowed difference between local and
// remote clocks for NTCP2 handshake timestamp validation. Per the I2P spec,
// connections with clock skew exceeding this value should be rejected.
const ClockSkewTolerance = 60 * time.Second

// Replay cache constants.
//
// Spec reference: https://geti2p.net/spec/ntcp2#replay-prevention
//
// Bob must maintain a local cache of previously-used ephemeral keys (X values
// from message 1) and reject duplicates to prevent replay attacks.
const (
	// replayCacheTTL is the time-to-live for replay cache entries.
	// Entries older than this are evicted. Set to 2× the clock skew tolerance
	// (120 seconds) to cover legitimate retransmissions within the skew window.
	replayCacheTTL = 2 * ClockSkewTolerance

	// replayCacheCleanupInterval is how often the cache runs eviction of
	// expired entries.
	replayCacheCleanupInterval = 30 * time.Second

	// replayCacheMaxSize is the maximum number of entries before forced eviction
	// of the oldest entries. This prevents memory exhaustion under attack.
	replayCacheMaxSize = 100000
)

// ReplayCache is a thread-safe, bounded, TTL-based cache for detecting
// replayed NTCP2 handshake ephemeral keys. It is shared across all listener
// goroutines within a single router instance.
//
// The cache stores the first 32 bytes of each message 1 (the ephemeral key X)
// and rejects duplicates within the TTL window.
//
// ReplayCache implements the ReplayDetector interface.
type ReplayCache struct {
	cache *replaycache.TTLCache
}

// compile-time interface check
var _ ReplayDetector = (*ReplayCache)(nil)

// NewReplayCache creates a new replay cache and starts a background cleanup
// goroutine. Call Close() when the cache is no longer needed.
func NewReplayCache() *ReplayCache {
	flog("NewReplayCache").Debug("Creating NTCP2 replay cache")
	return &ReplayCache{
		cache: replaycache.New(replaycache.Config{
			TTL:             replayCacheTTL,
			MaxSize:         replayCacheMaxSize,
			CleanupInterval: replayCacheCleanupInterval,
		}),
	}
}

// CheckAndAdd checks whether an ephemeral key has been seen before.
// If the key is new, it is added to the cache and false is returned (not a replay).
// If the key has been seen within the TTL window, true is returned (replay detected).
//
// This is the primary method called by the listener before processing message 1.
func (rc *ReplayCache) CheckAndAdd(ephemeralKey [32]byte) bool {
	result := rc.cache.CheckAndAdd(ephemeralKey)
	if result {
		flog("ReplayCache.CheckAndAdd").Warn("Replay detected for ephemeral key")
	}
	return result
}

// Size returns the current number of entries in the cache.
func (rc *ReplayCache) Size() int {
	return rc.cache.Size()
}

// Close stops the background cleanup goroutine and releases resources.
// Close is idempotent — calling it more than once is safe and will not panic.
func (rc *ReplayCache) Close() {
	flog("ReplayCache.Close").Debug("Closing NTCP2 replay cache")
	rc.cache.Close()
}
