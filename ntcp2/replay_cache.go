package ntcp2

import (
	"sync"
	"time"

	"github.com/go-i2p/go-noise/mod/replaycache"
	"github.com/go-i2p/logger"
)

// ClockSkewTolerance is the maximum allowed difference between local and
// remote clocks for NTCP2 handshake timestamp validation.
//
// Per the I2P spec, connections with clock skew exceeding this value
// should be rejected.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
const ClockSkewTolerance = 60 * time.Second

// Replay cache constants.
//
// Bob must maintain a local cache of previously-used ephemeral keys (X
// values from message 1) and reject duplicates to prevent replay attacks.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
const (
	// replayCacheTTL is the default time-to-live for replay cache entries.
	// Entries older than this are evicted.
	//
	// ntcp2.rst §"Session Request": "Bob must maintain a local cache of
	// previously-used handshake values and reject duplicates, to prevent replay
	// attacks. Values in the cache must have a lifetime of at least 2*D", where
	// D is the maximum tolerated clock skew. With the default D of
	// ClockSkewTolerance (60 s) that is 120 s. Use replayCacheTTLFor so a
	// non-default MaxClockSkew still satisfies the 2*D floor.
	replayCacheTTL = 2 * ClockSkewTolerance

	// replayCacheCleanupInterval is how often the cache runs eviction of
	// expired entries.
	replayCacheCleanupInterval = 30 * time.Second

	// replayCacheMaxSize is the maximum number of entries before forced eviction
	// of the oldest entries. This prevents memory exhaustion under attack.
	replayCacheMaxSize = 100000
)

// ReplayCache is a thread-safe, bounded, TTL-based cache for detecting
// replayed NTCP2 handshake ephemeral keys.
//
// A replay attack is when an attacker re-sends a previously captured
// handshake message, hoping the receiver will treat it as new. To defend
// against this, the cache remembers the ephemeral keys it has already seen
// and rejects duplicates.
//
// The cache stores the first 32 bytes of each message 1 (the ephemeral key
// X) and rejects duplicates within the TTL (time-to-live) window. It is
// shared across all listener goroutines within a single router instance.
//
// ReplayCache implements the ReplayDetector interface.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
type ReplayCache struct {
	cache *replaycache.TTLCache
}

// compile-time interface check
var _ ReplayDetector = (*ReplayCache)(nil)

// NewReplayCache creates a new replay cache with the default TTL
// (2 × ClockSkewTolerance) and starts a background cleanup goroutine that
// periodically removes expired entries.
//
// Call Close() when the cache is no longer needed.
func NewReplayCache() *ReplayCache {
	return NewReplayCacheWithTTL(replayCacheTTL)
}

// NewReplayCacheWithTTL creates a replay cache whose entries live for at least
// ttl.
//
// ntcp2.rst §"Session Request" requires cached handshake values to have a
// lifetime of at least 2*D, where D is the responder's maximum tolerated clock
// skew, so a cache built for a config with a custom MaxClockSkew should use
// replayCacheTTLFor that value. A non-positive ttl falls back to the default.
func NewReplayCacheWithTTL(ttl time.Duration) *ReplayCache {
	flog("NewReplayCacheWithTTL", logger.Fields{"ttl": ttl}).Debug("Creating NTCP2 replay cache")
	if ttl <= 0 {
		ttl = replayCacheTTL
	}
	return &ReplayCache{
		cache: replaycache.New(replaycache.Config{
			TTL:             ttl,
			MaxSize:         replayCacheMaxSize,
			CleanupInterval: replayCacheCleanupInterval,
		}),
	}
}

// replayCacheTTLFor returns the replay-cache lifetime required for a maximum
// clock skew of d, i.e. the spec's 2*D floor.
func replayCacheTTLFor(d time.Duration) time.Duration {
	if d <= 0 {
		return replayCacheTTL
	}
	return 2 * d
}

// defaultReplayCaches holds the process-wide fallback replay caches, keyed by
// TTL, used by any responder whose Config does not supply a ReplayDetector.
var defaultReplayCaches sync.Map // time.Duration -> *ReplayCache

// fallbackReplayDetector returns a replay cache for responders that were not
// given one.
//
// ntcp2.rst §"Session Request" makes the duplicate-handshake-value cache
// mandatory ("Bob must maintain a local cache of previously-used handshake
// values and reject duplicates"), so replay protection must not be opt-in: a
// responder with no configured detector still needs one. The cache is shared
// across such responders for a given skew so that a replay arriving on a
// different connection is still caught.
func fallbackReplayDetector(maxSkew time.Duration) *ReplayCache {
	ttl := replayCacheTTLFor(maxSkew)
	if existing, ok := defaultReplayCaches.Load(ttl); ok {
		return existing.(*ReplayCache)
	}
	rc := NewReplayCacheWithTTL(ttl)
	// Load-or-store so concurrent first handshakes share a single cache.
	actual, _ := defaultReplayCaches.LoadOrStore(ttl, rc)
	if actual != rc {
		rc.Close()
	}
	return actual.(*ReplayCache)
}

// CheckAndAdd checks whether an ephemeral key has been seen before.
//
// If the key is new, it is added to the cache and false is returned (not a
// replay). If the key has been seen within the TTL window, true is returned
// (replay detected).
//
// This is the primary method called by the listener before processing
// message 1.
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
//
// Close is idempotent — calling it more than once is safe and will not
// panic.
func (rc *ReplayCache) Close() {
	flog("ReplayCache.Close").Debug("Closing NTCP2 replay cache")
	rc.cache.Close()
}
