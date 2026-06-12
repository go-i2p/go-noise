// Package replaycache provides a thread-safe, bounded, TTL-based cache for
// detecting replayed [32]byte keys. It is used by both the ntcp2 and ratchet
// packages to prevent handshake replay attacks within configurable freshness
// windows.
package replaycache

import (
	"container/list"
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// defaultCleanupInterval is the fallback cleanup interval used when neither
// CleanupInterval nor TTL provide a positive duration. It guarantees that
// time.NewTicker in cleanupLoop never receives a non-positive interval (MEDIUM-1).
const defaultCleanupInterval = 60 * time.Second

// defaultMaxSize is the fallback maximum number of cache entries used when
// MaxSize is non-positive. It prevents silent weakening of replay detection.
const defaultMaxSize = 10000

// Config holds the parameters for constructing a TTLCache.
type Config struct {
	// TTL is the time-to-live for cache entries. Entries older than TTL
	// are considered expired and will not trigger replay detection.
	TTL time.Duration

	// MaxSize is the maximum number of entries before forced eviction
	// of the oldest entries. This prevents memory exhaustion under attack.
	MaxSize int

	// CleanupInterval controls how often the background goroutine evicts
	// expired entries.
	CleanupInterval time.Duration

	// NowFunc returns the current time. If nil, time.Now is used.
	// This field exists so callers can inject a test clock.
	NowFunc func() time.Time
}

// cacheEntry is the value stored in insertOrder list elements.
type cacheEntry struct {
	key        [32]byte
	insertedAt time.Time
}

// TTLCache is a thread-safe, bounded, TTL-based cache for detecting
// replayed [32]byte keys. Call New to create an instance and Close
// to release its background goroutine.
//
// ACCT-4: entries are tracked in insertion order via a doubly-linked list so
// that evictOldestLocked runs in O(k) — removing k entries from the front —
// rather than the previous O(n log n) full-sort approach.
type TTLCache struct {
	mu sync.RWMutex
	// entries maps a [32]byte key to its *list.Element in insertOrder.
	entries map[[32]byte]*list.Element
	// insertOrder is a doubly-linked list of *cacheEntry maintained in
	// insertion order (front = oldest, back = newest). This enables O(k)
	// eviction of the k oldest entries without sorting.
	insertOrder     *list.List
	ttl             time.Duration
	maxSize         int
	cleanupInterval time.Duration
	done            chan struct{}
	closeOnce       sync.Once
	nowFunc         func() time.Time
}

// New creates a new TTLCache and starts a background cleanup goroutine.
// Call Close when the cache is no longer needed.
// Defaults: if CleanupInterval is non-positive, defaults to TTL; if TTL is
// also non-positive, defaults to defaultCleanupInterval so the background
// cleanup goroutine never panics (MEDIUM-1).
// If MaxSize is non-positive, defaults to defaultMaxSize (see LOW-2 audit finding).
func New(cfg Config) *TTLCache {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "New", "ttl": cfg.TTL, "max_size": cfg.MaxSize}).Debug("Creating new replay cache")
	nf := cfg.NowFunc
	if nf == nil {
		nf = time.Now
	}

	// Default CleanupInterval to TTL, then to defaultCleanupInterval, so
	// time.NewTicker in cleanupLoop never panics on an all-non-positive
	// config (MEDIUM-1). A zero-value Config{} is therefore safe.
	cleanupInterval := resolveCleanupInterval(cfg)

	// Default MaxSize to defaultMaxSize if not specified or non-positive.
	// This prevents silent weakening of replay detection.
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}

	c := &TTLCache{
		entries:         make(map[[32]byte]*list.Element),
		insertOrder:     list.New(),
		ttl:             cfg.TTL,
		maxSize:         maxSize,
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
		nowFunc:         nf,
	}
	go c.cleanupLoop()
	return c
}

// resolveCleanupInterval returns a strictly positive cleanup interval for the
// given config. It prefers CleanupInterval, falls back to TTL, and finally to
// defaultCleanupInterval, guaranteeing time.NewTicker never receives a
// non-positive duration (MEDIUM-1).
func resolveCleanupInterval(cfg Config) time.Duration {
	if cfg.CleanupInterval > 0 {
		return cfg.CleanupInterval
	}
	if cfg.TTL > 0 {
		return cfg.TTL
	}
	return defaultCleanupInterval
}

// CheckAndAdd returns true if the key has been seen within the TTL window
// (replay detected). If the key is new or expired, it is recorded and
// false is returned.
func (c *TTLCache) CheckAndAdd(key [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFunc()

	if elem, exists := c.entries[key]; exists {
		entry := elem.Value.(*cacheEntry)
		if now.Sub(entry.insertedAt) < c.ttl {
			log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.CheckAndAdd"}).Debug("Replay detected in cache")
			return true // replay detected
		}
		// Entry expired — remove from list and map, then re-insert below.
		c.insertOrder.Remove(elem)
		delete(c.entries, key)
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}

	elem := c.insertOrder.PushBack(&cacheEntry{key: key, insertedAt: now})
	c.entries[key] = elem
	return false
}

// Size returns the current number of entries in the cache.
func (c *TTLCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Close stops the background cleanup goroutine and releases resources.
// Close is idempotent — calling it more than once is safe.
func (c *TTLCache) Close() {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.Close"}).Debug("Closing replay cache")
	c.closeOnce.Do(func() { close(c.done) })
}

// Reset removes all entries from the cache.
func (c *TTLCache) Reset() {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.Reset"}).Debug("Clearing all replay cache entries")
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		delete(c.entries, k)
	}
	c.insertOrder.Init()
}

// cleanupLoop periodically evicts expired entries.
func (c *TTLCache) cleanupLoop() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// evictExpired removes all entries older than the TTL.
// Since insertOrder is chronological (front = oldest), we iterate from the
// front and stop as soon as we hit a non-expired entry, giving O(expired)
// performance rather than O(all) when few entries have expired.
func (c *TTLCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := c.nowFunc().Add(-c.ttl)
	for {
		front := c.insertOrder.Front()
		if front == nil {
			break
		}
		entry := front.Value.(*cacheEntry)
		if !entry.insertedAt.Before(cutoff) {
			break // remaining entries are newer, stop early
		}
		c.insertOrder.Remove(front)
		delete(c.entries, entry.key)
	}
}

// evictOldestLocked removes the oldest 10% of entries when the cache
// is full. ACCT-4: replaces the previous O(n log n) sort-and-slice approach
// with O(k) list-front removal. Must be called with c.mu held for writing.
func (c *TTLCache) evictOldestLocked() {
	evictCount := len(c.entries) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	for i := 0; i < evictCount; i++ {
		front := c.insertOrder.Front()
		if front == nil {
			break
		}
		entry := front.Value.(*cacheEntry)
		c.insertOrder.Remove(front)
		delete(c.entries, entry.key)
	}
}
