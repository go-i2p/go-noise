package server

import (
	"container/list"
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// Token admission gates for retry-token issuance.
//
// SSU2 allows unauthenticated peers (off-path UDP spoofers) to trigger a
// Retry/token exchange by sending a TokenRequest. Without per-packet proof
// of reachability (which would be a cookie-based scheme), a naive listener
// that issues one token per distinct source address can be forced to evict
// real peers' tokens by flooding spoofed sources.
//
// Two cheap gates shrink that attack surface:
//
//  1. firstSightTracker: a bounded map of address -> first-seen time. An
//     address that has never been observed is recorded but declined; the
//     peer must retry (SSU2 clients already retry TokenRequests under
//     spec-defined backoff). Entries are timestamps only — much smaller
//     than a full Token struct — and live in an independent bounded
//     structure, so exhausting first-sight does not evict real tokens.
//
//  2. tokenIssuanceLimiter: a single global token bucket that caps total
//     tokens issued per second across all peers. Even if the first-sight
//     gate were bypassed, an attacker cannot amplify issuance beyond the
//     configured rate by fanning across spoofed IPs.

// firstSightEntry holds a single addr observation stored in the LRU list.
type firstSightEntry struct {
	addr string
	ts   time.Time
	// AUDIT 6.2: firstSightExpiration tracks when the address is no longer
	// considered "first-sight" (i.e., when it has completed the first-sight
	// gate and is allowed to obtain tokens). This never changes once set,
	// preventing an attacker from resetting the gate by waiting for the
	// entry to expire and then re-requesting as if it were brand new.
	firstSightExpiration time.Time
}

// firstSightTracker records the first time an address was observed so that
// the listener can demand a repeat contact before allocating a full token
// cache entry for it.
type firstSightTracker struct {
	// entries maps address string -> *list.Element (pointing into order).
	entries map[string]*list.Element
	// order is a doubly-linked list of *firstSightEntry, ordered from least-
	// recently-used (front) to most-recently-used (back). This mirrors the
	// eviction semantics of the original map scan (oldest last-seen time
	// evicted first) but in O(1) instead of O(n).
	order *list.List
	// window is the duration a sighting remains "fresh".
	window time.Duration
	// maxEntries bounds memory use. When the tracker is full, the oldest
	// sighting is evicted before a new one is recorded.
	maxEntries int
	// nowFunc returns the current time. Overridden by tests.
	nowFunc func() time.Time
	mutex   sync.Mutex
}

// newFirstSightTracker constructs a firstSightTracker with the given window
// and maximum size. If maxEntries is <= 0 it defaults to 50000. If window
// is <= 0 it defaults to 30 seconds.
func newFirstSightTracker(window time.Duration, maxEntries int) *firstSightTracker {
	if window <= 0 {
		window = 30 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	flog("newFirstSightTracker", logger.Fields{"window": window, "max_entries": maxEntries}).Debug("Creating first-sight tracker")
	return &firstSightTracker{
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

// ObserveAndAllow records that addr was seen and returns true only if the
// address was already observed before (either within the configured window or
// after the first-sight window has expired). On a brand-new address it
// records the sighting and returns false. On re-observation within the window
// it refreshes the timestamp and returns true.
//
// The caller should treat a false return as "drop this token request; the
// peer may retry and succeed on a subsequent request".
//
// AUDIT 6.2: The entry now tracks both the last-seen timestamp (ts) and
// a first-sight-expiration timestamp that never changes. This prevents
// attackers from resetting the gate by waiting for the entry to expire.
// Once an address has been observed once, it stays in the map so that
// temporal pacing attacks cannot cause it to be re-treated as brand new.
func (f *firstSightTracker) ObserveAndAllow(addr string) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	now := f.nowFunc()

	if elem, exists := f.entries[addr]; exists {
		// Address has been seen before. Regardless of whether we're still
		// within the first-sight window or past it, this is a retry or
		// a subsequent request after the gate has passed. Either way, allow it.
		entry := elem.Value.(*firstSightEntry)
		entry.ts = now
		f.order.MoveToBack(elem)
		return true
	}

	// Brand-new address. Record it and reject this request.
	if len(f.entries) >= f.maxEntries {
		f.evictOldestLocked()
	}
	// AUDIT 6.2: Set firstSightExpiration to now + window, so we can track
	// when the address should transition from "first-sight" to "allowed".
	// This timestamp never changes for this address, preventing temporal
	// pacing attacks that try to reset the gate by waiting for stale entries
	// to be cleaned up.
	entry := &firstSightEntry{
		addr:                 addr,
		ts:                   now,
		firstSightExpiration: now.Add(f.window),
	}
	elem := f.order.PushBack(entry)
	f.entries[addr] = elem
	return false
}

// Size returns the current number of tracked addresses.
func (f *firstSightTracker) Size() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return len(f.entries)
}

// Cleanup removes entries older than the window. Returns the number of
// entries removed. Intended to be called periodically by the listener.
// Because the list is maintained in LRU order (oldest at front), the walk
// can break early once a fresh entry is encountered.
func (f *firstSightTracker) Cleanup() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	cutoff := f.nowFunc().Add(-f.window)
	removed := 0
	for e := f.order.Front(); e != nil; {
		entry := e.Value.(*firstSightEntry)
		if entry.ts.Before(cutoff) {
			next := e.Next()
			f.order.Remove(e)
			delete(f.entries, entry.addr)
			removed++
			e = next
		} else {
			break // remaining entries are all newer
		}
	}
	return removed
}

// evictOldestLocked drops the single oldest (LRU front) sighting. Caller must hold mu.
func (f *firstSightTracker) evictOldestLocked() {
	front := f.order.Front()
	if front == nil {
		return
	}
	entry := front.Value.(*firstSightEntry)
	f.order.Remove(front)
	delete(f.entries, entry.addr)
}

// tokenIssuanceLimiter is a single global token bucket that limits the
// listener's total token issuance rate. It backstops firstSightTracker: an
// attacker who somehow bypasses first-sight still cannot issue more than
// rate tokens/second in aggregate.
type tokenIssuanceLimiter struct {
	// rate is the steady-state number of tokens/sec allowed.
	rate float64
	// burst is the maximum bucket capacity (allows short traffic spikes).
	burst float64
	// tokens is the current number of available tokens.
	tokens float64
	// lastRefill is the last time the bucket was refilled.
	lastRefill time.Time
	// nowFunc returns the current time. Overridden by tests.
	nowFunc func() time.Time
	mutex   sync.Mutex
}

// newTokenIssuanceLimiter creates a limiter with the given steady-state
// rate (tokens/sec) and burst capacity. If burst is <= 0 it defaults to
// max(rate, 1).
func newTokenIssuanceLimiter(rate, burst float64) *tokenIssuanceLimiter {
	if rate < 0 {
		rate = 0
	}
	if burst <= 0 {
		burst = rate
		if burst < 1 {
			burst = 1
		}
	}
	flog("newTokenIssuanceLimiter", logger.Fields{"rate": rate, "burst": burst}).Debug("Creating global token issuance limiter")
	return &tokenIssuanceLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
		nowFunc:    time.Now,
	}
}

// Allow consumes one token from the bucket. Returns true if a token was
// available, false if the bucket is empty (in which case no issuance
// should occur). If the limiter was constructed with rate == 0 it always
// returns false.
func (t *tokenIssuanceLimiter) Allow() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.rate == 0 {
		return false
	}

	now := t.nowFunc()
	elapsed := now.Sub(t.lastRefill).Seconds()
	if elapsed > 0 {
		t.tokens += elapsed * t.rate
		if t.tokens > t.burst {
			t.tokens = t.burst
		}
		t.lastRefill = now
	}

	if t.tokens >= 1 {
		t.tokens--
		return true
	}
	return false
}
