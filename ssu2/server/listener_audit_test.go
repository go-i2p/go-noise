package server

import (
	"strconv"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIPRateLimiter_LRUEviction verifies that the IP rate limiter enforces its
// capacity bound and evicts the least-recently-used IP in O(1), rather than
// growing without bound (AUDIT 8.4 — remote memory-exhaustion DoS).
func TestIPRateLimiter_LRUEviction(t *testing.T) {
	const maxIPs = 4
	rl := newIPRateLimiter(10, maxIPs)

	// Fill to capacity: ip0..ip3.
	for i := 0; i < maxIPs; i++ {
		require.True(t, rl.Allow("ip"+strconv.Itoa(i)))
	}

	rl.mutex.Lock()
	assert.Equal(t, maxIPs, len(rl.entries), "should be exactly at capacity")
	assert.Equal(t, maxIPs, rl.order.Len(), "order list must track entries")
	rl.mutex.Unlock()

	// Touch ip0 so it becomes most-recently-used; ip1 is now the LRU.
	require.True(t, rl.Allow("ip0"))

	// Insert a new IP, forcing eviction of the LRU (ip1).
	require.True(t, rl.Allow("ip4"))

	rl.mutex.Lock()
	assert.Equal(t, maxIPs, len(rl.entries), "capacity must remain bounded after insert")
	assert.Equal(t, maxIPs, rl.order.Len(), "order list must remain bounded")
	_, ip1Present := rl.entries["ip1"]
	_, ip0Present := rl.entries["ip0"]
	_, ip4Present := rl.entries["ip4"]
	rl.mutex.Unlock()

	assert.False(t, ip1Present, "least-recently-used IP (ip1) should have been evicted")
	assert.True(t, ip0Present, "recently-touched IP (ip0) must be retained")
	assert.True(t, ip4Present, "newly-added IP (ip4) must be present")
}

// TestIPRateLimiter_Unlimited verifies that a zero maxIPs disables eviction.
func TestIPRateLimiter_Unlimited(t *testing.T) {
	rl := newIPRateLimiter(10, 0)
	for i := 0; i < 100; i++ {
		require.True(t, rl.Allow("ip"+strconv.Itoa(i)))
	}
	rl.mutex.Lock()
	assert.Equal(t, 100, len(rl.entries), "no eviction should occur when maxIPs == 0")
	rl.mutex.Unlock()
}

// TestSSU2Config_MaxSessionsDefault verifies the listener session cap has a
// sane bounded default (AUDIT 8.2 — unbounded session accumulation).
func TestSSU2Config_MaxSessionsDefault(t *testing.T) {
	cfg, err := NewSSU2Config(data.Hash{}, false)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Greater(t, cfg.MaxSessions, 0, "MaxSessions must default to a bounded value")
}
