package replaycache

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() Config {
	return Config{
		TTL:             120 * time.Second,
		MaxSize:         100000,
		CleanupInterval: 30 * time.Second,
	}
}

func TestTTLCache_NewKeyNotReplay(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	var key [32]byte
	key[0] = 0x42
	assert.False(t, c.CheckAndAdd(key), "first insert should not be a replay")
}

func TestTTLCache_DuplicateKeyIsReplay(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	var key [32]byte
	key[0] = 0x42
	assert.False(t, c.CheckAndAdd(key))
	assert.True(t, c.CheckAndAdd(key), "second insert should be detected as replay")
}

func TestTTLCache_DifferentKeysNotReplay(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	var key1, key2 [32]byte
	key1[0] = 0x01
	key2[0] = 0x02
	assert.False(t, c.CheckAndAdd(key1))
	assert.False(t, c.CheckAndAdd(key2))
}

func TestTTLCache_Size(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	assert.Equal(t, 0, c.Size())

	var key1, key2 [32]byte
	key1[0] = 0x01
	key2[0] = 0x02

	c.CheckAndAdd(key1)
	assert.Equal(t, 1, c.Size())

	c.CheckAndAdd(key2)
	assert.Equal(t, 2, c.Size())

	// Duplicate doesn't increase size
	c.CheckAndAdd(key1)
	assert.Equal(t, 2, c.Size())
}

func TestTTLCache_Concurrent(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	const numGoroutines = 100
	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var key [32]byte
			key[0] = byte(idx % 10)
			c.CheckAndAdd(key)
		}(i)
	}
	wg.Wait()
	assert.LessOrEqual(t, c.Size(), 10)
	assert.Greater(t, c.Size(), 0)
}

// insertExpiredKey adds an expired entry directly into the cache for testing eviction behavior.
func insertExpiredKey(c *TTLCache, keyByte byte) [32]byte {
	var key [32]byte
	key[0] = keyByte
	c.mu.Lock()
	entry := &cacheEntry{key: key, insertedAt: time.Now().Add(-3 * c.ttl)}
	elem := c.insertOrder.PushBack(entry)
	c.entries[key] = elem
	c.mu.Unlock()
	return key
}

func TestTTLCache_EvictExpired(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	insertExpiredKey(c, 0x01)

	assert.Equal(t, 1, c.Size())
	c.evictExpired()
	assert.Equal(t, 0, c.Size())
}

func TestTTLCache_ExpiredKeyNotReplay(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	key := insertExpiredKey(c, 0x42)

	assert.False(t, c.CheckAndAdd(key), "expired key should not be a replay")
}

func TestTTLCache_MaxSizeEviction(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSize = 100
	c := New(cfg)
	defer c.Close()

	c.mu.Lock()
	for i := 0; i < cfg.MaxSize; i++ {
		var key [32]byte
		key[0] = byte(i >> 8)
		key[1] = byte(i)
		entry := &cacheEntry{key: key, insertedAt: time.Now()}
		elem := c.insertOrder.PushBack(entry)
		c.entries[key] = elem
	}
	c.mu.Unlock()

	require.Equal(t, cfg.MaxSize, c.Size())

	var newKey [32]byte
	newKey[31] = 0xFF
	c.CheckAndAdd(newKey)

	assert.LessOrEqual(t, c.Size(), cfg.MaxSize)
}

func TestTTLCache_DoubleClose(t *testing.T) {
	c := New(testConfig())
	c.Close()
	assert.NotPanics(t, func() { c.Close() }, "double Close must not panic")
}

func TestTTLCache_ZeroConfigNoPanic(t *testing.T) {
	// A zero-value Config has non-positive TTL and CleanupInterval. New must
	// not panic in its background cleanup goroutine (MEDIUM-1).
	var c *TTLCache
	assert.NotPanics(t, func() { c = New(Config{}) }, "New(Config{}) must not panic")
	defer c.Close()

	// Give the background cleanupLoop a moment to start its ticker; a
	// non-positive interval would panic the goroutine and crash the process.
	time.Sleep(50 * time.Millisecond)

	var key [32]byte
	key[0] = 0x42
	// With a zero TTL every entry is immediately expired, so no replay is
	// detected; the assertion of interest is simply that nothing panicked.
	assert.False(t, c.CheckAndAdd(key), "first insert should not be a replay")
}

func TestTTLCache_ConcurrentClose(t *testing.T) {
	c := New(testConfig())
	const n = 10
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Close()
		}()
	}
	wg.Wait()
}

func TestTTLCache_Reset(t *testing.T) {
	c := New(testConfig())
	defer c.Close()

	var key [32]byte
	key[0] = 0x01
	c.CheckAndAdd(key)
	assert.Equal(t, 1, c.Size())

	c.Reset()
	assert.Equal(t, 0, c.Size())
}

func TestTTLCache_CustomNowFunc(t *testing.T) {
	now := time.Now()
	cfg := testConfig()
	cfg.NowFunc = func() time.Time { return now }
	c := New(cfg)
	defer c.Close()

	var key [32]byte
	key[0] = 0x01
	assert.False(t, c.CheckAndAdd(key))
	assert.True(t, c.CheckAndAdd(key))

	// Advance past TTL
	cfg.NowFunc = nil // can't change after construction
	c.nowFunc = func() time.Time { return now.Add(cfg.TTL + time.Second) }
	assert.False(t, c.CheckAndAdd(key), "should not replay after TTL expiry")
}
