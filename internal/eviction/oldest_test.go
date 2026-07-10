package eviction

import (
	"testing"
	"time"
)

// TestEvictOldestByTime_EmptyMap verifies an empty map returns found=false
// and does not panic.
func TestEvictOldestByTime_EmptyMap(t *testing.T) {
	items := map[string]time.Time{}

	key, ts, found := EvictOldestByTime(items, func(v time.Time) time.Time { return v })
	if found {
		t.Fatalf("expected found=false for empty map, got key=%q ts=%v", key, ts)
	}
	if key != "" {
		t.Errorf("expected zero-value key for empty map, got %q", key)
	}
	if !ts.IsZero() {
		t.Errorf("expected zero-value time for empty map, got %v", ts)
	}
}

// TestEvictOldestByTime_SingleEntry verifies the sole entry is evicted and
// removed from the map.
func TestEvictOldestByTime_SingleEntry(t *testing.T) {
	now := time.Now()
	items := map[string]time.Time{"only": now}

	key, ts, found := EvictOldestByTime(items, func(v time.Time) time.Time { return v })
	if !found {
		t.Fatal("expected found=true for single-entry map")
	}
	if key != "only" {
		t.Errorf("expected key %q, got %q", "only", key)
	}
	if !ts.Equal(now) {
		t.Errorf("expected timestamp %v, got %v", now, ts)
	}
	if _, exists := items["only"]; exists {
		t.Error("expected evicted entry to be removed from the map")
	}
	if len(items) != 0 {
		t.Errorf("expected map to be empty after eviction, got %d entries", len(items))
	}
}

// TestEvictOldestByTime_PicksOldest verifies the entry with the earliest
// timestamp is chosen among several, regardless of map iteration order.
func TestEvictOldestByTime_PicksOldest(t *testing.T) {
	base := time.Now()
	items := map[string]time.Time{
		"newest": base.Add(2 * time.Hour),
		"oldest": base,
		"middle": base.Add(1 * time.Hour),
	}

	key, ts, found := EvictOldestByTime(items, func(v time.Time) time.Time { return v })
	if !found {
		t.Fatal("expected found=true")
	}
	if key != "oldest" {
		t.Errorf("expected oldest entry to be evicted, got key %q", key)
	}
	if !ts.Equal(base) {
		t.Errorf("expected timestamp %v, got %v", base, ts)
	}
	if len(items) != 2 {
		t.Errorf("expected 2 remaining entries, got %d", len(items))
	}
	if _, exists := items["oldest"]; exists {
		t.Error("expected 'oldest' key to be deleted from the map")
	}
}

// TestEvictOldestByTime_TieBreak verifies that when multiple entries share
// the exact same timestamp, exactly one is deterministically evicted (no
// panic, no double-eviction) and the map's other tied entries survive.
func TestEvictOldestByTime_TieBreak(t *testing.T) {
	tie := time.Now()
	items := map[string]time.Time{
		"a": tie,
		"b": tie,
		"c": tie,
	}

	key, ts, found := EvictOldestByTime(items, func(v time.Time) time.Time { return v })
	if !found {
		t.Fatal("expected found=true")
	}
	if !ts.Equal(tie) {
		t.Errorf("expected timestamp %v, got %v", tie, ts)
	}
	if len(items) != 2 {
		t.Errorf("expected exactly one entry evicted (2 remaining), got %d remaining", len(items))
	}
	if _, exists := items[key]; exists {
		t.Errorf("expected evicted key %q to be removed from the map", key)
	}
}

// TestEvictOldestByTime_CustomKeyType verifies the generic function works
// with non-string comparable key types.
func TestEvictOldestByTime_CustomKeyType(t *testing.T) {
	base := time.Now()
	items := map[int]time.Time{
		1: base.Add(time.Minute),
		2: base,
	}

	key, _, found := EvictOldestByTime(items, func(v time.Time) time.Time { return v })
	if !found {
		t.Fatal("expected found=true")
	}
	if key != 2 {
		t.Errorf("expected key 2 (oldest), got %d", key)
	}
}

// TestEvictOldestByTime_CustomValueType verifies getTime can extract a
// timestamp from a struct value rather than requiring V to itself be a
// time.Time, matching real bounded-cache usage patterns.
func TestEvictOldestByTime_CustomValueType(t *testing.T) {
	type entry struct {
		insertedAt time.Time
		payload    string
	}

	base := time.Now()
	items := map[string]entry{
		"first":  {insertedAt: base, payload: "old"},
		"second": {insertedAt: base.Add(time.Second), payload: "new"},
	}

	key, ts, found := EvictOldestByTime(items, func(v entry) time.Time { return v.insertedAt })
	if !found {
		t.Fatal("expected found=true")
	}
	if key != "first" {
		t.Errorf("expected 'first' to be evicted as oldest, got %q", key)
	}
	if !ts.Equal(base) {
		t.Errorf("expected timestamp %v, got %v", base, ts)
	}
	if _, exists := items["first"]; exists {
		t.Error("expected 'first' entry to be removed from the map")
	}
	if _, exists := items["second"]; !exists {
		t.Error("expected 'second' entry to survive eviction")
	}
}
