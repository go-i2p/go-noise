package eviction

import "time"

// EvictOldestByTime removes the oldest entry from items based on the timestamp
// returned by getTime. It returns the evicted key, its timestamp, and whether
// an entry was removed.
func EvictOldestByTime[K comparable, V any](items map[K]V, getTime func(V) time.Time) (K, time.Time, bool) {
	var zeroKey K
	var oldestKey K
	var oldestTime time.Time
	found := false

	for key, value := range items {
		currentTime := getTime(value)
		if !found || currentTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = currentTime
			found = true
		}
	}

	if !found {
		return zeroKey, time.Time{}, false
	}

	delete(items, oldestKey)
	return oldestKey, oldestTime, true
}
