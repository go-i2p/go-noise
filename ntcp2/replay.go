package ntcp2

// ReplayDetector checks for replayed ephemeral keys during NTCP2
// handshakes.
//
// A replay attack is when an attacker re-sends a previously captured
// handshake message, hoping the receiver will treat it as new. To defend
// against this, implementations maintain a TTL-based (time-to-live) cache
// of recently seen ephemeral keys and reject duplicates.
//
// The cache should automatically evict entries older than the configured
// TTL (typically derived from ClockSkewTolerance). Implementations must be
// safe for concurrent use.
//
// See [I2P Spec: NTCP2](https://i2p.net/en/docs/specs/ntcp2/) for details.
type ReplayDetector interface {
	// CheckAndAdd returns true if the ephemeral key has been seen before
	// (a replay). If the key is new, it is added to the cache and false is
	// returned.
	CheckAndAdd(ephemeralKey [32]byte) bool

	// Size returns the current number of entries in the replay cache.
	Size() int

	// Close releases resources (stops the cleanup goroutine, if any).
	Close()
}
