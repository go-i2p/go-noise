package ratchet

import (
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// defaultNSMaxPastAge is the maximum acceptable age of the DateTime block
	// in a New Session message. Default: 5 minutes per ratchet.md §"Parameters".
	defaultNSMaxPastAge = 5 * time.Minute

	// defaultNSMaxFutureAge is the maximum acceptable forward skew of the DateTime
	// block in a New Session message. Default: 2 minutes per ratchet.md §"Parameters".
	defaultNSMaxFutureAge = 2 * time.Minute

	// nsReplayCacheMaxSize is the maximum number of NS ephemeral keys tracked
	// before forced eviction. This prevents memory exhaustion under attack.
	nsReplayCacheMaxSize = 50000

	// nsReplayCacheCleanupInterval controls how often expired NS replay entries
	// are evicted.
	nsReplayCacheCleanupInterval = 30 * time.Second
)

// SessionManagerOption configures optional SessionManager parameters.
type SessionManagerOption func(*SessionManager)

// WithNSMaxPastAge overrides the default maximum past age for NS DateTime freshness.
func WithNSMaxPastAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxPastAge = d
	}
}

// WithNSMaxFutureAge overrides the default maximum future age for NS DateTime freshness.
func WithNSMaxFutureAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxFutureAge = d
	}
}

// validateNSDateTimeFreshness parses the decrypted NS payload, locates the
// required DateTime block (first block per ratchet.md §1b), and verifies that
// its timestamp is within the asymmetric freshness window:
//   - Past: at most nsMaxPastAge ago (default 5 minutes)
//   - Future: at most nsMaxFutureAge ahead (default 2 minutes)
//
// Spec ref: ratchet.md §"Parameters" — max clock skew: −5 minutes to +2 minutes.
func (sm *SessionManager) validateNSDateTimeFreshness(payload []byte) error {
	flog("validateNSDateTimeFreshness", logger.Fields{"payload_len": len(payload)}).Debug("Validating NS DateTime freshness")
	blocks, err := ParsePayload(payload)
	if err != nil {
		return oops.Wrapf(err, "NS payload parse failed during freshness check")
	}
	if len(blocks) == 0 || blocks[0].Type != BlockDateTime {
		return oops.Errorf("NS payload is missing required DateTime block at position 0")
	}
	msgTime, err := blocks[0].DateTime()
	if err != nil {
		return oops.Wrapf(err, "NS DateTime block is malformed")
	}
	elapsed := nowFunc().Sub(msgTime)
	if elapsed > sm.nsMaxPastAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v old, max past age is %v (stale or replay)",
			elapsed, sm.nsMaxPastAge,
		)
	}
	if elapsed < -sm.nsMaxFutureAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v in the future, max future skew is %v",
			-elapsed, sm.nsMaxFutureAge,
		)
	}
	return nil
}

// nsReplayCacheTTL computes the replay cache TTL from the freshness window.
// The +1 minute buffer beyond the freshness window accounts for:
//   - Clock skew between sender and receiver (beyond the configured tolerance)
//   - Network jitter and packet reordering delays
//   - Race conditions at window boundaries during concurrent processing
//
// This ensures that legitimate messages near the window edge are not incorrectly
// rejected as replays while still preventing long-lived replay attacks.
func nsReplayCacheTTL(pastAge, futureAge time.Duration) time.Duration {
	return pastAge + futureAge + time.Minute // +1m for clock skew + network jitter
}
