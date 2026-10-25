package ratchet

import (
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// defaultNSMaxPastAge is the maximum acceptable age of the DateTime block
	// in a New Session message. Default: 5 minutes per ecies.rst §"Parameters".
	defaultNSMaxPastAge = 5 * time.Minute

	// defaultNSMaxFutureAge is the maximum acceptable forward skew of the DateTime
	// block in a New Session message. Default: 2 minutes per ecies.rst §"Parameters".
	defaultNSMaxFutureAge = 2 * time.Minute

	// nsReplayCacheMaxSize is the maximum number of NS ephemeral keys tracked
	// before forced eviction. This prevents memory exhaustion under attack.
	nsReplayCacheMaxSize = 50000

	// nsReplayCacheCleanupInterval controls how often expired NS replay entries
	// are evicted.
	nsReplayCacheCleanupInterval = 30 * time.Second
)

// SessionManagerOption configures optional [SessionManager] parameters.
//
// Options are passed to [NewSessionManager] to customize behavior without
// changing the function signature.
type SessionManagerOption func(*SessionManager)

// WithNSMaxPastAge overrides the default maximum past age for New Session
// DateTime freshness. A New Session message whose timestamp is older than
// this is rejected as stale or replayed. The default is 5 minutes.
func WithNSMaxPastAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxPastAge = d
	}
}

// WithNSMaxFutureAge overrides the default maximum future age for New
// Session DateTime freshness. A New Session message whose timestamp is more
// than this far in the future is rejected (it indicates clock skew or a
// forged message). The default is 2 minutes.
func WithNSMaxFutureAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxFutureAge = d
	}
}

// validateNSDateTimeFreshness parses the decrypted NS payload, locates the
// required DateTime block (first block per ecies.rst §1b), and verifies that
// its timestamp is within the asymmetric freshness window:
//   - Past: at most nsMaxPastAge ago (default 5 minutes)
//   - Future: at most nsMaxFutureAge ahead (default 2 minutes)
//
// Spec ref: ecies.rst §"Parameters" — max clock skew: −5 minutes to +2 minutes.
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
	return checkTimeWindow(nowFunc().Sub(msgTime), sm.nsMaxPastAge, sm.nsMaxFutureAge)
}

// checkTimeWindow returns an error when elapsed falls outside the acceptable
// freshness bounds. elapsed = now − msgTime (positive = message is in the past).
func checkTimeWindow(elapsed, pastAge, futureAge time.Duration) error {
	if elapsed > pastAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v old, max past age is %v (stale or replay)",
			elapsed, pastAge,
		)
	}
	if elapsed < -futureAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v in the future, max future skew is %v",
			-elapsed, futureAge,
		)
	}
	return nil
}

// nsReplayFilterDuration is how long a seen NS ephemeral key is retained for
// replay detection.
//
// Spec ref: ecies.md §"Implementation Considerations" -> §"Parameters" -
// "NS replay filter duration: 5 minutes".
// Java I2P (ECIESAEADEngine) uses the same 5 minutes (MAX_NS_AGE).
const nsReplayFilterDuration = 5 * time.Minute

// nsReplayCacheTTL returns the replay filter duration required by the spec,
// widened only if a deployment configures a longer freshness window than the
// default -5/+2 minutes (an entry must never stop being tracked while its
// message could still pass the freshness check).
//
// The previous implementation used pastAge + futureAge + 1m = 8 minutes, which
// over-retained relative to the specified 5-minute filter.
func nsReplayCacheTTL(pastAge, futureAge time.Duration) time.Duration {
	needed := pastAge + futureAge
	if needed <= nsReplayFilterDuration {
		return nsReplayFilterDuration
	}
	return needed
}
