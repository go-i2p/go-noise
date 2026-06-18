package reliability

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// RTTEstimator tracks round-trip time measurements for congestion control.
// It implements the algorithm from RFC 6298 (Computing TCP's Retransmission Timer)
// with exponentially weighted moving averages for smoothed RTT and variance.
//
// The estimator is thread-safe and can be used concurrently by multiple goroutines.
// It maintains three key metrics:
//   - smoothedRTT: Exponentially weighted moving average of RTT samples
//   - rttVariance: Mean deviation to account for RTT variability
//   - minRTT: Minimum observed RTT (used for congestion detection)
//
// The Retransmission Timeout (RTO) is calculated as:
//
//	RTO = smoothedRTT + max(G, K*rttVariance)
//
// where G is the clock granularity (1ms) and K=4 per RFC 6298.
type RTTEstimator struct {
	// smoothedRTT is the exponentially weighted moving average of RTT samples
	// Formula: SRTT = (1-alpha) * SRTT + alpha * RTT_sample
	// where alpha = 1/8
	smoothedRTT time.Duration

	// rttVariance tracks the mean deviation of RTT samples
	// Formula: RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - RTT_sample|
	// where beta = 1/4
	rttVariance time.Duration

	// minRTT is the minimum RTT observed (used for congestion detection)
	minRTT time.Duration

	// initialized tracks whether we have received the first RTT sample
	initialized bool

	// mutex protects all fields for concurrent access
	mutex sync.RWMutex
}

const (
	// RFC 6298 constants
	rttAlpha         = 0.125            // 1/8 - weight for new RTT samples
	rttBeta          = 0.25             // 1/4 - weight for variance updates
	RTTKMultiplier   = 4.0              // Multiplier for variance in RTO calculation
	ClockGranularity = time.Millisecond // Minimum clock granularity for RTO

	// Initial RTO value (RFC 6298 section 2.1)
	InitialRTO = 1 * time.Second

	// Bounds for RTO (RFC 6298 section 2.4)
	MinRTO = 1 * time.Second
	MaxRTO = 60 * time.Second
)

// NewRTTEstimator creates a new RTT estimator with default initial values.
// The estimator starts uninitialized; the first Update() call will set initial values
// according to RFC 6298 section 2.2:
//   - SRTT = RTT_sample
//   - RTTVAR = RTT_sample / 2
//   - RTO = SRTT + max(G, K*RTTVAR)
func NewRTTEstimator() *RTTEstimator {
	flog("NewRTTEstimator").Debug("Creating new RTTEstimator")
	return &RTTEstimator{
		smoothedRTT: 0,
		rttVariance: 0,
		minRTT:      0,
		initialized: false,
	}
}

// Update adds a new RTT sample and updates the estimator state.
// The sample parameter should be a positive duration representing the measured RTT.
// Negative or zero samples are ignored.
//
// For the first sample (RFC 6298 section 2.2):
//   - SRTT = sample
//   - RTTVAR = sample / 2
//   - minRTT = sample
//
// For subsequent samples (RFC 6298 section 2.3):
//   - RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - sample|
//   - SRTT = (1-alpha) * SRTT + alpha * sample
//   - minRTT = min(minRTT, sample)
func (r *RTTEstimator) Update(sample time.Duration) {
	flog("Update", logger.Fields{"sample": sample}).Debug("Adding RTT sample")
	if sample <= 0 {
		return // Ignore invalid samples
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.initialized {
		// First RTT measurement (RFC 6298 section 2.2)
		r.smoothedRTT = sample
		r.rttVariance = sample / 2
		r.minRTT = sample
		r.initialized = true
		return
	}

	// Subsequent measurements (RFC 6298 section 2.3)
	// Calculate absolute difference for variance
	var diff time.Duration
	if sample > r.smoothedRTT {
		diff = sample - r.smoothedRTT
	} else {
		diff = r.smoothedRTT - sample
	}

	// RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - sample|
	r.rttVariance = time.Duration(float64(r.rttVariance)*(1-rttBeta) + float64(diff)*rttBeta)

	// SRTT = (1-alpha) * SRTT + alpha * sample
	r.smoothedRTT = time.Duration(float64(r.smoothedRTT)*(1-rttAlpha) + float64(sample)*rttAlpha)

	// Update minimum RTT
	if sample < r.minRTT {
		r.minRTT = sample
	}
}

// GetRTO returns the Retransmission Timeout calculated from current estimates.
// The RTO is computed according to RFC 6298 section 2.2-2.3:
//
//	RTO = SRTT + max(G, K*RTTVAR)
//
// where G is the clock granularity (1ms) and K=4.
// The result is clamped to [MinRTO, MaxRTO] = [1s, 60s].
//
// If no samples have been recorded, returns the initial RTO of 1 second.
func (r *RTTEstimator) GetRTO() time.Duration {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if !r.initialized {
		return InitialRTO
	}

	// RTO = SRTT + max(G, K*RTTVAR)
	variance := time.Duration(RTTKMultiplier * float64(r.rttVariance))
	if variance < ClockGranularity {
		variance = ClockGranularity
	}

	rto := r.smoothedRTT + variance

	// Clamp to bounds (RFC 6298 section 2.4)
	if rto < MinRTO {
		rto = MinRTO
	} else if rto > MaxRTO {
		rto = MaxRTO
	}

	return rto
}

// GetSmoothedRTT returns the current smoothed RTT estimate.
// This is the exponentially weighted moving average of all RTT samples.
// Returns 0 if no samples have been recorded yet.
func (r *RTTEstimator) GetSmoothedRTT() time.Duration {
	return withRLock(&r.mutex, func() time.Duration { return r.smoothedRTT })
}

// GetRTTVariance returns the current RTT variance estimate.
// This represents the mean deviation of RTT samples from the smoothed RTT.
// Returns 0 if no samples have been recorded yet.
func (r *RTTEstimator) GetRTTVariance() time.Duration {
	return withRLock(&r.mutex, func() time.Duration { return r.rttVariance })
}

// GetMinRTT returns the minimum RTT observed across all samples.
// This can be used for congestion detection - a significant increase
// in RTT relative to minRTT may indicate network congestion.
// Returns 0 if no samples have been recorded yet.
func (r *RTTEstimator) GetMinRTT() time.Duration {
	return withRLock(&r.mutex, func() time.Duration { return r.minRTT })
}

// IsInitialized returns true if at least one RTT sample has been recorded.
// Before initialization, GetRTO() returns a default value.
func (r *RTTEstimator) IsInitialized() bool {
	return withRLock(&r.mutex, func() bool { return r.initialized })
}

// Reset clears all state and returns the estimator to uninitialized state.
// This is useful when connection properties change significantly (e.g., path migration).
func (r *RTTEstimator) Reset() {
	flog("Reset").Debug("Clearing RTT estimator state")
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.smoothedRTT = 0
	r.rttVariance = 0
	r.minRTT = 0
	r.initialized = false
}
