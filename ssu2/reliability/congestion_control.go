package reliability

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Congestion block flag bits per SSU2 spec §Congestion block.
const (
	// CongestionFlagRequestACK requests the peer send an immediate ACK (bit 0).
	CongestionFlagRequestACK uint8 = 1 << 0

	// CongestionFlagECN signals Explicit Congestion Notification (bit 1).
	CongestionFlagECN uint8 = 1 << 1
)

// EncodeCongestionBlock creates a Congestion block (type 21) with the given flags.
func EncodeCongestionBlock(flags uint8) *SSU2Block {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "EncodeCongestionBlock", "flags": flags}).Debug("Encoding congestion block")
	return NewSSU2Block(BlockTypeCongestion, []byte{flags})
}

// DecodeCongestionBlock parses a Congestion block and returns the flag byte.
func DecodeCongestionBlock(block *SSU2Block) (uint8, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeCongestionBlock"}).Debug("Decoding congestion block")
	if block == nil {
		return 0, oops.Errorf("block is nil")
	}
	if block.Type != BlockTypeCongestion {
		return 0, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeCongestion, block.Type)
	}
	if len(block.Data) < 1 {
		return 0, oops.Errorf("Congestion block too short: %d bytes (minimum 1)", len(block.Data))
	}
	return block.Data[0], nil
}

// Congestion control constants per SSU2 specification.
// This implements Westwood+ congestion control with RFC 9002 persistent
// congestion detection (§7.6). Westwood+ uses bandwidth estimation to set
// ssthresh on loss, providing better performance over lossy links than
// Reno's simple CWND/2 multiplicative decrease.
//
// The SSU2 spec recommends Westwood+ or similar for I2P's lossy overlay links.
const (
	// MinCongestionWindow is the minimum congestion window per SSU2 spec (1280 bytes)
	MinCongestionWindow = 1280

	// InitialCongestionWindow is the initial CWND per SSU2 spec: 3×MTU.
	// Using IPv4 MTU (1472) as the baseline gives 4416 bytes.
	InitialCongestionWindow = MaxPacketSizeIPv4 * 3

	// MaxCongestionWindow is the maximum CWND to prevent memory exhaustion
	MaxCongestionWindow = 1024 * 1024 // 1 MB

	// SlowStartThreshold is the initial ssthresh (start in slow start mode)
	InitialSlowStartThreshold = MaxCongestionWindow

	// persistentCongestionMultiplier is the kPersistentCongestionThreshold
	// from RFC 9002 §7.6.2. If all packets sent within a time span of
	// 3 * (smoothed_rtt + 4 * rttvar + timerGranularity) are lost, a
	// persistent congestion event is declared.
	persistentCongestionMultiplier = 3

	// timerGranularity is the system timer granularity (RFC 9002 uses 1ms).
	timerGranularity = time.Millisecond

	// bweAlpha is the EWMA smoothing factor for bandwidth estimation.
	// Westwood+ uses 7/8 old + 1/8 new.
	bweAlpha = 0.875
)

// CongestionState represents the current congestion control state
type CongestionState int

const (
	// SlowStart is the initial state where CWND increases exponentially
	SlowStart CongestionState = iota

	// CongestionAvoidance is the state where CWND increases linearly
	CongestionAvoidance

	// Recovery is the state during fast recovery after packet loss
	Recovery
)

// String returns a human-readable name for the congestion state
func (s CongestionState) String() string {
	switch s {
	case SlowStart:
		return "SlowStart"
	case CongestionAvoidance:
		return "CongestionAvoidance"
	case Recovery:
		return "Recovery"
	default:
		return "Unknown"
	}
}

// CongestionController manages congestion window for SSU2 connections.
// It implements Westwood+ congestion control with:
//   - Slow Start: Exponential growth until ssthresh or loss
//   - Congestion Avoidance: Linear growth after ssthresh
//   - Fast Recovery: Quick recovery from packet loss
//   - Bandwidth Estimation: ACK-clocked BWE for smarter loss response
//
// On loss, ssthresh = max(BWE * minRTT, MinCWND) instead of Reno's cwnd/2,
// yielding better throughput on lossy I2P overlay links.
//
// The controller is thread-safe and can be used concurrently.
type CongestionController struct {
	// cwnd is the congestion window in bytes
	cwnd int

	// ssthresh is the slow start threshold in bytes
	ssthresh int

	// state is the current congestion control state
	state CongestionState

	// bytesAcked tracks bytes acknowledged since last CWND increase
	// Used for linear increase in congestion avoidance
	bytesAcked int

	// rttEstimator provides RTT measurements for decisions
	rttEstimator *RTTEstimator

	// bytesInFlight tracks unacknowledged bytes currently sent
	bytesInFlight int

	// bandwidthEstimate is the Westwood+ EWMA bandwidth estimate (bytes/sec).
	bandwidthEstimate float64

	// lastAckTime is the timestamp of the most recent ACK, used to compute
	// per-ACK bandwidth samples for the Westwood+ BWE filter.
	lastAckTime time.Time

	// congestionEpochStart is the time the current loss/recovery epoch began.
	// Loss events within one RTT of this time are coalesced to prevent
	// over-reducing cwnd from multiple losses in the same window (G-1).
	congestionEpochStart time.Time

	// mtu is the session's Maximum Segment Size, used as the linear increment
	// in congestion avoidance (M-1). Defaults to MinCongestionWindow (1280).
	mtu int

	// mutex protects all fields for concurrent access
	mutex sync.RWMutex
}

// NewCongestionController creates a new congestion controller.
// If rttEstimator is nil, congestion control will work without RTT-based decisions.
// Uses the default IPv4 MTU for initial CWND; prefer NewCongestionControllerWithMTU
// to derive CWND from the session's actual MTU (M-5).
func NewCongestionController(rttEstimator *RTTEstimator) *CongestionController {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewCongestionController"}).Debug("Creating with default IPv4 MTU")
	return NewCongestionControllerWithMTU(rttEstimator, MaxPacketSizeIPv4)
}

// NewCongestionControllerWithMTU creates a congestion controller with the
// initial CWND derived from the given MTU (3 × mtu per SSU2 spec §Congestion).
// This correctly handles IPv6 sessions where the MTU (1452) differs from
// the IPv4 default (1472) (M-5).
func NewCongestionControllerWithMTU(rttEstimator *RTTEstimator, mtu int) *CongestionController {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewCongestionControllerWithMTU", "mtu": mtu}).Debug("Creating new CongestionController")
	if mtu <= 0 {
		mtu = MaxPacketSizeIPv4
	}
	return &CongestionController{
		cwnd:          mtu * 3,
		ssthresh:      InitialSlowStartThreshold,
		state:         SlowStart,
		bytesAcked:    0,
		bytesInFlight: 0,
		rttEstimator:  rttEstimator,
		mtu:           mtu,
	}
}

// GetCWND returns the current congestion window in bytes.
func (cc *CongestionController) GetCWND() int {
	return withRLock(&cc.mutex, func() int { return cc.cwnd })
}

// GetState returns the current congestion control state.
func (cc *CongestionController) GetState() CongestionState {
	return withRLock(&cc.mutex, func() CongestionState { return cc.state })
}

// GetSSThresh returns the current slow start threshold.
func (cc *CongestionController) GetSSThresh() int {
	return withRLock(&cc.mutex, func() int { return cc.ssthresh })
}

// GetBytesInFlight returns the current bytes in flight (unacknowledged).
func (cc *CongestionController) GetBytesInFlight() int {
	return withRLock(&cc.mutex, func() int { return cc.bytesInFlight })
}

// CanSend returns true if more data can be sent given the congestion window.
// It compares bytes in flight against the current CWND.
func (cc *CongestionController) CanSend(packetSize int) bool {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.bytesInFlight+packetSize <= cc.cwnd
}

// AvailableWindow returns the number of bytes that can still be sent.
// This is CWND minus bytes currently in flight.
func (cc *CongestionController) AvailableWindow() int {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	available := cc.cwnd - cc.bytesInFlight
	if available < 0 {
		return 0
	}
	return available
}

// OnPacketSent records that a packet of the given size has been sent.
// This increases bytes in flight.
func (cc *CongestionController) OnPacketSent(packetSize int) {
	if packetSize <= 0 {
		return
	}

	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.bytesInFlight += packetSize
}

// OnAck processes an acknowledgment for the specified number of bytes.
// This implements CWND growth based on the current state and updates the
// Westwood+ bandwidth estimate from ACK inter-arrival times.
func (cc *CongestionController) OnAck(ackedBytes int) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "OnAck", "ackedBytes": ackedBytes}).Debug("Processing acknowledgment")
	if ackedBytes <= 0 {
		return
	}

	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Update Westwood+ bandwidth estimate from ACK timing.
	now := time.Now()
	if !cc.lastAckTime.IsZero() {
		dt := now.Sub(cc.lastAckTime).Seconds()
		if dt > 0 {
			sample := float64(ackedBytes) / dt
			if cc.bandwidthEstimate == 0 {
				cc.bandwidthEstimate = sample
			} else {
				cc.bandwidthEstimate = bweAlpha*cc.bandwidthEstimate + (1-bweAlpha)*sample
			}
		}
	}
	cc.lastAckTime = now

	// Decrease bytes in flight
	cc.bytesInFlight -= ackedBytes
	if cc.bytesInFlight < 0 {
		cc.bytesInFlight = 0
	}

	cc.dispatchAckByState(ackedBytes)
}

// dispatchAckByState routes ACK handling to the state-specific strategy.
// Caller must hold cc.mutex.
func (cc *CongestionController) dispatchAckByState(ackedBytes int) {
	switch cc.state {
	case SlowStart:
		cc.handleSlowStartAck(ackedBytes)
	case CongestionAvoidance:
		cc.handleCongestionAvoidanceAck(ackedBytes)
	case Recovery:
		// In recovery, just acknowledge bytes without CWND increase
		// Exit recovery when all lost packets are acknowledged
	}
}

// handleSlowStartAck processes ACK during slow start phase.
// CWND increases by ackedBytes for each ACK (exponential growth).
func (cc *CongestionController) handleSlowStartAck(ackedBytes int) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "handleSlowStartAck", "ackedBytes": ackedBytes, "cwnd": cc.cwnd}).Debug("Exponential growth")
	// Increase CWND by the number of bytes acknowledged
	cc.cwnd += ackedBytes

	// Cap at maximum
	if cc.cwnd > MaxCongestionWindow {
		cc.cwnd = MaxCongestionWindow
	}

	// Check if we should transition to congestion avoidance
	if cc.cwnd >= cc.ssthresh {
		cc.state = CongestionAvoidance
	}
}

// handleCongestionAvoidanceAck processes ACK during congestion avoidance.
// CWND increases by approximately MSS per RTT (linear growth).
// We track bytes acked and increase CWND when we've acked CWND bytes.
func (cc *CongestionController) handleCongestionAvoidanceAck(ackedBytes int) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "handleCongestionAvoidanceAck", "ackedBytes": ackedBytes, "cwnd": cc.cwnd}).Debug("Linear growth")
	// Accumulate acknowledged bytes
	cc.bytesAcked += ackedBytes

	// M-1: Use the session's actual MTU as MSS increment instead of
	// the minimum (1280). This correctly handles IPv4 (1472) and IPv6 (1452).
	mss := cc.mtu
	if mss < MinCongestionWindow {
		mss = MinCongestionWindow
	}

	// Increase CWND by MSS when we've acknowledged CWND bytes
	// This gives approximately one MSS increase per RTT
	if cc.bytesAcked >= cc.cwnd {
		cc.cwnd += mss
		cc.bytesAcked -= cc.cwnd // Carry over excess
		if cc.bytesAcked < 0 {
			cc.bytesAcked = 0
		}
	}

	// Cap at maximum
	if cc.cwnd > MaxCongestionWindow {
		cc.cwnd = MaxCongestionWindow
	}
}

// handleCongestionEvent processes a congestion signal (loss or ECN) by
// coalescing events within the same RTT window, computing ssthresh via
// Westwood+ BWE, and transitioning to the specified state. Caller must
// NOT hold cc.mutex.
func (cc *CongestionController) handleCongestionEvent(targetState CongestionState) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	if cc.state == Recovery {
		return
	}

	now := time.Now()
	if !cc.congestionEpochStart.IsZero() && cc.rttEstimator != nil {
		rtt := cc.rttEstimator.GetSmoothedRTT()
		if rtt > 0 && now.Sub(cc.congestionEpochStart) < rtt {
			return
		}
	}
	cc.congestionEpochStart = now

	cc.ssthresh = cc.westwoodSSThresh()
	cc.cwnd = cc.ssthresh
	cc.state = targetState
	cc.bytesAcked = 0
}

// OnPacketLoss handles a detected packet loss event.
// Westwood+ sets ssthresh = max(BWE * minRTT, MinCWND) instead of Reno's
// cwnd/2, providing a more accurate window estimate based on measured
// throughput. Falls back to cwnd/2 when no BWE is available.
//
// Loss events within the same RTT window are coalesced: only the first
// loss triggers a cwnd reduction. Subsequent losses within one RTT of the
// epoch start are absorbed without further reduction (G-1).
func (cc *CongestionController) OnPacketLoss() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "OnPacketLoss"}).Debug("Packet loss detected")
	cc.handleCongestionEvent(Recovery)
}

// OnRetransmissionTimeout handles an RTO event (more severe than packet loss).
// Uses Westwood+ BWE for ssthresh, then resets to slow start with MinCWND.
func (cc *CongestionController) OnRetransmissionTimeout() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "OnRetransmissionTimeout"}).Debug("Retransmission timeout")
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Westwood+ ssthresh from bandwidth estimate
	cc.ssthresh = cc.westwoodSSThresh()

	// Reset CWND to minimum (restart slow start)
	cc.cwnd = MinCongestionWindow

	// Clear bytes in flight (they will be retransmitted)
	cc.bytesInFlight = 0

	// Enter slow start
	cc.state = SlowStart
	cc.bytesAcked = 0
}

// westwoodSSThresh computes ssthresh using Westwood+ bandwidth estimation:
// ssthresh = max(BWE * minRTT, MinCWND). Falls back to cwnd/2 when BWE or
// minRTT is unavailable. Caller must hold cc.mutex.
func (cc *CongestionController) westwoodSSThresh() int {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "westwoodSSThresh", "bwe": cc.bandwidthEstimate}).Debug("Computing ssthresh")
	if cc.bandwidthEstimate > 0 && cc.rttEstimator != nil {
		minRTT := cc.rttEstimator.GetMinRTT()
		if minRTT > 0 {
			bwWindow := int(cc.bandwidthEstimate * minRTT.Seconds())
			if bwWindow < MinCongestionWindow {
				return MinCongestionWindow
			}
			if bwWindow > cc.cwnd {
				// BWE overestimate; cap at cwnd to avoid inflation
				return cc.cwnd
			}
			return bwWindow
		}
	}
	// Fallback: Reno-style cwnd/2
	half := cc.cwnd / 2
	if half < MinCongestionWindow {
		return MinCongestionWindow
	}
	return half
}

// ExitRecovery transitions from recovery state to congestion avoidance.
// This should be called when all lost packets have been acknowledged.
func (cc *CongestionController) ExitRecovery() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "ExitRecovery"}).Debug("Transitioning from recovery to congestion avoidance")
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	if cc.state == Recovery {
		cc.state = CongestionAvoidance
		cc.bytesAcked = 0
	}
}

// PersistentCongestionThreshold returns the duration after which sustained
// packet loss is considered persistent congestion (RFC 9002 §7.6.2).
// threshold = persistentCongestionMultiplier * (smoothed_rtt + max(4*rttvar, timerGranularity))
func (cc *CongestionController) PersistentCongestionThreshold() time.Duration {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	if cc.rttEstimator == nil {
		return 3 * time.Second // Safe default when no RTT yet
	}
	rto := cc.rttEstimator.GetRTO()
	return time.Duration(persistentCongestionMultiplier) * rto
}

// OnPersistentCongestion handles a persistent congestion event per RFC 9002 §7.6.2.
// All outstanding data is assumed lost. The congestion window is collapsed to
// the minimum (2 * MinCongestionWindow per RFC 9002) and slow start is re-entered.
func (cc *CongestionController) OnPersistentCongestion() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "OnPersistentCongestion"}).Warn("Persistent congestion detected")
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.cwnd = 2 * MinCongestionWindow
	cc.ssthresh = cc.cwnd
	cc.bytesInFlight = 0
	cc.bytesAcked = 0
	cc.state = SlowStart
}

// DetectPersistentCongestion checks whether a set of lost packets indicates
// persistent congestion per RFC 9002 §7.6.2. It returns true (and triggers
// OnPersistentCongestion) when the time span between the earliest and latest
// lost packet send times exceeds PersistentCongestionThreshold and no
// acknowledged packet was sent between them (ackInRange=false).
//
// Parameters:
//   - earliestLossSendTime: send time of the earliest declared-lost packet
//   - latestLossSendTime: send time of the latest declared-lost packet
//   - ackInRange: true if any acknowledged packet was sent between
//     earliestLossSendTime and latestLossSendTime
func (cc *CongestionController) DetectPersistentCongestion(
	earliestLossSendTime, latestLossSendTime time.Time,
	ackInRange bool,
) bool {
	if ackInRange {
		return false
	}
	if earliestLossSendTime.IsZero() || latestLossSendTime.IsZero() {
		return false
	}
	span := latestLossSendTime.Sub(earliestLossSendTime)
	if span < 0 {
		span = -span
	}
	threshold := cc.PersistentCongestionThreshold()
	if span > threshold {
		cc.OnPersistentCongestion()
		return true
	}
	return false
}

// Reset returns the controller to initial state.
// This is useful after connection migration or significant path changes.
func (cc *CongestionController) Reset() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "Reset"}).Debug("Resetting to initial state")
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.cwnd = InitialCongestionWindow
	cc.ssthresh = InitialSlowStartThreshold
	cc.state = SlowStart
	cc.bytesAcked = 0
	cc.bytesInFlight = 0
	cc.bandwidthEstimate = 0
	cc.lastAckTime = time.Time{}
}

// GetStats returns current congestion control statistics.
func (cc *CongestionController) GetStats() CongestionStats {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	return CongestionStats{
		CWND:              cc.cwnd,
		SSThresh:          cc.ssthresh,
		State:             cc.state,
		BytesInFlight:     cc.bytesInFlight,
		BandwidthEstimate: cc.bandwidthEstimate,
	}
}

// CongestionStats contains a snapshot of congestion control state.
type CongestionStats struct {
	CWND              int
	SSThresh          int
	State             CongestionState
	BytesInFlight     int
	BandwidthEstimate float64 // bytes/sec, Westwood+
}

// UpdateRTTEstimator sets or replaces the RTT estimator.
// This can be used to attach an RTT estimator after creation.
func (cc *CongestionController) UpdateRTTEstimator(rtt *RTTEstimator) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.rttEstimator = rtt
}

// ShouldProbe returns true if the controller recommends probing for more bandwidth.
// This is useful for implementing bandwidth probing during idle periods.
func (cc *CongestionController) ShouldProbe() bool {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	// Probe if CWND is less than half of max and we have capacity
	return cc.cwnd < MaxCongestionWindow/2 && cc.bytesInFlight < cc.cwnd/2
}

// OnECN handles an Explicit Congestion Notification signal from a peer's
// Congestion block (flag bit 1). ECN is treated as a congestion signal
// equivalent to a single packet loss: ssthresh is set via Westwood+ BWE
// and CWND is reduced, but with the same epoch-coalescing as OnPacketLoss
// to avoid over-reducing within a single RTT window.
func (cc *CongestionController) OnECN() {
	cc.handleCongestionEvent(CongestionAvoidance)
}

// SetCWND manually sets the congestion window (for testing or special cases).
// The value is clamped to [MinCongestionWindow, MaxCongestionWindow].
func (cc *CongestionController) SetCWND(cwnd int) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	if cwnd < MinCongestionWindow {
		cwnd = MinCongestionWindow
	} else if cwnd > MaxCongestionWindow {
		cwnd = MaxCongestionWindow
	}
	cc.cwnd = cwnd
}

// TimeSinceLastAck can be used for idle timeout detection.
// If no RTT estimator is set or it's not initialized, returns 0.
func (cc *CongestionController) GetRTO() time.Duration {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	if cc.rttEstimator == nil {
		return time.Second // Default RTO
	}
	return cc.rttEstimator.GetRTO()
}
