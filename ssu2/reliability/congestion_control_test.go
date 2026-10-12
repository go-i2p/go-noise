package reliability

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCongestionController tests controller creation
func TestNewCongestionController(t *testing.T) {
	t.Run("creates with default values", func(t *testing.T) {
		cc := NewCongestionController(nil)
		require.NotNil(t, cc)

		assert.Equal(t, InitialCongestionWindow, cc.GetCWND())
		assert.Equal(t, InitialSlowStartThreshold, cc.GetSSThresh())
		assert.Equal(t, SlowStart, cc.GetState())
		assert.Equal(t, 0, cc.GetBytesInFlight())
	})

	t.Run("creates with RTT estimator", func(t *testing.T) {
		rtt := NewRTTEstimator()
		cc := NewCongestionController(rtt)
		require.NotNil(t, cc)

		assert.Equal(t, InitialCongestionWindow, cc.GetCWND())
	})
}

// TestCongestionState_String tests state string representation
func TestCongestionState_String(t *testing.T) {
	tests := []struct {
		state    CongestionState
		expected string
	}{
		{SlowStart, "SlowStart"},
		{CongestionAvoidance, "CongestionAvoidance"},
		{Recovery, "Recovery"},
		{CongestionState(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// TestCongestionController_CanSend tests send permission checking
func TestCongestionController_CanSend(t *testing.T) {
	t.Run("can send when window has space", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Initial state: no bytes in flight
		assert.True(t, cc.CanSend(1000))
		assert.True(t, cc.CanSend(MinCongestionWindow))
	})

	t.Run("cannot send when window is full", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Fill the window
		cc.OnPacketSent(cc.GetCWND())

		assert.False(t, cc.CanSend(1))
		assert.False(t, cc.CanSend(MinCongestionWindow))
	})

	t.Run("partial window available", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Use half the window
		halfCWND := cc.GetCWND() / 2
		cc.OnPacketSent(halfCWND)

		// Can send up to remaining half
		assert.True(t, cc.CanSend(halfCWND))
		assert.False(t, cc.CanSend(halfCWND+1))
	})
}

// TestCongestionController_AvailableWindow tests available window calculation
func TestCongestionController_AvailableWindow(t *testing.T) {
	t.Run("full window available initially", func(t *testing.T) {
		cc := NewCongestionController(nil)
		assert.Equal(t, InitialCongestionWindow, cc.AvailableWindow())
	})

	t.Run("partial window after sending", func(t *testing.T) {
		cc := NewCongestionController(nil)
		sent := InitialCongestionWindow / 2
		cc.OnPacketSent(sent)

		expected := InitialCongestionWindow - sent
		assert.Equal(t, expected, cc.AvailableWindow())
	})

	t.Run("zero window when full", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.OnPacketSent(cc.GetCWND() + 1000) // Over-send

		assert.Equal(t, 0, cc.AvailableWindow())
	})
}

// TestCongestionController_OnPacketSent tests bytes in flight tracking
func TestCongestionController_OnPacketSent(t *testing.T) {
	t.Run("increases bytes in flight", func(t *testing.T) {
		cc := NewCongestionController(nil)

		cc.OnPacketSent(1000)
		assert.Equal(t, 1000, cc.GetBytesInFlight())

		cc.OnPacketSent(500)
		assert.Equal(t, 1500, cc.GetBytesInFlight())
	})

	t.Run("ignores zero and negative", func(t *testing.T) {
		cc := NewCongestionController(nil)

		cc.OnPacketSent(0)
		assert.Equal(t, 0, cc.GetBytesInFlight())

		cc.OnPacketSent(-100)
		assert.Equal(t, 0, cc.GetBytesInFlight())
	})
}

// TestCongestionController_SlowStart tests slow start behavior
func TestCongestionController_SlowStart(t *testing.T) {
	t.Run("starts in slow start", func(t *testing.T) {
		cc := NewCongestionController(nil)
		assert.Equal(t, SlowStart, cc.GetState())
	})

	t.Run("CWND increases exponentially", func(t *testing.T) {
		cc := NewCongestionController(nil)
		initialCWND := cc.GetCWND()

		// Simulate sending and receiving ACKs
		ackedBytes := 1000
		cc.OnPacketSent(ackedBytes)
		cc.OnAck(ackedBytes)

		// CWND should increase by ackedBytes
		assert.Equal(t, initialCWND+ackedBytes, cc.GetCWND())
	})

	t.Run("transitions to congestion avoidance at ssthresh", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Set low ssthresh to trigger transition
		cc.SetCWND(MinCongestionWindow)
		cc.mutex.Lock()
		cc.ssthresh = MinCongestionWindow * 2
		cc.mutex.Unlock()

		// ACK enough to cross threshold
		cc.OnAck(MinCongestionWindow * 2)

		assert.Equal(t, CongestionAvoidance, cc.GetState())
	})
}

// TestCongestionController_CongestionAvoidance tests linear growth
func TestCongestionController_CongestionAvoidance(t *testing.T) {
	t.Run("CWND increases linearly", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Force into congestion avoidance
		cc.mutex.Lock()
		cc.state = CongestionAvoidance
		cc.cwnd = 10000
		cc.mutex.Unlock()

		initialCWND := cc.GetCWND()

		// ACK an entire CWND worth of data
		cc.OnAck(initialCWND)

		// CWND should increase by one MSS (session MTU, default MaxPacketSizeIPv4)
		assert.Equal(t, initialCWND+MaxPacketSizeIPv4, cc.GetCWND())
	})

	t.Run("partial ACKs accumulate", func(t *testing.T) {
		cc := NewCongestionController(nil)

		cc.mutex.Lock()
		cc.state = CongestionAvoidance
		cc.cwnd = 10000
		cc.mutex.Unlock()

		initialCWND := cc.GetCWND()

		// ACK half the CWND
		cc.OnAck(initialCWND / 2)
		assert.Equal(t, initialCWND, cc.GetCWND()) // No increase yet

		// ACK the other half
		cc.OnAck(initialCWND / 2)
		assert.Equal(t, initialCWND+MaxPacketSizeIPv4, cc.GetCWND()) // Now increases
	})
}

// TestCongestionController_OnPacketLoss tests loss handling
func TestCongestionController_OnPacketLoss(t *testing.T) {
	t.Run("reduces CWND and enters recovery", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Set specific CWND for testing
		testCWND := 20000
		cc.SetCWND(testCWND)

		cc.OnPacketLoss()

		// CWND should be halved
		assert.Equal(t, testCWND/2, cc.GetCWND())
		assert.Equal(t, testCWND/2, cc.GetSSThresh())
		assert.Equal(t, Recovery, cc.GetState())
	})

	t.Run("respects minimum CWND", func(t *testing.T) {
		cc := NewCongestionController(nil)

		// Set to minimum
		cc.SetCWND(MinCongestionWindow)

		cc.OnPacketLoss()

		// Should not go below minimum
		assert.Equal(t, MinCongestionWindow, cc.GetCWND())
		assert.Equal(t, MinCongestionWindow, cc.GetSSThresh())
	})

	t.Run("does not reduce further in recovery", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(20000)

		cc.OnPacketLoss()
		cwndAfterFirstLoss := cc.GetCWND()

		cc.OnPacketLoss() // Second loss while in recovery

		// Should not reduce again
		assert.Equal(t, cwndAfterFirstLoss, cc.GetCWND())
	})
}

// TestCongestionController_OnRetransmissionTimeout tests RTO handling
func TestCongestionController_OnRetransmissionTimeout(t *testing.T) {
	t.Run("resets to minimum CWND", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(50000)
		cc.OnPacketSent(10000)

		cc.OnRetransmissionTimeout()

		assert.Equal(t, MinCongestionWindow, cc.GetCWND())
		assert.Equal(t, 25000, cc.GetSSThresh()) // 50000 / 2
		assert.Equal(t, SlowStart, cc.GetState())
		assert.Equal(t, 0, cc.GetBytesInFlight())
	})

	t.Run("ssthresh respects minimum", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(MinCongestionWindow)

		cc.OnRetransmissionTimeout()

		assert.Equal(t, MinCongestionWindow, cc.GetSSThresh())
	})
}

// TestCongestionController_ExitRecovery tests recovery exit
func TestCongestionController_ExitRecovery(t *testing.T) {
	t.Run("transitions to congestion avoidance", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(20000)
		cc.OnPacketLoss()

		assert.Equal(t, Recovery, cc.GetState())

		cc.ExitRecovery()

		assert.Equal(t, CongestionAvoidance, cc.GetState())
	})

	t.Run("no-op when not in recovery", func(t *testing.T) {
		cc := NewCongestionController(nil)
		assert.Equal(t, SlowStart, cc.GetState())

		cc.ExitRecovery()

		assert.Equal(t, SlowStart, cc.GetState())
	})
}

// TestCongestionController_Reset tests state reset
func TestCongestionController_Reset(t *testing.T) {
	cc := NewCongestionController(nil)

	// Modify all state
	cc.SetCWND(50000)
	cc.OnPacketSent(10000)
	cc.OnPacketLoss()

	cc.Reset()

	assert.Equal(t, InitialCongestionWindow, cc.GetCWND())
	assert.Equal(t, InitialSlowStartThreshold, cc.GetSSThresh())
	assert.Equal(t, SlowStart, cc.GetState())
	assert.Equal(t, 0, cc.GetBytesInFlight())
}

// TestCongestionController_GetStats tests stats snapshot
func TestCongestionController_GetStats(t *testing.T) {
	cc := NewCongestionController(nil)
	cc.SetCWND(25000)
	cc.OnPacketSent(5000)

	stats := cc.GetStats()

	assert.Equal(t, 25000, stats.CWND)
	assert.Equal(t, InitialSlowStartThreshold, stats.SSThresh)
	assert.Equal(t, SlowStart, stats.State)
	assert.Equal(t, 5000, stats.BytesInFlight)
}

// TestCongestionController_ShouldProbe tests bandwidth probing decision
func TestCongestionController_ShouldProbe(t *testing.T) {
	t.Run("probes when low CWND and low utilization", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(MaxCongestionWindow / 4)

		assert.True(t, cc.ShouldProbe())
	})

	t.Run("does not probe when CWND is high", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(MaxCongestionWindow)

		assert.False(t, cc.ShouldProbe())
	})
}

// TestCongestionController_SetCWND tests manual CWND setting
func TestCongestionController_SetCWND(t *testing.T) {
	t.Run("clamps to minimum", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(100)

		assert.Equal(t, MinCongestionWindow, cc.GetCWND())
	})

	t.Run("clamps to maximum", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(MaxCongestionWindow * 2)

		assert.Equal(t, MaxCongestionWindow, cc.GetCWND())
	})

	t.Run("accepts valid values", func(t *testing.T) {
		cc := NewCongestionController(nil)
		cc.SetCWND(50000)

		assert.Equal(t, 50000, cc.GetCWND())
	})
}

// TestCongestionController_GetRTO tests RTO retrieval
func TestCongestionController_GetRTO(t *testing.T) {
	t.Run("returns default when no estimator", func(t *testing.T) {
		cc := NewCongestionController(nil)

		rto := cc.GetRTO()
		assert.Equal(t, time.Second, rto)
	})

	t.Run("returns estimator RTO when available", func(t *testing.T) {
		rtt := NewRTTEstimator()
		rtt.Update(100 * time.Millisecond)

		cc := NewCongestionController(rtt)

		rto := cc.GetRTO()
		assert.Greater(t, rto, time.Duration(0))
	})
}

// TestCongestionController_UpdateRTTEstimator tests estimator attachment
func TestCongestionController_UpdateRTTEstimator(t *testing.T) {
	cc := NewCongestionController(nil)

	rtt := NewRTTEstimator()
	rtt.Update(50 * time.Millisecond)

	cc.UpdateRTTEstimator(rtt)

	// Now GetRTO should use the new estimator
	rto := cc.GetRTO()
	assert.Greater(t, rto, time.Duration(0))
}

// TestCongestionController_Concurrent tests thread safety
func TestCongestionController_Concurrent(t *testing.T) {
	cc := NewCongestionController(nil)
	var wg sync.WaitGroup

	// Run multiple goroutines performing different operations
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cc.OnPacketSent(100)
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cc.OnAck(50)
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				cc.OnPacketLoss()
				cc.ExitRecovery()
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = cc.GetCWND()
				_ = cc.CanSend(1000)
				_ = cc.AvailableWindow()
			}
		}()
	}

	wg.Wait()

	// Should not panic and CWND should be valid
	cwnd := cc.GetCWND()
	assert.GreaterOrEqual(t, cwnd, MinCongestionWindow)
	assert.LessOrEqual(t, cwnd, MaxCongestionWindow)
}

// TestCongestionController_OnAck_IgnoresInvalid tests invalid ACK handling
func TestCongestionController_OnAck_IgnoresInvalid(t *testing.T) {
	cc := NewCongestionController(nil)
	initialCWND := cc.GetCWND()

	cc.OnAck(0)
	assert.Equal(t, initialCWND, cc.GetCWND())

	cc.OnAck(-100)
	assert.Equal(t, initialCWND, cc.GetCWND())
}

// TestCongestionController_BytesInFlightNeverNegative tests underflow protection
func TestCongestionController_BytesInFlightNeverNegative(t *testing.T) {
	cc := NewCongestionController(nil)

	// ACK more than was sent
	cc.OnPacketSent(100)
	cc.OnAck(200)

	assert.Equal(t, 0, cc.GetBytesInFlight())
}

// TestCongestionController_Constants verifies spec-defined constants
func TestCongestionController_Constants(t *testing.T) {
	// Per SSU2 spec: Minimum congestion window: 1280 bytes
	assert.Equal(t, 1280, MinCongestionWindow)
}

// --- Westwood+ Bandwidth Estimation Tests ---

func TestCongestionController_BWE_UpdatedOnAck(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(50 * time.Millisecond)
	cc := NewCongestionController(rtt)

	// First ACK sets lastAckTime; second ACK produces a BWE sample.
	cc.OnPacketSent(5000)
	cc.OnAck(5000)
	time.Sleep(10 * time.Millisecond)
	cc.OnPacketSent(5000)
	cc.OnAck(5000)

	stats := cc.GetStats()
	assert.Greater(t, stats.BandwidthEstimate, 0.0, "BWE should be positive after second ACK")
}

func TestCongestionController_BWE_SSThreshOnLoss(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(100 * time.Millisecond)
	cc := NewCongestionController(rtt)

	// Build up a BWE by sending and acking data with a small delay.
	for i := 0; i < 10; i++ {
		cc.OnPacketSent(1280)
		time.Sleep(5 * time.Millisecond)
		cc.OnAck(1280)
	}

	cwndBefore := cc.GetCWND()
	cc.OnPacketLoss()

	// Westwood+ ssthresh should be BWE*minRTT, not necessarily cwnd/2
	ssthresh := cc.GetSSThresh()
	assert.GreaterOrEqual(t, ssthresh, MinCongestionWindow)
	assert.LessOrEqual(t, ssthresh, cwndBefore)
}

func TestCongestionController_BWE_FallbackNoEstimator(t *testing.T) {
	// Without RTT estimator, falls back to Reno-style cwnd/2
	cc := NewCongestionController(nil)
	cc.SetCWND(20000)

	cc.OnPacketLoss()
	assert.Equal(t, 10000, cc.GetSSThresh(), "should fall back to cwnd/2")
	assert.Equal(t, 10000, cc.GetCWND())
}

func TestCongestionController_BWE_ResetClearsBWE(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(50 * time.Millisecond)
	cc := NewCongestionController(rtt)

	// Two ACKs to generate a BWE.
	cc.OnPacketSent(1280)
	cc.OnAck(1280)
	time.Sleep(5 * time.Millisecond)
	cc.OnPacketSent(1280)
	cc.OnAck(1280)
	assert.Greater(t, cc.GetStats().BandwidthEstimate, 0.0)

	cc.Reset()
	assert.Equal(t, 0.0, cc.GetStats().BandwidthEstimate)
}

func TestCongestionController_BWE_RTOUsesBWE(t *testing.T) {
	rtt := NewRTTEstimator()
	rtt.Update(100 * time.Millisecond)
	cc := NewCongestionController(rtt)

	// Build BWE
	for i := 0; i < 10; i++ {
		cc.OnPacketSent(1280)
		time.Sleep(5 * time.Millisecond)
		cc.OnAck(1280)
	}

	cc.OnRetransmissionTimeout()
	assert.Equal(t, MinCongestionWindow, cc.GetCWND())
	assert.GreaterOrEqual(t, cc.GetSSThresh(), MinCongestionWindow)
	assert.Equal(t, SlowStart, cc.GetState())
}
