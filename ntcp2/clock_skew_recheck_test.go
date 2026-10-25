// Tests for recheckClockSkewAfterConfirm: the responder's mandatory
// post-SessionConfirmed clock-skew recheck.
//
// ntcp2.md §"Clock Skew Guidelines": "If Alice does reply with Session
// Confirmed ... Bob should adjust the calculated clock skew by subtracting
// half the RTT. If the adjusted clock skew exceeds the maximum, Bob should
// then reply with a Disconnect message containing a clock skew reason code,
// and close the connection."
// Reference: Java i2p.i2p InboundEstablishState.verifyInbound()
// (`_peerSkew -= ((rtt / 2) + 500) / 1000`, then REASON_SKEW = 7).

package ntcp2

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A peer whose clock is within tolerance after the half-RTT adjustment must
// not be disconnected: the recheck is a no-op and returns nil.
func TestRecheckClockSkewAfterConfirm_WithinTolerance(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()
	defer responder.Close()

	cfg := responder.ntcp2Config.Load()
	require.NotNil(t, cfg)

	now := time.Now()
	// Peer clock 50 s ahead, RTT 4 s: adjusted skew = 50 + 2 = 52 s < 60 s.
	cfg.peerTimestampSecs = uint64(now.Add(50 * time.Second).Unix())
	cfg.msg1ReceivedAt = now
	cfg.msg3ReceivedAt = now.Add(4 * time.Second)

	require.NoError(t, responder.recheckClockSkewAfterConfirm(cfg, responder.noiseConn.Underlying()),
		"adjusted skew within tolerance must keep the connection")
}

// A peer whose RTT-adjusted skew exceeds the maximum must receive a
// termination frame with reason 7 (clock skew), and the recheck must return
// an error so Handshake() fails.
func TestRecheckClockSkewAfterConfirm_ExceedsToleranceSendsReason7(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()

	cfg := responder.ntcp2Config.Load()
	require.NotNil(t, cfg)

	now := time.Now()
	// Peer clock 55 s ahead, RTT 12 s: adjusted skew = 55 + 6 = 61 s > 60 s.
	cfg.peerTimestampSecs = uint64(now.Add(55 * time.Second).Unix())
	cfg.msg1ReceivedAt = now
	cfg.msg3ReceivedAt = now.Add(12 * time.Second)

	err := responder.recheckClockSkewAfterConfirm(cfg, responder.noiseConn.Underlying())
	require.Error(t, err, "adjusted skew over the maximum must fail the handshake")
	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "MSG3_CLOCK_SKEW_RECHECK", oopsErr.Code())

	// The spec's "Disconnect message containing a clock skew reason code" is a
	// data-phase Termination block (§"Termination": rsn 7). The initiator must
	// receive it as a valid frame, then see the graceful close.
	buf := make([]byte, 4096)
	_ = initiator.SetReadDeadline(time.Now().Add(3 * time.Second))
	rn, rerr := initiator.Read(buf)
	require.NoError(t, rerr, "initiator must receive the clock-skew termination frame")
	require.GreaterOrEqual(t, rn, TerminationBlockSize+BlockHeaderSize)
	assert.Equal(t, byte(TerminationBlockType), buf[0], "block type must be Termination")
	assert.Equal(t, byte(TerminationReasonClockSkew), buf[11],
		"reason must be clock skew (7)")

	_, err = initiator.Read(buf)
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed),
		"expected EOF/closed after graceful close, got %v", err)
}
