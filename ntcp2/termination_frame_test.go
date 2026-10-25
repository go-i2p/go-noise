// Tests for SendTerminationFrame: the data-phase teardown frame used when an
// AEAD failure kills a session. A receive-side AEAD failure leaves the
// outbound cipher/nonce/SipHash state in sync, so exactly one more properly
// framed write is valid and the peer can decrypt it.

package ntcp2

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestTerminationBlock mirrors the NTCP2 spec Termination block:
// [type:1=0x04][size:2=9][validFramesReceived:8][reason:1].
func buildTestTerminationBlock(reason byte, validFrames uint64) []byte {
	block := make([]byte, 12)
	block[0] = 0x04
	binary.BigEndian.PutUint16(block[1:3], 9)
	binary.BigEndian.PutUint64(block[3:11], validFrames)
	block[11] = reason
	return block
}

// SendTerminationFrame must refuse to run before the handshake completed:
// there are no data-phase keys to seal with.
func TestSendTerminationFrame_RejectsBeforeHandshake(t *testing.T) {
	p := newPipedNTCP2Conn(t)
	p.conn.established.Store(false)
	p.conn.broken.Store(true)

	n, err := p.conn.SendTerminationFrame(buildTestTerminationBlock(4, 0))
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Contains(t, err.Error(), "before handshake completion")
}

// After an inbound AEAD failure (broken set), SendTerminationFrame must still
// seal a real data-phase frame that the peer can decrypt. This is the core
// C12 guarantee: the termination reaches the peer as a valid frame, not raw
// cleartext.
func TestSendTerminationFrame_PeerDecryptsAfterBroken(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()
	defer responder.Close()

	// Exchange one clean frame each way so both sides have advanced nonces.
	clean := []byte("established traffic")
	_, err := initiator.Write(clean)
	require.NoError(t, err)
	buf := make([]byte, 4096)
	_, err = responder.Read(buf)
	require.NoError(t, err)

	// Simulate the responder's inbound AEAD failure: mark broken, as the
	// read path does before the teardown hook runs.
	responder.broken.Store(true)

	block := buildTestTerminationBlock(4, 1)
	n, err := responder.SendTerminationFrame(block)
	require.NoError(t, err, "broken receive state must not block the outbound teardown frame")
	assert.Equal(t, len(block), n)

	_ = initiator.SetReadDeadline(time.Now().Add(3 * time.Second))
	rn, rerr := initiator.Read(buf)
	require.NoError(t, rerr, "initiator must receive the termination frame")
	assert.Equal(t, block, buf[:rn], "termination block must arrive intact and encrypted")

	// The responder wrote exactly one data-phase frame: the termination.
	assert.Equal(t, uint64(1), responder.writeNonce, "termination frame advances write nonce")
}

// A write failure inside SendTerminationFrame must surface the error so the
// caller falls back to the abnormal close.
func TestSendTerminationFrame_WriteErrorPropagates(t *testing.T) {
	p := newPipedNTCP2Conn(t)
	p.withSipHash([2]uint64{1, 2})
	p.conn.established.Store(true)

	// Close the peer end so the write fails.
	p.server.Close()

	_, err := p.conn.SendTerminationFrame(buildTestTerminationBlock(4, 0))
	assert.Error(t, err)
}

// applyProbingResistance must close gracefully (not RST) when the hook returns
// nil, so the termination frame flushes; the peer must then read the frame
// followed by EOF.
func TestApplyProbingResistance_GracefulWhenTerminationSent(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()

	var hookCalled bool
	var hookSawConn *Conn
	responder.OnAEADError = func(conn *Conn, validFrames uint64) error {
		hookCalled = true
		hookSawConn = conn
		block := buildTestTerminationBlock(4, validFrames)
		_, err := conn.SendTerminationFrame(block)
		return err
	}

	// Drive the AEAD failure path directly.
	underlying := responder.noiseConn.Underlying()
	responder.applyProbingResistance(underlying, true)

	assert.True(t, hookCalled, "OnAEADError hook must run for data-phase failures")
	assert.Same(t, responder, hookSawConn, "hook must receive the Conn, not the raw socket")
	assert.True(t, responder.underlyingClosed.Load(), "socket must be closed after teardown")

	buf := make([]byte, 4096)
	_ = initiator.SetReadDeadline(time.Now().Add(3 * time.Second))
	rn, err := initiator.Read(buf)
	require.NoError(t, err, "initiator must receive the termination frame before close")
	require.GreaterOrEqual(t, rn, 12)
	assert.Equal(t, byte(0x04), buf[0], "block type must be Termination")
	assert.Equal(t, byte(4), buf[11], "reason must be AEAD failure (4)")

	_, err = initiator.Read(buf)
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed),
		"expected EOF/closed after graceful close, got %v", err)
}

// With no hook registered, applyProbingResistance must still send the spec's
// default termination block (reason 4 = data phase AEAD failure) and then
// close gracefully so the frame flushes.
//
// The previous expectation here (abnormal RST close with no frame when no
// hook is set) encoded a non-spec behaviour: ntcp2.md §"Notes" (AEAD Error
// Handling) — "the recipient should send a payload with a termination block
// containing an 'AEAD failure' reason code, and close the connection" — and
// i2pd sends the block unconditionally on a data-phase AEAD failure
// (libi2pd/NTCP2.cpp:1280 → NTCP2Session::Terminate →
// NTCP2Session::SendTermination, NTCP2.cpp:1655-1673). The OnAEADError hook
// is an optional transport-layer override, not a precondition for the frame.
func TestApplyProbingResistance_DefaultTerminationWithoutHook(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()

	responder.OnAEADError = nil
	underlying := responder.noiseConn.Underlying()
	responder.applyProbingResistance(underlying, true)

	assert.True(t, responder.underlyingClosed.Load(), "socket must be closed after teardown")

	buf := make([]byte, 4096)
	_ = initiator.SetReadDeadline(time.Now().Add(3 * time.Second))
	rn, err := initiator.Read(buf)
	require.NoError(t, err, "initiator must receive the default termination frame")
	require.GreaterOrEqual(t, rn, 12)
	assert.Equal(t, byte(TerminationBlockType), buf[0], "block type must be Termination")
	assert.Equal(t, byte(TerminationReasonDataPhaseAEAD), buf[11],
		"reason must be data phase AEAD failure (4)")

	_, err = initiator.Read(buf)
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed),
		"expected EOF/closed after graceful close, got %v", err)
}

// If the connection cannot seal a termination frame (here: no length
// obfuscator configured, so the outbound modifier pipeline is incomplete),
// applyProbingResistance must fall back to the spec's abnormal close (RST).
func TestApplyProbingResistance_RSTWhenTerminationCannotBeSealed(t *testing.T) {
	initiator, responder := setupHandshakedPair(t)
	defer initiator.Close()

	responder.OnAEADError = nil
	responder.lengthObfuscator.Store(nil) // force sendTerminationBlock to fail
	underlying := responder.noiseConn.Underlying()
	responder.applyProbingResistance(underlying, true)

	assert.True(t, responder.underlyingClosed.Load())

	buf := make([]byte, 1024)
	_ = initiator.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := initiator.Read(buf)
	assert.Error(t, err, "no termination frame should arrive when sealing fails")
}
