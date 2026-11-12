package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleIncomingPacket_RecoveredPanics proves the I2P-004 listener-side
// seam: a panic raised while processing one inbound datagram on a packet
// worker — here from a nil PacketRouter reached via RoutePacket, standing in
// for any listener-level or path-manager callback bug triggered by remote
// input — must be recovered and the packet dropped, NOT propagated to kill the
// worker goroutine and the router process.
func TestHandleIncomingPacket_RecoveredPanics(t *testing.T) {
	introKey := randomKey(t)
	l := newTestListenerWithIntroKey(t, introKey)

	// A TokenRequest decodes through the intro-key protector and matches our
	// network ID, so handleIncomingPacket reaches RoutePacket. With the router
	// nil, RoutePacket dereferences its nil receiver and panics — the exact
	// class of failure the seam must contain.
	spec := &IntroKeyMessageSpec{
		MessageType:  MessageTypeTokenRequest,
		DestConnID:   0x1122334455667788,
		SourceConnID: 0x99aabbccddeeff00,
		Token:        make([]byte, TokenSize),
		Blocks:       []*SSU2Block{NewDateTimeBlock(), NewSSU2Block(BlockTypePadding, make([]byte, 24))},
	}
	wire, _, err := BuildIntroKeyMessage(introKey, spec)
	require.NoError(t, err)

	// Swap in a nil router to force a panic inside RoutePacket, and restore the
	// real one before the listener's Close() cleanup runs (Close dereferences
	// the router).
	origRouter := l.router
	l.router = nil
	defer func() { l.router = origRouter }()

	assert.NotPanics(t, func() {
		l.handleIncomingPacket(wire, testPeerAddr())
	}, "handleIncomingPacket must recover panics from packet processing")

	// The recovered panic is counted as a routing error so operators can see it.
	assert.NotZero(t, l.Stats()["routing_errors"],
		"a recovered panic must increment the routing_errors counter")
}
