package session

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panicProbeConn builds a minimal established session whose data-phase
// processing panics: its dataHandler is nil, so ProcessDataPacket dereferences
// a nil receiver. This gives a deterministic, remote-input-shaped panic at the
// exact point the I2P-004 seam must contain.
func panicProbeConn() *SSU2Conn {
	return &SSU2Conn{
		underlying: &mockPacketConn{localAddr: &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 8888}},
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999},
		state:      1, // StateEstablished
		closeChan:  make(chan struct{}),
	}
}

func panicProbePacket() *SSU2Packet {
	return &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: 0,
		Header:       make([]byte, ShortHeaderSize),
		Payload:      make([]byte, MinPayloadSize),
	}
}

// TestProcessInboundPacket_RecoveredPanics proves the I2P-004 session-side
// seam: a panic raised while processing an inbound data packet (here from a
// nil dataHandler, standing in for any DataHandler-callback bug reachable from
// remote input) must be recovered and the packet dropped, NOT propagated to
// kill the read-worker goroutine and the process.
func TestProcessInboundPacket_RecoveredPanics(t *testing.T) {
	conn := panicProbeConn()

	// The inner body must panic — this is the panic the seam exists to catch.
	require.Panics(t, func() {
		conn.processInboundPacket(panicProbePacket())
	})

	// The public entry point must swallow that same panic.
	assert.NotPanics(t, func() {
		conn.ProcessInboundPacket(panicProbePacket())
	}, "ProcessInboundPacket must recover panics from packet processing")
}

// TestRecoverPacketContainsPanic exercises the recoverPacket helper directly:
// a panicking fn is contained, a clean fn runs to completion.
func TestRecoverPacketContainsPanic(t *testing.T) {
	var reached bool
	assert.NotPanics(t, func() {
		recoverPacket(func() {
			reached = true
			panic("simulated callback panic")
		})
	})
	assert.True(t, reached, "recoverPacket must run fn before recovering")

	var cleanRan bool
	recoverPacket(func() { cleanRan = true })
	assert.True(t, cleanRan)
}

// TestRecoverTickContainsPanic exercises the recoverTick helper used by the
// DataHandler reaper (I2P-004): a panicking cleanup tick is contained, a clean
// tick runs normally.
func TestRecoverTickContainsPanic(t *testing.T) {
	var ran bool
	assert.NotPanics(t, func() {
		recoverTick("test.tick", func() {
			ran = true
			panic("simulated cleanup panic")
		})
	})
	assert.True(t, ran)

	var cleanRan bool
	recoverTick("test.tick", func() { cleanRan = true })
	assert.True(t, cleanRan)
}
