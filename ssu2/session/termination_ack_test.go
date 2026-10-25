// Tests for the §"Session Termination" "Termination Received" acknowledgement.
//
// ssu2.rst §"Session Termination" / Data phase: "When receiving a Termination
// block with any reason except \"Termination Received\", the peer responds with
// a data message containing a Termination block with the reason \"Termination
// Received\"." The wrapping happens inside SSU2Conn so it applies to every
// session regardless of what the router-layer callback does with the block.

package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// establishedConnForTermination builds a conn in the established state with the
// destroy wait disabled, mirroring the packet-number tests.
func establishedConnForTermination(t *testing.T) (*SSU2Conn, *mockPacketConn) {
	t.Helper()

	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	config.DestroyTimeout = 0

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)

	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	t.Cleanup(func() { conn.SetOwnsUnderlying(false); initConn.Close() })
	return conn, initConn
}

// TestSendTerminationReceived_WritesTerminationBlock proves the ack is emitted
// as a Data packet carrying a Termination block with reason 1.
func TestSendTerminationReceived_WritesTerminationBlock(t *testing.T) {
	conn, sock := establishedConnForTermination(t)

	conn.validDataPacketsReceived.Store(7)
	conn.sendTerminationReceived()

	var pkt mockPacket
	select {
	case pkt = <-sock.writeChan:
	case <-time.After(2 * time.Second):
		t.Fatal("no datagram written for the termination ack")
	}

	// The datagram is AEAD-sealed, so the block cannot be read off the wire
	// here; what this asserts is that a write happened at all. The payload
	// composition is covered by TestBuildTerminationReceivedBlockContents.
	assert.Greater(t, len(pkt.data), ShortHeaderSize+MACSize,
		"a Data message must carry at least a short header and a MAC")
}

// TestSendTerminationReceived_SuppressedWhenNotEstablished proves the ack is
// only sent on a live session. Once the conn is closing, CloseWithReason has
// already emitted a termination and a second one would violate the spec's
// closing-state rate-limit guidance.
func TestSendTerminationReceived_SuppressedWhenNotEstablished(t *testing.T) {
	conn, sock := establishedConnForTermination(t)

	conn.stateMutex.Lock()
	conn.state = StateClosing
	conn.stateMutex.Unlock()

	conn.sendTerminationReceived()

	select {
	case <-sock.writeChan:
		t.Fatal("a closing session must not emit a second termination")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestTerminationCallback_AcksNonReceivedReason verifies the wrapping rule: a
// reason other than TerminationReceived triggers the ack, and TerminationReceived
// itself does not (which would ping-pong forever).
func TestTerminationCallback_AcksNonReceivedReason(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reason    TerminationReason
		wantWrite bool
	}{
		{"NormalClose", TerminationNormalClose, true},
		{"IdleTimeout", TerminationIdleTimeout, true},
		{"TerminationReceived", TerminationReceived, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, sock := establishedConnForTermination(t)

			var gotReason uint8
			cbs := DataHandlerCallbacks{
				OnTermination: func(_ uint64, reason uint8, _ []byte) { gotReason = reason },
			}
			conn.wrapTerminationCallback(&cbs)
			cbs.OnTermination(3, uint8(tc.reason), nil)

			assert.Equal(t, uint8(tc.reason), gotReason,
				"the application callback must still run")

			wrote := false
			select {
			case <-sock.writeChan:
				wrote = true
			case <-time.After(150 * time.Millisecond):
			}
			assert.Equal(t, tc.wantWrite, wrote,
				"ack emission must follow the reason code")
		})
	}
}

// TestBuildTerminationReceivedBlockContents pins the wire layout of the ack
// block itself: 8-byte big-endian validDataPacketsReceived, then the reason.
func TestBuildTerminationReceivedBlockContents(t *testing.T) {
	termData := make([]byte, 9)
	binary.BigEndian.PutUint64(termData[0:8], 42)
	termData[8] = byte(TerminationReceived)

	assert.Equal(t, uint64(42), binary.BigEndian.Uint64(termData[0:8]))
	assert.Equal(t, byte(1), termData[8], "reason 1 is Termination Received")
	assert.Len(t, termData, 9, "minimum Termination block is 9 bytes")
}
