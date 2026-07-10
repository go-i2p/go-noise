package handshake

import (
	"testing"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

func newTestHandlerForFragmentTests(t *testing.T) *HandshakeHandler {
	t.Helper()
	dh, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	// validateFragmentOrdering is a pure function of its packets argument and
	// does not depend on handshake role/state; use responder role (initiator
	// = false) since it does not require a remote static key upfront.
	handler, err := NewHandshakeHandler(false, dh.Private[:32], nil, nil)
	require.NoError(t, err)
	return handler
}

// buildFragmentPacket constructs a minimal SSU2Packet with a 14-byte-plus
// Header carrying the given (fragNum, totalFrags) nibble pair at Header[13],
// suitable for validateFragmentOrdering.
func buildFragmentPacket(headerLen int, fragNum, totalFrags int) *SSU2Packet {
	pkt := &SSU2Packet{MessageType: MessageTypeSessionConfirmed}
	pkt.Header = make([]byte, headerLen)
	if headerLen > 13 {
		pkt.Header[13] = byte((fragNum&0x0F)<<4 | (totalFrags & 0x0F))
	}
	return pkt
}

func TestValidateFragmentOrdering_EmptyPacketsRejected(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	err := handler.validateFragmentOrdering(nil)
	if err == nil {
		t.Fatal("expected error for empty packet slice")
	}
}

// TestValidateFragmentOrdering_ShortHeaderRejected is the regression test for
// AUDIT.md Level 6/10: validateFragmentOrdering must reject a packet whose
// Header is shorter than 14 bytes (the minimum needed to read Header[13])
// rather than panicking with an index-out-of-range, so the function is safe
// in isolation regardless of caller-side guards.
func TestValidateFragmentOrdering_ShortHeaderRejected(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)

	t.Run("first packet header too short", func(t *testing.T) {
		short := buildFragmentPacket(13, 0, 1) // only 13 bytes; Header[13] out of range
		err := handler.validateFragmentOrdering([]*SSU2Packet{short})
		if err == nil {
			t.Fatal("expected error for short header on first packet, got nil (or a panic would have occurred without the fix)")
		}
	})

	t.Run("second packet header too short", func(t *testing.T) {
		first := buildFragmentPacket(14, 0, 2)
		shortSecond := buildFragmentPacket(10, 1, 2)
		err := handler.validateFragmentOrdering([]*SSU2Packet{first, shortSecond})
		if err == nil {
			t.Fatal("expected error for short header on second packet")
		}
	})

	t.Run("zero-length header", func(t *testing.T) {
		empty := &SSU2Packet{MessageType: MessageTypeSessionConfirmed, Header: nil}
		err := handler.validateFragmentOrdering([]*SSU2Packet{empty})
		if err == nil {
			t.Fatal("expected error for nil/empty header")
		}
	})
}

func TestValidateFragmentOrdering_SingleFragment(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	pkt := buildFragmentPacket(14, 0, 1)
	if err := handler.validateFragmentOrdering([]*SSU2Packet{pkt}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateFragmentOrdering_MultipleFragmentsInOrder(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	packets := []*SSU2Packet{
		buildFragmentPacket(14, 0, 3),
		buildFragmentPacket(14, 1, 3),
		buildFragmentPacket(14, 2, 3),
	}
	if err := handler.validateFragmentOrdering(packets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateFragmentOrdering_WrongFragmentCount(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	// Declares totalFrags=3 but only 2 packets provided.
	packets := []*SSU2Packet{
		buildFragmentPacket(14, 0, 3),
		buildFragmentPacket(14, 1, 3),
	}
	if err := handler.validateFragmentOrdering(packets); err == nil {
		t.Fatal("expected error for fragment count mismatch")
	}
}

func TestValidateFragmentOrdering_OutOfOrderFragments(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	packets := []*SSU2Packet{
		buildFragmentPacket(14, 0, 2),
		buildFragmentPacket(14, 0, 2), // wrong fragNum, should be 1
	}
	if err := handler.validateFragmentOrdering(packets); err == nil {
		t.Fatal("expected error for out-of-order fragment numbering")
	}
}

func TestValidateFragmentOrdering_WrongMessageType(t *testing.T) {
	handler := newTestHandlerForFragmentTests(t)
	pkt := buildFragmentPacket(14, 0, 1)
	pkt.MessageType = MessageTypeData // wrong type
	if err := handler.validateFragmentOrdering([]*SSU2Packet{pkt}); err == nil {
		t.Fatal("expected error for wrong message type")
	}
}
