package reliability

import (
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReceiveWindow is SSU2's inbound packet-number filter: it drops duplicates and
// packets that are too old, and otherwise hands a packet straight to the caller.
//
// It is deliberately NOT a reordering buffer. ssu2.rst §"Delivery Guarantees":
// "As with other I2P transports NTCP, NTCP2, and SSU 1, this transport is not a
// general-purpose facility for delivery of an in-order stream of bytes. It is
// designed for transport of I2NP messages. There is no 'stream' abstraction
// provided. ... As for SSU 1, it does NOT provide in-order delivery of I2NP
// messages. ... I2NP messages may be delivered to the far-end out-of-order, or
// may not be delivered at all."
//
// Buffering until a gap fills would be wrong in two ways: it introduces
// head-of-line blocking the transport never promises to avoid, and because SSU2
// never retransmits a data packet with the same packet number (§"Packet
// Numbering": "Data Packets are never retransmitted with the same packet
// number. Any retransmission of packet contents ... must use the next unused
// packet number"), a single lost packet would leave the buffer permanently unable
// to advance, stalling the session. Loss and duplication are handled one layer up
// by I2NP itself: "This protocol does NOT completely prevent duplicate delivery
// of I2NP messages. The router should enforce I2NP expiration and use a Bloom
// filter or other mechanism based on the I2NP message ID."
//
// What the spec does require is bounded duplicate detection, from §"Packet
// Numbering": "Endpoints that track all individual packets for the purposes of
// detecting duplicates are at risk of accumulating excessive state. The data
// required for detecting duplicates can be limited by maintaining a minimum
// packet number below which all packets are immediately dropped."
//
// That is the model implemented here:
//
//   - floor: the lowest packet number still eligible, everything below is dropped, and
//   - seen: a fixed-size bitset covering [floor, floor+capacity) marking the numbers already delivered.
//
// The floor slides forward as newer packet numbers arrive, recycling the bitset
// so memory stays flat for the life of the session.
//
// Thread-safe: Insert may be called concurrently.
type ReceiveWindow struct {
	// floor is the lowest packet number still eligible for delivery.
	floor uint32

	// seen is a bitset over [floor, floor+capacity); bit i records whether
	// packet number floor+i has already been delivered. All arithmetic on
	// indices is modular, so packet-number wrap-around needs no special case.
	seen []uint64

	// capacity is the number of packet numbers the bitset tracks.
	capacity uint32

	// mutex protects floor and seen.
	mutex sync.RWMutex
}

// SSU2Packet is defined in packet.go

const (
	// DefaultMaxWindowSize is the default number of packet numbers tracked for
	// duplicate detection.
	//
	// It matches the largest ACK range a peer can describe in one ACK block
	// (ssu2.rst §"Ack" allows up to 512 ranges), so any packet number a peer can
	// still legitimately refer to is inside our dedup span.
	DefaultMaxWindowSize = 512

	// MaxPacketNumber is the maximum packet number (2^32 - 1 per ssu2.rst
	// §"Packet Number").
	MaxPacketNumber = 0xFFFFFFFF
)

// NewReceiveWindow creates a packet-number filter whose first eligible packet
// number is expected.
//
// Parameters:
//   - expected: the first packet number we expect to receive (the initial floor)
//   - maxSize:    how many packet numbers to track for duplicate detection
//     (use DefaultMaxWindowSize if unsure)
//
// Returns a new ReceiveWindow ready to filter packets.
func NewReceiveWindow(expected uint32, maxSize uint) *ReceiveWindow {
	flog("NewReceiveWindow", logger.Fields{"expected": expected, "maxSize": maxSize}).Debug("Creating SSU2 packet-number filter")
	if maxSize == 0 {
		maxSize = DefaultMaxWindowSize
	}
	capacity := uint32(maxSize)
	return &ReceiveWindow{
		floor:    expected,
		seen:     make([]uint64, (capacity+63)/64),
		capacity: capacity,
	}
}

// seqBefore reports whether packet number a comes before b in the circular
// uint32 space, assuming the two are within 2^31 of each other (RFC 1982
// serial-number arithmetic).
//
// Packet numbers wrap at 2^32 within a session (ssu2.rst §"Packet Number": "The
// packet number may wrap around during the session"), so every comparison must be
// modular rather than a plain integer comparison.
func seqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

// Insert filters one inbound data-phase packet.
//
// On success it returns the packet in a slice, in arrival order: there is no
// reordering, per §"Delivery Guarantees". The slice holds exactly one packet; the
// plural form is kept so the read path stays uniform.
//
// It returns an error when the packet must be discarded:
//   - below the floor (older than anything still tracked), or
//   - a duplicate inside the tracked span.
//
// Both are "silently drop" cases in the spec, so callers treat the error as a
// discard signal rather than a connection failure.
//
// Thread-safe.
func (rw *ReceiveWindow) Insert(packet *SSU2Packet) ([]*SSU2Packet, error) {
	flog("Insert").Debug("Filtering inbound SSU2 packet")
	if packet == nil {
		return nil, oops.Errorf("cannot insert nil packet")
	}

	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	pktNum := packet.PacketNumber

	// Older than the tracked span: a duplicate or an extremely late arrival.
	// "maintaining a minimum packet number below which all packets are
	// immediately dropped".
	if seqBefore(pktNum, rw.floor) {
		return nil, oops.
			With("packetNumber", pktNum).
			With("floor", rw.floor).
			Errorf("packet below the duplicate-detection floor (old or duplicate)")
	}

	// Newer than the tracked span: slide the floor so pktNum is the newest
	// tracked number, forgetting the span we have moved past. Bounded state is
	// the point, so a duplicate older than the slide is tolerated rather than
	// remembered forever.
	if off := pktNum - rw.floor; off >= rw.capacity {
		rw.floor = pktNum - rw.capacity + 1
		for i := range rw.seen {
			rw.seen[i] = 0
		}
	}

	bit := pktNum - rw.floor
	if rw.seen[bit/64]&(1<<(bit%64)) != 0 {
		return nil, oops.
			With("packetNumber", pktNum).
			With("floor", rw.floor).
			Errorf("duplicate packet already delivered")
	}

	rw.seen[bit/64] |= 1 << (bit % 64)
	return []*SSU2Packet{packet}, nil
}

// GetExpected returns the lowest packet number still eligible for delivery.
// Thread-safe.
func (rw *ReceiveWindow) GetExpected() uint32 {
	return withRLock(&rw.mutex, func() uint32 { return rw.floor })
}

// GetMaxSize returns the number of packet numbers tracked for duplicates.
func (rw *ReceiveWindow) GetMaxSize() int {
	return withRLock(&rw.mutex, func() int { return int(rw.capacity) })
}

// MarkSeen records a packet number as already delivered without delivering it.
//
// It exists to pre-seed the filter with a handshake packet that shares the
// data-phase numbering space. ssu2.md §"Packet Numbering" starts Alice's
// outbound numbering at 0 with Session Confirmed, so a responder must treat
// packet number 0 as consumed before the first data packet arrives; otherwise
// a peer's data-phase packet 0 (or a retransmitted Session Confirmed routed to
// the data path) would be accepted as new. Reference: Java
// PeerState2.java:146 "_receivedMessages.set(0)" for inbound sessions.
//
// Numbers below the floor are already unconditionally dropped, so marking them
// is a no-op. Thread-safe.
func (rw *ReceiveWindow) MarkSeen(pktNum uint32) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if seqBefore(pktNum, rw.floor) {
		return
	}
	bit := pktNum - rw.floor
	if bit >= rw.capacity {
		// Outside the tracked span; nothing to remember without sliding, and
		// sliding here would forget legitimately pending numbers.
		return
	}
	rw.seen[bit/64] |= 1 << (bit % 64)
}

// GetWindowSize returns how many packet numbers are currently recorded as
// delivered. Thread-safe.
func (rw *ReceiveWindow) GetWindowSize() int {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()

	count := 0
	for _, word := range rw.seen {
		for word != 0 {
			word &= word - 1 // clear the lowest set bit
			count++
		}
	}
	return count
}

// SetExpected moves the floor to expected, forgetting every recorded packet
// number. Used when a session's numbering baseline changes, for example when a
// First Packet Number block is negotiated.
//
// Thread-safe.
func (rw *ReceiveWindow) SetExpected(expected uint32) {
	flog("SetExpected", logger.Fields{"expected": expected}).Debug("Moving SSU2 packet-number floor")
	rw.Clear(expected)
}

// Clear resets the filter, forgetting every recorded packet number and setting
// the floor to expected. Thread-safe.
func (rw *ReceiveWindow) Clear(expected uint32) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	rw.floor = expected
	for i := range rw.seen {
		rw.seen[i] = 0
	}
}

// HasGaps reports whether any packet number is currently recorded. Nothing is
// ever buffered waiting for a gap under the spec's no-reordering model, so the
// name is a legacy hold-over.
//
// Deprecated: gaps are not a concept in SSU2, which "does NOT provide in-order
// delivery of I2NP messages".
func (rw *ReceiveWindow) HasGaps() bool {
	return rw.GetWindowSize() > 0
}

// GetGapInfo reports the lowest and highest recorded packet numbers and how many
// are recorded. With nothing recorded it returns the floor and a count of 0.
// Thread-safe.
func (rw *ReceiveWindow) GetGapInfo() (minBuffered, maxBuffered uint32, count int) {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()

	lowest, highest := rw.capacity, uint32(0)
	for i := uint32(0); i < rw.capacity; i++ {
		if rw.seen[i/64]&(1<<(i%64)) != 0 {
			count++
			if i < lowest {
				lowest = i
			}
			if i > highest {
				highest = i
			}
		}
	}
	if count == 0 {
		return rw.floor, rw.floor, 0
	}
	return rw.floor + lowest, rw.floor + highest, count
}
