package reliability

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// MaxNACKRangesPerACK is the maximum number of NACK/ACK range pairs
	// allowed in a single ACK block. With 1280-byte MTU and SSU2 overhead,
	// the realistic bound is ~150 ranges per packet, but we cap at 200 to
	// prevent resource exhaustion from malicious peers sending excessive ranges.
	MaxNACKRangesPerACK = 200

	// minACKInterval is the minimum time between consecutive ACKs to prevent
	// ACK amplification under bursty load. Even if ackThreshold is reached,
	// we won't send another ACK until this interval has elapsed since the last one.
	minACKInterval = 5 * time.Millisecond
)

// ACKHandler manages acknowledgment generation and processing for SSU2 connections.
// It tracks received packets, generates ACK blocks, and processes incoming ACKs
// to manage retransmission and congestion control.
//
// ACK Block Format (Type 12) per SSU2 spec:
//   - Bytes 0-3: Through Packet Number (highest PN being acked, big-endian)
//   - Byte 4:    acnt — number of consecutive packets acked at and below the
//     Through PN, MINUS 1 (so 0 means only the Through PN itself)
//   - Bytes 5+:  Optional ranges, each 2 bytes:
//     Byte 0: nacks minus 1 (gap of non-received packets)
//     Byte 1: acks minus 1  (run of received packets)
//
// Minimum size: 5 bytes (4-byte Through PN + 1-byte acnt)
type ACKHandler struct {
	mu sync.Mutex

	// receivedPackets tracks packet numbers we've received and need to ACK
	receivedPackets []uint32

	// pendingACKs tracks packets awaiting acknowledgment
	pendingACKs map[uint32]*PendingACK

	// lastACKTime is when we last sent an ACK
	lastACKTime time.Time

	// ackDelay is the calculated delay before sending ACK
	ackDelay time.Duration

	// ackThreshold is the number of received packets that triggers an
	// immediate ACK regardless of delay timer.
	ackThreshold int

	// maxACKDataSize is the maximum size in bytes of the ACK block data
	// (excluding the 3-byte block header). This prevents ACK blocks from
	// consuming excessive MTU space. Default: 504 bytes (~half of 1280 MTU
	// minus headers).
	maxACKDataSize int
}

// PendingACK tracks an unacknowledged packet awaiting confirmation.
type PendingACK struct {
	PacketNumber uint32
	SentTime     time.Time
	Retries      int
}

// NewACKHandler creates a new ACK handler with default settings.
func NewACKHandler() *ACKHandler {
	flog("NewACKHandler").Debug("Creating new ACKHandler")
	return &ACKHandler{
		receivedPackets: make([]uint32, 0, 64),
		pendingACKs:     make(map[uint32]*PendingACK),
		ackDelay:        10 * time.Millisecond, // Default from ssu2.rst
		ackThreshold:    10,
		maxACKDataSize:  504, // ~half of 1280 MTU minus headers
	}
}

// RecordReceived marks a packet number as received and needing acknowledgment.
// This should be called for every successfully processed inbound packet.
func (h *ACKHandler) RecordReceived(packetNum uint32) {
	flog("RecordReceived", logger.Fields{"packetNum": packetNum}).Debug("RecordReceived: marking packet as received")
	h.mu.Lock()
	defer h.mu.Unlock()
	h.receivedPackets = append(h.receivedPackets, packetNum)
}

// SetACKThreshold sets the number of received packets that triggers an
// immediate ACK. Must be >= 1.
func (h *ACKHandler) SetACKThreshold(threshold int) {
	flog("SetACKThreshold", logger.Fields{"threshold": threshold}).Debug("SetACKThreshold: updating ACK threshold")
	if threshold < 1 {
		threshold = 1
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ackThreshold = threshold
}

// SetMaxACKDataSize sets the maximum ACK block data size in bytes.
// This limits ACK blocks to fit within the available MTU. Must be >= 5
// (minimum ACK block: 4-byte throughPN + 1-byte acnt).
func (h *ACKHandler) SetMaxACKDataSize(size int) {
	flog("SetMaxACKDataSize", logger.Fields{"size": size}).Debug("SetMaxACKDataSize: updating max ACK data size")
	if size < 5 {
		size = 5
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.maxACKDataSize = size
}

// ShouldSendACK determines if an ACK should be sent based on timing and packet count.
// Per ssu2.rst: ACK delay = max(10, min(rtt/6, 150)) ms
func (h *ACKHandler) ShouldSendACK(rtt time.Duration) bool {
	flog("ShouldSendACK", logger.Fields{"rtt": rtt}).Debug("ShouldSendACK: checking if ACK should be sent")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) == 0 {
		return false
	}

	// Calculate dynamic ACK delay based on RTT
	delay := rtt / 6
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > 150*time.Millisecond {
		delay = 150 * time.Millisecond
	}
	h.ackDelay = delay

	// Send ACK if delay elapsed or we have many packets
	// BUT always enforce minACKInterval to prevent amplification under bursts
	timeSinceLastACK := time.Since(h.lastACKTime)
	thresholdOrDelayMet := timeSinceLastACK >= h.ackDelay || len(h.receivedPackets) >= h.ackThreshold
	return timeSinceLastACK >= minACKInterval && thresholdOrDelayMet
}

// GenerateACK creates an ACK block (Type 12) for all received packets.
// Returns nil if there are no packets to acknowledge.
func (h *ACKHandler) GenerateACK() (*SSU2Block, error) {
	flog("GenerateACK").Debug("Generating ACK block")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) == 0 {
		return nil, nil
	}

	sorted := SortDescDedupPackets(h.receivedPackets)
	throughPN := sorted[0]
	acnt := countConsecutiveFromTop(sorted) - 1

	rangeBytes := buildACKRanges(sorted, int(acnt)+1, h.maxACKDataSize-5)

	data := make([]byte, 5+len(rangeBytes))
	binary.BigEndian.PutUint32(data[0:4], throughPN)
	data[4] = uint8(acnt)
	copy(data[5:], rangeBytes)

	block := NewSSU2Block(BlockTypeACK, data)
	h.lastACKTime = time.Now()
	h.receivedPackets = h.receivedPackets[:0]

	return block, nil
}

// countConsecutiveFromTop counts how many packets form a consecutive run
// from the highest packet number downward.
func countConsecutiveFromTop(sorted []uint32) int {
	flog("countConsecutiveFromTop", logger.Fields{"sortedLen": len(sorted)}).Debug("countConsecutiveFromTop: counting consecutive packets from top")
	count := 1
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1]-1 {
			count++
		} else {
			break
		}
	}
	return count
}

// buildACKRanges builds nack/ack range pairs for non-consecutive packets.
func buildACKRanges(sorted []uint32, start, maxBytes int) []byte {
	flog("buildACKRanges", logger.Fields{"start": start, "maxBytes": maxBytes, "sortedLen": len(sorted)}).Debug("buildACKRanges: building ACK range pairs")
	var rangeBytes []byte
	i := start
	for i < len(sorted) {
		if len(rangeBytes)+2 > maxBytes {
			break
		}
		prevPN := sorted[i-1]
		nextPN := sorted[i]
		nackCount := int(prevPN - nextPN - 1)
		if nackCount < 1 {
			nackCount = 1
		}
		if nackCount > 256 {
			nackCount = 256
		}

		ackRun := 1
		j := i + 1
		for j < len(sorted) && sorted[j] == sorted[j-1]-1 {
			ackRun++
			j++
		}
		if ackRun > 256 {
			ackRun = 256
		}

		rangeBytes = append(rangeBytes, uint8(nackCount-1), uint8(ackRun-1))
		i = j
	}
	return rangeBytes
}

// ProcessACK handles an incoming ACK block, removing acknowledged packets
// from the pending queue. Returns the list of acked packet numbers.
func (h *ACKHandler) ProcessACK(ackBlock *SSU2Block) ([]uint32, error) {
	flog("ProcessACK").Debug("Processing ACK block")
	h.mu.Lock()
	defer h.mu.Unlock()
	if ackBlock.Type != BlockTypeACK {
		return nil, oops.Errorf("expected ACK block type %d, got %d",
			BlockTypeACK, ackBlock.Type)
	}

	data := ackBlock.Data
	if len(data) < 5 {
		return nil, oops.Errorf("ACK block too short: %d bytes, minimum 5", len(data))
	}

	// Parse header
	throughPN := binary.BigEndian.Uint32(data[0:4])
	acnt := int(data[4])

	var ackedPackets []uint32

	// Initial consecutive run: throughPN down through throughPN-acnt
	if uint32(acnt) > throughPN {
		return nil, oops.Errorf("ACK acnt (%d) exceeds throughPN (%d)", acnt, throughPN)
	}
	for i := 0; i <= acnt; i++ {
		pn := throughPN - uint32(i)
		ackedPackets = append(ackedPackets, pn)
		delete(h.pendingACKs, pn)
	}

	// cursor tracks the next position below the last acked packet
	// Use int64 to detect underflow from malformed ACK ranges (AUDIT H-7).
	base := throughPN - uint32(acnt)
	if base == 0 {
		return ackedPackets, nil
	}
	cursor := int64(base - 1)

	// Parse optional nack/ack range pairs
	offset := 5
	rangeCount := 0
	for offset+1 < len(data) {
		rangeCount++
		if rangeCount > MaxNACKRangesPerACK {
			return nil, oops.
				Code("ACK_TOO_MANY_RANGES").
				In("ssu2.reliability").
				Errorf("ACK block contains too many NACK/ACK ranges: %d (max %d)",
					rangeCount, MaxNACKRangesPerACK)
		}

		nacks := int64(data[offset]) + 1  // stored minus 1 per spec
		acks := int64(data[offset+1]) + 1 // stored minus 1 per spec
		offset += 2

		// Skip the gap (nacked packets) — check for underflow
		if nacks > cursor {
			return nil, oops.Errorf("ACK nack range (%d) exceeds cursor (%d)", nacks, cursor)
		}
		cursor -= nacks
		if cursor < 0 {
			return nil, oops.Errorf("ACK cursor underflow after nacks: cursor=%d", cursor)
		}

		// Collect the ack run — check for underflow
		if acks > cursor+1 {
			return nil, oops.Errorf("ACK ack range (%d) exceeds remaining cursor (%d)", acks, cursor)
		}
		for i := int64(0); i < acks; i++ {
			ackedPackets = append(ackedPackets, uint32(cursor))
			delete(h.pendingACKs, uint32(cursor))
			cursor--
			if cursor < 0 {
				return nil, oops.Errorf("ACK cursor underflow in ack loop: cursor=%d", cursor)
			}
		}
	}

	return ackedPackets, nil
}

// AddPending marks a packet as sent and awaiting acknowledgment.
func (h *ACKHandler) AddPending(packetNum uint32) {
	flog("AddPending", logger.Fields{"packetNum": packetNum}).Debug("AddPending: marking packet as pending ACK")
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingACKs[packetNum] = &PendingACK{
		PacketNumber: packetNum,
		SentTime:     time.Now(),
		Retries:      0,
	}
}

// GetPending returns all packet numbers currently awaiting acknowledgment.
func (h *ACKHandler) GetPending() []uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := make([]uint32, 0, len(h.pendingACKs))
	for pktNum := range h.pendingACKs {
		pending = append(pending, pktNum)
	}
	return pending
}

// GetPendingPacket returns details about a specific pending packet.
func (h *ACKHandler) GetPendingPacket(packetNum uint32) (*PendingACK, bool) {
	return withLock2(&h.mu, func() (*PendingACK, bool) {
		ack, exists := h.pendingACKs[packetNum]
		return ack, exists
	})
}

// HasPending returns true if there are packets awaiting acknowledgment.
func (h *ACKHandler) HasPending() bool {
	return withLock(&h.mu, func() bool { return len(h.pendingACKs) > 0 })
}

// ClearPending removes all pending acknowledgments (used on connection close).
//
// IMPORTANT: No-wake contract
// ---------------------------
// This method does NOT notify any goroutines that may be waiting on pending ACKs.
// The current implementation is correct because:
//   - No existing code blocks waiting for ACKs to be sent or acknowledged
//   - ClearPending is only called during connection teardown
//
// If a future feature adds wait-for-ACK semantics (e.g., FlushWrites() or
// WaitForAck(packetNum)), you MUST either:
//  1. Document that waiters must watch for connection closure separately, OR
//  2. Add a broadcast channel that ClearPending signals to unblock all waiters
//
// Failure to address this will cause silent goroutine leaks when connections close
// while waiters are blocked on ACK delivery.
func (h *ACKHandler) ClearPending() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingACKs = make(map[uint32]*PendingACK)
	h.receivedPackets = h.receivedPackets[:0]
}

// SortDescDedupPackets returns a deduplicated copy of packets sorted in
// descending order.
func SortDescDedupPackets(packets []uint32) []uint32 {
	if len(packets) == 0 {
		return nil
	}

	sorted := make([]uint32, len(packets))
	copy(sorted, packets)

	// Sort descending (simple insertion sort — received lists are typically small)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] < key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Deduplicate (sorted is descending, so duplicates are adjacent)
	out := sorted[:1]
	for i := 1; i < len(sorted); i++ {
		if sorted[i] != out[len(out)-1] {
			out = append(out, sorted[i])
		}
	}

	return out
}
