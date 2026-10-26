package reliability

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal/eviction"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

const (
	// maxACKRangeCount is the largest value representable in the single-byte
	// acnt, nack-count, and ack-count fields of an SSU2 ACK block. Per
	// ssu2.rst "Ack" the acnt is "0-255" and each range is "1 byte nack
	// count followed by 1 byte ack count, 0-255 each". Runs longer than this
	// are carried over into additional ack-only or nack-only range pairs.
	maxACKRangeCount = 255

	// MaxNACKRangesPerACK is the maximum number of NACK/ACK range pairs
	// allowed in a single ACK block. With 1280-byte MTU and SSU2 overhead,
	// the realistic bound is ~150 ranges per packet, but we cap at 200 to
	// prevent resource exhaustion from malicious peers sending excessive ranges.
	MaxNACKRangesPerACK = 200

	// defaultACKThreshold is the number of ack-eliciting packets that triggers an
	// ACK. ssu2.md §"ACK Frequency": "A receiver should send an ACK block after
	// receiving at least two ack-eliciting packets."
	defaultACKThreshold = 2

	// minACKInterval is the minimum time between consecutive ACKs to prevent
	// ACK amplification under bursty load. Even if ackThreshold is reached,
	// we won't send another ACK until this interval has elapsed since the last one.
	minACKInterval = 5 * time.Millisecond

	// maxReceivedPackets bounds ACKHandler.receivedPackets independent of how
	// promptly the caller invokes ShouldSendACK/GenerateACK to drain it.
	// Without this cap, a peer sending packets faster than the local side
	// generates ACKs (or a stalled local ACK-generation loop) could grow this
	// slice unboundedly — a memory-exhaustion risk, compounded by
	// SortDescDedupPackets's O(n²) insertion sort on the eventual drain.
	// Matches DefaultMaxWindowSize (ssu2/reliability/receive_window.go), the
	// SSU2-spec-mandated maximum ACK-range window size; the receive window
	// itself bounds accepted packets to this same size in normal operation, so
	// this cap should not be reached under non-adversarial conditions.
	maxReceivedPackets = DefaultMaxWindowSize

	// maxPendingACKs bounds ACKHandler.pendingACKs as defense-in-depth,
	// independent of the congestion controller that normally limits
	// outstanding in-flight sends long before this map would grow
	// unreasonably large. A caller bug or a stalled/misbehaving congestion
	// integration should not be able to grow this map without limit.
	maxPendingACKs = DefaultMaxWindowSize
)

// ACKHandler manages acknowledgment generation and processing for SSU2 connections.
// It tracks received packets, generates ACK blocks, and processes incoming ACKs
// to manage retransmission and congestion control.
//
// ACK Block Format (Type 12) per SSU2 spec:
//   - Bytes 0-3: Through Packet Number (highest PN being acked, big-endian)
//   - Byte 4:    acnt — number of packets acked consecutively *below* the
//     Through PN (so 0 means only the Through PN itself), capped at 255
//   - Bytes 5+:  Optional ranges, each 2 bytes of raw counts:
//     Byte 0: nack count (gap of non-received packets), 0-255
//     Byte 1: ack count  (run of received packets), 0-255
//
// Per ssu2.rst "Ack" the range counts are raw, not decremented: "Range
// nack may be zero if acking more than 255 consecutive packets. Range ack may
// be zero if nacking more than 255 consecutive packets. Range nack and ack may
// not both be zero." The spec's worked example — "We want to ACK 10 9 8 6 5 2
// 1 0, and NACK 7 4 3: Ack Through 10, acnt 2, range: 1 2 (nack 7, ack 6 5),
// range: 2 3 (nack 4 3, ack 2 1 0)" — is encoded byte-for-byte by this format.
//
// Minimum size: 5 bytes (4-byte Through PN + 1-byte acnt)
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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
		ackDelay:        10 * time.Millisecond, // ssu2.md §"Recommended Constants": "ACK delay: max(10, min(rtt/6, 150)) ms"
		// ssu2.md §"Congestion Control" -> §"ACK Frequency": "A receiver should
		// send an ACK block after receiving at least two ack-eliciting packets."
		ackThreshold:   defaultACKThreshold,
		maxACKDataSize: 504, // ~half of 1280 MTU minus headers
	}
}

// IsAckEliciting reports whether a decrypted data-phase payload contains any
// block that elicits an ACK.
//
// ssu2.md §"Congestion Control" -> §"Generating ACKs":
//
//	"In-session data packets containing any block EXCEPT for the following are
//	 ack-eliciting: ACK block / Address block / DateTime block / Padding block /
//	 Termination block"
//
// Out-of-session packets (handshake messages, peer test 5-7) have their own
// acknowledgement mechanisms and are not classified here.
func IsAckEliciting(blockTypes []uint8) bool {
	for _, t := range blockTypes {
		switch t {
		case BlockTypeACK, BlockTypeAddress, BlockTypeDateTime, BlockTypePadding, BlockTypeTermination:
			continue
		}
		return true
	}
	return false
}

// RecordReceived marks a packet number as received and needing acknowledgment.
// Callers must only record ack-eliciting packets (see IsAckEliciting); packets
// that are not ack-eliciting are "only acknowledged when an ACK block is sent for
// other reasons" (§Generating ACKs).
//
// Once receivedPackets reaches maxReceivedPackets, further packet numbers are
// dropped (not appended) rather than growing the slice unboundedly; the
// caller's own receive window already independently rejects/dedupes packets
// outside its bounds, so reaching this cap indicates the local side is
// falling behind on ACK generation, not a new attack surface being opened.
func (h *ACKHandler) RecordReceived(packetNum uint32) {
	flog("RecordReceived", logger.Fields{"packetNum": packetNum}).Debug("RecordReceived: marking packet as received")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) >= maxReceivedPackets {
		flog("RecordReceived", logger.Fields{"packetNum": packetNum, "cap": maxReceivedPackets}).Warn("RecordReceived: receivedPackets at capacity, dropping packet number instead of growing unboundedly")
		return
	}
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
	// consecutive counts the run at and below throughPN; acnt is the number of
	// packets acked strictly below throughPN.
	consecutive := countConsecutiveFromTop(sorted)
	acnt := consecutive - 1

	var rangeBytes []byte
	// acnt is a single byte, so a run longer than 256 packets spills into
	// ack-only ranges (nack count 0), which ssu2.rst permits: "Range nack may
	// be zero if acking more than 255 consecutive packets."
	if acnt > maxACKRangeCount {
		remaining := acnt - maxACKRangeCount
		acnt = maxACKRangeCount
		for remaining > 0 {
			chunk := remaining
			if chunk > maxACKRangeCount {
				chunk = maxACKRangeCount
			}
			var ok bool
			rangeBytes, ok = appendACKRange(rangeBytes, 0, uint8(chunk), h.maxACKDataSize-5)
			if !ok {
				break
			}
			remaining -= chunk
		}
	}

	rangeBytes = append(rangeBytes, buildACKRanges(sorted, consecutive, h.maxACKDataSize-5-len(rangeBytes))...)

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

// appendACKRange appends a single nack/ack range pair to out. It reports false
// when the pair would not fit within maxBytes, leaving out unchanged.
func appendACKRange(out []byte, nacks, acks uint8, maxBytes int) ([]byte, bool) {
	if len(out)+2 > maxBytes {
		return out, false
	}
	return append(out, nacks, acks), true
}

// buildACKRanges builds nack/ack range pairs for the packets below the initial
// consecutive run. Each pair carries raw counts (0-255) as ssu2.rst specifies.
// Gaps or ack runs longer than one byte spill into additional single-sided
// ranges, which the spec permits: "Range nack may be zero if acking more than
// 255 consecutive packets. Range ack may be zero if nacking more than 255
// consecutive packets."
//
// start is the index into sorted (descending) of the first packet number not
// already covered by the acnt field or by previously emitted ranges.
func buildACKRanges(sorted []uint32, start, maxBytes int) []byte {
	flog("buildACKRanges", logger.Fields{"start": start, "maxBytes": maxBytes, "sortedLen": len(sorted)}).Debug("buildACKRanges: building ACK range pairs")
	var rangeBytes []byte
	i := start
	for i < len(sorted) {
		prevPN := sorted[i-1]
		nextPN := sorted[i]
		// sorted is descending and deduplicated, and i always follows the end
		// of a run, so the gap is at least one packet.
		nackCount := int(prevPN - nextPN - 1)
		if nackCount < 1 {
			nackCount = 1
		}

		ackRun := 1
		j := i + 1
		for j < len(sorted) && sorted[j] == sorted[j-1]-1 {
			ackRun++
			j++
		}

		// Spill an over-long gap into nack-only ranges (ack count 0).
		for nackCount > maxACKRangeCount {
			var ok bool
			rangeBytes, ok = appendACKRange(rangeBytes, maxACKRangeCount, 0, maxBytes)
			if !ok {
				return rangeBytes
			}
			nackCount -= maxACKRangeCount
		}

		if ackRun <= maxACKRangeCount {
			var ok bool
			rangeBytes, ok = appendACKRange(rangeBytes, uint8(nackCount), uint8(ackRun), maxBytes)
			if !ok {
				return rangeBytes
			}
			i = j
			continue
		}

		// Over-long ack run: pair the gap with the first chunk, then spill the
		// remainder into ack-only ranges (nack count 0).
		var ok bool
		rangeBytes, ok = appendACKRange(rangeBytes, uint8(nackCount), maxACKRangeCount, maxBytes)
		if !ok {
			return rangeBytes
		}
		for remaining := ackRun - maxACKRangeCount; remaining > 0; {
			chunk := remaining
			if chunk > maxACKRangeCount {
				chunk = maxACKRangeCount
			}
			rangeBytes, ok = appendACKRange(rangeBytes, 0, uint8(chunk), maxBytes)
			if !ok {
				return rangeBytes
			}
			remaining -= chunk
		}
		i = j
	}
	return rangeBytes
}

// ProcessACK handles an incoming ACK block, removing acknowledged packets
// from the pending queue. Returns the list of acked packet numbers.
func (h *ACKHandler) ProcessACK(ackBlock *SSU2Block) ([]uint32, error) {
	acked, _, err := h.ProcessACKWithNacks(ackBlock)
	return acked, err
}

// ProcessACKWithNacks is ProcessACK with the negatively acknowledged packet
// numbers as a second return value.
//
// ssu2.md §"Congestion Control" -> §"Packet Numbers": "ACKs and NACKs contain
// packet numbers. Transmitters must maintain a data structure with a mapping of
// packet numbers to their contents. When a packet is ACKed or NACKed, the
// transmitter must determine what I2NP messages and fragments were in that
// packet, to decide what to retransmit." A loss response therefore needs the
// NACK set, which ProcessACK discards.
func (h *ACKHandler) ProcessACKWithNacks(ackBlock *SSU2Block) (acked []uint32, nacked []uint32, err error) {
	flog("ProcessACK").Debug("Processing ACK block")
	h.mu.Lock()
	defer h.mu.Unlock()
	if ackBlock.Type != BlockTypeACK {
		return nil, nil, oops.Errorf("expected ACK block type %d, got %d",
			BlockTypeACK, ackBlock.Type)
	}

	data := ackBlock.Data
	if len(data) < 5 {
		return nil, nil, oops.Errorf("ACK block too short: %d bytes, minimum 5", len(data))
	}

	// Parse header
	throughPN := binary.BigEndian.Uint32(data[0:4])
	acnt := int(data[4])

	var ackedPackets []uint32
	var nackedPackets []uint32

	// Initial consecutive run: throughPN down through throughPN-acnt
	if uint32(acnt) > throughPN {
		return nil, nil, oops.Errorf("ACK acnt (%d) exceeds throughPN (%d)", acnt, throughPN)
	}
	for i := 0; i <= acnt; i++ {
		pn := throughPN - uint32(i)
		ackedPackets = append(ackedPackets, pn)
		delete(h.pendingACKs, pn)
	}

	// cursor tracks the next position below the last acked packet.
	// Use int64 to detect underflow from malformed ACK ranges.
	base := throughPN - uint32(acnt)
	if base == 0 {
		return ackedPackets, nackedPackets, nil
	}
	cursor := int64(base - 1)

	// Parse optional nack/ack range pairs
	offset := 5
	rangeCount := 0
	for offset+1 < len(data) {
		rangeCount++
		if rangeCount > MaxNACKRangesPerACK {
			return nil, nil, oops.
				Code("ACK_TOO_MANY_RANGES").
				In("ssu2.reliability").
				Errorf("ACK block contains too many NACK/ACK ranges: %d (max %d)",
					rangeCount, MaxNACKRangesPerACK)
		}

		nacks := int64(data[offset])  // raw nack count per ssu2.rst
		acks := int64(data[offset+1]) // raw ack count per ssu2.rst
		offset += 2

		if nacks == 0 && acks == 0 {
			return nil, nil, oops.Errorf("ACK range with both nack and ack counts zero (forbidden by ssu2.rst)")
		}

		// Skip the gap (nacked packets) — check for underflow. The gap is
		// recorded as well as skipped: those packet numbers are what the peer
		// told us it did not get.
		//
		// A cursor of N means N+1 numbers are still available at or below it
		// (N, N-1, … 0), which is why the bound is cursor+1 rather than cursor:
		// a run that ends exactly at packet 0 is legal, e.g. the ssu2.md example
		// "ack 2 1 0" reached by a range that finishes the bitfield.
		if nacks > cursor+1 {
			return nil, nil, oops.Errorf("ACK nack range (%d) exceeds cursor (%d)", nacks, cursor)
		}
		for i := int64(0); i < nacks; i++ {
			nackedPackets = append(nackedPackets, uint32(cursor-i))
		}
		cursor -= nacks
		if cursor < 0 {
			// The bitfield ran down to packet 0. Nothing is left below it, so a
			// nonzero ack run here is malformed.
			if acks > 0 {
				return nil, nil, oops.Errorf("ACK ack range (%d) below packet 0", acks)
			}
			break
		}

		// Collect the ack run — check for underflow
		if acks > cursor+1 {
			return nil, nil, oops.Errorf("ACK ack range (%d) exceeds remaining cursor (%d)", acks, cursor)
		}
		for i := int64(0); i < acks; i++ {
			ackedPackets = append(ackedPackets, uint32(cursor))
			delete(h.pendingACKs, uint32(cursor))
			cursor--
		}
		// cursor reaches -1 once packet 0 has been acknowledged. No packet
		// numbers remain below it, so any further ranges cannot be meaningful
		// (matches ssu2.rst, where ranges stop once the lowest PN is covered).
		if cursor < 0 {
			break
		}
	}

	return ackedPackets, nackedPackets, nil
}

// AddPending marks a packet as sent and awaiting acknowledgment. If the
// pending map is at capacity (maxPendingACKs), the oldest pending entry (by
// SentTime) is evicted first, as defense-in-depth independent of the
// congestion controller that normally bounds outstanding sends.
func (h *ACKHandler) AddPending(packetNum uint32) {
	flog("AddPending", logger.Fields{"packetNum": packetNum}).Debug("AddPending: marking packet as pending ACK")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.pendingACKs) >= maxPendingACKs {
		evictedKey, _, evicted := eviction.EvictOldestByTime(h.pendingACKs, func(p *PendingACK) time.Time { return p.SentTime })
		if evicted {
			flog("AddPending", logger.Fields{"packetNum": packetNum, "evicted": evictedKey, "cap": maxPendingACKs}).Warn("AddPending: pendingACKs at capacity, evicting oldest entry")
		}
	}
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
