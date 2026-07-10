package reliability

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewACKHandler tests ACK handler creation
func TestNewACKHandler(t *testing.T) {
	handler := NewACKHandler()

	assert.NotNil(t, handler)
	assert.Empty(t, handler.receivedPackets)
	assert.Empty(t, handler.pendingACKs)
	assert.Equal(t, 10*time.Millisecond, handler.ackDelay)
	assert.False(t, handler.HasPending())
}

// TestACKHandler_RecordReceived tests recording received packets
func TestACKHandler_RecordReceived(t *testing.T) {
	handler := NewACKHandler()

	handler.RecordReceived(100)
	handler.RecordReceived(101)
	handler.RecordReceived(102)

	assert.Len(t, handler.receivedPackets, 3)
	assert.Contains(t, handler.receivedPackets, uint32(100))
	assert.Contains(t, handler.receivedPackets, uint32(101))
	assert.Contains(t, handler.receivedPackets, uint32(102))
}

// TestACKHandler_RecordReceived_BoundedGrowth is the regression test for the
// AUDIT.md MEDIUM finding: receivedPackets must not grow past
// maxReceivedPackets even when the caller never drains it via
// ShouldSendACK/GenerateACK, guarding against unbounded memory growth
// combined with SortDescDedupPackets's O(n^2) drain cost.
func TestACKHandler_RecordReceived_BoundedGrowth(t *testing.T) {
	handler := NewACKHandler()

	for i := 0; i < maxReceivedPackets+1000; i++ {
		handler.RecordReceived(uint32(i))
	}

	assert.LessOrEqual(t, len(handler.receivedPackets), maxReceivedPackets,
		"receivedPackets must never exceed maxReceivedPackets (%d), got %d", maxReceivedPackets, len(handler.receivedPackets))
	assert.Equal(t, maxReceivedPackets, len(handler.receivedPackets),
		"expected receivedPackets to fill exactly to the cap")
}

// TestACKHandler_ShouldSendACK tests ACK sending decision
func TestACKHandler_ShouldSendACK(t *testing.T) {
	tests := []struct {
		name             string
		packets          []uint32
		rtt              time.Duration
		timeSinceLastACK time.Duration
		want             bool
	}{
		{
			name:    "no packets",
			packets: []uint32{},
			rtt:     100 * time.Millisecond,
			want:    false,
		},
		{
			name:             "delay not elapsed",
			packets:          []uint32{1, 2, 3},
			rtt:              100 * time.Millisecond,
			timeSinceLastACK: 5 * time.Millisecond,
			want:             false,
		},
		{
			name:             "delay elapsed",
			packets:          []uint32{1, 2, 3},
			rtt:              60 * time.Millisecond,
			timeSinceLastACK: 11 * time.Millisecond,
			want:             true,
		},
		{
			name:    "many packets",
			packets: make([]uint32, 15), // 15 packets triggers immediate ACK
			rtt:     100 * time.Millisecond,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			for _, pkt := range tt.packets {
				handler.RecordReceived(pkt)
			}

			if tt.timeSinceLastACK > 0 {
				handler.lastACKTime = time.Now().Add(-tt.timeSinceLastACK)
			}

			got := handler.ShouldSendACK(tt.rtt)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestACKHandler_ShouldSendACK_DelayCalculation tests dynamic ACK delay
func TestACKHandler_ShouldSendACK_DelayCalculation(t *testing.T) {
	tests := []struct {
		name      string
		rtt       time.Duration
		wantDelay time.Duration
	}{
		{
			name:      "low RTT - capped at 10ms",
			rtt:       30 * time.Millisecond,
			wantDelay: 10 * time.Millisecond,
		},
		{
			name:      "medium RTT",
			rtt:       120 * time.Millisecond,
			wantDelay: 20 * time.Millisecond, // 120/6 = 20
		},
		{
			name:      "high RTT - capped at 150ms",
			rtt:       2000 * time.Millisecond,
			wantDelay: 150 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			handler.RecordReceived(1)
			handler.lastACKTime = time.Now().Add(-200 * time.Millisecond)

			handler.ShouldSendACK(tt.rtt)
			assert.Equal(t, tt.wantDelay, handler.ackDelay)
		})
	}
}

// TestACKHandler_GenerateACK tests ACK block generation
func TestACKHandler_GenerateACK(t *testing.T) {
	tests := []struct {
		name          string
		packets       []uint32
		wantNil       bool
		wantThroughPN uint32
		wantAcnt      uint8
		wantDataLen   int // total expected data length
	}{
		{
			name:    "no packets",
			packets: []uint32{},
			wantNil: true,
		},
		{
			name:          "single packet",
			packets:       []uint32{100},
			wantThroughPN: 100,
			wantAcnt:      0,
			wantDataLen:   5, // header only, no ranges
		},
		{
			name:          "contiguous range",
			packets:       []uint32{100, 101, 102, 103},
			wantThroughPN: 103,
			wantAcnt:      3,
			wantDataLen:   5,
		},
		{
			name:          "two separate ranges",
			packets:       []uint32{100, 101, 105, 106, 110},
			wantThroughPN: 110,
			wantAcnt:      0, // only 110 in top run
			wantDataLen:   9, // 5 header + 2 range pairs
		},
		{
			name:          "out of order",
			packets:       []uint32{105, 100, 102, 101, 103},
			wantThroughPN: 105,
			wantAcnt:      0, // 105 alone at the top
			wantDataLen:   7, // 5 header + 1 range pair (gap=1, ack-run=100-103)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			for _, pkt := range tt.packets {
				handler.RecordReceived(pkt)
			}

			block, err := handler.GenerateACK()
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, block)
				return
			}

			require.NotNil(t, block)
			assert.Equal(t, BlockTypeACK, block.Type)
			assert.GreaterOrEqual(t, len(block.Data), 5)

			// Verify through-PN and acnt
			throughPN := binary.BigEndian.Uint32(block.Data[0:4])
			assert.Equal(t, tt.wantThroughPN, throughPN)
			assert.Equal(t, tt.wantAcnt, block.Data[4])
			assert.Equal(t, tt.wantDataLen, len(block.Data))

			// Verify received packets cleared
			assert.Empty(t, handler.receivedPackets)
		})
	}
}

// TestACKHandler_GenerateACK_Format tests ACK block data format per SSU2 spec
func TestACKHandler_GenerateACK_Format(t *testing.T) {
	handler := NewACKHandler()
	handler.RecordReceived(100)
	handler.RecordReceived(101)
	handler.RecordReceived(102)

	block, err := handler.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, block)

	data := block.Data
	require.Len(t, data, 5) // contiguous run: header only, no range pairs

	// Bytes 0-3: Through PN = 102
	throughPN := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(102), throughPN)

	// Byte 4: acnt = 2 (3 packets minus 1)
	assert.Equal(t, uint8(2), data[4])
}

// TestACKHandler_ProcessACK tests processing incoming ACK blocks
func TestACKHandler_ProcessACK(t *testing.T) {
	tests := []struct {
		name        string
		createBlock func() *SSU2Block
		wantPackets []uint32
		wantError   bool
	}{
		{
			name: "contiguous range only",
			createBlock: func() *SSU2Block {
				// Through PN = 102, acnt = 2 → acks 102, 101, 100
				data := make([]byte, 5)
				binary.BigEndian.PutUint32(data[0:4], 102)
				data[4] = 2
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantPackets: []uint32{102, 101, 100},
		},
		{
			name: "with one nack/ack range",
			createBlock: func() *SSU2Block {
				// Through PN = 106, acnt = 1 (106, 105)
				// Range: nacks=2 (gap of 2: 104,103), acks=3 (3 acked: 102,101,100)
				// SSU2 spec: values stored minus 1
				data := make([]byte, 7)
				binary.BigEndian.PutUint32(data[0:4], 106)
				data[4] = 1 // acnt (2-1=1)
				data[5] = 1 // nacks minus 1 (2-1=1)
				data[6] = 2 // acks minus 1 (3-1=2)
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantPackets: []uint32{106, 105, 102, 101, 100},
		},
		{
			name: "single packet ack",
			createBlock: func() *SSU2Block {
				// Through PN = 50, acnt = 0 → only packet 50
				data := make([]byte, 5)
				binary.BigEndian.PutUint32(data[0:4], 50)
				data[4] = 0
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantPackets: []uint32{50},
		},
		{
			name: "wrong block type",
			createBlock: func() *SSU2Block {
				return NewSSU2Block(BlockTypePadding, []byte{1, 2, 3, 4, 5})
			},
			wantError: true,
		},
		{
			name: "too short",
			createBlock: func() *SSU2Block {
				return NewSSU2Block(BlockTypeACK, []byte{1, 2, 3}) // Only 3 bytes
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			block := tt.createBlock()

			packets, err := handler.ProcessACK(block)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantPackets, packets)
		})
	}
}

// TestACKHandler_AddPending tests adding pending ACKs
func TestACKHandler_AddPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)

	assert.True(t, handler.HasPending())
	assert.Len(t, handler.pendingACKs, 3)

	pending, exists := handler.GetPendingPacket(100)
	assert.True(t, exists)
	assert.Equal(t, uint32(100), pending.PacketNumber)
	assert.Equal(t, 0, pending.Retries)
	assert.WithinDuration(t, time.Now(), pending.SentTime, time.Second)
}

// TestACKHandler_AddPending_BoundedGrowth is the regression test for the
// AUDIT.md LOW finding: pendingACKs must not grow past maxPendingACKs even
// when the caller keeps adding new pending entries without any being
// acknowledged, evicting the oldest entry first as defense-in-depth.
func TestACKHandler_AddPending_BoundedGrowth(t *testing.T) {
	handler := NewACKHandler()

	for i := 0; i < maxPendingACKs+500; i++ {
		handler.AddPending(uint32(i))
	}

	assert.LessOrEqual(t, len(handler.pendingACKs), maxPendingACKs,
		"pendingACKs must never exceed maxPendingACKs (%d), got %d", maxPendingACKs, len(handler.pendingACKs))

	// The oldest entries (packet 0) should have been evicted; the most
	// recently added entry must still be present.
	_, oldestStillPresent := handler.GetPendingPacket(0)
	assert.False(t, oldestStillPresent, "expected oldest pending entry to be evicted")

	_, newestPresent := handler.GetPendingPacket(uint32(maxPendingACKs + 499))
	assert.True(t, newestPresent, "expected most recently added pending entry to still be present")
}

// TestACKHandler_GetPending tests retrieving pending packet list
func TestACKHandler_GetPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)

	pending := handler.GetPending()
	assert.Len(t, pending, 3)
	assert.Contains(t, pending, uint32(100))
	assert.Contains(t, pending, uint32(101))
	assert.Contains(t, pending, uint32(102))
}

// TestACKHandler_ProcessACK_RemovesPending tests ACK processing removes pending
func TestACKHandler_ProcessACK_RemovesPending(t *testing.T) {
	handler := NewACKHandler()

	// Add pending packets
	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)
	handler.AddPending(200)

	assert.Len(t, handler.pendingACKs, 4)

	// Create ACK for packets 100-102 (through PN = 102, acnt = 2)
	data := make([]byte, 5)
	binary.BigEndian.PutUint32(data[0:4], 102)
	data[4] = 2
	block := NewSSU2Block(BlockTypeACK, data)

	_, err := handler.ProcessACK(block)
	require.NoError(t, err)

	// Packets 100-102 should be removed, 200 should remain
	assert.Len(t, handler.pendingACKs, 1)
	_, exists := handler.GetPendingPacket(200)
	assert.True(t, exists)
	_, exists = handler.GetPendingPacket(100)
	assert.False(t, exists)
}

// TestACKHandler_ClearPending tests clearing all pending ACKs
func TestACKHandler_ClearPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.RecordReceived(200)
	handler.RecordReceived(201)

	assert.True(t, handler.HasPending())
	assert.NotEmpty(t, handler.receivedPackets)

	handler.ClearPending()

	assert.False(t, handler.HasPending())
	assert.Empty(t, handler.receivedPackets)
	assert.Empty(t, handler.pendingACKs)
}

// TestACKHandler_RoundTrip tests full ACK cycle
func TestACKHandler_RoundTrip(t *testing.T) {
	sender := NewACKHandler()
	receiver := NewACKHandler()

	// Sender sends packets 100-102
	sender.AddPending(100)
	sender.AddPending(101)
	sender.AddPending(102)

	// Receiver records receiving them
	receiver.RecordReceived(100)
	receiver.RecordReceived(101)
	receiver.RecordReceived(102)

	// Receiver generates ACK
	ackBlock, err := receiver.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, ackBlock)

	// Sender processes ACK
	ackedPackets, err := sender.ProcessACK(ackBlock)
	require.NoError(t, err)

	// Verify all packets acknowledged
	assert.ElementsMatch(t, []uint32{100, 101, 102}, ackedPackets)
	assert.False(t, sender.HasPending())
}

// TestSortDescDedupPackets tests the sort/dedup helper
func TestSortDescDedupPackets(t *testing.T) {
	tests := []struct {
		name    string
		packets []uint32
		want    []uint32
	}{
		{
			name:    "empty",
			packets: []uint32{},
			want:    nil,
		},
		{
			name:    "single packet",
			packets: []uint32{100},
			want:    []uint32{100},
		},
		{
			name:    "already sorted descending",
			packets: []uint32{103, 102, 101, 100},
			want:    []uint32{103, 102, 101, 100},
		},
		{
			name:    "ascending needs reversal",
			packets: []uint32{100, 101, 105, 106},
			want:    []uint32{106, 105, 101, 100},
		},
		{
			name:    "with duplicates",
			packets: []uint32{105, 100, 102, 100, 105, 101, 103},
			want:    []uint32{105, 103, 102, 101, 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortDescDedupPackets(tt.packets)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestACKHandler_GenerateACK_MinimalBlock tests that a single-packet ACK
// produces a valid 5-byte block.
func TestACKHandler_GenerateACK_MinimalBlock(t *testing.T) {
	handler := NewACKHandler()
	handler.RecordReceived(42)

	block, err := handler.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, block)

	data := block.Data
	require.Len(t, data, 5)

	throughPN := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(42), throughPN)
	assert.Equal(t, uint8(0), data[4]) // acnt = 0 → only throughPN
}

// Benchmark tests
func BenchmarkACKHandler_RecordReceived(b *testing.B) {
	handler := NewACKHandler()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.RecordReceived(uint32(i))
	}
}

func BenchmarkACKHandler_GenerateACK(b *testing.B) {
	handler := NewACKHandler()
	for i := 0; i < 10; i++ {
		handler.RecordReceived(uint32(i * 10))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.GenerateACK()
		// Re-add packets for next iteration
		for j := 0; j < 10; j++ {
			handler.RecordReceived(uint32(j * 10))
		}
	}
}

func BenchmarkACKHandler_ProcessACK(b *testing.B) {
	// Create ACK block: Through PN = 110, acnt = 10 (packets 100-110)
	data := make([]byte, 5)
	binary.BigEndian.PutUint32(data[0:4], 110)
	data[4] = 10
	block := NewSSU2Block(BlockTypeACK, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler := NewACKHandler()
		for j := uint32(100); j <= 110; j++ {
			handler.AddPending(j)
		}
		_, _ = handler.ProcessACK(block)
	}
}

func BenchmarkSortDescDedupPackets(b *testing.B) {
	packets := make([]uint32, 100)
	for i := 0; i < 100; i++ {
		packets[i] = uint32(i * 2) // Create gaps
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SortDescDedupPackets(packets)
	}
}

// FuzzProcessACK fuzzes the ACK block parsing to detect cursor underflow and other
// parsing bugs. This addresses AUDIT H-7.
func FuzzProcessACK(f *testing.F) {
	// Seed with valid ACK block
	seed := make([]byte, 9)
	binary.BigEndian.PutUint32(seed[0:4], 100) // throughPN
	seed[4] = 5                                // acnt (6 packets: 100-95)
	seed[5] = 2                                // nacks-1
	seed[6] = 3                                // acks-1
	seed[7] = 1                                // nacks-1
	seed[8] = 0                                // acks-1
	f.Add(seed)

	// Seed with edge cases
	f.Add([]byte{0, 0, 0, 10, 0})            // Minimal valid ACK
	f.Add([]byte{0, 0, 0, 0, 0})             // throughPN=0, acnt=0
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0}) // Max throughPN
	f.Add([]byte{0, 0, 0, 100, 99})          // acnt=99, near throughPN

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 {
			return // Too short to be valid
		}

		handler := NewACKHandler()

		// Add some pending packets
		for i := uint32(0); i < 200; i++ {
			handler.AddPending(i)
		}

		block := &SSU2Block{
			Type: BlockTypeACK,
			Data: data,
		}

		// ProcessACK should never panic, even with malformed input
		_, err := handler.ProcessACK(block)
		// We expect an error for most fuzzed inputs, but no panic
		if err != nil {
			// Verify error message doesn't expose internal panic
			_ = err.Error()
		}
	})
}

// TestACKHandler_BurstACKAmplification tests that ACK generation respects minACKInterval
// to prevent ACK amplification under bursty traffic (M-6 audit finding).
func TestACKHandler_BurstACKAmplification(t *testing.T) {
	handler := NewACKHandler()
	handler.SetACKThreshold(2) // Low threshold to trigger easily

	const rtt = 100 * time.Millisecond
	const burstSize = 50
	const burstInterval = 1 * time.Millisecond // Very fast bursts

	acksGenerated := 0

	// Send packets in rapid bursts
	for burst := 0; burst < 10; burst++ {
		// Send a burst of packets
		for i := 0; i < burstSize; i++ {
			packetNum := uint32(burst*burstSize + i)
			handler.RecordReceived(packetNum)

			// Check if we should ACK after each packet
			if handler.ShouldSendACK(rtt) {
				ack, err := handler.GenerateACK()
				require.NoError(t, err)
				if ack != nil {
					acksGenerated++
				}
			}
		}

		// Small delay between bursts (less than minACKInterval)
		time.Sleep(burstInterval)
	}

	// Verify that minACKInterval prevented excessive ACKs
	// Without the fix, we'd generate ~250 ACKs (5 bursts * 50 packets / threshold of 2)
	// With the fix and minACKInterval=5ms, and bursts every 1ms, we should get far fewer
	maxExpectedACKs := 30 // Conservative upper bound
	assert.LessOrEqual(t, acksGenerated, maxExpectedACKs,
		"Generated %d ACKs under burst load; minACKInterval should limit amplification", acksGenerated)

	// Should still generate some ACKs (not zero)
	assert.Greater(t, acksGenerated, 0, "Should generate at least some ACKs")
}
