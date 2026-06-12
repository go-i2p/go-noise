package ssu2

import (
	"sync"
	"testing"
	"time"
)

// TestNewReceiveWindow verifies window initialization.
func TestNewReceiveWindow(t *testing.T) {
	tests := []struct {
		name         string
		expected     uint32
		maxSize      uint
		wantMaxSize  int
		wantExpected uint32
	}{
		{
			name:         "valid parameters",
			expected:     1000,
			maxSize:      100,
			wantMaxSize:  100,
			wantExpected: 1000,
		},
		{
			name:         "zero expected",
			expected:     0,
			maxSize:      50,
			wantMaxSize:  50,
			wantExpected: 0,
		},
		{
			name:         "max uint32 expected",
			expected:     MaxPacketNumber,
			maxSize:      200,
			wantMaxSize:  200,
			wantExpected: MaxPacketNumber,
		},
		{
			name:         "zero maxSize uses default",
			expected:     100,
			maxSize:      0,
			wantMaxSize:  DefaultMaxWindowSize,
			wantExpected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := NewReceiveWindow(tt.expected, tt.maxSize)

			if rw == nil {
				t.Fatal("NewReceiveWindow returned nil")
			}

			if rw.GetExpected() != tt.wantExpected {
				t.Errorf("expected = %d, want %d", rw.GetExpected(), tt.wantExpected)
			}

			if rw.GetMaxSize() != tt.wantMaxSize {
				t.Errorf("maxSize = %d, want %d", rw.GetMaxSize(), tt.wantMaxSize)
			}

			if rw.GetWindowSize() != 0 {
				t.Errorf("initial window size = %d, want 0", rw.GetWindowSize())
			}

			if rw.HasGaps() {
				t.Error("new window should not have gaps")
			}
		})
	}
}

// TestReceiveWindow_InsertExpected verifies inserting the expected packet.
func TestReceiveWindow_InsertExpected(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	packet := &SSU2Packet{
		PacketNumber: 1000,
		Timestamp:    time.Now(),
	}

	ready, err := rw.Insert(packet)
	if err != nil {
		t.Fatalf("Insert() error = %v, want nil", err)
	}

	if len(ready) != 1 {
		t.Fatalf("ready packets = %d, want 1", len(ready))
	}

	if ready[0].PacketNumber != 1000 {
		t.Errorf("ready[0].PacketNumber = %d, want 1000", ready[0].PacketNumber)
	}

	if rw.GetExpected() != 1001 {
		t.Errorf("expected = %d, want 1001", rw.GetExpected())
	}

	if rw.GetWindowSize() != 0 {
		t.Errorf("window size = %d, want 0", rw.GetWindowSize())
	}
}

// TestReceiveWindow_InsertFuture verifies buffering future packets.
func TestReceiveWindow_InsertFuture(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	packet := &SSU2Packet{
		PacketNumber: 1005,
		Timestamp:    time.Now(),
	}

	ready, err := rw.Insert(packet)
	if err != nil {
		t.Fatalf("Insert() error = %v, want nil", err)
	}

	if len(ready) != 0 {
		t.Errorf("ready packets = %d, want 0 (buffered)", len(ready))
	}

	if rw.GetExpected() != 1000 {
		t.Errorf("expected = %d, want 1000 (unchanged)", rw.GetExpected())
	}

	if rw.GetWindowSize() != 1 {
		t.Errorf("window size = %d, want 1", rw.GetWindowSize())
	}

	if !rw.HasGaps() {
		t.Error("window should have gaps after buffering future packet")
	}
}

// TestReceiveWindow_InsertOld verifies rejecting old packets.
func TestReceiveWindow_InsertOld(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	packet := &SSU2Packet{
		PacketNumber: 999,
		Timestamp:    time.Now(),
	}

	ready, err := rw.Insert(packet)

	if err == nil {
		t.Fatal("Insert() error = nil, want error for old packet")
	}

	if len(ready) != 0 {
		t.Errorf("ready packets = %d, want 0", len(ready))
	}

	if rw.GetExpected() != 1000 {
		t.Errorf("expected = %d, want 1000 (unchanged)", rw.GetExpected())
	}
}

// TestReceiveWindow_InsertDuplicate verifies rejecting duplicate packets.
func TestReceiveWindow_InsertDuplicate(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Insert first packet
	packet1 := &SSU2Packet{
		PacketNumber: 1000,
		Timestamp:    time.Now(),
	}
	_, _ = rw.Insert(packet1)

	// Try duplicate
	packet2 := &SSU2Packet{
		PacketNumber: 1000,
		Timestamp:    time.Now(),
	}

	ready, err := rw.Insert(packet2)

	if err == nil {
		t.Fatal("Insert() error = nil, want error for duplicate")
	}

	if len(ready) != 0 {
		t.Errorf("ready packets = %d, want 0", len(ready))
	}
}

// TestReceiveWindow_InsertDuplicateFuture verifies rejecting duplicate future packets.
func TestReceiveWindow_InsertDuplicateFuture(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer future packet
	packet1 := &SSU2Packet{
		PacketNumber: 1005,
		Timestamp:    time.Now(),
	}
	_, _ = rw.Insert(packet1)

	// Try duplicate future packet
	packet2 := &SSU2Packet{
		PacketNumber: 1005,
		Timestamp:    time.Now(),
	}

	ready, err := rw.Insert(packet2)

	if err == nil {
		t.Fatal("Insert() error = nil, want error for duplicate future packet")
	}

	if len(ready) != 0 {
		t.Errorf("ready packets = %d, want 0", len(ready))
	}

	if rw.GetWindowSize() != 1 {
		t.Errorf("window size = %d, want 1 (no change)", rw.GetWindowSize())
	}
}

// TestReceiveWindow_InsertNil verifies rejecting nil packets.
func TestReceiveWindow_InsertNil(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	ready, err := rw.Insert(nil)

	if err == nil {
		t.Fatal("Insert(nil) error = nil, want error")
	}

	if ready != nil {
		t.Errorf("Insert(nil) ready = %v, want nil", ready)
	}
}

// TestReceiveWindow_SequentialPackets verifies processing in-order packets.
func TestReceiveWindow_SequentialPackets(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for i := uint32(1000); i < 1010; i++ {
		packet := &SSU2Packet{
			PacketNumber: i,
			Timestamp:    time.Now(),
		}

		ready, err := rw.Insert(packet)
		if err != nil {
			t.Fatalf("Insert(%d) error = %v, want nil", i, err)
		}

		if len(ready) != 1 {
			t.Errorf("Insert(%d) ready packets = %d, want 1", i, len(ready))
		}

		if ready[0].PacketNumber != i {
			t.Errorf("ready[0].PacketNumber = %d, want %d", ready[0].PacketNumber, i)
		}
	}

	if rw.GetExpected() != 1010 {
		t.Errorf("expected = %d, want 1010", rw.GetExpected())
	}

	if rw.GetWindowSize() != 0 {
		t.Errorf("window size = %d, want 0", rw.GetWindowSize())
	}
}

// TestReceiveWindow_OutOfOrderRelease verifies releasing buffered packets in order.
func TestReceiveWindow_OutOfOrderRelease(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer packets out of order: 1002, 1001, 1003
	packets := []*SSU2Packet{
		{PacketNumber: 1002},
		{PacketNumber: 1001},
		{PacketNumber: 1003},
	}

	for _, pkt := range packets {
		ready, err := rw.Insert(pkt)
		if err != nil {
			t.Fatalf("Insert(%d) error = %v", pkt.PacketNumber, err)
		}
		if len(ready) != 0 {
			t.Errorf("Insert(%d) should buffer, got %d ready", pkt.PacketNumber, len(ready))
		}
	}

	if rw.GetWindowSize() != 3 {
		t.Fatalf("window size = %d, want 3", rw.GetWindowSize())
	}

	// Insert missing packet 1000, should release all
	packet := &SSU2Packet{PacketNumber: 1000}
	ready, err := rw.Insert(packet)
	if err != nil {
		t.Fatalf("Insert(1000) error = %v, want nil", err)
	}

	if len(ready) != 4 {
		t.Fatalf("ready packets = %d, want 4", len(ready))
	}

	// Verify order: 1000, 1001, 1002, 1003
	expectedOrder := []uint32{1000, 1001, 1002, 1003}
	for i, pktNum := range expectedOrder {
		if ready[i].PacketNumber != pktNum {
			t.Errorf("ready[%d].PacketNumber = %d, want %d", i, ready[i].PacketNumber, pktNum)
		}
	}

	if rw.GetExpected() != 1004 {
		t.Errorf("expected = %d, want 1004", rw.GetExpected())
	}

	if rw.GetWindowSize() != 0 {
		t.Errorf("window size = %d, want 0 (all released)", rw.GetWindowSize())
	}
}

// TestReceiveWindow_PartialGapFill verifies partial gap filling.
func TestReceiveWindow_PartialGapFill(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer 1001, 1002, 1005
	for _, pktNum := range []uint32{1001, 1002, 1005} {
		pkt := &SSU2Packet{PacketNumber: pktNum}
		_, _ = rw.Insert(pkt)
	}

	// Insert 1000, should release 1000, 1001, 1002 (stop at gap before 1005)
	packet := &SSU2Packet{PacketNumber: 1000}
	ready, err := rw.Insert(packet)
	if err != nil {
		t.Fatalf("Insert(1000) error = %v", err)
	}

	if len(ready) != 3 {
		t.Fatalf("ready packets = %d, want 3", len(ready))
	}

	// Verify released: 1000, 1001, 1002
	for i, expected := range []uint32{1000, 1001, 1002} {
		if ready[i].PacketNumber != expected {
			t.Errorf("ready[%d].PacketNumber = %d, want %d", i, ready[i].PacketNumber, expected)
		}
	}

	if rw.GetExpected() != 1003 {
		t.Errorf("expected = %d, want 1003", rw.GetExpected())
	}

	if rw.GetWindowSize() != 1 {
		t.Errorf("window size = %d, want 1 (1005 still buffered)", rw.GetWindowSize())
	}
}

// TestReceiveWindow_WindowFull verifies window size limit enforcement.
func TestReceiveWindow_WindowFull(t *testing.T) {
	maxSize := uint(10)
	rw := NewReceiveWindow(1000, maxSize)

	// Fill window with future packets
	for i := uint32(1001); i < 1001+uint32(maxSize); i++ {
		pkt := &SSU2Packet{PacketNumber: i}
		_, err := rw.Insert(pkt)
		if err != nil {
			t.Fatalf("Insert(%d) error = %v, want nil", i, err)
		}
	}

	if rw.GetWindowSize() != int(maxSize) {
		t.Fatalf("window size = %d, want %d", rw.GetWindowSize(), maxSize)
	}

	// Try to insert one more (should fail)
	pkt := &SSU2Packet{PacketNumber: 1001 + uint32(maxSize)}
	ready, err := rw.Insert(pkt)

	if err == nil {
		t.Fatal("Insert() error = nil, want error for full window")
	}

	if len(ready) != 0 {
		t.Errorf("ready packets = %d, want 0", len(ready))
	}

	if rw.GetWindowSize() != int(maxSize) {
		t.Errorf("window size = %d, want %d (unchanged)", rw.GetWindowSize(), maxSize)
	}
}

// TestReceiveWindow_Clear verifies window clearing.
func TestReceiveWindow_Clear(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer some packets
	for i := uint32(1005); i < 1010; i++ {
		pkt := &SSU2Packet{PacketNumber: i}
		_, _ = rw.Insert(pkt)
	}

	if rw.GetWindowSize() != 5 {
		t.Fatalf("window size = %d, want 5", rw.GetWindowSize())
	}

	// Clear to new expected
	rw.Clear(2000)

	if rw.GetExpected() != 2000 {
		t.Errorf("expected = %d, want 2000", rw.GetExpected())
	}

	if rw.GetWindowSize() != 0 {
		t.Errorf("window size = %d, want 0 (cleared)", rw.GetWindowSize())
	}

	if rw.HasGaps() {
		t.Error("cleared window should not have gaps")
	}
}

// TestReceiveWindow_SetExpected verifies updating expected packet number.
func TestReceiveWindow_SetExpected(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer some packets: 1005, 1006, 1007
	for i := uint32(1005); i < 1008; i++ {
		pkt := &SSU2Packet{PacketNumber: i}
		_, _ = rw.Insert(pkt)
	}

	// Set expected to 1006 (discard 1005, keep 1006, 1007)
	rw.SetExpected(1006)

	if rw.GetExpected() != 1006 {
		t.Errorf("expected = %d, want 1006", rw.GetExpected())
	}

	if rw.GetWindowSize() != 2 {
		t.Errorf("window size = %d, want 2 (1006, 1007)", rw.GetWindowSize())
	}

	// Packet 1006 is still buffered, trying to insert it again should fail
	pkt := &SSU2Packet{PacketNumber: 1006}
	ready, err := rw.Insert(pkt)
	if err == nil {
		t.Error("Insert(1006) should fail (duplicate of buffered packet)")
	}
	if len(ready) != 0 {
		t.Errorf("ready = %d, want 0", len(ready))
	}

	// Window state should be unchanged
	if rw.GetWindowSize() != 2 {
		t.Errorf("window size after dup = %d, want 2 (unchanged)", rw.GetWindowSize())
	}
}

// TestReceiveWindow_GetGapInfo verifies gap diagnostics.
func TestReceiveWindow_GetGapInfo(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// No gaps initially
	min, max, count := rw.GetGapInfo()
	if min != 0 || max != 0 || count != 0 {
		t.Errorf("empty window gap info = (%d, %d, %d), want (0, 0, 0)", min, max, count)
	}

	// Buffer packets: 1005, 1007, 1010
	for _, pktNum := range []uint32{1005, 1007, 1010} {
		pkt := &SSU2Packet{PacketNumber: pktNum}
		_, _ = rw.Insert(pkt)
	}

	min, max, count = rw.GetGapInfo()
	if min != 1005 || max != 1010 || count != 3 {
		t.Errorf("gap info = (%d, %d, %d), want (1005, 1010, 3)", min, max, count)
	}
}

// TestReceiveWindow_Concurrency verifies thread-safety.
func TestReceiveWindow_Concurrency(t *testing.T) {
	rw := NewReceiveWindow(0, 1000)

	const numGoroutines = 100
	const packetsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent inserts
	for i := 0; i < numGoroutines; i++ {
		go func(offset int) {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				pktNum := uint32(offset*packetsPerGoroutine + j)
				pkt := &SSU2Packet{
					PacketNumber: pktNum,
					Timestamp:    time.Now(),
				}
				_, _ = rw.Insert(pkt) // Ignore errors (duplicates expected)
			}
		}(i)
	}

	wg.Wait()

	// Verify final state is consistent
	expected := rw.GetExpected()
	windowSize := rw.GetWindowSize()

	t.Logf("After concurrent inserts: expected=%d, windowSize=%d", expected, windowSize)

	// Expected should have advanced
	if expected == 0 {
		t.Error("expected = 0, should have advanced")
	}

	// Total packets = expected + windowSize should be reasonable
	totalProcessed := int(expected) + windowSize
	if totalProcessed > numGoroutines*packetsPerGoroutine {
		t.Errorf("totalProcessed = %d > max possible %d", totalProcessed, numGoroutines*packetsPerGoroutine)
	}
}

// TestReceiveWindow_ConcurrentReads verifies concurrent read operations.
func TestReceiveWindow_ConcurrentReads(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// Buffer some packets
	for i := uint32(1005); i < 1010; i++ {
		pkt := &SSU2Packet{PacketNumber: i}
		_, _ = rw.Insert(pkt)
	}

	const numReaders = 50
	const readsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numReaders)

	// Concurrent reads
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < readsPerGoroutine; j++ {
				_ = rw.GetExpected()
				_ = rw.GetWindowSize()
				_ = rw.HasGaps()
				_, _, _ = rw.GetGapInfo()
			}
		}()
	}

	wg.Wait()

	// Verify state unchanged
	if rw.GetExpected() != 1000 {
		t.Errorf("expected = %d, want 1000 (reads should not modify)", rw.GetExpected())
	}

	if rw.GetWindowSize() != 5 {
		t.Errorf("window size = %d, want 5 (reads should not modify)", rw.GetWindowSize())
	}
}

// BenchmarkReceiveWindow_Insert measures insertion performance.
func BenchmarkReceiveWindow_Insert(b *testing.B) {
	rw := NewReceiveWindow(0, 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &SSU2Packet{
			PacketNumber: uint32(i),
			Timestamp:    time.Now(),
		}
		_, _ = rw.Insert(pkt)
	}
}

// BenchmarkReceiveWindow_InsertOutOfOrder measures out-of-order insertion.
func BenchmarkReceiveWindow_InsertOutOfOrder(b *testing.B) {
	rw := NewReceiveWindow(0, 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Insert every other packet (creates gaps)
		pkt := &SSU2Packet{
			PacketNumber: uint32(i * 2),
			Timestamp:    time.Now(),
		}
		_, _ = rw.Insert(pkt)
	}
}

// BenchmarkReceiveWindow_GetExpected measures read performance.
func BenchmarkReceiveWindow_GetExpected(b *testing.B) {
	rw := NewReceiveWindow(1000, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rw.GetExpected()
	}
}

// BenchmarkReceiveWindow_Concurrent measures concurrent access performance.
func BenchmarkReceiveWindow_Concurrent(b *testing.B) {
	rw := NewReceiveWindow(0, 100000)

	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			pkt := &SSU2Packet{
				PacketNumber: i,
				Timestamp:    time.Now(),
			}
			_, _ = rw.Insert(pkt)
			i++
		}
	})
}
