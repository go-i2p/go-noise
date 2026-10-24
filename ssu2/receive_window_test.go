package ssu2

import (
	"sync"
	"testing"
	"time"
)

// These tests cover the SSU2 inbound packet-number filter.
//
// ssu2.rst §"Delivery Guarantees" is explicit that SSU2 "does NOT provide
// in-order delivery of I2NP messages", so the filter must deliver every new
// packet immediately and must never hold one back waiting for a gap. Its only
// job is bounded duplicate detection, from §"Packet Numbering": "The data
// required for detecting duplicates can be limited by maintaining a minimum
// packet number below which all packets are immediately dropped."

// newTestPacket builds a packet with the given number.
func newTestPacket(pktNum uint32) *SSU2Packet {
	return &SSU2Packet{PacketNumber: pktNum, Timestamp: time.Now()}
}

// TestNewReceiveWindow verifies filter initialization.
func TestNewReceiveWindow(t *testing.T) {
	tests := []struct {
		name         string
		expected     uint32
		maxSize      uint
		wantMaxSize  int
		wantExpected uint32
	}{
		{name: "valid parameters", expected: 1000, maxSize: 100, wantMaxSize: 100, wantExpected: 1000},
		{name: "zero expected", expected: 0, maxSize: 50, wantMaxSize: 50, wantExpected: 0},
		{name: "max uint32 expected", expected: MaxPacketNumber, maxSize: 200, wantMaxSize: 200, wantExpected: MaxPacketNumber},
		{name: "zero maxSize uses default", expected: 100, maxSize: 0, wantMaxSize: DefaultMaxWindowSize, wantExpected: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := NewReceiveWindow(tt.expected, tt.maxSize)
			if rw == nil {
				t.Fatal("NewReceiveWindow returned nil")
			}
			if rw.GetExpected() != tt.wantExpected {
				t.Errorf("floor = %d, want %d", rw.GetExpected(), tt.wantExpected)
			}
			if rw.GetMaxSize() != tt.wantMaxSize {
				t.Errorf("capacity = %d, want %d", rw.GetMaxSize(), tt.wantMaxSize)
			}
			if rw.GetWindowSize() != 0 {
				t.Errorf("initial recorded count = %d, want 0", rw.GetWindowSize())
			}
		})
	}
}

// TestReceiveWindow_InsertDeliversImmediately verifies that the expected packet
// is returned for delivery at once.
func TestReceiveWindow_InsertDeliversImmediately(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	ready, err := rw.Insert(newTestPacket(1000))
	if err != nil {
		t.Fatalf("Insert() error = %v, want nil", err)
	}
	if len(ready) != 1 || ready[0].PacketNumber != 1000 {
		t.Fatalf("ready = %v, want exactly packet 1000", ready)
	}
	// The floor only moves when the tracked span is exceeded.
	if rw.GetExpected() != 1000 {
		t.Errorf("floor = %d, want 1000 (unchanged)", rw.GetExpected())
	}
	if rw.GetWindowSize() != 1 {
		t.Errorf("recorded count = %d, want 1", rw.GetWindowSize())
	}
}

// TestReceiveWindow_OutOfOrderNotBuffered is the core spec test: an out-of-order
// packet must be delivered immediately, not held for the missing one.
func TestReceiveWindow_OutOfOrderNotBuffered(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	// 1002, 1001, 1003 arrive before 1000. Each must be delivered on arrival.
	for _, pktNum := range []uint32{1002, 1001, 1003} {
		ready, err := rw.Insert(newTestPacket(pktNum))
		if err != nil {
			t.Fatalf("Insert(%d) error = %v", pktNum, err)
		}
		if len(ready) != 1 || ready[0].PacketNumber != pktNum {
			t.Errorf("Insert(%d) ready = %d packets, want 1 delivered immediately (no head-of-line blocking)", pktNum, len(ready))
		}
	}

	// Late arrival of 1000 is still new, so it is delivered too.
	ready, err := rw.Insert(newTestPacket(1000))
	if err != nil {
		t.Fatalf("Insert(1000) error = %v", err)
	}
	if len(ready) != 1 {
		t.Errorf("Insert(1000) ready = %d, want 1", len(ready))
	}
}

// TestReceiveWindow_LostPacketDoesNotStallSession guards the regression that
// made the old reordering buffer a denial-of-service: because SSU2 never
// retransmits a data packet with the same number, a buffered gap could never
// fill and every later packet would be dropped forever.
func TestReceiveWindow_LostPacketDoesNotStallSession(t *testing.T) {
	rw := NewReceiveWindow(0, 16)

	// Packet 0 arrives, then 1 is lost, then 2..40 arrive.
	if _, err := rw.Insert(newTestPacket(0)); err != nil {
		t.Fatalf("Insert(0) error = %v", err)
	}
	for pktNum := uint32(2); pktNum < 40; pktNum++ {
		ready, err := rw.Insert(newTestPacket(pktNum))
		if err != nil {
			t.Fatalf("Insert(%d) error = %v: session stalled after one lost packet", pktNum, err)
		}
		if len(ready) != 1 {
			t.Errorf("Insert(%d) ready = %d, want 1", pktNum, len(ready))
		}
	}
}

// TestReceiveWindow_InsertOld verifies packets below the floor are dropped.
func TestReceiveWindow_InsertOld(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	if _, err := rw.Insert(newTestPacket(999)); err == nil {
		t.Fatal("Insert(999) error = nil, want error for packet below the floor")
	}
	if rw.GetExpected() != 1000 {
		t.Errorf("floor = %d, want 1000 (unchanged)", rw.GetExpected())
	}
	if rw.GetWindowSize() != 0 {
		t.Errorf("recorded count = %d, want 0", rw.GetWindowSize())
	}
}

// TestReceiveWindow_InsertDuplicate verifies duplicates are dropped inside the
// tracked span.
func TestReceiveWindow_InsertDuplicate(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for _, pktNum := range []uint32{1000, 1005} {
		if _, err := rw.Insert(newTestPacket(pktNum)); err != nil {
			t.Fatalf("Insert(%d) error = %v", pktNum, err)
		}
		ready, err := rw.Insert(newTestPacket(pktNum))
		if err == nil {
			t.Errorf("Insert(%d) twice: error = nil, want duplicate error", pktNum)
		}
		if len(ready) != 0 {
			t.Errorf("Insert(%d) twice: ready = %d, want 0", pktNum, len(ready))
		}
	}
}

// TestReceiveWindow_InsertNil verifies a nil packet is rejected.
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

// TestReceiveWindow_SequentialPackets verifies an in-order run is delivered
// packet-for-packet.
func TestReceiveWindow_SequentialPackets(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for i := uint32(1000); i < 1010; i++ {
		ready, err := rw.Insert(newTestPacket(i))
		if err != nil {
			t.Fatalf("Insert(%d) error = %v", i, err)
		}
		if len(ready) != 1 || ready[0].PacketNumber != i {
			t.Errorf("Insert(%d) ready = %v, want exactly that packet", i, ready)
		}
	}
	if rw.GetWindowSize() != 10 {
		t.Errorf("recorded count = %d, want 10", rw.GetWindowSize())
	}
}

// TestReceiveWindow_FloorAdvancesAndStateStaysBounded verifies the bounded-state
// requirement: as newer numbers arrive the floor slides and the recorded set
// never exceeds the configured capacity.
func TestReceiveWindow_FloorAdvancesAndStateStaysBounded(t *testing.T) {
	capacity := uint(10)
	rw := NewReceiveWindow(1000, capacity)

	for i := uint32(1000); i < 3000; i++ {
		if _, err := rw.Insert(newTestPacket(i)); err != nil {
			t.Fatalf("Insert(%d) error = %v", i, err)
		}
		if got := rw.GetWindowSize(); got > int(capacity) {
			t.Fatalf("recorded count = %d after Insert(%d), want <= %d", got, i, capacity)
		}
	}

	if rw.GetExpected() <= 1000 {
		t.Errorf("floor = %d, want it to have advanced past 1000", rw.GetExpected())
	}
	// Everything below the floor is now dropped as old.
	if _, err := rw.Insert(newTestPacket(1000)); err == nil {
		t.Error("Insert(1000) after the floor advanced: error = nil, want drop")
	}
}

// TestReceiveWindow_Wraparound verifies modular packet-number arithmetic, since
// ssu2.rst allows numbers to wrap within a session.
func TestReceiveWindow_Wraparound(t *testing.T) {
	rw := NewReceiveWindow(MaxPacketNumber-2, 100)

	for _, pktNum := range []uint32{MaxPacketNumber - 2, MaxPacketNumber - 1, MaxPacketNumber, 0, 1} {
		ready, err := rw.Insert(newTestPacket(pktNum))
		if err != nil {
			t.Fatalf("Insert(%d) across the wrap: error = %v", pktNum, err)
		}
		if len(ready) != 1 {
			t.Errorf("Insert(%d) ready = %d, want 1", pktNum, len(ready))
		}
	}

	// Duplicates are still detected across the wrap boundary.
	if _, err := rw.Insert(newTestPacket(0)); err == nil {
		t.Error("Insert(0) again: error = nil, want duplicate error")
	}
	// A number behind the wrapped floor is dropped as old.
	if _, err := rw.Insert(newTestPacket(MaxPacketNumber - 2)); err == nil {
		t.Error("Insert behind the wrapped floor: error = nil, want drop")
	}
}

// TestReceiveWindow_Clear verifies resetting the filter.
func TestReceiveWindow_Clear(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for i := uint32(1005); i < 1010; i++ {
		if _, err := rw.Insert(newTestPacket(i)); err != nil {
			t.Fatalf("Insert(%d) error = %v", i, err)
		}
	}
	if rw.GetWindowSize() != 5 {
		t.Fatalf("recorded count = %d, want 5", rw.GetWindowSize())
	}

	rw.Clear(2000)

	if rw.GetExpected() != 2000 {
		t.Errorf("floor = %d, want 2000", rw.GetExpected())
	}
	if rw.GetWindowSize() != 0 {
		t.Errorf("recorded count = %d, want 0 after Clear", rw.GetWindowSize())
	}
	// 1005 is now below the floor and must be dropped rather than delivered.
	if _, err := rw.Insert(newTestPacket(1005)); err == nil {
		t.Error("Insert(1005) after Clear: error = nil, want drop")
	}
}

// TestReceiveWindow_SetExpected verifies rebaselining the floor.
func TestReceiveWindow_SetExpected(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for i := uint32(1005); i < 1008; i++ {
		if _, err := rw.Insert(newTestPacket(i)); err != nil {
			t.Fatalf("Insert(%d) error = %v", i, err)
		}
	}

	rw.SetExpected(1006)

	if rw.GetExpected() != 1006 {
		t.Errorf("floor = %d, want 1006", rw.GetExpected())
	}
	if rw.GetWindowSize() != 0 {
		t.Errorf("recorded count = %d, want 0 (SetExpected forgets the span)", rw.GetWindowSize())
	}
	// 1006 is above the new floor and was forgotten, so it is deliverable again.
	ready, err := rw.Insert(newTestPacket(1006))
	if err != nil {
		t.Fatalf("Insert(1006) error = %v, want nil", err)
	}
	if len(ready) != 1 {
		t.Errorf("Insert(1006) ready = %d, want 1", len(ready))
	}
}

// TestReceiveWindow_GetGapInfo verifies the diagnostics accessor reports the
// recorded span.
func TestReceiveWindow_GetGapInfo(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	if min, max, count := rw.GetGapInfo(); min != 1000 || max != 1000 || count != 0 {
		t.Errorf("empty filter gap info = (%d, %d, %d), want (1000, 1000, 0)", min, max, count)
	}

	for _, pktNum := range []uint32{1005, 1007, 1010} {
		if _, err := rw.Insert(newTestPacket(pktNum)); err != nil {
			t.Fatalf("Insert(%d) error = %v", pktNum, err)
		}
	}

	if min, max, count := rw.GetGapInfo(); min != 1005 || max != 1010 || count != 3 {
		t.Errorf("gap info = (%d, %d, %d), want (1005, 1010, 3)", min, max, count)
	}
}

// TestReceiveWindow_Concurrency verifies thread-safety under concurrent inserts.
func TestReceiveWindow_Concurrency(t *testing.T) {
	rw := NewReceiveWindow(0, 1000)

	const numGoroutines = 100
	const packetsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(offset int) {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				pktNum := uint32(offset*packetsPerGoroutine + j)
				_, _ = rw.Insert(newTestPacket(pktNum)) // duplicates from overlap are expected
			}
		}(i)
	}
	wg.Wait()

	if got := rw.GetWindowSize(); got > 1000 {
		t.Errorf("recorded count = %d, want <= capacity 1000", got)
	}
	if rw.GetExpected() == 0 {
		t.Error("floor = 0, want it to have advanced past the capacity")
	}
}

// TestReceiveWindow_ConcurrentReads verifies read operations do not mutate state.
func TestReceiveWindow_ConcurrentReads(t *testing.T) {
	rw := NewReceiveWindow(1000, 100)

	for i := uint32(1005); i < 1010; i++ {
		if _, err := rw.Insert(newTestPacket(i)); err != nil {
			t.Fatalf("Insert(%d) error = %v", i, err)
		}
	}

	const numReaders = 50
	const readsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < readsPerGoroutine; j++ {
				_ = rw.GetExpected()
				_ = rw.GetWindowSize()
				_, _, _ = rw.GetGapInfo()
			}
		}()
	}
	wg.Wait()

	if rw.GetExpected() != 1000 {
		t.Errorf("floor = %d, want 1000 (reads must not modify)", rw.GetExpected())
	}
	if rw.GetWindowSize() != 5 {
		t.Errorf("recorded count = %d, want 5 (reads must not modify)", rw.GetWindowSize())
	}
}

// BenchmarkReceiveWindow_Insert measures in-order insert performance.
func BenchmarkReceiveWindow_Insert(b *testing.B) {
	rw := NewReceiveWindow(0, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rw.Insert(newTestPacket(uint32(i)))
	}
}

// BenchmarkReceiveWindow_InsertOutOfOrder measures out-of-order insert cost.
func BenchmarkReceiveWindow_InsertOutOfOrder(b *testing.B) {
	rw := NewReceiveWindow(0, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rw.Insert(newTestPacket(uint32(i * 2)))
	}
}

// BenchmarkReceiveWindow_GetExpected measures floor read performance.
func BenchmarkReceiveWindow_GetExpected(b *testing.B) {
	rw := NewReceiveWindow(1000, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rw.GetExpected()
	}
}

// BenchmarkReceiveWindow_Concurrent measures concurrent insert performance.
func BenchmarkReceiveWindow_Concurrent(b *testing.B) {
	rw := NewReceiveWindow(0, 100000)
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			_, _ = rw.Insert(newTestPacket(i))
			i++
		}
	})
}
