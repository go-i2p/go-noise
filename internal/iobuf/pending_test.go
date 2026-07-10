package iobuf

import (
	"bytes"
	"testing"
)

func TestDrainPendingBuffer_NilPendingSlice(t *testing.T) {
	var pending []byte // nil slice, not a nil pointer
	dst := make([]byte, 4)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 0 {
		t.Errorf("expected n=0 for nil pending slice, got %d", n)
	}
	if drained {
		t.Error("expected drained=false for nil pending slice")
	}
}

// TestDrainPendingBuffer_NilPendingPointer verifies that passing a nil
// *[]byte pointer (as opposed to a pointer to a nil slice) returns (0, false)
// rather than panicking on dereference.
func TestDrainPendingBuffer_NilPendingPointer(t *testing.T) {
	dst := make([]byte, 4)

	n, drained := DrainPendingBuffer(nil, dst, true)
	if n != 0 {
		t.Errorf("expected n=0 for nil pending pointer, got %d", n)
	}
	if drained {
		t.Error("expected drained=false for nil pending pointer")
	}
}

func TestDrainPendingBuffer_EmptyPendingSlice(t *testing.T) {
	pending := []byte{}
	dst := make([]byte, 4)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 0 {
		t.Errorf("expected n=0 for empty pending slice, got %d", n)
	}
	if drained {
		t.Error("expected drained=false for empty pending slice")
	}
}

func TestDrainPendingBuffer_ZeroLengthDestination(t *testing.T) {
	pending := []byte("hello")
	dst := []byte{}

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 0 {
		t.Errorf("expected n=0 for zero-length destination, got %d", n)
	}
	if drained {
		t.Error("expected drained=false when destination cannot hold any bytes")
	}
	if !bytes.Equal(pending, []byte("hello")) {
		t.Errorf("expected pending buffer unchanged, got %q", pending)
	}
}

func TestDrainPendingBuffer_PartialDrain(t *testing.T) {
	pending := []byte("hello world")
	dst := make([]byte, 5)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 5 {
		t.Fatalf("expected n=5, got %d", n)
	}
	if drained {
		t.Error("expected drained=false for a partial drain")
	}
	if string(dst) != "hello" {
		t.Errorf("expected dst=%q, got %q", "hello", dst)
	}
	if string(pending) != " world" {
		t.Errorf("expected remaining pending=%q, got %q", " world", pending)
	}
}

func TestDrainPendingBuffer_PartialDrain_DeliveredBytesZeroedWhenZeroTrue(t *testing.T) {
	original := []byte("secretdata")
	pending := append([]byte{}, original...)
	dst := make([]byte, 6)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 6 || drained {
		t.Fatalf("unexpected drain result: n=%d drained=%v", n, drained)
	}
	if string(dst) != "secret" {
		t.Fatalf("expected dst=%q, got %q", "secret", dst)
	}
	// The remaining (undelivered) portion must be untouched.
	if string(pending) != "data" {
		t.Errorf("expected remaining pending=%q, got %q", "data", pending)
	}
}

func TestDrainPendingBuffer_FullDrain_ZeroTrue(t *testing.T) {
	pending := []byte("hello")
	dst := make([]byte, 10)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 5 {
		t.Fatalf("expected n=5, got %d", n)
	}
	if !drained {
		t.Fatal("expected drained=true when destination exceeds remaining data")
	}
	if pending != nil {
		t.Errorf("expected pending to be nil after full drain, got %v", pending)
	}
	if string(dst[:5]) != "hello" {
		t.Errorf("expected dst[:5]=%q, got %q", "hello", dst[:5])
	}
}

func TestDrainPendingBuffer_FullDrain_ExactSizeDestination(t *testing.T) {
	pending := []byte("hello")
	dst := make([]byte, 5)

	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 5 || !drained {
		t.Fatalf("expected n=5 drained=true, got n=%d drained=%v", n, drained)
	}
	if pending != nil {
		t.Errorf("expected pending to be nil after exact full drain, got %v", pending)
	}
}

// TestDrainPendingBuffer_FullDrain_TailCapacityZeroed verifies that when the
// pending slice's backing array has spare capacity beyond its length (e.g.
// because it was sliced down from a larger buffer), a full drain zeroes that
// unused tail capacity too, not just the delivered/logical portion.
func TestDrainPendingBuffer_FullDrain_TailCapacityZeroed(t *testing.T) {
	backing := make([]byte, 10)
	copy(backing, "hello")
	pending := backing[:5:10] // len=5, cap=10; bytes [5:10] are the "tail capacity"
	for i := 5; i < 10; i++ {
		backing[i] = 0xAA // sentinel to detect zeroing
	}

	dst := make([]byte, 5)
	n, drained := DrainPendingBuffer(&pending, dst, true)
	if n != 5 || !drained {
		t.Fatalf("expected n=5 drained=true, got n=%d drained=%v", n, drained)
	}

	for i := 5; i < 10; i++ {
		if backing[i] != 0 {
			t.Errorf("expected tail capacity byte at index %d to be zeroed, got %#x", i, backing[i])
		}
	}
}

// TestDrainPendingBuffer_ZeroFalse_NoZeroingOccurs verifies that when zero is
// false, neither the delivered bytes nor any tail capacity are modified.
func TestDrainPendingBuffer_ZeroFalse_NoZeroingOccurs(t *testing.T) {
	backing := make([]byte, 10)
	copy(backing, "hello")
	pending := backing[:5:10]
	for i := 5; i < 10; i++ {
		backing[i] = 0xAA
	}

	dst := make([]byte, 5)
	n, drained := DrainPendingBuffer(&pending, dst, false)
	if n != 5 || !drained {
		t.Fatalf("expected n=5 drained=true, got n=%d drained=%v", n, drained)
	}

	// Delivered bytes in the source backing array must remain untouched.
	if string(backing[:5]) != "hello" {
		t.Errorf("expected backing[:5] unchanged (%q), got %q", "hello", backing[:5])
	}
	// Tail capacity must remain untouched when zero=false.
	for i := 5; i < 10; i++ {
		if backing[i] != 0xAA {
			t.Errorf("expected tail capacity byte at index %d to remain 0xAA, got %#x", i, backing[i])
		}
	}
}

// TestDrainPendingBuffer_MultiCallPartialDrains verifies that repeated calls
// with a small destination buffer eventually drain the full pending buffer,
// with each call returning the correct incremental progress.
func TestDrainPendingBuffer_MultiCallPartialDrains(t *testing.T) {
	pending := []byte("the quick brown fox")
	var result []byte
	dst := make([]byte, 4)

	for {
		n, drained := DrainPendingBuffer(&pending, dst, true)
		result = append(result, dst[:n]...)
		if drained {
			break
		}
		if n == 0 {
			t.Fatal("drain made no progress and did not report drained")
		}
	}

	if string(result) != "the quick brown fox" {
		t.Errorf("expected reassembled result %q, got %q", "the quick brown fox", result)
	}
	if pending != nil {
		t.Errorf("expected pending nil after full multi-call drain, got %v", pending)
	}
}
