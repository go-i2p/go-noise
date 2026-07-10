package cryptorand

import "testing"

func TestRandInRange_LowerGreaterThanUpper(t *testing.T) {
	v, err := RandInRange(10, 5)
	if err == nil {
		t.Fatal("RandInRange(10, 5) expected error when lower > upper, got nil")
	}
	if v != 0 {
		t.Errorf("RandInRange(10, 5) returned %d on error, want 0", v)
	}
}

func TestRandInRange_LowerEqualsUpper(t *testing.T) {
	v, err := RandInRange(42, 42)
	if err != nil {
		t.Fatalf("RandInRange(42, 42) unexpected error: %v", err)
	}
	if v != 42 {
		t.Errorf("RandInRange(42, 42) = %d, want 42", v)
	}
}

func TestRandInRange_NegativeEqualBounds(t *testing.T) {
	v, err := RandInRange(-5, -5)
	if err != nil {
		t.Fatalf("RandInRange(-5, -5) unexpected error: %v", err)
	}
	if v != -5 {
		t.Errorf("RandInRange(-5, -5) = %d, want -5", v)
	}
}

func TestRandInRange_WithinBounds(t *testing.T) {
	const lower, upper = 5, 10
	for i := 0; i < 200; i++ {
		v, err := RandInRange(lower, upper)
		if err != nil {
			t.Fatalf("RandInRange(%d, %d) unexpected error: %v", lower, upper, err)
		}
		if v < lower || v > upper {
			t.Fatalf("RandInRange(%d, %d) = %d, out of bounds", lower, upper, v)
		}
	}
}

func TestRandInRange_NegativeToPositiveRange(t *testing.T) {
	const lower, upper = -10, 10
	seenNegative, seenPositive := false, false
	for i := 0; i < 500; i++ {
		v, err := RandInRange(lower, upper)
		if err != nil {
			t.Fatalf("RandInRange(%d, %d) unexpected error: %v", lower, upper, err)
		}
		if v < lower || v > upper {
			t.Fatalf("RandInRange(%d, %d) = %d, out of bounds", lower, upper, v)
		}
		if v < 0 {
			seenNegative = true
		}
		if v > 0 {
			seenPositive = true
		}
	}
	if !seenNegative || !seenPositive {
		t.Errorf("expected both negative and positive values across 500 draws from [%d, %d], seenNegative=%v seenPositive=%v", lower, upper, seenNegative, seenPositive)
	}
}

func TestRandInRange_LargeRange(t *testing.T) {
	const lower, upper = 0, 1 << 40
	for i := 0; i < 50; i++ {
		v, err := RandInRange(lower, upper)
		if err != nil {
			t.Fatalf("RandInRange(%d, %d) unexpected error: %v", lower, upper, err)
		}
		if v < lower || v > upper {
			t.Fatalf("RandInRange(%d, %d) = %d, out of bounds", lower, upper, v)
		}
	}
}

func TestRandInRange_Uniqueness(t *testing.T) {
	const lower, upper = 0, 1 << 30
	v1, err := RandInRange(lower, upper)
	if err != nil {
		t.Fatalf("first RandInRange call error: %v", err)
	}
	v2, err := RandInRange(lower, upper)
	if err != nil {
		t.Fatalf("second RandInRange call error: %v", err)
	}
	// Extremely unlikely (but not impossible) for two draws from a huge range
	// to collide; a persistent collision across reruns would indicate a bug.
	if v1 == v2 {
		t.Logf("RandInRange produced identical values %d on two calls from a %d-wide range; this is astronomically unlikely but not itself proof of a bug on a single run", v1, upper-lower+1)
	}
}
