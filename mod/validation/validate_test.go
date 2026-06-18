package validation

import (
	"testing"
	"time"
)

type validationTestCase struct {
	name    string
	fn      func() error
	wantErr bool
}

func runValidationTests(t *testing.T, cases []validationTestCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePattern_Empty(t *testing.T) {
	err := ValidatePattern("", "test")
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
}

func TestValidatePattern_Valid(t *testing.T) {
	for _, p := range []string{"XX", "IK", "XK", "NK"} {
		if err := ValidatePattern(p, "test"); err != nil {
			t.Errorf("ValidatePattern(%q) unexpected error: %v", p, err)
		}
	}
}

func TestValidateHandshakeTimeout_Zero(t *testing.T) {
	runValidationTests(t, []validationTestCase{
		{name: "Zero", fn: func() error { return ValidateHandshakeTimeout(0, "test") }, wantErr: true},
		{name: "Negative", fn: func() error { return ValidateHandshakeTimeout(-time.Second, "test") }, wantErr: true},
		{name: "Positive", fn: func() error { return ValidateHandshakeTimeout(5*time.Second, "test") }, wantErr: false},
	})
}

func TestValidateKeyLength_Empty(t *testing.T) {
	if err := ValidateKeyLength(nil, "static", "test"); err != nil {
		t.Fatalf("nil key should be valid: %v", err)
	}
	if err := ValidateKeyLength([]byte{}, "static", "test"); err != nil {
		t.Fatalf("empty key should be valid: %v", err)
	}
}

func TestValidateKeyLength_Valid32(t *testing.T) {
	key := make([]byte, 32)
	if err := ValidateKeyLength(key, "static", "test"); err != nil {
		t.Fatalf("32-byte key should be valid: %v", err)
	}
}

func TestValidateKeyLength_Wrong(t *testing.T) {
	for _, n := range []int{1, 16, 31, 33, 64} {
		key := make([]byte, n)
		if err := ValidateKeyLength(key, "static", "test"); err == nil {
			t.Errorf("expected error for %d-byte key", n)
		}
	}
}

func TestValidateRetryConfig_Valid(t *testing.T) {
	cases := []struct {
		retries int
		backoff time.Duration
	}{
		{-1, 0},                     // infinite retries, no backoff
		{0, 0},                      // no retries
		{3, 100 * time.Millisecond}, // normal case
		{0, time.Second},            // no retries, with backoff
	}
	for _, tc := range cases {
		if err := ValidateRetryConfig(tc.retries, tc.backoff, "test"); err != nil {
			t.Errorf("ValidateRetryConfig(%d, %v) unexpected error: %v", tc.retries, tc.backoff, err)
		}
	}
}

func TestValidateRetryConfig_InvalidRetries(t *testing.T) {
	runValidationTests(t, []validationTestCase{
		{name: "LessThanNegativeOne", fn: func() error { return ValidateRetryConfig(-2, 0, "test") }, wantErr: true},
		{name: "LargeNegativeRetries", fn: func() error { return ValidateRetryConfig(-100, time.Second, "test") }, wantErr: true},
	})
}

func TestValidateRetryConfig_NegativeBackoff(t *testing.T) {
	if err := ValidateRetryConfig(3, -time.Second, "test"); err == nil {
		t.Fatal("expected error for negative backoff")
	}
}

func TestRunValidators_Empty(t *testing.T) {
	if err := RunValidators(); err != nil {
		t.Fatalf("no validators should return nil: %v", err)
	}
}

func TestRunValidators_AllPass(t *testing.T) {
	pass := func() error { return nil }
	if err := RunValidators(pass, pass, pass); err != nil {
		t.Fatalf("all-pass should return nil: %v", err)
	}
}

func TestRunValidators_StopsAtFirstError(t *testing.T) {
	calls := 0
	pass := func() error { calls++; return nil }
	fail := func() error { calls++; return ValidatePattern("", "test") }
	after := func() error { calls++; return nil }

	err := RunValidators(pass, fail, after)
	if err == nil {
		t.Fatal("expected error from failing validator")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls (pass + fail), got %d", calls)
	}
}
