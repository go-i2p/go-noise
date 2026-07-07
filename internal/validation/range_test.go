package validation

import "testing"

func TestCompareIntRange(t *testing.T) {
	tests := []struct {
		name  string
		value int
		lower int
		upper int
		want  RangeComparison
	}{
		{"below range", 0, 1, 10, BelowRange},
		{"at lower bound (inclusive)", 1, 1, 10, InRange},
		{"inside range", 5, 1, 10, InRange},
		{"at upper bound (inclusive)", 10, 1, 10, InRange},
		{"above range", 11, 1, 10, AboveRange},
		{"negative range: below", -20, -10, -1, BelowRange},
		{"negative range: at lower bound", -10, -10, -1, InRange},
		{"negative range: inside", -5, -10, -1, InRange},
		{"negative range: at upper bound", -1, -10, -1, InRange},
		{"negative range: above", 0, -10, -1, AboveRange},
		{"zero-width range: match", 5, 5, 5, InRange},
		{"zero-width range: below", 4, 5, 5, BelowRange},
		{"zero-width range: above", 6, 5, 5, AboveRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareIntRange(tt.value, tt.lower, tt.upper); got != tt.want {
				t.Errorf("CompareIntRange(%d, %d, %d) = %v, want %v", tt.value, tt.lower, tt.upper, got, tt.want)
			}
		})
	}
}

func TestCompareFloat64Range(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		lower float64
		upper float64
		want  RangeComparison
	}{
		{"below range", 0.5, 1.0, 10.0, BelowRange},
		{"at lower bound (inclusive)", 1.0, 1.0, 10.0, InRange},
		{"inside range", 5.5, 1.0, 10.0, InRange},
		{"at upper bound (inclusive)", 10.0, 1.0, 10.0, InRange},
		{"above range", 10.01, 1.0, 10.0, AboveRange},
		{"negative range: below", -20.5, -10.0, -1.0, BelowRange},
		{"negative range: at bounds", -1.0, -10.0, -1.0, InRange},
		{"zero-width range: match", 2.5, 2.5, 2.5, InRange},
		{"zero-width range: below", 2.4, 2.5, 2.5, BelowRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareFloat64Range(tt.value, tt.lower, tt.upper); got != tt.want {
				t.Errorf("CompareFloat64Range(%v, %v, %v) = %v, want %v", tt.value, tt.lower, tt.upper, got, tt.want)
			}
		})
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		want   float64
		wantOK bool
	}{
		{"int", 42, 42.0, true},
		{"negative int", -7, -7.0, true},
		{"int64", int64(100), 100.0, true},
		{"float64", 3.14, 3.14, true},
		{"unsupported string", "not a number", 0, false},
		{"unsupported nil", nil, 0, false},
		{"unsupported bool", true, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ToFloat64(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ToFloat64(%v) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("ToFloat64(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
