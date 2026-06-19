package validation

// RangeComparison describes where a value falls relative to an inclusive range.
type RangeComparison int

const (
	BelowRange RangeComparison = iota
	InRange
	AboveRange
)

// CompareIntRange compares an integer against an inclusive [lower, upper] range.
func CompareIntRange(value, lower, upper int) RangeComparison {
	if value < lower {
		return BelowRange
	}
	if value > upper {
		return AboveRange
	}
	return InRange
}

// CompareFloat64Range compares a float64 against an inclusive [lower, upper] range.
func CompareFloat64Range(value, lower, upper float64) RangeComparison {
	if value < lower {
		return BelowRange
	}
	if value > upper {
		return AboveRange
	}
	return InRange
}

// ToFloat64 converts supported numeric types to float64 for range checks.
// Returns false if the type is unsupported.
func ToFloat64(value interface{}) (float64, bool) {
	switch val := value.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	default:
		return 0, false
	}
}
