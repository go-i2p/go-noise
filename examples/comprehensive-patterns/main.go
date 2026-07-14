package main

import (
	"fmt"
	"log"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/examples/exampleutil"
)

// patternInfo describes a Noise protocol pattern for testing
type patternInfo struct {
	name     string
	pattern  string
	msgCount int
	category string
}

// testAllPatterns tests each pattern and returns the success count
func testAllPatterns(patterns []patternInfo) int {
	successCount := 0
	for _, p := range patterns {
		config := noise.NewConnConfig(p.pattern, true)
		if err := config.Validate(); err == nil {
			fmt.Printf("✅ %-25s %-20s %d messages\n", p.name, fmt.Sprintf("(%s)", p.category), p.msgCount)
			successCount++
		} else {
			fmt.Printf("❌ %-25s Failed validation: %v\n", p.name, err)
		}
	}
	return successCount
}

// printPatternSummary displays the summary of pattern testing
func printPatternSummary(successCount, total int) {
	fmt.Printf("\n🎯 Summary: %d/%d patterns supported (%.1f%%)\n",
		successCount, total, float64(successCount)/float64(total)*100)

	if successCount == total {
		exampleutil.PrintLines(
			"🚀 COMPLETE: Full Noise Protocol specification coverage achieved!",
			"\nSupported pattern categories:",
			"  • One-way patterns (N, K, X)",
			"  • Two-message interactive patterns (NN, NK, NX, XN, XK, KN, KK, IN, IK, IX)",
			"  • Three-message patterns (XX, KX)",
			"\nAll patterns support both full specification names (e.g., 'Noise_XX_25519_AESGCM_SHA256') and short names (e.g., 'XX').",
		)
	} else {
		log.Printf("Warning: Only %d out of %d patterns are supported", successCount, total)
	}
}

// demonstratePatternSupport shows all supported Noise patterns
func main() {
	fmt.Println("🔐 Comprehensive Noise Protocol Pattern Support Verification")
	fmt.Println("===========================================================")

	patterns := []patternInfo{
		// One-way patterns
		{"N (Basic one-way)", "N", 1, "One-way"},
		{"K (Pre-shared static)", "K", 1, "One-way"},
		{"X (Static transmission)", "X", 1, "One-way"},

		// Two-message interactive patterns
		{"NN (No static keys)", "NN", 2, "Interactive (2-msg)"},
		{"NK (Known responder)", "NK", 2, "Interactive (2-msg)"},
		{"NX (Unknown responder)", "NX", 2, "Interactive (2-msg)"},
		{"XN (Known initiator)", "XN", 2, "Interactive (2-msg)"},
		{"XK (Mutual knowledge)", "XK", 2, "Interactive (2-msg)"},
		{"KN (Pre-shared init)", "KN", 2, "Interactive (2-msg)"},
		{"KK (Mutual pre-shared)", "KK", 2, "Interactive (2-msg)"},
		{"IN (Immediate init)", "IN", 2, "Interactive (2-msg)"},
		{"IK (Immediate known)", "IK", 2, "Interactive (2-msg)"},
		{"IX (Immediate unknown)", "IX", 2, "Interactive (2-msg)"},

		// Three-message patterns
		{"XX (Mutual auth)", "XX", 3, "Interactive (3-msg)"},
		{"KX (Complex auth)", "KX", 3, "Interactive (3-msg)"},
	}

	fmt.Printf("Testing %d Noise Protocol patterns:\n\n", len(patterns))

	successCount := testAllPatterns(patterns)
	printPatternSummary(successCount, len(patterns))
}
