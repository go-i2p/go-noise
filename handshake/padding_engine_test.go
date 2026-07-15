package handshake

import (
	"bytes"
	"testing"
)

// TestRemoveTrailingAEADPadding_RoundTrip verifies that padding added via
// AddAEADPadding is fully and correctly removed by RemoveTrailingAEADPadding
// for the common, unambiguous case.
func TestRemoveTrailingAEADPadding_RoundTrip(t *testing.T) {
	engine, err := NewPaddingEngine(PaddingEngineConfig{
		MinPadding: 0,
		MaxPadding: 32,
		TestMode:   true,
		Domain:     "test",
	})
	if err != nil {
		t.Fatalf("NewPaddingEngine() error = %v", err)
	}

	original := []byte("hello, i2p application payload")
	padded, err := engine.AddAEADPadding(original, 10)
	if err != nil {
		t.Fatalf("AddAEADPadding() error = %v", err)
	}
	if len(padded) != len(original)+I2PBlockHeaderSize+10 {
		t.Fatalf("padded length = %d, want %d", len(padded), len(original)+I2PBlockHeaderSize+10)
	}

	stripped, err := engine.RemoveTrailingAEADPadding(padded, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPadding() unexpected error = %v", err)
	}
	if !bytes.Equal(stripped, original) {
		t.Errorf("RemoveTrailingAEADPadding() = %v, want %v", stripped, original)
	}
}

// TestRemoveTrailingAEADPadding_NoPaddingPresent verifies the zero-candidate
// case (e.g. sender's configured padding size was 0, so no block was ever
// appended) safely returns the input unchanged rather than erroring.
func TestRemoveTrailingAEADPadding_NoPaddingPresent(t *testing.T) {
	engine, err := NewPaddingEngine(PaddingEngineConfig{
		MinPadding: 0,
		MaxPadding: 32,
		Domain:     "test",
	})
	if err != nil {
		t.Fatalf("NewPaddingEngine() error = %v", err)
	}

	original := []byte("no padding block appended to this payload")
	result, err := engine.RemoveTrailingAEADPadding(original, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPadding() unexpected error = %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Errorf("RemoveTrailingAEADPadding() = %v, want unchanged %v", result, original)
	}
}

// TestRemoveTrailingAEADPadding_AmbiguousFailsClosed constructs a buffer with
// two coincidentally valid-looking trailing padding block headers within the
// scan window and verifies the function now fails closed with an error
// instead of silently guessing (regression test for AUDIT.md item: ambiguous
// reverse-scan heuristic).
func TestRemoveTrailingAEADPadding_AmbiguousFailsClosed(t *testing.T) {
	engine, err := NewPaddingEngine(PaddingEngineConfig{
		MinPadding: 0,
		MaxPadding: 32,
		Domain:     "test",
	})
	if err != nil {
		t.Fatalf("NewPaddingEngine() error = %v", err)
	}

	// data = [A,B,C,D, 254,0,3, 254,0,0]
	// Candidate 1: paddingSize=0 at start=7 (data[7..9] = 254,0,0).
	// Candidate 2: paddingSize=3 at start=4 (data[4..6] = 254,0,3).
	// Both satisfy header-byte + declared-size-matches-offset checks.
	data := []byte{'A', 'B', 'C', 'D', 254, 0, 3, 254, 0, 0}

	_, err = engine.RemoveTrailingAEADPadding(data, engine.Config.MaxPadding)
	if err == nil {
		t.Fatal("RemoveTrailingAEADPadding() expected ambiguity error, got nil")
	}
}

// TestRemoveTrailingAEADPadding_MinPaddingNarrowsScanWindow verifies that a
// configured MinPadding lower-bounds the scan, so a below-minimum coincidental
// match is ignored rather than counted toward ambiguity or wrongly selected.
func TestRemoveTrailingAEADPadding_MinPaddingNarrowsScanWindow(t *testing.T) {
	engine, err := NewPaddingEngine(PaddingEngineConfig{
		MinPadding: 1,
		MaxPadding: 32,
		Domain:     "test",
	})
	if err != nil {
		t.Fatalf("NewPaddingEngine() error = %v", err)
	}

	// Same buffer as the ambiguity test, but MinPadding=1 excludes the
	// paddingSize=0 candidate (start=7), leaving only the paddingSize=3
	// candidate (start=4) as a single, unambiguous match.
	data := []byte{'A', 'B', 'C', 'D', 254, 0, 3, 254, 0, 0}

	result, err := engine.RemoveTrailingAEADPadding(data, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPadding() unexpected error = %v", err)
	}
	want := []byte{'A', 'B', 'C', 'D'}
	if !bytes.Equal(result, want) {
		t.Errorf("RemoveTrailingAEADPadding() = %v, want %v", result, want)
	}
}
