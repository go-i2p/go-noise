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
// scan window and verifies the function fails closed with an error instead of
// silently guessing which header is the real one.
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

// TestRemoveTrailingAEADPaddingStructured_FEFixedTrailingBytesIsNotStripped is
// the H-017 repro at the level the fix operates: a payload that is a real I2P
// block stream and merely *ends* in bytes that look like a padding header.
//
// The block's data ends FE 00 00. The heuristic scan reads those three bytes as
// "[type=254][size=0]" and strips them, silently shortening the frame so the
// transport parses a truncated block. Walking the stream forward reaches the
// same bytes as data *inside* the preceding block, so the frame is returned
// intact.
func TestRemoveTrailingAEADPaddingStructured_FEFixedTrailingBytesIsNotStripped(t *testing.T) {
	engine := newPaddingTestEngine(t, 0, 32)

	// [type=3 (I2NP)][size=6][01 02 03 FE 00 00] — no padding block appended.
	payload := []byte{0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0xFE, 0x00, 0x00}

	stripped, err := engine.RemoveTrailingAEADPaddingStructured(payload, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPaddingStructured() unexpected error = %v", err)
	}
	if !bytes.Equal(stripped, payload) {
		t.Errorf("RemoveTrailingAEADPaddingStructured() truncated an unpadded frame: got %v, want %v",
			stripped, payload)
	}

	// The same bytes with no block structure are opaque, and the scan is all
	// there is to go on: documented here so the difference in behaviour is
	// explicit rather than accidental.
	if _, scanErr := engine.RemoveTrailingAEADPadding(payload, engine.Config.MaxPadding); scanErr != nil {
		t.Logf("scan on a block-stream payload: %v", scanErr)
	}
}

// TestRemoveTrailingAEADPaddingStructured_StripsRealPaddingBlock verifies the
// structural path still removes the padding block that AddAEADPadding appended.
func TestRemoveTrailingAEADPaddingStructured_StripsRealPaddingBlock(t *testing.T) {
	engine := newPaddingTestEngine(t, 0, 32)

	// [type=3][size=5][...] followed by a genuine trailing padding block.
	frame := []byte{0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	padded, err := engine.AddAEADPadding(frame, 7)
	if err != nil {
		t.Fatalf("AddAEADPadding() error = %v", err)
	}

	stripped, err := engine.RemoveTrailingAEADPaddingStructured(padded, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPaddingStructured() unexpected error = %v", err)
	}
	if !bytes.Equal(stripped, frame) {
		t.Errorf("RemoveTrailingAEADPaddingStructured() = %v, want %v", stripped, frame)
	}
}

// TestRemoveTrailingAEADPaddingStructured_TwoCandidatesIsNotAmbiguous shows the
// structural path removes the remote-peer-controlled ambiguity the scan fails
// closed on.
//
// The scan sees two coincidental padding headers in this frame and returns an
// error, which the transport treats as "abort the connection": a peer that can
// choose message content can therefore drop a link at will. The structural walk
// has exactly one boundary to consider, so it resolves the frame and reports no
// error.
func TestRemoveTrailingAEADPaddingStructured_TwoCandidatesIsNotAmbiguous(t *testing.T) {
	engine := newPaddingTestEngine(t, 0, 32)

	// [type=3][size=7][01 02 03 04 254 00 03] then a real trailing padding
	// block [254][0000]. The embedded FE 00 03 is data, not a header.
	frame := []byte{0x03, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04, 0xFE, 0x00, 0x03}
	padded := append(append([]byte(nil), frame...), 0xFE, 0x00, 0x00)

	if _, scanErr := engine.RemoveTrailingAEADPadding(padded, engine.Config.MaxPadding); scanErr == nil {
		t.Log("scan did not report ambiguity for this frame; structural path is still exact")
	}

	stripped, err := engine.RemoveTrailingAEADPaddingStructured(padded, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPaddingStructured() unexpected error = %v (a peer must not be able to force teardown with message content)", err)
	}
	if !bytes.Equal(stripped, frame) {
		t.Errorf("RemoveTrailingAEADPaddingStructured() = %v, want %v", stripped, frame)
	}
}

// TestRemoveTrailingAEADPaddingStructured_FallsBackForOpaquePayload verifies a
// payload that does not parse as a block stream still goes through the scan, so
// callers whose data has no structure keep their existing behaviour.
func TestRemoveTrailingAEADPaddingStructured_FallsBackForOpaquePayload(t *testing.T) {
	engine := newPaddingTestEngine(t, 0, 32)

	// Opaque text with a genuine trailing padding block appended. The prefix is
	// not a block stream (the walk would run off the end of a bogus size), so
	// the scan must be what removes the padding.
	original := []byte("opaque payload with no block structure at all")
	padded, err := engine.AddAEADPadding(original, 6)
	if err != nil {
		t.Fatalf("AddAEADPadding() error = %v", err)
	}

	stripped, err := engine.RemoveTrailingAEADPaddingStructured(padded, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPaddingStructured() unexpected error = %v", err)
	}
	if !bytes.Equal(stripped, original) {
		t.Errorf("RemoveTrailingAEADPaddingStructured() = %q, want %q", stripped, original)
	}
}

// TestRemoveTrailingAEADPaddingStructured_PaddingNotLastIsUntouched verifies a
// frame whose padding block is followed by more blocks is returned as-is for the
// transport's block-ordering validator to reject, rather than being repaired.
func TestRemoveTrailingAEADPaddingStructured_PaddingNotLastIsUntouched(t *testing.T) {
	engine := newPaddingTestEngine(t, 0, 32)

	frame := []byte{
		0xFE, 0x00, 0x02, 0xAA, 0xBB, // padding, not last
		0x03, 0x00, 0x01, 0x01, // i2np
	}

	stripped, err := engine.RemoveTrailingAEADPaddingStructured(frame, engine.Config.MaxPadding)
	if err != nil {
		t.Fatalf("RemoveTrailingAEADPaddingStructured() unexpected error = %v", err)
	}
	if !bytes.Equal(stripped, frame) {
		t.Errorf("RemoveTrailingAEADPaddingStructured() = %v, want unchanged %v", stripped, frame)
	}
}

func newPaddingTestEngine(t *testing.T, minPad, maxPad int) *PaddingEngine {
	t.Helper()
	engine, err := NewPaddingEngine(PaddingEngineConfig{
		MinPadding: minPad,
		MaxPadding: maxPad,
		Domain:     "test",
	})
	if err != nil {
		t.Fatalf("NewPaddingEngine() error = %v", err)
	}
	return engine
}
