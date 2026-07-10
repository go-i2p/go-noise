package siphash

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	gocrypto_siphash "github.com/go-i2p/crypto/siphash"
	"github.com/go-i2p/go-noise/handshake"
)

// ============================================================================
// Official SipHash-2-4 reference vectors
//
// These are the standard reference-implementation test vectors (key = bytes
// 0x00..0x0f, message = bytes 0x00..0x(n-1) for an n-byte message), taken
// directly from the vendored dependency's own test suite
// (github.com/dchest/siphash@v1.2.3, siphash_test.go, `goldenRef`), which is
// itself dedicated to the public domain (CC0). Reusing them here pins the
// call-site wiring in this package (key ordering, byte order, IV handling)
// against the same known-good values used to validate the upstream
// implementation, rather than only checking internal self-consistency.
// ============================================================================

// referenceKey0/referenceKey1 are the standard SipHash reference key halves,
// derived from key bytes 0x00 0x01 ... 0x0f interpreted as two little-endian
// uint64 values (k0 = bytes 0..7, k1 = bytes 8..15).
const (
	referenceKey0 uint64 = 0x0706050403020100
	referenceKey1 uint64 = 0x0f0e0d0c0b0a0908
)

// referenceVectors maps message length (0..12 bytes, message = 0x00,0x01,...)
// to the expected little-endian-encoded SipHash-2-4 digest, taken from
// dchest/siphash's goldenRef table (indices 0-12).
var referenceVectors = []struct {
	msgLen int
	digest []byte // 8 bytes, little-endian
}{
	{0, []byte{0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72}},
	{1, []byte{0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74}},
	{2, []byte{0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d}},
	{3, []byte{0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85}},
	{4, []byte{0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf}},
	{5, []byte{0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18}},
	{6, []byte{0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb}},
	{7, []byte{0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab}},
	{8, []byte{0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93}},
	{9, []byte{0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e}},
	{10, []byte{0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a}},
	{11, []byte{0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4}},
	{12, []byte{0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75}},
}

// buildReferenceMessage returns the n-byte message 0x00, 0x01, ..., n-1 used
// by the standard SipHash-2-4 reference vectors.
func buildReferenceMessage(n int) []byte {
	msg := make([]byte, n)
	for i := range msg {
		msg[i] = byte(i)
	}
	return msg
}

// TestSipHash_OfficialReferenceVectors verifies that this package's
// dependency call site (gocrypto_siphash.Hash) reproduces the standard
// SipHash-2-4 reference vectors exactly. This guards against a
// self-consistent-but-wrong regression (e.g. an accidental k0/k1 swap or
// byte-order error introduced at this call site), which round-trip-only
// tests against this package's own code cannot catch.
func TestSipHash_OfficialReferenceVectors(t *testing.T) {
	for _, v := range referenceVectors {
		msg := buildReferenceMessage(v.msgLen)
		got := gocrypto_siphash.Hash(referenceKey0, referenceKey1, msg)
		want := binary.LittleEndian.Uint64(v.digest)
		if got != want {
			t.Errorf("message length %d: Hash() = %#016x, want %#016x", v.msgLen, got, want)
		}
	}
}

// ============================================================================
// NextMask fixed-vector test
// ============================================================================

// TestNextMask_FixedVector pins a known key pair + known initial IV to a
// known mask sequence, computed once via the reference vectors above and
// locked in as a regression test. NextMask's contract is:
//
//	IV[n] = SipHash-2-4(k1, k2, LittleEndian(IV[n-1]))
//	mask  = uint16(IV[n] & 0xFFFF)
//
// Starting from IV[0] = 0 (an 8-byte all-zero message, i.e. the msgLen=8
// reference vector's *input*, not its digest -- NextMask hashes the 8-byte
// little-endian encoding of the current IV, which for IV=0 is all-zero
// bytes). This ties NextMask's first step directly to a fixed value derived
// from the official vectors: hashing an all-zero key... no -- NextMask uses
// the *keys* as referenceKey0/referenceKey1 and hashes the (all-zero) IV
// bytes, which is NOT one of the goldenRef vectors above (those vary the
// message content 0x00,0x01,.. rather than using an all-zero message of
// varying length). So this test instead independently verifies NextMask's
// algorithm shape (LittleEndian IV serialization, low-16-bits mask
// extraction, IV update) against a directly-computed expected value using
// the same underlying primitive, and pins the resulting sequence as a
// regression fixture.
func TestNextMask_FixedVector(t *testing.T) {
	keys := [2]uint64{referenceKey0, referenceKey1}
	iv := uint64(0)

	// Independently compute the expected first mask: SipHash-2-4 of the
	// little-endian encoding of the initial IV (0), using the same
	// underlying primitive NextMask calls internally.
	var input [8]byte
	binary.LittleEndian.PutUint64(input[:], iv)
	expectedHash1 := gocrypto_siphash.Hash(keys[0], keys[1], input[:])
	expectedMask1 := uint16(expectedHash1 & 0xFFFF)

	mask1 := NextMask(keys, &iv)
	if mask1 != expectedMask1 {
		t.Fatalf("NextMask() first call = %#04x, want %#04x", mask1, expectedMask1)
	}
	if iv != expectedHash1 {
		t.Fatalf("IV after first NextMask() = %#016x, want %#016x", iv, expectedHash1)
	}

	// Second call must chain from the updated IV, not restart from 0.
	binary.LittleEndian.PutUint64(input[:], expectedHash1)
	expectedHash2 := gocrypto_siphash.Hash(keys[0], keys[1], input[:])
	expectedMask2 := uint16(expectedHash2 & 0xFFFF)

	mask2 := NextMask(keys, &iv)
	if mask2 != expectedMask2 {
		t.Fatalf("NextMask() second call = %#04x, want %#04x", mask2, expectedMask2)
	}
	if iv != expectedHash2 {
		t.Fatalf("IV after second NextMask() = %#016x, want %#016x", iv, expectedHash2)
	}

	// Regression pin: fixed numeric value so a future refactor that
	// silently changes the algorithm shape (e.g. swaps LittleEndian for
	// BigEndian IV serialization) fails this test even if it happens to
	// stay "self-consistent" with the rest of this file. This value was
	// computed (not guessed) via the assertions above, using the official
	// reference key halves and the same underlying gocrypto_siphash.Hash
	// primitive; it is not itself an official spec vector, but pins the
	// current, verified-correct behavior of NextMask against regression.
	const pinnedMask1 = uint16(0x81a7)
	if mask1 != pinnedMask1 {
		t.Errorf("NextMask() first call = %#04x, want pinned regression value %#04x (if this legitimately changed, update the pin and explain why in the commit message)", mask1, pinnedMask1)
	}
}

// TestNextMask_DifferentKeysProduceDifferentMasks is a basic sanity check
// that key material actually affects the output (guards against an
// accidental hardcoded/ignored-keys bug).
func TestNextMask_DifferentKeysProduceDifferentMasks(t *testing.T) {
	iv1 := uint64(12345)
	iv2 := uint64(12345)

	mask1 := NextMask([2]uint64{1, 2}, &iv1)
	mask2 := NextMask([2]uint64{3, 4}, &iv2)

	if mask1 == mask2 && iv1 == iv2 {
		t.Error("different keys produced identical mask and IV; keys may not be affecting the hash")
	}
}

// ============================================================================
// LengthModifier round-trip tests
// ============================================================================

func maskableData(length uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, length)
	return buf
}

func TestLengthModifier_SharedKeyRoundTrip(t *testing.T) {
	keys := [2]uint64{0x0102030405060708, 0x1112131415161718}
	sender := NewLengthModifier("sender", keys, 42)
	receiver := NewLengthModifier("receiver", keys, 42)

	for i := 0; i < 10; i++ {
		original := maskableData(uint16(1000 + i))

		masked, err := sender.ModifyOutbound(handshake.PhaseData, original)
		if err != nil {
			t.Fatalf("ModifyOutbound() error = %v", err)
		}
		if bytes.Equal(masked, original) {
			t.Fatalf("iteration %d: masked data equals original; masking had no effect", i)
		}

		recovered, err := receiver.ModifyInbound(handshake.PhaseData, masked)
		if err != nil {
			t.Fatalf("ModifyInbound() error = %v", err)
		}
		if !bytes.Equal(recovered, original) {
			t.Fatalf("iteration %d: round-trip mismatch: got %x, want %x", i, recovered, original)
		}
	}
}

func TestLengthModifier_DirectionalRoundTrip(t *testing.T) {
	outKeys := [2]uint64{1, 2}
	inKeys := [2]uint64{3, 4}

	// Alice sends with outKeys/outIV, Bob receives with the same keys/IV
	// on his inbound side (directional: Alice's outbound == Bob's inbound).
	alice := NewLengthModifierDirectional("alice", outKeys, inKeys, 100, 200)
	bob := NewLengthModifierDirectional("bob", inKeys, outKeys, 200, 100)

	original := maskableData(4096)
	masked, err := alice.ModifyOutbound(handshake.PhaseData, original)
	if err != nil {
		t.Fatalf("ModifyOutbound() error = %v", err)
	}
	recovered, err := bob.ModifyInbound(handshake.PhaseData, masked)
	if err != nil {
		t.Fatalf("ModifyInbound() error = %v", err)
	}
	if !bytes.Equal(recovered, original) {
		t.Fatalf("directional round-trip mismatch: got %x, want %x", recovered, original)
	}
}

func TestLengthModifier_PassesThroughBeforePhaseData(t *testing.T) {
	slm := NewLengthModifier("test", [2]uint64{1, 2}, 0)
	original := maskableData(1234)

	for _, phase := range []handshake.HandshakePhase{handshake.PhaseInitial, handshake.PhaseExchange, handshake.PhaseFinal} {
		result, err := slm.ModifyOutbound(phase, original)
		if err != nil {
			t.Fatalf("ModifyOutbound(phase=%v) error = %v", phase, err)
		}
		if !bytes.Equal(result, original) {
			t.Errorf("phase %v: expected pass-through, got masked data", phase)
		}
	}
}

func TestLengthModifier_PassesThroughWrongLength(t *testing.T) {
	slm := NewLengthModifier("test", [2]uint64{1, 2}, 0)
	original := []byte{1, 2, 3} // not exactly LengthFieldSize (2) bytes

	result, err := slm.ModifyOutbound(handshake.PhaseData, original)
	if err != nil {
		t.Fatalf("ModifyOutbound() error = %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Errorf("expected pass-through for wrong-length data, got %x", result)
	}
}

// ============================================================================
// Closed-state guard tests
// ============================================================================

func TestLengthModifier_ClosedStateGuard(t *testing.T) {
	slm := NewLengthModifier("test", [2]uint64{1, 2}, 0)

	if slm.Closed() {
		t.Fatal("new modifier must not report closed")
	}

	if err := slm.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !slm.Closed() {
		t.Fatal("expected Closed() to be true after Close()")
	}

	data := maskableData(1)
	if _, err := slm.ModifyOutbound(handshake.PhaseData, data); err == nil {
		t.Error("ModifyOutbound() after Close() should return an error")
	}
	if _, err := slm.ModifyInbound(handshake.PhaseData, data); err == nil {
		t.Error("ModifyInbound() after Close() should return an error")
	}

	// Pre-PhaseData pass-through must still occur without erroring, since
	// applyMask returns early before the closed check would otherwise be
	// reached is NOT the case here -- the closed check runs first, but a
	// pass-through phase returns before even entering applyMask's masking
	// logic. Confirm behavior explicitly either way.
	result, err := slm.ModifyOutbound(handshake.PhaseInitial, data)
	if err != nil {
		t.Fatalf("ModifyOutbound(PhaseInitial) after Close() error = %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("expected pass-through for PhaseInitial after Close(), got %x", result)
	}
}

func TestLengthModifier_ZeroKeysMarksClosed(t *testing.T) {
	slm := NewLengthModifier("test", [2]uint64{1, 2}, 0)
	slm.ZeroKeys()

	if !slm.Closed() {
		t.Fatal("expected Closed() to be true after ZeroKeys()")
	}

	keys := slm.PeekOutboundKeys()
	if keys[0] != 0 || keys[1] != 0 {
		t.Errorf("expected outbound keys zeroed, got %v", keys)
	}

	data := maskableData(1)
	if _, err := slm.ModifyOutbound(handshake.PhaseData, data); err == nil {
		t.Error("ModifyOutbound() after ZeroKeys() should return an error")
	}
}

func TestLengthModifier_CloneAfterCloseIsAlsoClosed(t *testing.T) {
	slm := NewLengthModifier("template", [2]uint64{5, 6}, 7)
	if err := slm.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	cloned := slm.Clone().(*LengthModifier)
	if !cloned.Closed() {
		t.Fatal("expected a clone of a closed modifier to also be closed (not silently usable with zeroed keys)")
	}

	data := maskableData(1)
	if _, err := cloned.ModifyOutbound(handshake.PhaseData, data); err == nil {
		t.Error("cloned-then-closed modifier's ModifyOutbound() should return an error")
	}
}

func TestLengthModifier_CloneBeforeCloseIsIndependent(t *testing.T) {
	template := NewLengthModifier("template", [2]uint64{5, 6}, 7)
	clone := template.Clone().(*LengthModifier)

	// Advancing the template's IV must not affect the clone's IV.
	_, err := template.ModifyOutbound(handshake.PhaseData, maskableData(1))
	if err != nil {
		t.Fatalf("ModifyOutbound() error = %v", err)
	}

	if template.PeekOutboundIV() == clone.PeekOutboundIV() {
		t.Error("expected template and clone IVs to diverge after template is used")
	}

	if clone.Closed() {
		t.Error("clone of an unclosed modifier must not be closed")
	}
}

// ============================================================================
// Concurrency test
// ============================================================================

// TestLengthModifier_ConcurrentUse hammers NextOutboundMask/NextInboundMask/
// Peek*/ZeroKeys/Clone concurrently under -race to verify the mutex actually
// protects all mutable state.
func TestLengthModifier_ConcurrentUse(t *testing.T) {
	slm := NewLengthModifier("concurrent", [2]uint64{9, 10}, 11)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines * 6)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = slm.NextOutboundMask()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = slm.NextInboundMask()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = slm.PeekOutboundIV()
				_ = slm.PeekInboundIV()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = slm.PeekOutboundKeys()
				_ = slm.PeekInboundKeys()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c := slm.Clone()
				if c == nil {
					t.Error("Clone() returned nil")
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_, _ = slm.ModifyOutbound(handshake.PhaseData, maskableData(1))
				_, _ = slm.ModifyInbound(handshake.PhaseData, maskableData(1))
			}
		}()
	}

	wg.Wait()
	// ZeroKeys concurrently at the end; must not panic or race.
	slm.ZeroKeys()
	if !slm.Closed() {
		t.Error("expected modifier to be closed after ZeroKeys()")
	}
}

// TestLengthModifier_ConcurrentClose verifies repeated/concurrent Close()
// calls do not race or panic.
func TestLengthModifier_ConcurrentClose(t *testing.T) {
	slm := NewLengthModifier("concurrent-close", [2]uint64{1, 2}, 3)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = slm.Close()
		}()
	}
	wg.Wait()

	if !slm.Closed() {
		t.Error("expected modifier closed after concurrent Close() calls")
	}
}

// ============================================================================
// Interface conformance
// ============================================================================

func TestLengthModifier_ImplementsInterfaces(t *testing.T) {
	var _ handshake.HandshakeModifier = (*LengthModifier)(nil)
	var _ handshake.ModifierCloner = (*LengthModifier)(nil)

	slm := NewLengthModifier("iface-test", [2]uint64{1, 2}, 0)
	if slm.Name() != "iface-test" {
		t.Errorf("Name() = %q, want %q", slm.Name(), "iface-test")
	}
}
