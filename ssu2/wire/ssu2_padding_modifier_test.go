package wire

import (
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GN-012: SSU2PaddingModifier is exercised from the external ssu2 package, but
// Close() and several EstimatePaddingSize / calculateMTUAwarePadding branches
// were never reached, so ./ssu2/wire coverage showed the family near 0%. These
// in-package tests pin the MTU-aware clamping contract that protects against a
// negative or oversized make([]byte, n) at the UDP write path.

func mustPaddingModifier(t *testing.T, minPad, maxPad, mtu int, aead bool, ratio float64) *SSU2PaddingModifier {
	t.Helper()
	m, err := NewSSU2PaddingModifierWithMTU("wire-test", minPad, maxPad, mtu, aead, ratio)
	require.NoError(t, err)
	return m
}

// Close is a documented no-op (no key material held) but must be covered and
// return nil.
func TestSSU2PaddingModifier_Close(t *testing.T) {
	m := mustPaddingModifier(t, 0, 64, defaultMTU, true, 1.0)
	require.NoError(t, m.Close())
}

func TestSSU2PaddingModifier_Name(t *testing.T) {
	m := mustPaddingModifier(t, 0, 64, defaultMTU, true, 1.0)
	assert.Equal(t, "wire-test", m.Name())
}

// EstimatePaddingSize must clamp through every branch: below-min, above-max,
// no-room, MTU-limited, and the plain ratio result.
func TestSSU2PaddingModifier_EstimatePaddingSize_Branches(t *testing.T) {
	tests := []struct {
		name          string
		min, max, mtu int
		ratio         float64
		dataLen       int
		want          int
	}{
		// ratioPadding = ceil(10*0.1) = 1 < min(50) -> return min.
		{"below min", 50, 100, 1500, 0.1, 10, 50},
		// ratioPadding = ceil(100*2.0) = 200 > max(10) -> return max.
		{"above max", 0, 10, 1500, 2.0, 100, 10},
		// ratioPadding = ceil(1280*0.05) = 64, within [0,64]; available =
		// 1280-1280-32 < 0 -> return 0.
		{"no room", 0, 64, 1280, 0.05, 1280, 0},
		// ratioPadding = ceil(1200*0.05) = 60; available = 1280-1200-32 = 48;
		// 60 > 48 -> return 48.
		{"mtu limited", 0, 64, 1280, 0.05, 1200, 48},
		// ratioPadding = ceil(100*0.5) = 50, within [0,64], available ample.
		{"plain ratio", 0, 64, 1500, 0.5, 100, 50},
		// ratio == 0 -> midpoint of [min,max] = (10+30)/2 = 20.
		{"zero ratio midpoint", 10, 30, 1500, 0.0, 100, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := mustPaddingModifier(t, tc.min, tc.max, tc.mtu, true, tc.ratio)
			assert.Equal(t, tc.want, m.EstimatePaddingSize(tc.dataLen))
		})
	}
}

// EstimatePaddingSize must never return a negative value even when dataLen
// exceeds the MTU outright.
func TestSSU2PaddingModifier_EstimatePaddingSize_NonNegative(t *testing.T) {
	m := mustPaddingModifier(t, 0, 64, 1280, true, 1.0)
	assert.GreaterOrEqual(t, m.EstimatePaddingSize(5000), 0)
}

// calculateMTUAwarePadding must clamp padding so the padded frame never
// exceeds the MTU, and must skip padding entirely when all params are zero.
func TestSSU2PaddingModifier_CalculateMTUAwarePadding(t *testing.T) {
	t.Run("clamps to available space", func(t *testing.T) {
		m := mustPaddingModifier(t, 0, 1000, 1280, true, 1.0)
		// dataLen leaves only a little room; padding must not overflow the MTU.
		pad := m.calculateMTUAwarePadding(1200)
		overhead := m.headerOverhead() + aeadTagSize + handshake.I2PBlockHeaderSize
		assert.LessOrEqual(t, 1200+overhead+pad, 1280, "padded frame must fit the MTU")
	})

	t.Run("no room yields zero", func(t *testing.T) {
		m := mustPaddingModifier(t, 0, 64, 1280, true, 1.0)
		assert.Equal(t, 0, m.calculateMTUAwarePadding(1280))
	})

	t.Run("all-zero params skip padding", func(t *testing.T) {
		m := mustPaddingModifier(t, 0, 0, 1280, true, 0.0)
		assert.Equal(t, 0, m.calculateMTUAwarePadding(100))
	})
}

// headerOverhead differs by mode: AEAD uses the 16-byte short header, cleartext
// the 32-byte long header.
func TestSSU2PaddingModifier_HeaderOverhead(t *testing.T) {
	aead := mustPaddingModifier(t, 0, 64, 1280, true, 1.0)
	assert.Equal(t, ShortHeaderSize, aead.headerOverhead())

	clear := mustPaddingModifier(t, 0, 64, 1280, false, 1.0)
	assert.Equal(t, LongHeaderSize, clear.headerOverhead())
}

// GetMTU / GetPaddingParams must reflect constructor and post-update state.
func TestSSU2PaddingModifier_Accessors(t *testing.T) {
	m := mustPaddingModifier(t, 4, 40, 1400, true, 0.5)
	assert.Equal(t, 1400, m.GetMTU())

	minPad, maxPad, ratio := m.GetPaddingParams()
	assert.Equal(t, 4, minPad)
	assert.Equal(t, 40, maxPad)
	assert.Equal(t, 0.5, ratio)

	require.NoError(t, m.UpdatePaddingParams(8, 80, 1.0))
	minPad, maxPad, ratio = m.GetPaddingParams()
	assert.Equal(t, 8, minPad)
	assert.Equal(t, 80, maxPad)
	assert.Equal(t, 1.0, ratio)

	require.NoError(t, m.SetMTU(1500))
	assert.Equal(t, 1500, m.GetMTU())
}

// validateMTU must reject values outside [1280,1500] at both the constructor
// and SetMTU seams.
func TestSSU2PaddingModifier_ValidateMTU(t *testing.T) {
	_, err := NewSSU2PaddingModifierWithMTU("bad", 0, 64, 1279, true, 1.0)
	require.Error(t, err)
	_, err = NewSSU2PaddingModifierWithMTU("bad", 0, 64, 1501, true, 1.0)
	require.Error(t, err)

	m := mustPaddingModifier(t, 0, 64, 1280, true, 1.0)
	require.Error(t, m.SetMTU(0))
	require.Error(t, m.SetMTU(2000))
	require.NoError(t, m.SetMTU(1280))
	require.NoError(t, m.SetMTU(1500))
}

// The convenience constructors must delegate to the MTU constructor with the
// documented defaults.
func TestSSU2PaddingModifier_ConvenienceConstructors(t *testing.T) {
	m, err := NewSSU2PaddingModifier("default-mtu", 0, 64, true)
	require.NoError(t, err)
	assert.Equal(t, defaultMTU, m.GetMTU())

	m2, err := NewSSU2PaddingModifierWithRatio("ratio", 0, 64, true, 2.0)
	require.NoError(t, err)
	assert.Equal(t, defaultMTU, m2.GetMTU())
	_, _, ratio := m2.GetPaddingParams()
	assert.Equal(t, 2.0, ratio)
}

// WithTestMode must make padding deterministic across two identical calls.
func TestSSU2PaddingModifier_WithTestModeDeterministic(t *testing.T) {
	m := mustPaddingModifier(t, 10, 50, 1500, true, 1.0).WithTestMode()

	data := make([]byte, 100)
	a, err := m.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	b, err := m.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	assert.Equal(t, len(a), len(b), "test mode must produce deterministic padding length")
	assert.Greater(t, len(a), len(data), "padding must grow the frame")
}

// AEAD-mode outbound padding must round-trip through inbound removal once the
// phase is at-or-past Final.
func TestSSU2PaddingModifier_ModifyRoundTrip(t *testing.T) {
	m := mustPaddingModifier(t, 10, 50, 1500, true, 1.0).WithTestMode()

	data := make([]byte, 200)
	padded, err := m.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	require.Greater(t, len(padded), len(data))

	removed, err := m.ModifyInbound(handshake.PhaseFinal, padded)
	require.NoError(t, err)
	assert.Equal(t, len(data), len(removed), "inbound removal must restore the original length")
}

// In cleartext mode, padding is folded into the KDF and ModifyInbound must be
// a pass-through (it cannot strip what it cannot locate).
func TestSSU2PaddingModifier_CleartextInboundPassthrough(t *testing.T) {
	m := mustPaddingModifier(t, 10, 50, 1500, false, 1.0).WithTestMode()

	data := make([]byte, 200)
	padded, err := m.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	require.Greater(t, len(padded), len(data))

	removed, err := m.ModifyInbound(handshake.PhaseInitial, padded)
	require.NoError(t, err)
	assert.Equal(t, padded, removed, "cleartext inbound padding is not removable")
}

// Before the Final phase, an AEAD modifier must not pad (the phase gate).
func TestSSU2PaddingModifier_AEADSkipsEarlyPhase(t *testing.T) {
	m := mustPaddingModifier(t, 10, 50, 1500, true, 1.0).WithTestMode()
	data := make([]byte, 200)
	out, err := m.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	assert.Equal(t, data, out, "AEAD modifier must not pad pre-Final phases")
}

// The constructor validates padding params (via the shared engine) before the
// MTU, so an invalid range must be rejected there.
func TestSSU2PaddingModifier_ConstructorRejectsBadPadding(t *testing.T) {
	_, err := NewSSU2PaddingModifierWithMTU("bad-pad", 64, 32, 1280, true, 1.0) // max < min
	require.Error(t, err)

	_, err = NewSSU2PaddingModifierWithMTU("bad-pad", 0, 64, 1280, true, 100.0) // ratio too high
	require.Error(t, err)
}

// UpdatePaddingParams must reject an invalid range without mutating state.
func TestSSU2PaddingModifier_UpdatePaddingParamsRejectsBad(t *testing.T) {
	m := mustPaddingModifier(t, 4, 40, 1400, true, 0.5)

	require.Error(t, m.UpdatePaddingParams(50, 10, 1.0)) // max < min

	// State must be unchanged after the rejected update.
	minPad, maxPad, ratio := m.GetPaddingParams()
	assert.Equal(t, 4, minPad)
	assert.Equal(t, 40, maxPad)
	assert.Equal(t, 0.5, ratio)
}
