package ssu2

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSSU2TestModifier creates a deterministic (TestMode) SSU2 padding modifier.
func newSSU2TestModifier(t *testing.T, name string, minPad, maxPad int, aeadMode bool) (*SSU2PaddingModifier, error) {
	t.Helper()
	mod, err := NewSSU2PaddingModifier(name, minPad, maxPad, aeadMode)
	if err != nil {
		return nil, err
	}
	return mod.WithTestMode(), nil
}

// TestNewSSU2PaddingModifier tests the constructor validation
func TestNewSSU2PaddingModifier(t *testing.T) {
	tests := []struct {
		name        string
		modName     string
		minPad      int
		maxPad      int
		aeadMode    bool
		expectError bool
	}{
		{
			name:        "valid parameters",
			modName:     "test-padding",
			minPad:      0,
			maxPad:      64,
			aeadMode:    true,
			expectError: false,
		},
		{
			name:        "negative min padding",
			modName:     "test",
			minPad:      -1,
			maxPad:      64,
			aeadMode:    true,
			expectError: true,
		},
		{
			name:        "max less than min",
			modName:     "test",
			minPad:      100,
			maxPad:      50,
			aeadMode:    true,
			expectError: true,
		},
		{
			name:        "max exceeds limit",
			modName:     "test",
			minPad:      0,
			maxPad:      65517,
			aeadMode:    true,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod, err := NewSSU2PaddingModifier(tt.modName, tt.minPad, tt.maxPad, tt.aeadMode)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mod)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mod)
				assert.Equal(t, tt.modName, mod.Name())
			}
		})
	}
}

// TestNewSSU2PaddingModifierWithRatio tests ratio-based constructor
func TestNewSSU2PaddingModifierWithRatio(t *testing.T) {
	tests := []struct {
		name        string
		ratio       float64
		expectError bool
	}{
		{"valid ratio 0.0", 0.0, false},
		{"valid ratio 1.0", 1.0, false},
		{"valid ratio 15.9375", 15.9375, false},
		{"invalid negative ratio", -0.1, true},
		{"invalid too large ratio", 16.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod, err := NewSSU2PaddingModifierWithRatio("test", 0, 64, true, tt.ratio)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mod)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mod)
			}
		})
	}
}

// TestNewSSU2PaddingModifierWithMTU tests MTU-based constructor
func TestNewSSU2PaddingModifierWithMTU(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		expectError bool
	}{
		{"valid MTU 1280", 1280, false},
		{"valid MTU 1500", 1500, false},
		{"valid MTU 1400", 1400, false},
		{"invalid MTU too small", 1279, true},
		{"invalid MTU too large", 1501, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod, err := NewSSU2PaddingModifierWithMTU("test", 0, 64, tt.mtu, true, 0.0)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mod)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mod)
				assert.Equal(t, tt.mtu, mod.GetMTU())
			}
		})
	}
}

// TestSSU2PaddingModifier_MTUConstraints tests MTU-aware padding
func TestSSU2PaddingModifier_MTUConstraints(t *testing.T) {
	mod, err := NewSSU2PaddingModifierWithMTU("test-mtu", 0, 200, 1280, true, 0.0)
	require.NoError(t, err)

	// Large data that exceeds MTU after overhead
	largeData := make([]byte, 1200)
	_, err = rand.Read(largeData)
	require.NoError(t, err)

	result, err := mod.ModifyOutbound(handshake.PhaseFinal, largeData)
	require.NoError(t, err)

	// Result should not exceed MTU
	assert.LessOrEqual(t, len(result), 1280, "padded data should respect MTU")
}

// TestSSU2PaddingModifier_CleartextPadding tests cleartext padding
func TestSSU2PaddingModifier_CleartextPadding(t *testing.T) {
	mod, err := newSSU2TestModifier(t, "test-cleartext", 16, 32, false)
	require.NoError(t, err)

	data := []byte("Hello, SSU2!")

	// Apply padding in Initial phase (cleartext)
	padded, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	assert.Greater(t, len(padded), len(data), "padding should be added")

	// ModifyInbound should return data as-is (cleartext padding in KDF)
	recovered, err := mod.ModifyInbound(handshake.PhaseInitial, padded)
	require.NoError(t, err)
	assert.Equal(t, padded, recovered, "cleartext padding not removed on inbound")
}

// TestSSU2PaddingModifier_AEADPadding tests AEAD padding
func TestSSU2PaddingModifier_AEADPadding(t *testing.T) {
	mod, err := newSSU2TestModifier(t, "test-aead", 16, 32, true)
	require.NoError(t, err)

	data := []byte("Hello, SSU2!")

	// Apply AEAD padding in Final phase
	padded, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	assert.Greater(t, len(padded), len(data), "AEAD padding should be added")

	// Verify block format
	assert.Equal(t, byte(254), padded[len(data)], "should have padding block type 254")

	// Remove padding
	recovered, err := mod.ModifyInbound(handshake.PhaseFinal, padded)
	require.NoError(t, err)
	assert.Equal(t, data, recovered, "AEAD padding should be removed")
}

// TestSSU2PaddingModifier_Roundtrip tests padding roundtrip
func TestSSU2PaddingModifier_Roundtrip(t *testing.T) {
	mod, err := NewSSU2PaddingModifierWithRatio("test-roundtrip", 0, 64, true, 1.0)
	require.NoError(t, err)

	testData := [][]byte{
		[]byte("short"),
		[]byte("medium length data"),
		make([]byte, 100),
		make([]byte, 500),
	}

	for _, data := range testData {
		t.Run(string(rune(len(data)))+"_bytes", func(t *testing.T) {
			if len(data) > 20 {
				_, _ = rand.Read(data)
			}

			// Add padding
			padded, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
			require.NoError(t, err)
			assert.Greater(t, len(padded), len(data))

			// Remove padding
			recovered, err := mod.ModifyInbound(handshake.PhaseFinal, padded)
			require.NoError(t, err)
			assert.Equal(t, data, recovered)
		})
	}
}

// TestSSU2PaddingModifier_PhaseSpecific tests phase-specific behavior
func TestSSU2PaddingModifier_PhaseSpecific(t *testing.T) {
	// Test cleartext modifier (messages 1-2)
	cleartextMod, err := NewSSU2PaddingModifier("cleartext", 16, 32, false)
	require.NoError(t, err)

	// Test AEAD modifier (message 3+)
	aeadMod, err := NewSSU2PaddingModifier("aead", 16, 32, true)
	require.NoError(t, err)

	data := []byte("test data")

	// Cleartext should pad in Initial/Exchange but not Final
	padded1, _ := cleartextMod.ModifyOutbound(handshake.PhaseInitial, data)
	assert.Greater(t, len(padded1), len(data), "cleartext pads in Initial")

	padded2, _ := cleartextMod.ModifyOutbound(handshake.PhaseFinal, data)
	assert.Equal(t, data, padded2, "cleartext doesn't pad in Final")

	// AEAD should not pad in Initial/Exchange but pads in Final
	padded3, _ := aeadMod.ModifyOutbound(handshake.PhaseInitial, data)
	assert.Equal(t, data, padded3, "AEAD doesn't pad in Initial")

	padded4, _ := aeadMod.ModifyOutbound(handshake.PhaseFinal, data)
	assert.Greater(t, len(padded4), len(data), "AEAD pads in Final")
}

// TestSSU2PaddingModifier_UpdatePaddingParams tests dynamic parameter updates
func TestSSU2PaddingModifier_UpdatePaddingParams(t *testing.T) {
	mod, err := NewSSU2PaddingModifier("test-update", 0, 64, true)
	require.NoError(t, err)

	// Update parameters
	err = mod.UpdatePaddingParams(32, 128, 2.0)
	require.NoError(t, err)

	minPad, maxPad, ratio := mod.GetPaddingParams()
	assert.Equal(t, 32, minPad)
	assert.Equal(t, 128, maxPad)
	assert.Equal(t, 2.0, ratio)

	// Invalid updates
	err = mod.UpdatePaddingParams(-1, 64, 0.0)
	assert.Error(t, err)

	err = mod.UpdatePaddingParams(0, 64, 20.0)
	assert.Error(t, err)
}

// TestSSU2PaddingModifier_SetMTU tests dynamic MTU updates
func TestSSU2PaddingModifier_SetMTU(t *testing.T) {
	mod, err := NewSSU2PaddingModifier("test-mtu-update", 0, 64, true)
	require.NoError(t, err)

	// Update MTU
	err = mod.SetMTU(1500)
	require.NoError(t, err)
	assert.Equal(t, 1500, mod.GetMTU())

	// Invalid MTU
	err = mod.SetMTU(1000)
	assert.Error(t, err)

	err = mod.SetMTU(2000)
	assert.Error(t, err)
}

// TestSSU2PaddingModifier_RatioPadding tests ratio-based padding calculation
func TestSSU2PaddingModifier_RatioPadding(t *testing.T) {
	tests := []struct {
		ratio       float64
		dataLen     int
		minExpected int
	}{
		{1.0, 100, 100}, // 100% padding
		{0.5, 100, 50},  // 50% padding
		{2.0, 100, 200}, // 200% padding
	}

	for _, tt := range tests {
		t.Run(string(rune(int(tt.ratio*10))), func(t *testing.T) {
			mod, err := NewSSU2PaddingModifierWithRatio("test", 0, 500, true, tt.ratio)
			require.NoError(t, err)

			data := make([]byte, tt.dataLen)
			padded, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
			require.NoError(t, err)

			// Padding should be approximately ratio-based (with random variation)
			paddingAdded := len(padded) - len(data) - 3 // Subtract AEAD block header
			assert.GreaterOrEqual(t, paddingAdded, tt.minExpected/2, "padding should be significant")
		})
	}
}

// TestSSU2PaddingModifier_ZeroPadding tests no-padding scenario
func TestSSU2PaddingModifier_ZeroPadding(t *testing.T) {
	mod, err := NewSSU2PaddingModifier("test-zero", 0, 0, true)
	require.NoError(t, err)

	data := []byte("test data")
	result, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)

	assert.Equal(t, data, result, "no padding should be added when min/max are 0")
}

// TestSSU2PaddingModifier_ThreadSafety tests concurrent operations
func TestSSU2PaddingModifier_ThreadSafety(t *testing.T) {
	mod, err := NewSSU2PaddingModifier("test-concurrent", 0, 64, true)
	require.NoError(t, err)

	done := make(chan bool, 3)
	data := []byte("concurrent test")

	// Concurrent ModifyOutbound
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = mod.ModifyOutbound(handshake.PhaseFinal, data)
		}
		done <- true
	}()

	// Concurrent UpdatePaddingParams
	go func() {
		for i := 0; i < 100; i++ {
			_ = mod.UpdatePaddingParams(0, 128, 1.0)
		}
		done <- true
	}()

	// Concurrent SetMTU
	go func() {
		for i := 0; i < 100; i++ {
			_ = mod.SetMTU(1400)
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}
}

// TestSSU2PaddingModifier_EstimatePaddingSize tests padding estimation
func TestSSU2PaddingModifier_EstimatePaddingSize(t *testing.T) {
	mod, err := NewSSU2PaddingModifierWithRatio("test-estimate", 0, 64, true, 1.0)
	require.NoError(t, err)

	estimate := mod.EstimatePaddingSize(100)
	assert.Greater(t, estimate, 0, "should estimate non-zero padding")
	assert.LessOrEqual(t, estimate, 64, "should not exceed max padding")
}

// TestSSU2PaddingModifier_EstimatePaddingSize_NeverNegative is the regression
// test for AUDIT.md Level 5 item 2: when dataLen is close to or exceeds the
// MTU, availableSpace can go negative; EstimatePaddingSize must clamp to 0
// (matching calculateMTUAwarePadding's existing behavior) rather than
// returning a negative size that could panic a caller doing
// make([]byte, negativeValue).
func TestSSU2PaddingModifier_EstimatePaddingSize_NeverNegative(t *testing.T) {
	const mtu = 1280
	mod, err := NewSSU2PaddingModifierWithMTU("test-estimate-negative", 0, 64, mtu, true, 1.0)
	require.NoError(t, err)

	// dataLen deliberately exceeds the MTU so availableSpace = mtu - dataLen
	// - overhead is negative.
	estimate := mod.EstimatePaddingSize(mtu + 100)
	assert.GreaterOrEqual(t, estimate, 0, "EstimatePaddingSize must never return a negative value")
}

// TestSSU2PaddingModifier_MTUBoundaries tests MTU boundary conditions
func TestSSU2PaddingModifier_MTUBoundaries(t *testing.T) {
	tests := []struct {
		mtu     int
		dataLen int
		maxPad  int
	}{
		{1280, 1000, 200},
		{1500, 1200, 300},
		{1400, 1100, 250},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.mtu)), func(t *testing.T) {
			mod, err := NewSSU2PaddingModifierWithMTU("test", 0, tt.maxPad, tt.mtu, true, 0.0)
			require.NoError(t, err)

			data := make([]byte, tt.dataLen)
			padded, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
			require.NoError(t, err)

			// Total size should respect MTU
			assert.LessOrEqual(t, len(padded), tt.mtu, "should respect MTU limit")
		})
	}
}

// TestSSU2PaddingModifier_SecureRandomness tests that production mode uses secure random
func TestSSU2PaddingModifier_SecureRandomness(t *testing.T) {
	mod1, err := NewSSU2PaddingModifier("prod1", 16, 32, true)
	require.NoError(t, err)

	mod2, err := NewSSU2PaddingModifier("prod2", 16, 32, true)
	require.NoError(t, err)

	data := []byte("test data for randomness")

	// Same data should produce different padding due to random variation
	padded1, err := mod1.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)

	padded2, err := mod2.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)

	// Padded data should differ (very unlikely to match with secure random)
	assert.False(t, bytes.Equal(padded1, padded2), "production mode should use secure random")
}

// TestSSU2PaddingModifier_DeterministicTesting tests deterministic mode
func TestSSU2PaddingModifier_DeterministicTesting(t *testing.T) {
	mod, err := newSSU2TestModifier(t, "test-deterministic", 16, 32, true)
	require.NoError(t, err)

	data := []byte("deterministic test")

	// Same data should produce same padding in test mode
	padded1, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)

	padded2, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)

	assert.Equal(t, padded1, padded2, "test mode should be deterministic")
}

// BenchmarkSSU2Padding benchmarks padding operations
func BenchmarkSSU2Padding(b *testing.B) {
	mod, _ := NewSSU2PaddingModifier("bench", 0, 64, true)
	data := make([]byte, 100)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ModifyOutbound(handshake.PhaseFinal, data)
	}
}

// BenchmarkSSU2PaddingRemoval benchmarks padding removal
func BenchmarkSSU2PaddingRemoval(b *testing.B) {
	mod, _ := NewSSU2PaddingModifier("bench", 0, 64, true)
	data := make([]byte, 100)
	padded, _ := mod.ModifyOutbound(handshake.PhaseFinal, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ModifyInbound(handshake.PhaseFinal, padded)
	}
}
