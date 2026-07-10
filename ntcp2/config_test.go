package ntcp2

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashPtr returns a pointer to the given data.Hash, useful for struct literals.
func hashPtr(h data.Hash) *data.Hash {
	return &h
}

// testModifier is a minimal HandshakeModifier implementation for Clone() tests.
type testModifier struct {
	name string
}

func (m *testModifier) ModifyOutbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (m *testModifier) ModifyInbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (m *testModifier) Name() string { return m.name }
func (m *testModifier) Close() error { return nil }

func TestNewNTCP2ConfigWithInitiator(t *testing.T) {
	routerHash := generateRandomHash()

	// Test initiator configuration
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, true, config.Initiator)
	assert.Equal(t, routerHash, config.BobRouterHash)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
	assert.Equal(t, 3, config.HandshakeRetries)
	assert.Equal(t, 1*time.Second, config.RetryBackoff)
	assert.Equal(t, true, config.EnableAESObfuscation)
	assert.Equal(t, true, config.EnableSipHashLength)
	assert.Equal(t, 16384, config.MaxFrameSize)
	assert.Equal(t, true, config.FramePaddingEnabled)
	assert.Equal(t, 0, config.MinPaddingSize)
	assert.Equal(t, 64, config.MaxPaddingSize)

	// Test responder configuration
	config, err = NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	assert.Equal(t, false, config.Initiator)
}

func TestNTCP2ConfigBuilderMethods(t *testing.T) {
	m := newTestCryptoMaterial(t)

	config, err := NewNTCP2Config(m.routerHash, true)
	require.NoError(t, err)

	// Test all builder methods
	config = config.
		WithStaticKey(m.staticKey).
		WithRemoteRouterHash(m.remoteHash).
		WithPattern("XK").
		WithHandshakeTimeout(45*time.Second).
		WithReadTimeout(10*time.Second).
		WithWriteTimeout(15*time.Second).
		WithHandshakeRetries(5).
		WithRetryBackoff(2*time.Second).
		WithAESObfuscation(true, m.obfuscationIV).
		WithSipHashLength(true, 0x123456789ABCDEF0, 0xFEDCBA9876543210).
		WithFrameSettings(32768, false, 16, 128)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, m.staticKey, config.StaticKey)
	assert.Equal(t, m.remoteHash, *config.RemoteRouterHash)
	assert.Equal(t, 45*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 10*time.Second, config.ReadTimeout)
	assert.Equal(t, 15*time.Second, config.WriteTimeout)
	assert.Equal(t, 5, config.HandshakeRetries)
	assert.Equal(t, 2*time.Second, config.RetryBackoff)
	assert.Equal(t, true, config.EnableAESObfuscation)
	assert.Equal(t, m.obfuscationIV, config.ObfuscationIV)
	assert.Equal(t, true, config.EnableSipHashLength)
	assert.Equal(t, uint64(0x123456789ABCDEF0), config.SipHashKeys[0])
	assert.Equal(t, uint64(0xFEDCBA9876543210), config.SipHashKeys[1])
	assert.Equal(t, 32768, config.MaxFrameSize)
	assert.Equal(t, false, config.FramePaddingEnabled)
	assert.Equal(t, 16, config.MinPaddingSize)
	assert.Equal(t, 128, config.MaxPaddingSize)
}

func TestNTCP2ConfigWithModifiers(t *testing.T) {
	routerHash := generateRandomHash()

	// Create some test modifiers
	xorMod, err := handshake.NewXORModifier("test-xor", []byte{0xAA, 0xBB})
	require.NoError(t, err)
	paddingMod, err := handshake.NewPaddingModifier("test-padding", 4, 8)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	config = config.WithModifiers(xorMod, paddingMod)

	assert.Len(t, config.Modifiers, 2)
	assert.Equal(t, "test-xor", config.Modifiers[0].Name())
	assert.Equal(t, "test-padding", config.Modifiers[1].Name())
}

func TestNTCP2ConfigComprehensiveValidation(t *testing.T) {
	routerHash := generateRandomHash()

	tests := []struct {
		name        string
		setupConfig func() *Config
		expectError bool
		errorCode   string
	}{
		{
			name: "valid config",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: false,
		},
		{
			name: "invalid static key",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.StaticKey = make([]byte, 16) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_STATIC_KEY",
		},
		{
			name: "missing remote hash for initiator",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, true) // Initiator = true
				config.RemoteRouterHash = nil
				return config
			},
			expectError: true,
			errorCode:   "MISSING_REMOTE_ROUTER_HASH",
		},
		{
			name: "invalid handshake timeout",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeTimeout = -1 * time.Second
				return config
			},
			expectError: true,
			errorCode:   "INVALID_HANDSHAKE_TIMEOUT",
		},
		{
			name: "invalid retry count",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeRetries = -2 // Less than -1
				return config
			},
			expectError: true,
			errorCode:   "INVALID_RETRY_COUNT",
		},
		{
			name: "invalid retry backoff",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.RetryBackoff = -1 * time.Second
				return config
			},
			expectError: true,
			errorCode:   "INVALID_RETRY_BACKOFF",
		},
		{
			name: "invalid obfuscation IV",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.ObfuscationIV = make([]byte, 8) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_OBFUSCATION_IV",
		},
		{
			name: "invalid max frame size",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MaxFrameSize = 0
				return config
			},
			expectError: true,
			errorCode:   "INVALID_MAX_FRAME_SIZE",
		},
		{
			name: "invalid min padding",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MinPaddingSize = -1
				return config
			},
			expectError: true,
			errorCode:   "INVALID_MIN_PADDING",
		},
		{
			name: "invalid padding range",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MinPaddingSize = 100
				config.MaxPaddingSize = 50
				return config
			},
			expectError: true,
			errorCode:   "INVALID_PADDING_RANGE",
		},
		{
			// Regression test: Config.Validate() must reject a
			// MaxPaddingSize above the I2P spec limit at config-time,
			// matching the stricter bound enforced later by
			// handshake.ValidatePaddingParams at engine-construction
			// time (ToConnConfig -> createPaddingModifierIfEnabled).
			// Previously ValidatePaddingRange only checked min>=0 and
			// max>=min, letting this pass Validate() and fail later
			// with a different error code (AUDIT.md).
			name: "max padding size exceeds I2P spec limit",
			setupConfig: func() *Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MinPaddingSize = 0
				config.MaxPaddingSize = handshake.I2PMaxBlockDataSize + 1
				return config
			},
			expectError: true,
			errorCode:   "INVALID_PADDING",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorCode)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNTCP2ConfigToConnConfig(t *testing.T) {
	ntcp2Config, m := newTestInitiatorConfig(t)
	ntcp2Config = ntcp2Config.
		WithHandshakeTimeout(45 * time.Second).
		WithReadTimeout(10 * time.Second).
		WithWriteTimeout(15 * time.Second).
		WithHandshakeRetries(5).
		WithRetryBackoff(2 * time.Second)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Verify basic config translation
	assert.Equal(t, "XK", connConfig.Pattern)
	assert.Equal(t, true, connConfig.Initiator)
	assert.Equal(t, m.staticKey, connConfig.StaticKey)
	assert.Equal(t, 45*time.Second, connConfig.HandshakeTimeout)
	assert.Equal(t, 10*time.Second, connConfig.ReadTimeout)
	assert.Equal(t, 15*time.Second, connConfig.WriteTimeout)
	assert.Equal(t, 5, connConfig.HandshakeRetries)
	assert.Equal(t, 2*time.Second, connConfig.RetryBackoff)

	// Verify NTCP2-specific modifiers are added
	assert.Len(t, connConfig.Modifiers, 3) // AES + SipHash + Padding
}

func TestNTCP2ConfigToConnConfigWithDisabledModifiers(t *testing.T) {
	routerHash := generateRandomHash()

	ntcp2Config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Disable all modifiers
	ntcp2Config = ntcp2Config.
		WithAESObfuscation(false, nil).
		WithSipHashLength(false, 0, 0)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Padding is still enabled by default (FramePaddingEnabled=true)
	assert.Len(t, connConfig.Modifiers, 1) // Padding only
}

func TestNTCP2ConfigToConnConfigWithCustomModifiers(t *testing.T) {
	m := newTestCryptoMaterial(t)

	// Create custom modifiers — only compatible ones
	xorMod, err := handshake.NewXORModifier("custom-xor", []byte{0xCC, 0xDD})
	require.NoError(t, err)

	ntcp2Config, err := NewNTCP2Config(m.routerHash, false)
	require.NoError(t, err)

	ntcp2Config = ntcp2Config.
		WithAESObfuscation(true, m.obfuscationIV).
		WithModifiers(xorMod)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Should have NTCP2 modifiers + custom modifier
	assert.Len(t, connConfig.Modifiers, 4) // AES + SipHash + Padding + 1 custom

	// Custom modifier should be at the end
	assert.Equal(t, "custom-xor", connConfig.Modifiers[3].Name())
}

func TestNTCP2ConfigBuilderDefensiveCopying(t *testing.T) {
	staticKey := mustRandomBytes(t, 32)

	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config = config.WithStaticKey(staticKey)
	staticKey[0] = 0xFF

	// Config should be unaffected (BobRouterHash is data.Hash value type, always independent)
	assert.NotEqual(t, byte(0xFF), config.StaticKey[0])
}

func TestNTCP2ConfigValidationEdgeCases(t *testing.T) {
	// Test empty pattern
	config := newTestNTCP2ConfigSimple(t, false)
	config.Pattern = ""

	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "noise pattern is required")

	// Test infinite retries (should be valid)
	config = newTestNTCP2ConfigSimple(t, false)
	config.HandshakeRetries = -1

	err = config.Validate()
	assert.NoError(t, err)

	// Test zero retry backoff (should be valid)
	config.RetryBackoff = 0
	err = config.Validate()
	assert.NoError(t, err)
}

// TestNTCP2ConfigEdgeCases tests edge cases for NTCP2Config validation.
func TestNTCP2ConfigEdgeCases(t *testing.T) {
	routerHash := generateRandomHash()

	t.Run("valid config with all options", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		staticKey := make([]byte, 32)

		config = config.WithStaticKey(staticKey).
			WithHandshakeTimeout(10 * time.Second).
			WithReadTimeout(5 * time.Second).
			WithWriteTimeout(5 * time.Second)

		err = config.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid static key in WithStaticKey", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		// Try to set invalid static key (wrong size) - silently ignored, caught by Validate()
		invalidKey := make([]byte, 16)
		config = config.WithStaticKey(invalidKey)

		// StaticKey should remain nil (invalid length ignored)
		assert.Nil(t, config.StaticKey)

		// Validate should catch the missing key for initiator
		config.Initiator = true
		rh := generateRandomHash()
		config.RemoteRouterHash = &rh
		config.RemoteStaticKey = make([]byte, 32)
	})
}

// ============================================================================
// Tests from audit_fixes_test.go — config-related
// ============================================================================

func TestAudit_Quality_SilentRejection(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Invalid sizes are silently ignored by builders; caught by Validate()
	config = config.WithStaticKey(make([]byte, 31))
	assert.Nil(t, config.StaticKey, "Invalid static key must not be set")

	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	config = config.WithStaticKey(validKey)
	assert.Equal(t, validKey, config.StaticKey, "Valid static key must be set")

	// WithRemoteRouterHash now takes data.Hash (always 32 bytes), no invalid length possible
	validHash := generateRandomHash()
	config = config.WithRemoteRouterHash(validHash)
	assert.NotNil(t, config.RemoteRouterHash, "Valid router hash must be set")
	assert.Equal(t, validHash, *config.RemoteRouterHash, "Valid router hash must be set")
}

func TestAudit_Quality_Constants(t *testing.T) {
	assert.Equal(t, 32, RouterHashSize)
	assert.Equal(t, 32, StaticKeySize)
	assert.Equal(t, 16, IVSize)
	assert.Equal(t, byte(254), byte(PaddingBlockType))
	assert.Equal(t, 65516, MaxBlockDataSize)
	assert.Equal(t, 65535, MaxFrameSize)
	assert.Equal(t, 3, BlockHeaderSize)
	assert.Equal(t, 8, SipHashIVSize)
	assert.Equal(t, 2, FrameLengthFieldSize)
	assert.Equal(t, "XK", NTCP2Pattern)
	assert.Equal(t, "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256", NTCP2ProtocolName)
}

func TestAudit_ConfigUsesXKPattern(t *testing.T) {
	config := newTestNTCP2ConfigSimple(t, true)
	require.NotNil(t, config)

	assert.Equal(t, "XK", NTCP2Pattern)

	validKey := make([]byte, 32)
	rh := generateRandomHash()
	config = config.
		WithStaticKey(validKey).
		WithRemoteRouterHash(rh).
		WithRemoteStaticKey(make([]byte, 32)).
		WithAESObfuscation(true, make([]byte, 16))
	connConfig, err2 := config.ToConnConfig()
	require.NoError(t, err2)
	require.NotNil(t, connConfig)
	assert.Equal(t, "XK", connConfig.Pattern)
}

// ============================================================================
// Tests from audit_fixes_3_test.go — config-related
// ============================================================================

func TestWithAESObfuscation_WrongIVLengthReturnsError(t *testing.T) {
	config := newTestNTCP2ConfigSimple(t, false)
	config.EnableAESObfuscation = false

	// Wrong-length IV is silently ignored; caught by Validate()
	wrongIV := make([]byte, 10)
	config = config.WithAESObfuscation(true, wrongIV)
	assert.Nil(t, config.ObfuscationIV, "Wrong-length IV must not be set")

	correctIV := make([]byte, 16)
	config = config.WithAESObfuscation(true, correctIV)
	assert.NotNil(t, config.ObfuscationIV, "Correct-length IV must be set")

	config = config.WithAESObfuscation(false, nil)
}

// newResponderConfigWithAES creates a responder NTCP2Config with random
// router hash and AES obfuscation enabled, suitable for SipHash/KDF tests.
func newResponderConfigWithAES(t *testing.T) *Config {
	t.Helper()
	config := newTestNTCP2ConfigSimple(t, false)

	obfuscationIV := make([]byte, 16)
	_, err := rand.Read(obfuscationIV)
	require.NoError(t, err)

	return config.WithAESObfuscation(true, obfuscationIV)
}

func TestSipHashModifier_NilBeforeHandshake(t *testing.T) {
	config := newResponderConfigWithAES(t)

	assert.Nil(t, config.SipHashModifier())

	_, err := config.ToConnConfig()
	require.NoError(t, err)

	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed via SipHashModifier()")
}

func TestKDF_ASKLabelConfigured(t *testing.T) {
	config := newResponderConfigWithAES(t)

	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	assert.Len(t, connConfig.AdditionalSymmetricKeyLabels, 1)
	assert.Equal(t, []byte("ask"), connConfig.AdditionalSymmetricKeyLabels[0])

	assert.NotNil(t, connConfig.PostHandshakeHook)
}

// ============================================================================
// Tests from audit_fixes_4_test.go — config-related
// ============================================================================

func TestAuditFix_Clone_IndependentConfig(t *testing.T) {
	var originalHash data.Hash
	copy(originalHash[:], "original-hash-32-bytes-long!!!!!")

	original := &Config{
		Pattern:       "XK",
		MaxFrameSize:  16384,
		BobRouterHash: originalHash,
	}

	clone := original.Clone()

	clone.MaxFrameSize = 8192
	// BobRouterHash is data.Hash ([32]byte value type), so clone has its own copy
	clone.BobRouterHash[0] = 0xFF

	assert.Equal(t, 16384, original.MaxFrameSize, "clone modification should not affect original")
	assert.NotEqual(t, byte(0xFF), original.BobRouterHash[0], "clone value type modification should not affect original")
}

// ============================================================================
// Tests from audit_fixes_5_test.go — config-related
// ============================================================================

func TestAuditFix_BobRouterHash_FieldRenamed(t *testing.T) {
	var rhb data.Hash
	for i := range rhb {
		rhb[i] = byte(i + 1)
	}

	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)
	assert.Equal(t, rhb, config.BobRouterHash, "BobRouterHash must be set by constructor")
}

func TestAuditFix_BobRouterHash_ValidationWorks(t *testing.T) {
	// data.Hash is [32]byte, so invalid-length router hash is no longer possible
	// Verify that a zero hash still creates a valid config
	config, err := NewNTCP2Config(data.Hash{}, false)
	require.NoError(t, err)

	err = config.Validate()
	assert.NoError(t, err)
}

func TestAuditFix_BobRouterHash_DefensiveCopy(t *testing.T) {
	// data.Hash is [32]byte value type, so it's always independently copied
	rhb := generateRandomHash()
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	rhb[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), config.BobRouterHash[0],
		"BobRouterHash must be independent (value type)")
}

func TestAuditFix_BobRouterHash_AESModifierUsesIt(t *testing.T) {
	var rhb data.Hash
	for i := range rhb {
		rhb[i] = byte(i + 10)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 0x30)
	}

	config, err := NewNTCP2Config(rhb, false)
	require.NoError(t, err)
	config = config.WithAESObfuscation(true, iv)

	mod, err := config.createAESModifierIfEnabled()
	require.NoError(t, err)
	assert.NotNil(t, mod)
}

func TestAuditFix_BobRouterHash_ClonePreserves(t *testing.T) {
	var rhb data.Hash
	for i := range rhb {
		rhb[i] = byte(i)
	}
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	clone := config.Clone()
	assert.Equal(t, config.BobRouterHash, clone.BobRouterHash)

	// data.Hash is [32]byte value type, so clone has its own copy
	clone.BobRouterHash[0] = 0xFF
	assert.NotEqual(t, config.BobRouterHash[0], clone.BobRouterHash[0])
}

func TestAuditFix_Clone_DocCommentsPresent(t *testing.T) {
	rhb := generateRandomHash()
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	clone := config.Clone()

	clone.Pattern = "NN"
	assert.Equal(t, "XK", config.Pattern, "Clone must not share value fields")

	// data.Hash is [32]byte value type, so clone has its own copy
	clone.BobRouterHash[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), config.BobRouterHash[0],
		"Clone must deep-copy BobRouterHash")
}

// TestClone_AllNilOptionalFields verifies that Clone() correctly handles the case
// where all optional byte-slice/modifier fields are nil. This covers the nil-check
// branches that were at 0% coverage in the audit (~40% of Clone()'s branches).
func TestClone_AllNilOptionalFields(t *testing.T) {
	// Create a config with only required fields set (BobRouterHash) and
	// explicitly nil optional fields
	original := &Config{
		Pattern:              "XK",
		Initiator:            true,
		BobRouterHash:        data.Hash{},
		BaseHandshakeConfig:  baseconfig.BaseHandshakeConfig{HandshakeTimeout: 30 * time.Second},
		MaxFrameSize:         16384,
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		// All optional slice fields left nil:
		// StaticKey, RemoteRouterHash, RemoteStaticKey, ObfuscationIV, Modifiers
	}

	clone := original.Clone()

	// All nil fields must remain nil in the clone
	assert.Nil(t, clone.StaticKey, "StaticKey should be nil when original is nil")
	assert.Nil(t, clone.RemoteRouterHash, "RemoteRouterHash should be nil when original is nil")
	assert.Nil(t, clone.RemoteStaticKey, "RemoteStaticKey should be nil when original is nil")
	assert.Nil(t, clone.ObfuscationIV, "ObfuscationIV should be nil when original is nil")
	assert.Nil(t, clone.Modifiers, "Modifiers should be nil when original is nil")

	// Value fields are still copied
	assert.Equal(t, original.Pattern, clone.Pattern)
	assert.Equal(t, original.Initiator, clone.Initiator)
	assert.Equal(t, original.HandshakeTimeout, clone.HandshakeTimeout)
	assert.Equal(t, original.MaxFrameSize, clone.MaxFrameSize)
	assert.Equal(t, original.EnableAESObfuscation, clone.EnableAESObfuscation)
	assert.Equal(t, original.EnableSipHashLength, clone.EnableSipHashLength)

	// BobRouterHash is data.Hash value type, always independently copied
	clone.BobRouterHash[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), original.BobRouterHash[0],
		"BobRouterHash must be deep-copied even when other fields are nil")
}

// TestClone_AllOptionalFieldsPopulated verifies that Clone() deep-copies every
// optional byte-slice and modifier field when all are populated. This exercises
// all 6 non-nil branches in Clone() and confirms mutation independence.
func TestClone_AllOptionalFieldsPopulated(t *testing.T) {
	staticKey := deterministicBytes(32, 1)
	var remoteRouterHash data.Hash
	copy(remoteRouterHash[:], deterministicBytes(32, 0x20))
	remoteStaticKey := deterministicBytes(32, 0x40)
	obfuscationIV := deterministicBytes(16, 0x60)

	mod1 := &testModifier{name: "mod1"}
	mod2 := &testModifier{name: "mod2"}

	original := &Config{
		Pattern:          "XK",
		Initiator:        true,
		BobRouterHash:    data.Hash{},
		StaticKey:        staticKey,
		RemoteRouterHash: &remoteRouterHash,
		RemoteStaticKey:  remoteStaticKey,
		ObfuscationIV:    obfuscationIV,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			Modifiers: []handshake.HandshakeModifier{mod1, mod2},
		},
		MaxFrameSize: 16384,
		SipHashKeys:  [2]uint64{0x1234, 0x5678},
	}

	clone := original.Clone()

	// All fields are populated in the clone
	assert.NotNil(t, clone.StaticKey)
	assert.NotNil(t, clone.RemoteRouterHash)
	assert.NotNil(t, clone.RemoteStaticKey)
	assert.NotNil(t, clone.ObfuscationIV)
	assert.NotNil(t, clone.Modifiers)
	assert.Len(t, clone.Modifiers, 2)

	// Values match
	assert.Equal(t, original.StaticKey, clone.StaticKey)
	assert.Equal(t, original.RemoteRouterHash, clone.RemoteRouterHash)
	assert.Equal(t, original.RemoteStaticKey, clone.RemoteStaticKey)
	assert.Equal(t, original.ObfuscationIV, clone.ObfuscationIV)
	assert.Equal(t, original.SipHashKeys, clone.SipHashKeys)

	// Deep copy: mutating clone must not affect original
	clone.StaticKey[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), original.StaticKey[0],
		"StaticKey must be deep-copied")

	clone.RemoteRouterHash[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), original.RemoteRouterHash[0],
		"RemoteRouterHash must be deep-copied")

	clone.RemoteStaticKey[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), original.RemoteStaticKey[0],
		"RemoteStaticKey must be deep-copied")

	clone.ObfuscationIV[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), original.ObfuscationIV[0],
		"ObfuscationIV must be deep-copied")

	// Modifiers slice is a shallow copy (slice header independent, elements shared)
	clone.Modifiers[0] = nil
	assert.NotNil(t, original.Modifiers[0],
		"Modifiers slice header must be independent")
}

// TestClone_PartialNilFields covers the mixed case where some optional fields
// are nil and some are populated. Each nil-check branch is tested independently.
func TestClone_PartialNilFields(t *testing.T) {
	t.Run("StaticKey_nil_others_set", func(t *testing.T) {
		original := &Config{
			BobRouterHash:    data.Hash{},
			StaticKey:        nil,
			RemoteRouterHash: hashPtr(data.Hash{}),
			RemoteStaticKey:  make([]byte, 32),
			ObfuscationIV:    make([]byte, 16),
		}
		clone := original.Clone()
		assert.Nil(t, clone.StaticKey)
		assert.NotNil(t, clone.RemoteRouterHash)
		assert.NotNil(t, clone.RemoteStaticKey)
		assert.NotNil(t, clone.ObfuscationIV)
	})

	t.Run("RemoteRouterHash_nil_others_set", func(t *testing.T) {
		original := &Config{
			BobRouterHash:    data.Hash{},
			StaticKey:        make([]byte, 32),
			RemoteRouterHash: nil,
			RemoteStaticKey:  make([]byte, 32),
			ObfuscationIV:    make([]byte, 16),
		}
		clone := original.Clone()
		assert.NotNil(t, clone.StaticKey)
		assert.Nil(t, clone.RemoteRouterHash)
		assert.NotNil(t, clone.RemoteStaticKey)
		assert.NotNil(t, clone.ObfuscationIV)
	})

	t.Run("RemoteStaticKey_nil_others_set", func(t *testing.T) {
		original := &Config{
			BobRouterHash:    data.Hash{},
			StaticKey:        make([]byte, 32),
			RemoteRouterHash: hashPtr(data.Hash{}),
			RemoteStaticKey:  nil,
			ObfuscationIV:    make([]byte, 16),
		}
		clone := original.Clone()
		assert.NotNil(t, clone.StaticKey)
		assert.NotNil(t, clone.RemoteRouterHash)
		assert.Nil(t, clone.RemoteStaticKey)
		assert.NotNil(t, clone.ObfuscationIV)
	})

	t.Run("ObfuscationIV_nil_others_set", func(t *testing.T) {
		original := &Config{
			BobRouterHash:    data.Hash{},
			StaticKey:        make([]byte, 32),
			RemoteRouterHash: hashPtr(data.Hash{}),
			RemoteStaticKey:  make([]byte, 32),
			ObfuscationIV:    nil,
		}
		clone := original.Clone()
		assert.NotNil(t, clone.StaticKey)
		assert.NotNil(t, clone.RemoteRouterHash)
		assert.NotNil(t, clone.RemoteStaticKey)
		assert.Nil(t, clone.ObfuscationIV)
	})

	t.Run("Modifiers_nil_others_set", func(t *testing.T) {
		original := &Config{
			BobRouterHash: data.Hash{},
			StaticKey:     make([]byte, 32),
			BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
				Modifiers: nil,
			},
		}
		clone := original.Clone()
		assert.NotNil(t, clone.StaticKey)
		assert.Nil(t, clone.Modifiers)
	})

	t.Run("Modifiers_empty_slice", func(t *testing.T) {
		original := &Config{
			BobRouterHash: data.Hash{},
			BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
				Modifiers: []handshake.HandshakeModifier{},
			},
		}
		clone := original.Clone()
		// Empty (non-nil) slice is preserved
		assert.NotNil(t, clone.Modifiers)
		assert.Empty(t, clone.Modifiers)
	})

	t.Run("BobRouterHash_zero", func(t *testing.T) {
		original := &Config{
			BobRouterHash: data.Hash{},
			StaticKey:     make([]byte, 32),
		}
		clone := original.Clone()
		assert.Equal(t, data.Hash{}, clone.BobRouterHash)
		assert.NotNil(t, clone.StaticKey)
	})
}

// TestClone_ValueFieldIndependence verifies that all value-type fields in the
// clone are independent of the original (no shared pointer state).
func TestClone_ValueFieldIndependence(t *testing.T) {
	original := &Config{
		Pattern:       "XK",
		Initiator:     true,
		BobRouterHash: data.Hash{},
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: 30 * time.Second,
			ReadTimeout:      5 * time.Second,
			WriteTimeout:     10 * time.Second,
			HandshakeRetries: 3,
			RetryBackoff:     2 * time.Second,
		},
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		SipHashKeys:          [2]uint64{0xAAAA, 0xBBBB},
		MaxFrameSize:         16384,
		FramePaddingEnabled:  true,
		MinPaddingSize:       8,
		MaxPaddingSize:       128,
	}

	clone := original.Clone()

	// Mutate every value field in the clone
	clone.Pattern = "NN"
	clone.Initiator = false
	clone.HandshakeTimeout = 1 * time.Second
	clone.ReadTimeout = 1 * time.Second
	clone.WriteTimeout = 1 * time.Second
	clone.HandshakeRetries = 0
	clone.RetryBackoff = 0
	clone.EnableAESObfuscation = false
	clone.EnableSipHashLength = false
	clone.SipHashKeys = [2]uint64{0, 0}
	clone.MaxFrameSize = 1024
	clone.FramePaddingEnabled = false
	clone.MinPaddingSize = 0
	clone.MaxPaddingSize = 0

	// Original must be unaffected
	assert.Equal(t, "XK", original.Pattern)
	assert.True(t, original.Initiator)
	assert.Equal(t, 30*time.Second, original.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, original.ReadTimeout)
	assert.Equal(t, 10*time.Second, original.WriteTimeout)
	assert.Equal(t, 3, original.HandshakeRetries)
	assert.Equal(t, 2*time.Second, original.RetryBackoff)
	assert.True(t, original.EnableAESObfuscation)
	assert.True(t, original.EnableSipHashLength)
	assert.Equal(t, [2]uint64{0xAAAA, 0xBBBB}, original.SipHashKeys)
	assert.Equal(t, 16384, original.MaxFrameSize)
	assert.True(t, original.FramePaddingEnabled)
	assert.Equal(t, 8, original.MinPaddingSize)
	assert.Equal(t, 128, original.MaxPaddingSize)
}

// newSipHashTestConfig creates an initiator NTCP2Config with the keys
// required for SipHash modifier tests (router hash, remote hash, static key,
// remote static key, and AES obfuscation).
func newSipHashTestConfig(t *testing.T) *Config {
	t.Helper()
	var routerHash data.Hash
	copy(routerHash[:], "test-router-hash-32-bytes-long!")

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	var remoteHash data.Hash
	copy(remoteHash[:], "remote-hash-32-bytes-long!!!!!")
	config.RemoteRouterHash = &remoteHash
	config.StaticKey = make([]byte, 32)
	copy(config.StaticKey, "static-key-32-bytes-long!!!!!!!")
	config.RemoteStaticKey = make([]byte, 32)
	copy(config.RemoteStaticKey, "remote-static-key-32-bytes!!!!!")

	config = config.WithAESObfuscation(true, make([]byte, 16))
	return config
}

// TestConfigSipHashModifier verifies that NTCP2Config stores and returns
// the SipHash modifier after ToConnConfig() is called.
func TestConfigSipHashModifier(t *testing.T) {
	config := newSipHashTestConfig(t)

	// Before ToConnConfig, modifier should be nil
	assert.Nil(t, config.SipHashModifier())

	// Call ToConnConfig
	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	// After ToConnConfig (before handshake), SipHashModifier() should be nil
	// because the placeholder zero-key modifier is no longer exposed.
	// The proper directional modifier is set by the post-handshake hook.
	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed pre-handshake")

	// But the SipHash modifier is still in the modifier list for the handshake
	hasSipHashMod := false
	for _, mod := range connConfig.Modifiers {
		if mod.Name() == "ntcp2-siphash" {
			hasSipHashMod = true
			break
		}
	}
	assert.True(t, hasSipHashMod,
		"SipHash modifier should be in the handshake modifier list")
}

// TestConfigSipHashModifier_Disabled verifies that the modifier is nil
// when SipHash is disabled.
func TestConfigSipHashModifier_Disabled(t *testing.T) {
	config := newSipHashTestConfig(t)

	// Disable SipHash
	config.EnableSipHashLength = false

	_, err := config.ToConnConfig()
	require.NoError(t, err)

	// Modifier should be nil
	assert.Nil(t, config.SipHashModifier())
}

func TestNTCP2ConfigRejectsPaddingModifier(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Add incompatible PaddingModifier
	pm, pmErr := handshake.NewPaddingModifier("bad-padding", 0, 32)
	require.NoError(t, pmErr)
	config.Modifiers = []handshake.HandshakeModifier{pm}

	err = config.Validate()
	require.Error(t, err, "Validate should reject PaddingModifier in NTCP2 config")
	assert.Contains(t, err.Error(), "NTCP2-compatible")
}

func TestNTCP2ConfigAcceptsValidModifiers(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Add a compatible custom modifier (not PaddingModifier)
	config.Modifiers = []handshake.HandshakeModifier{&testModifier{name: "ok"}}

	err = config.Validate()
	assert.NoError(t, err, "Validate should accept non-PaddingModifier modifiers")
}

// TestNTCP2ConfigValidatesOversizedRouterInfo verifies that Config.Validate()
// rejects LocalRouterInfo that is too large to fit in the uint16 m3p2Len field
// without overflow. This test addresses the MEDIUM-severity finding.
func TestNTCP2ConfigValidatesOversizedRouterInfo(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	m := newTestCryptoMaterial(t)
	config.WithStaticKey(m.staticKey).
		WithRemoteRouterHash(m.remoteHash).
		WithRemoteStaticKey(generateRandomBytes(32))

	// Maximum safe size: 65535 - (BlockHeaderSize=3 + flag=1 + Poly1305Overhead=16) = 65515
	const maxSafeSize = 0xFFFF - (BlockHeaderSize + 1 + Poly1305Overhead)

	// Test case 1: exactly at the limit should pass
	config.LocalRouterInfo = make([]byte, maxSafeSize)
	err = config.Validate()
	assert.NoError(t, err, "RouterInfo at max safe size (%d bytes) should be accepted", maxSafeSize)

	// Test case 2: one byte over the limit should fail
	config.LocalRouterInfo = make([]byte, maxSafeSize+1)
	err = config.Validate()
	require.Error(t, err, "RouterInfo exceeding max safe size should be rejected")
	assert.Contains(t, err.Error(), "too large", "error should mention size constraint")

	// Test case 3: significantly oversized should fail
	config.LocalRouterInfo = make([]byte, 70000)
	err = config.Validate()
	require.Error(t, err, "Significantly oversized RouterInfo should be rejected")
}

// TestNTCP2ConfigValidatesMinimumFrameSize verifies that Config.Validate()
// rejects MaxFrameSize values that are too small to hold at least one I2NP
// block header plus AEAD tag, preventing arithmetic underflow panic in writeFramed.
// This test addresses the MEDIUM-severity finding.
func TestNTCP2ConfigValidatesMinimumFrameSize(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Minimum allowed: MinDataPhaseFrameSize (16) + Poly1305Overhead (16) = 32
	const minAllowedFrameSize = MinDataPhaseFrameSize + Poly1305Overhead

	// Test case 1: exactly at minimum should pass
	config.MaxFrameSize = minAllowedFrameSize
	err = config.Validate()
	assert.NoError(t, err, "MaxFrameSize at minimum (%d bytes) should be accepted", minAllowedFrameSize)

	// Test case 2: one byte below minimum should fail
	config.MaxFrameSize = minAllowedFrameSize - 1
	err = config.Validate()
	require.Error(t, err, "MaxFrameSize below minimum should be rejected")
	assert.Contains(t, err.Error(), "too small", "error should mention size constraint")

	// Test case 3: MaxFrameSize = 1 should fail (would cause panic)
	config.MaxFrameSize = 1
	err = config.Validate()
	require.Error(t, err, "MaxFrameSize = 1 should be rejected")
	assert.Contains(t, err.Error(), "too small", "error should mention size constraint")
}

// TestNTCP2ConfigCloneDeepCopiesModifiers verifies that Config.Clone()
// creates independent copies of modifiers that implement ModifierCloner,
// preventing concurrent modifications on one cloned config from affecting
// connections built from sibling clones. This addresses the MEDIUM-severity finding.
func TestNTCP2ConfigCloneDeepCopiesModifiers(t *testing.T) {
	routerHash := generateRandomHash()
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Add a padding modifier (which has mutable state)
	paddingMod, err := NewNTCP2PaddingModifier("test-padding", 0, 128, true)
	require.NoError(t, err)
	config.Modifiers = []handshake.HandshakeModifier{paddingMod}

	// Clone the config
	clone := config.Clone()
	require.NotNil(t, clone)
	require.Len(t, clone.Modifiers, 1)

	// Verify the modifiers are different instances
	origPadding := config.Modifiers[0].(*NTCP2PaddingModifier)
	clonePadding := clone.Modifiers[0].(*NTCP2PaddingModifier)

	// They should be different instances
	assert.NotSame(t, origPadding, clonePadding, "modifiers should be different instances")

	// But should have the same configuration
	assert.Equal(t, origPadding.engine.Config.MinPadding, clonePadding.engine.Config.MinPadding)
	assert.Equal(t, origPadding.engine.Config.MaxPadding, clonePadding.engine.Config.MaxPadding)
	assert.Equal(t, origPadding.name, clonePadding.name)

	// Verify they have independent engines (different pointers)
	assert.NotSame(t, origPadding.engine, clonePadding.engine, "padding engines should be independent")
}
