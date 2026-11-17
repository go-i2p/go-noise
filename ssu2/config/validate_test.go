package config

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GN-012: ssu2/config's validators and ToConnConfig were entirely uncovered.
// These tests drive every validation branch with both valid and hostile
// (remote-supplied / mis-set) values and assert the specific oops error code,
// so a regression that loosens a bound or drops a check is caught.

func randKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// validResponder returns a responder config that passes Validate() out of the
// box (the default RouterInfoValidator is already set by NewSSU2Config).
func validResponder(t *testing.T) *SSU2Config {
	t.Helper()
	c, err := NewSSU2Config(generateRandomHash(), false)
	require.NoError(t, err)
	c.IntroKey = randKey32() // needed for ToConnConfig's ChaCha modifier
	return c
}

// validInitiator returns an initiator config with the required remote static
// key and intro key.
func validInitiator(t *testing.T) *SSU2Config {
	t.Helper()
	c, err := NewSSU2Config(generateRandomHash(), true)
	require.NoError(t, err)
	c.RemoteStaticKey = randKey32()
	c.RemoteIntroKey = randKey32()
	return c
}

func oopsCode(t *testing.T, err error) any {
	t.Helper()
	require.Error(t, err)
	var oe oops.OopsError
	require.ErrorAs(t, err, &oe)
	return oe.Code()
}

func TestSSU2Config_Validate_DefaultResponderPasses(t *testing.T) {
	require.NoError(t, validResponder(t).Validate())
}

func TestSSU2Config_Validate_DefaultInitiatorPasses(t *testing.T) {
	require.NoError(t, validInitiator(t).Validate())
}

func TestValidateBasicConfiguration_Pattern(t *testing.T) {
	c := validResponder(t)
	c.Pattern = ""
	assert.Equal(t, "INVALID_PATTERN", oopsCode(t, c.validateBasicConfiguration()))

	c.Pattern = "XK"
	require.NoError(t, c.validateBasicConfiguration())
}

func TestValidateCryptographicParameters(t *testing.T) {
	t.Run("static key wrong length", func(t *testing.T) {
		c := validResponder(t)
		c.StaticKey = []byte{1, 2, 3}
		assert.Equal(t, "INVALID_KEY_LENGTH", oopsCode(t, c.validateCryptographicParameters()))
	})

	t.Run("initiator missing remote static key", func(t *testing.T) {
		c, err := NewSSU2Config(generateRandomHash(), true)
		require.NoError(t, err)
		c.RemoteStaticKey = nil
		assert.Equal(t, "MISSING_REMOTE_STATIC_KEY", oopsCode(t, c.validateCryptographicParameters()))
	})

	t.Run("initiator remote static key wrong length", func(t *testing.T) {
		c := validInitiator(t)
		c.RemoteStaticKey = []byte{1, 2, 3}
		assert.Equal(t, "INVALID_REMOTE_STATIC_KEY", oopsCode(t, c.validateCryptographicParameters()))
	})

	t.Run("obfuscation IV wrong length", func(t *testing.T) {
		c := validResponder(t)
		c.ObfuscationIV = []byte{1, 2, 3}
		assert.Equal(t, "INVALID_OBFUSCATION_IV", oopsCode(t, c.validateCryptographicParameters()))
	})

	t.Run("obfuscation IV nil is fine", func(t *testing.T) {
		c := validResponder(t)
		c.ObfuscationIV = nil
		require.NoError(t, c.validateCryptographicParameters())
	})

	t.Run("responder missing router info validator", func(t *testing.T) {
		c := validResponder(t)
		c.RouterInfoValidator = nil
		assert.Equal(t, "MISSING_ROUTER_INFO_VALIDATOR", oopsCode(t, c.validateCryptographicParameters()))
	})
}

func TestValidateTimeoutConfiguration(t *testing.T) {
	t.Run("non-positive handshake timeout", func(t *testing.T) {
		c := validResponder(t)
		c.HandshakeTimeout = 0
		assert.Equal(t, "INVALID_TIMEOUT", oopsCode(t, c.validateTimeoutConfiguration()))
	})

	t.Run("retries below -1", func(t *testing.T) {
		c := validResponder(t)
		c.HandshakeRetries = -2
		assert.Equal(t, "INVALID_RETRY_COUNT", oopsCode(t, c.validateTimeoutConfiguration()))
	})

	t.Run("negative backoff", func(t *testing.T) {
		c := validResponder(t)
		c.RetryBackoff = -time.Second
		assert.Equal(t, "INVALID_RETRY_BACKOFF", oopsCode(t, c.validateTimeoutConfiguration()))
	})

	t.Run("non-positive keepalive", func(t *testing.T) {
		c := validResponder(t)
		c.KeepaliveInterval = 0
		assert.Equal(t, "INVALID_KEEPALIVE_INTERVAL", oopsCode(t, c.validateTimeoutConfiguration()))
	})
}

func TestValidateUDPConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		mtu           int
		maxPacketSize int
		wantCode      string
	}{
		{"mtu too low", 1279, 1500, "INVALID_MTU"},
		{"mtu too high", 1501, 1500, "INVALID_MTU"},
		{"max packet too low", 1280, 0, "INVALID_MAX_PACKET_SIZE"},
		{"max packet too high", 1280, 65536, "INVALID_MAX_PACKET_SIZE"},
		{"max packet below mtu", 1500, 1280, "PACKET_SIZE_LESS_THAN_MTU"},
		{"valid bounds", 1280, 1500, ""},
		{"valid upper bounds", 1500, 1500, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validResponder(t)
			c.MTU = tc.mtu
			c.MaxPacketSize = tc.maxPacketSize
			err := c.validateUDPConfiguration()
			if tc.wantCode == "" {
				require.NoError(t, err)
				return
			}
			assert.Equal(t, tc.wantCode, oopsCode(t, err))
		})
	}
}

func TestValidatePaddingConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		min, max int
		ratio    float64
		wantCode string
	}{
		{"negative min", -1, 64, 1.0, "INVALID_MIN_PADDING"},
		{"max below min", 64, 32, 1.0, "INVALID_PADDING_RANGE"},
		{"max exceeds spec limit", 0, 65535, 1.0, "INVALID_PADDING"},
		{"ratio too high", 0, 64, 100.0, "INVALID_PADDING_RATIO"},
		{"ratio negative", 0, 64, -0.5, "INVALID_PADDING_RATIO"},
		{"valid", 0, 64, 1.0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validResponder(t)
			c.MinPaddingSize = tc.min
			c.MaxPaddingSize = tc.max
			c.PaddingRatio = tc.ratio
			err := c.validatePaddingConfiguration()
			if tc.wantCode == "" {
				require.NoError(t, err)
				return
			}
			assert.Equal(t, tc.wantCode, oopsCode(t, err))
		})
	}
}

func TestValidateTokenConfiguration(t *testing.T) {
	t.Run("require retry with zero rate", func(t *testing.T) {
		c := validResponder(t)
		c.RequireRetry = true
		c.GlobalTokenIssuanceRate = 0
		assert.Equal(t, "INVALID_TOKEN_CONFIG", oopsCode(t, c.validateTokenConfiguration()))
	})

	t.Run("require retry with positive rate", func(t *testing.T) {
		c := validResponder(t)
		c.RequireRetry = true
		c.GlobalTokenIssuanceRate = 40
		require.NoError(t, c.validateTokenConfiguration())
	})

	t.Run("no retry required ignores rate", func(t *testing.T) {
		c := validResponder(t)
		c.RequireRetry = false
		c.GlobalTokenIssuanceRate = 0
		require.NoError(t, c.validateTokenConfiguration())
	})
}

// validateBounds is the numeric workhorse; exercise its type-error branch and
// both range boundaries directly.
func TestValidateBounds(t *testing.T) {
	t.Run("unsupported type", func(t *testing.T) {
		err := validateBounds(&boundsValidator{
			name: "weird", value: "not-a-number", min: 0, max: 10,
			code: "TYPE", msg: "bad %v (%v-%v)", context: "ssu2",
		})
		assert.Equal(t, "TYPE_ERROR", oopsCode(t, err))
	})

	t.Run("inclusive lower bound", func(t *testing.T) {
		require.NoError(t, validateBounds(&boundsValidator{
			name: "mtu", value: 1280, min: 1280, max: 1500,
			code: "INVALID_MTU", msg: "MTU (got %v, want %v-%v)", context: "ssu2",
		}))
	})

	t.Run("inclusive upper bound", func(t *testing.T) {
		require.NoError(t, validateBounds(&boundsValidator{
			name: "mtu", value: 1500, min: 1280, max: 1500,
			code: "INVALID_MTU", msg: "MTU (got %v, want %v-%v)", context: "ssu2",
		}))
	})

	t.Run("below range", func(t *testing.T) {
		err := validateBounds(&boundsValidator{
			name: "mtu", value: 1279, min: 1280, max: 1500,
			code: "INVALID_MTU", msg: "MTU (got %v, want %v-%v)", context: "ssu2",
		})
		assert.Equal(t, "INVALID_MTU", oopsCode(t, err))
	})

	t.Run("int64 and float64 accepted", func(t *testing.T) {
		require.NoError(t, validateBounds(&boundsValidator{
			name: "i64", value: int64(5), min: 0, max: 10, code: "C", msg: "%v %v %v", context: "ssu2",
		}))
		require.NoError(t, validateBounds(&boundsValidator{
			name: "f64", value: 5.5, min: 0, max: 10, code: "C", msg: "%v %v %v", context: "ssu2",
		}))
	})
}

func TestSSU2Config_ToConnConfig(t *testing.T) {
	t.Run("valid responder builds conn config", func(t *testing.T) {
		c := validResponder(t)
		c.StaticKey = randKey32()
		cc, err := c.ToConnConfig()
		require.NoError(t, err)
		require.NotNil(t, cc)
		assert.Equal(t, "XK", cc.Pattern)
		assert.False(t, cc.Initiator)
		assert.Equal(t, c.StaticKey, cc.StaticKey, "static key must be copied through")
		// ChaCha + padding modifiers are both enabled by default.
		assert.GreaterOrEqual(t, len(cc.Modifiers), 2)
	})

	t.Run("valid initiator builds conn config", func(t *testing.T) {
		c := validInitiator(t)
		cc, err := c.ToConnConfig()
		require.NoError(t, err)
		assert.True(t, cc.Initiator)
	})

	t.Run("invalid config is rejected before building", func(t *testing.T) {
		c := validResponder(t)
		c.MTU = 10 // fails UDP bounds
		_, err := c.ToConnConfig()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		// ToConnConfig wraps the underlying validation failure; the innermost
		// code is what surfaces through the oops error chain.
		assert.Equal(t, "INVALID_MTU", oe.Code())
	})

	t.Run("chaCha enabled without intro key fails", func(t *testing.T) {
		c := validResponder(t)
		c.IntroKey = nil // obfuscation is on by default but no key to key it with
		_, err := c.ToConnConfig()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "MISSING_INTRO_KEY", oe.Code())
	})

	t.Run("initiator chaCha without remote intro key fails", func(t *testing.T) {
		c := validInitiator(t)
		c.RemoteIntroKey = nil
		_, err := c.ToConnConfig()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "MISSING_INTRO_KEY", oe.Code())
	})

	t.Run("obfuscation disabled skips intro key requirement", func(t *testing.T) {
		c := validResponder(t)
		c.IntroKey = nil
		c.EnableChaChaObfuscation = false
		c.PaddingEnabled = false
		cc, err := c.ToConnConfig()
		require.NoError(t, err)
		assert.Empty(t, cc.Modifiers)
	})

	t.Run("padding modifier failure surfaces", func(t *testing.T) {
		// ToConnConfig runs Validate() first, which guards both the padding
		// params and the MTU range, so PADDING_MODIFIER_FAILED is only reachable
		// by invoking the builder directly with a config that never passed
		// Validate. An out-of-range MTU trips the modifier's own validateMTU.
		c := validResponder(t)
		c.MTU = 9000
		_, err := c.createPaddingModifierIfEnabled()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "INVALID_MTU", oe.Code())
	})
}

func TestCreateBaseConnConfig(t *testing.T) {
	c := validResponder(t)
	c.StaticKey = randKey32()
	cc := c.createBaseConnConfig()
	require.NotNil(t, cc)
	assert.Equal(t, c.Pattern, cc.Pattern)
	assert.Equal(t, c.HandshakeTimeout, cc.BaseHandshakeConfig.HandshakeTimeout)
	assert.Equal(t, c.HandshakeRetries, cc.BaseHandshakeConfig.HandshakeRetries)
	// Protocol name must be the SSU2 protocol string.
	assert.NotEmpty(t, cc.ProtocolName)
}

func TestCopyStaticKeyIfProvided(t *testing.T) {
	t.Run("copies when present", func(t *testing.T) {
		c := validResponder(t)
		c.StaticKey = randKey32()
		cc := c.createBaseConnConfig()
		c.copyStaticKeyIfProvided(cc)
		assert.Equal(t, c.StaticKey, cc.StaticKey)
	})

	t.Run("leaves empty when absent", func(t *testing.T) {
		c := validResponder(t)
		c.StaticKey = nil
		cc := c.createBaseConnConfig()
		c.copyStaticKeyIfProvided(cc)
		assert.Len(t, cc.StaticKey, 0)
	})
}

func TestSetupSSU2Modifiers(t *testing.T) {
	t.Run("appends user modifiers after built-ins", func(t *testing.T) {
		c := validResponder(t)
		// With no built-ins enabled, only user modifiers remain.
		c.EnableChaChaObfuscation = false
		c.PaddingEnabled = false
		mods, err := c.setupSSU2Modifiers()
		require.NoError(t, err)
		assert.Len(t, mods, len(c.Modifiers))
	})

	t.Run("chaCha failure aborts", func(t *testing.T) {
		c := validResponder(t)
		c.EnableChaChaObfuscation = true
		c.IntroKey = nil
		_, err := c.setupSSU2Modifiers()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "MISSING_INTRO_KEY", oe.Code())
	})

	t.Run("padding failure aborts", func(t *testing.T) {
		// ChaCha off, padding on, MTU out of the modifier's range: the padding
		// builder fails and setupSSU2Modifiers must propagate that error.
		c := validResponder(t)
		c.EnableChaChaObfuscation = false
		c.PaddingEnabled = true
		c.MTU = 9000
		_, err := c.setupSSU2Modifiers()
		require.Error(t, err)
		var oe oops.OopsError
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "INVALID_MTU", oe.Code())
	})
}

func TestCreateChaChaModifierIfEnabled(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		c := validResponder(t)
		c.EnableChaChaObfuscation = false
		m, err := c.createChaChaModifierIfEnabled()
		require.NoError(t, err)
		assert.Nil(t, m)
	})

	t.Run("responder uses own intro key", func(t *testing.T) {
		c := validResponder(t)
		m, err := c.createChaChaModifierIfEnabled()
		require.NoError(t, err)
		require.NotNil(t, m)
	})

	t.Run("initiator uses remote intro key", func(t *testing.T) {
		c := validInitiator(t)
		m, err := c.createChaChaModifierIfEnabled()
		require.NoError(t, err)
		require.NotNil(t, m)
	})
}

func TestCreatePaddingModifierIfEnabled(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		c := validResponder(t)
		c.PaddingEnabled = false
		m, err := c.createPaddingModifierIfEnabled()
		require.NoError(t, err)
		assert.Nil(t, m)
	})

	t.Run("enabled builds modifier", func(t *testing.T) {
		c := validResponder(t)
		m, err := c.createPaddingModifierIfEnabled()
		require.NoError(t, err)
		require.NotNil(t, m)
	})
}

// NewSSU2Config must produce a config that survives Validate() for both roles
// once the role-required keys are supplied.
func TestNewSSU2Config_Roles(t *testing.T) {
	var h data.Hash
	r, err := NewSSU2Config(h, false)
	require.NoError(t, err)
	require.NoError(t, r.validateCryptographicParameters(), "responder default validator is set")

	i, err := NewSSU2Config(h, true)
	require.NoError(t, err)
	i.RemoteStaticKey = randKey32()
	require.NoError(t, i.validateCryptographicParameters())
}
