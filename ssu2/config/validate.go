package config

import (
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	internalvalidation "github.com/go-i2p/go-noise/internal/validation"
	"github.com/go-i2p/go-noise/mod/validation"
	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// boundsValidator describes a numeric bounds check with error context.
type boundsValidator struct {
	name    string      // Field name for error reporting
	value   interface{} // Value to check (int, int64, float64, etc.)
	min     float64     // Minimum allowed (inclusive)
	max     float64     // Maximum allowed (inclusive)
	code    string      // Error code (e.g., "INVALID_MTU")
	msg     string      // Error message format string
	context string      // Additional context (e.g., "ssu2", "padding")
}

// Validate checks if the configuration is valid for SSU2.
func (sc *SSU2Config) Validate() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "Validate"}).Debug("Validating SSU2Config")
	return validation.RunValidators(
		sc.validateBasicConfiguration,
		sc.validateCryptographicParameters,
		sc.validateTimeoutConfiguration,
		sc.validateUDPConfiguration,
		sc.validatePaddingConfiguration,
		sc.validateTokenConfiguration,
	)
}

// validateBounds checks if a value satisfies min/max bounds and returns an oops error on failure.
// This is the workhorse for table-driven numeric validation.
func validateBounds(v boundsValidator) error {
	numVal, ok := internalvalidation.ToFloat64(v.value)
	if !ok {
		return oops.Code("TYPE_ERROR").In(v.context).Errorf("unsupported type for bounds validation")
	}

	if internalvalidation.CompareFloat64Range(numVal, v.min, v.max) != internalvalidation.InRange {
		return oops.
			Code(v.code).
			In(v.context).
			With(v.name, v.value).
			Errorf(v.msg, v.value, v.min, v.max)
	}
	return nil
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (sc *SSU2Config) validateBasicConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateBasicConfiguration", "pattern": sc.Pattern}).Debug("Checking pattern and router hash")
	// Validate pattern (SSU2 typically uses XK)
	if err := validation.ValidatePattern(sc.Pattern, "ssu2"); err != nil {
		return err
	}

	return nil
}

// validateCryptographicParameters checks keys, hashes, and obfuscation settings.
func (sc *SSU2Config) validateCryptographicParameters() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateCryptographicParameters", "initiator": sc.Initiator, "has_static_key": len(sc.StaticKey) > 0}).Debug("Checking keys and obfuscation settings")
	// Validate static key if provided
	if err := validation.ValidateKeyLength(sc.StaticKey, "static key", "ssu2"); err != nil {
		return err
	}

	// For initiator connections, the remote static key is required for the
	// Noise XK handshake (C-1). The router hash is used separately for
	// identity verification.
	if sc.Initiator && len(sc.RemoteStaticKey) == 0 {
		return oops.
			Code("MISSING_REMOTE_STATIC_KEY").
			In("ssu2").
			Errorf("remote static key is required for initiator connections (use WithRemoteStaticKey)")
	}

	if sc.Initiator && len(sc.RemoteStaticKey) != 0 && len(sc.RemoteStaticKey) != 32 {
		return oops.
			Code("INVALID_REMOTE_STATIC_KEY").
			In("ssu2").
			With("key_length", len(sc.RemoteStaticKey)).
			Errorf("remote static key must be 32 bytes")
	}

	// Validate ChaCha20 obfuscation IV if provided (8 bytes for SSU2)
	if sc.ObfuscationIV != nil && len(sc.ObfuscationIV) != 8 {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ssu2").
			With("iv_length", len(sc.ObfuscationIV)).
			Errorf("obfuscation IV must be 8 bytes")
	}

	// Per SSU2 spec §Session Confirmed (C-2): responders must validate
	// that the Noise-authenticated static key matches the RouterInfo.
	if !sc.Initiator && sc.RouterInfoValidator == nil {
		return oops.
			Code("MISSING_ROUTER_INFO_VALIDATOR").
			In("ssu2").
			Errorf("RouterInfoValidator is required for responder configs per SSU2 spec")
	}

	return nil
}

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (sc *SSU2Config) validateTimeoutConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateTimeoutConfiguration", "handshake_timeout": sc.HandshakeTimeout, "keepalive_interval": sc.KeepaliveInterval}).Debug("Checking timeout and retry settings")
	// Validate handshake timeout and retry configuration via shared helper.
	if err := validation.ValidateTransportConfig(sc.HandshakeTimeout, sc.HandshakeRetries, sc.RetryBackoff, "ssu2"); err != nil {
		return err
	}

	// Validate keepalive interval
	if sc.KeepaliveInterval <= 0 {
		return oops.
			Code("INVALID_KEEPALIVE_INTERVAL").
			In("ssu2").
			With("interval", sc.KeepaliveInterval).
			Errorf("keepalive interval must be positive")
	}

	return nil
}

// validateUDPConfiguration checks MTU, packet size, and fragmentation settings
// using a table-driven approach for numeric bounds checks.
func (sc *SSU2Config) validateUDPConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateUDPConfiguration", "mtu": sc.MTU, "max_packet_size": sc.MaxPacketSize}).Debug("Checking MTU and packet size settings")

	// Table-driven bounds checks for numeric configuration values.
	boundsChecks := []boundsValidator{
		{
			name:    "mtu",
			value:   sc.MTU,
			min:     1280,
			max:     1500,
			code:    "INVALID_MTU",
			msg:     "MTU must be between 1280 and 1500 bytes (got %v)",
			context: "ssu2",
		},
		{
			name:    "max_packet_size",
			value:   sc.MaxPacketSize,
			min:     1,
			max:     65535,
			code:    "INVALID_MAX_PACKET_SIZE",
			msg:     "max packet size must be between 1 and 65535 bytes (got %v)",
			context: "ssu2",
		},
	}

	for _, check := range boundsChecks {
		if err := validateBounds(check); err != nil {
			return err
		}
	}

	// Max packet size should be >= MTU for proper operation
	if sc.MaxPacketSize < sc.MTU {
		return oops.
			Code("PACKET_SIZE_LESS_THAN_MTU").
			In("ssu2").
			With("max_packet_size", sc.MaxPacketSize).
			With("mtu", sc.MTU).
			Errorf("max packet size must be >= MTU")
	}

	return nil
}

// validatePaddingConfiguration checks padding ranges and ratios.
func (sc *SSU2Config) validatePaddingConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validatePaddingConfiguration", "enabled": sc.PaddingEnabled, "min": sc.MinPaddingSize, "max": sc.MaxPaddingSize, "ratio": sc.PaddingRatio}).Debug("Checking padding ranges and ratios")
	if err := handshake.ValidatePaddingRange("ssu2", sc.MinPaddingSize, sc.MaxPaddingSize); err != nil {
		return err
	}

	// Validate padding ratio (I2P spec allows 0.0 to 15.9375)
	if sc.PaddingRatio < 0.0 || sc.PaddingRatio > 15.9375 {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ssu2").
			With("ratio", sc.PaddingRatio).
			Errorf("padding ratio must be between 0.0 and 15.9375")
	}

	return nil
}

// validateTokenConfiguration rejects configurations that would make the
// listener permanently unreachable: RequireRetry==true combined with
// GlobalTokenIssuanceRate==0 means every SessionRequest is answered with a
// Retry message whose token is never issued.
func (sc *SSU2Config) validateTokenConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateTokenConfiguration", "require_retry": sc.RequireRetry, "token_rate": sc.GlobalTokenIssuanceRate}).Debug("Checking token issuance configuration")
	if sc.RequireRetry && sc.GlobalTokenIssuanceRate <= 0 {
		return oops.
			Code("INVALID_TOKEN_CONFIG").
			In("ssu2").
			With("require_retry", sc.RequireRetry).
			With("token_rate", sc.GlobalTokenIssuanceRate).
			Errorf("GlobalTokenIssuanceRate must be > 0 when RequireRetry is true; otherwise all SessionRequests are rejected and the listener is permanently unreachable")
	}
	return nil
}

// ToConnConfig converts SSU2Config to a standard ConnConfig for use with NoiseConn.
// This includes setting up SSU2-specific modifiers based on the configuration.
func (sc *SSU2Config) ToConnConfig() (*noise.ConnConfig, error) {
	log.WithFields(logger.Fields{"pkg": "config", "func": "ToConnConfig"}).Debug("Converting SSU2Config to ConnConfig")
	if err := sc.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ssu2").
			Wrap(err)
	}

	config := sc.createBaseConnConfig()
	sc.copyStaticKeyIfProvided(config)

	modifiers, err := sc.setupSSU2Modifiers()
	if err != nil {
		return nil, err
	}

	config.Modifiers = modifiers
	return config, nil
}

// createBaseConnConfig creates a base ConnConfig with core SSU2 settings.
func (sc *SSU2Config) createBaseConnConfig() *noise.ConnConfig {
	return &noise.ConnConfig{
		Pattern:      sc.Pattern,
		Initiator:    sc.Initiator,
		StaticKey:    make([]byte, len(sc.StaticKey)),
		ProtocolName: []byte(ssu2hs.SSU2ProtocolName),
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: sc.HandshakeTimeout,
			ReadTimeout:      sc.ReadTimeout,
			WriteTimeout:     sc.WriteTimeout,
			HandshakeRetries: sc.HandshakeRetries,
			RetryBackoff:     sc.RetryBackoff,
		},
	}
}

// copyStaticKeyIfProvided copies the static key to the config if one is provided.
func (sc *SSU2Config) copyStaticKeyIfProvided(config *noise.ConnConfig) {
	if len(sc.StaticKey) > 0 {
		copy(config.StaticKey, sc.StaticKey)
	}
}

// setupSSU2Modifiers creates and configures all SSU2-specific handshake modifiers.
func (sc *SSU2Config) setupSSU2Modifiers() ([]handshake.HandshakeModifier, error) {
	var modifiers []handshake.HandshakeModifier

	chachaModifier, err := sc.createChaChaModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if chachaModifier != nil {
		modifiers = append(modifiers, chachaModifier)
	}

	paddingModifier, err := sc.createPaddingModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if paddingModifier != nil {
		modifiers = append(modifiers, paddingModifier)
	}

	modifiers = append(modifiers, sc.Modifiers...)
	return modifiers, nil
}

// createChaChaModifierIfEnabled creates a ChaCha20 obfuscation modifier if enabled.
// Per SSU2 spec, the ChaCha20 key is Bob's intro key:
//   - Initiator uses RemoteIntroKey (Bob's intro key)
//   - Responder uses IntroKey (own intro key, which IS Bob's intro key)
func (sc *SSU2Config) createChaChaModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !sc.EnableChaChaObfuscation {
		return nil, nil
	}

	// Select the correct intro key based on role
	var introKey []byte
	if sc.Initiator && len(sc.RemoteIntroKey) == 32 {
		introKey = sc.RemoteIntroKey
	} else if !sc.Initiator && len(sc.IntroKey) == 32 {
		introKey = sc.IntroKey
	} else {
		// Fallback to router hash for backward compatibility
		introKey = sc.RouterHash[:]
	}

	chachaModifier, err := wire.NewChaChaObfuscationModifier("ssu2-chacha", introKey)
	if err != nil {
		return nil, oops.
			Code("CHACHA_MODIFIER_FAILED").
			In("ssu2").
			Wrap(err)
	}
	return chachaModifier, nil
}

// createPaddingModifierIfEnabled creates an SSU2 padding modifier if enabled.
func (sc *SSU2Config) createPaddingModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !sc.PaddingEnabled {
		return nil, nil
	}

	paddingModifier, err := wire.NewSSU2PaddingModifierWithMTU(
		"ssu2-padding",
		sc.MinPaddingSize,
		sc.MaxPaddingSize,
		sc.MTU,
		true, // AEAD mode for SSU2
		sc.PaddingRatio,
	)
	if err != nil {
		return nil, oops.
			Code("PADDING_MODIFIER_FAILED").
			In("ssu2").
			Wrap(err)
	}
	return paddingModifier, nil
}
