package config

import (
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
)

// WithPattern sets the Noise protocol pattern.
// For SSU2, this should typically remain "XK".
func (sc *SSU2Config) WithPattern(pattern string) *SSU2Config {
	sc.Pattern = pattern
	return sc
}

// WithAllowLoopback controls whether loopback addresses (127.0.0.0/8, ::1)
// are permitted for dial and listen operations. By default, AllowLoopback
// is true (allowing tests and local development). In production, set to
// false or validate addresses before creating configs.
func (sc *SSU2Config) WithAllowLoopback(allow bool) *SSU2Config {
	sc.AllowLoopback = allow
	return sc
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519.
func (sc *SSU2Config) WithStaticKey(key []byte) *SSU2Config {
	if len(key) == 32 {
		sc.StaticKey = make([]byte, 32)
		copy(sc.StaticKey, key)
	}
	return sc
}

// WithLocalRouterInfo sets the local RouterInfo to transmit during handshake.
// The RouterInfo MUST contain an SSU2 RouterAddress with the "s" parameter
// matching the static public key derived from StaticKey, otherwise peers
// with strict static key verification will reject the handshake.
// Required for initiator connections; optional for responders.
func (sc *SSU2Config) WithLocalRouterInfo(routerInfo []byte) *SSU2Config {
	if len(routerInfo) > 0 {
		sc.LocalRouterInfo = make([]byte, len(routerInfo))
		copy(sc.LocalRouterInfo, routerInfo)
	}
	return sc
}

// WithRemoteRouterHash sets the remote peer's router identity hash.
// Used for identity verification.
func (sc *SSU2Config) WithRemoteRouterHash(hash data.Hash) *SSU2Config {
	h := hash
	sc.RemoteRouterHash = &h
	return sc
}

// WithRemoteStaticKey sets the remote peer's X25519 static public key.
// Required for initiator connections. The key must be 32 bytes (Curve25519).
// This is the "s" parameter from the peer's RouterAddress options, NOT the
// router hash.
func (sc *SSU2Config) WithRemoteStaticKey(key []byte) *SSU2Config {
	if len(key) == 32 {
		sc.RemoteStaticKey = make([]byte, 32)
		copy(sc.RemoteStaticKey, key)
	}
	return sc
}

// WithHandshakeTimeout sets the handshake timeout.
func (sc *SSU2Config) WithHandshakeTimeout(timeout time.Duration) *SSU2Config {
	baseconfig.SetHandshakeTimeout(&sc.BaseHandshakeConfig, timeout)
	return sc
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (sc *SSU2Config) WithReadTimeout(timeout time.Duration) *SSU2Config {
	baseconfig.SetReadTimeout(&sc.BaseHandshakeConfig, timeout)
	return sc
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (sc *SSU2Config) WithWriteTimeout(timeout time.Duration) *SSU2Config {
	baseconfig.SetWriteTimeout(&sc.BaseHandshakeConfig, timeout)
	return sc
}

// WithHandshakeRetries sets the number of handshake retry attempts.
// Use 0 for no retries, -1 for infinite retries.
func (sc *SSU2Config) WithHandshakeRetries(retries int) *SSU2Config {
	baseconfig.SetHandshakeRetries(&sc.BaseHandshakeConfig, retries)
	return sc
}

// WithRetryBackoff sets the base delay between retry attempts.
func (sc *SSU2Config) WithRetryBackoff(backoff time.Duration) *SSU2Config {
	baseconfig.SetRetryBackoff(&sc.BaseHandshakeConfig, backoff)
	return sc
}

// WithChaChaObfuscation enables or disables ChaCha20-based ephemeral key obfuscation.
// When enabled with a custom IV, the IV must be exactly 8 bytes.
func (sc *SSU2Config) WithChaChaObfuscation(enabled bool, customIV []byte) *SSU2Config {
	sc.EnableChaChaObfuscation = enabled
	if len(customIV) == 8 {
		sc.ObfuscationIV = make([]byte, 8)
		copy(sc.ObfuscationIV, customIV)
	}
	return sc
}

// WithMTU sets the Maximum Transmission Unit for UDP packets.
// Valid range: 1280-1500 bytes. Default is 1280 (IPv6 minimum).
func (sc *SSU2Config) WithMTU(mtu int) *SSU2Config {
	if mtu >= 1280 && mtu <= 1500 {
		sc.MTU = mtu
	}
	return sc
}

// WithPacketSettings configures UDP packet handling parameters.
// maxSize sets the maximum packet size (default: 1500 bytes).
// fragmentation enables splitting large messages (default: false).
func (sc *SSU2Config) WithPacketSettings(maxSize int, fragmentation bool) *SSU2Config {
	if maxSize > 0 {
		sc.MaxPacketSize = maxSize
	}
	sc.EnableFragmentation = fragmentation
	return sc
}

// WithPaddingSettings configures SSU2 frame padding parameters.
// enabled enables random padding (default: true).
// minPad and maxPad set the padding size range (default: 0-64 bytes).
// ratio sets the padding amount as ratio of data size (0.0-15.9375).
func (sc *SSU2Config) WithPaddingSettings(enabled bool, minPad, maxPad int, ratio float64) *SSU2Config {
	sc.PaddingEnabled = enabled
	if minPad >= 0 {
		sc.MinPaddingSize = minPad
	}
	if maxPad >= minPad {
		sc.MaxPaddingSize = maxPad
	}
	if ratio >= 0.0 && ratio <= 15.9375 {
		sc.PaddingRatio = ratio
	}
	return sc
}

// WithConnectionID sets the SSU2 connection identifier.
// If connID is 0, a random ID will be generated during connection creation.
func (sc *SSU2Config) WithConnectionID(connID uint64) *SSU2Config {
	sc.ConnectionID = connID
	return sc
}

// WithKeepalive sets the interval between keepalive packets.
// UDP connections require active keepalive to maintain state.
func (sc *SSU2Config) WithKeepalive(interval time.Duration) *SSU2Config {
	sc.KeepaliveInterval = interval
	return sc
}

// WithIdleTimeout sets the idle timeout after which the connection is closed.
func (sc *SSU2Config) WithIdleTimeout(timeout time.Duration) *SSU2Config {
	sc.IdleTimeout = timeout
	return sc
}

// WithFragmentTimeout sets the duration after which incomplete fragment sets are discarded.
func (sc *SSU2Config) WithFragmentTimeout(timeout time.Duration) *SSU2Config {
	sc.FragmentTimeout = timeout
	return sc
}

// WithDestroyTimeout sets the time to wait after sending a Termination block
// before releasing session resources. Set to 0 to skip the wait (e.g. in tests).
func (sc *SSU2Config) WithDestroyTimeout(timeout time.Duration) *SSU2Config {
	sc.DestroyTimeout = timeout
	return sc
}

// WithMaxClockSkew sets the maximum allowed clock skew for handshake timestamp
// validation. Set to 0 to disable skew checking.
func (sc *SSU2Config) WithMaxClockSkew(skew time.Duration) *SSU2Config {
	sc.MaxClockSkew = skew
	return sc
}

// WithReceiveWindowSize sets the maximum number of out-of-order packets
// the receive window will buffer. Use 0 for DefaultMaxWindowSize.
func (sc *SSU2Config) WithReceiveWindowSize(size uint) *SSU2Config {
	sc.ReceiveWindowSize = size
	return sc
}

// WithTokenCacheMaxSize sets the maximum number of retry tokens cached by the listener.
func (sc *SSU2Config) WithTokenCacheMaxSize(maxSize int) *SSU2Config {
	if maxSize > 0 {
		sc.TokenCacheMaxSize = maxSize
	}
	return sc
}

// WithGlobalTokenIssuanceRate sets the global cap on retry-token issuance
// across all source addresses (tokens/sec). Pass 0 to disable issuance
// entirely. Negative values are clamped to 0.
func (sc *SSU2Config) WithGlobalTokenIssuanceRate(rate float64) *SSU2Config {
	if rate < 0 {
		rate = 0
	}
	sc.GlobalTokenIssuanceRate = rate
	return sc
}

// WithGlobalTokenIssuanceBurst sets the burst capacity of the global
// token-issuance bucket. Values <= 0 are ignored (the default is preserved).
func (sc *SSU2Config) WithGlobalTokenIssuanceBurst(burst float64) *SSU2Config {
	if burst > 0 {
		sc.GlobalTokenIssuanceBurst = burst
	}
	return sc
}

// WithFirstSightRequired controls whether the listener requires a previously
// observed sighting before issuing a token. When true (the default), a
// brand-new source address must re-request to receive a token. Setting this
// to false disables the gate entirely.
func (sc *SSU2Config) WithFirstSightRequired(required bool) *SSU2Config {
	sc.FirstSightRequired = required
	return sc
}

// WithFirstSightWindow sets how long a first-sight record stays fresh.
// Values <= 0 are ignored.
func (sc *SSU2Config) WithFirstSightWindow(window time.Duration) *SSU2Config {
	if window > 0 {
		sc.FirstSightWindow = window
	}
	return sc
}

// WithFirstSightMaxEntries bounds the memory held by the first-sight
// tracker. Values <= 0 are ignored.
func (sc *SSU2Config) WithFirstSightMaxEntries(maxEntries int) *SSU2Config {
	if maxEntries > 0 {
		sc.FirstSightMaxEntries = maxEntries
	}
	return sc
}

// WithModifiers sets additional handshake modifiers for custom obfuscation.
// These are applied in addition to SSU2's standard modifiers.
func (sc *SSU2Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *SSU2Config {
	// Make defensive copy
	sc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(sc.Modifiers, modifiers)
	return sc
}

// WithRouterInfoValidator sets the RouterInfo validation callback.
// The validator is invoked on the responder after handshake completion to verify
// that the peer's RouterInfo contains the Noise-authenticated static key.
func (sc *SSU2Config) WithRouterInfoValidator(validator func(routerInfo, authenticatedStaticKey []byte) error) *SSU2Config {
	sc.RouterInfoValidator = validator
	return sc
}
