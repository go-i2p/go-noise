package config

import (
	"crypto/subtle"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Default timeout values per SSU2 specification (ssu2.rst)
const (
	// DefaultHandshakeTimeout is the spec-defined handshake timeout of 15 seconds.
	// Per ssu2.rst: "Handshake timeout: 15 seconds"
	DefaultHandshakeTimeout = 15 * time.Second
)

// DefaultRouterInfoValidator validates that the Noise-authenticated static
// key matches the "s" option in an SSU2 address within the RouterInfo.
//
// It parses the RouterInfo binary payload, locates SSU2 router addresses,
// and compares the static key from the "s" option against the
// Noise-authenticated static key using constant-time comparison.
//
// Per SSU2 spec §SessionConfirmed Notes, the responder must verify that
// the static key authenticated by the Noise handshake corresponds to the
// key published in the peer's RouterInfo.
func DefaultRouterInfoValidator(routerInfo, authenticatedStaticKey []byte) error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "DefaultRouterInfoValidator", "router_info_len": len(routerInfo), "static_key_len": len(authenticatedStaticKey)}).Debug("Validating router info against authenticated static key")
	if len(routerInfo) == 0 {
		return oops.
			Code("EMPTY_ROUTER_INFO").
			In("ssu2").
			Errorf("RouterInfo is empty")
	}
	if len(authenticatedStaticKey) == 0 {
		return oops.
			Code("EMPTY_STATIC_KEY").
			In("ssu2").
			Errorf("authenticated static key is empty")
	}

	ri, _, err := router_info.ReadRouterInfo(routerInfo)
	if err != nil {
		return oops.
			Code("ROUTER_INFO_PARSE_FAILED").
			In("ssu2").
			Wrapf(err, "failed to parse RouterInfo")
	}

	for _, addr := range ri.RouterAddresses() {
		if addr == nil || !addr.IsSSU2() {
			continue
		}
		staticKey, err := addr.StaticKey()
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(staticKey[:], authenticatedStaticKey) == 1 {
			return nil
		}
	}

	return oops.
		Code("ROUTER_INFO_KEY_MISMATCH").
		In("ssu2").
		Errorf("no SSU2 address in RouterInfo contains the Noise-authenticated static key")
}

// NewSSU2Config creates a new SSU2Config with sensible defaults.
// routerHash is the local router identity hash.
// initiator indicates whether this connection will initiate the handshake.
func NewSSU2Config(routerHash data.Hash, initiator bool) (*SSU2Config, error) {
	log.WithFields(logger.Fields{"pkg": "config", "func": "NewSSU2Config", "initiator": initiator}).Debug("Creating new SSU2Config")
	return &SSU2Config{
		Pattern:                  "XK",
		Initiator:                initiator,
		RouterHash:               routerHash,
		HandshakeTimeout:         DefaultHandshakeTimeout,
		ReadTimeout:              0, // No timeout by default
		WriteTimeout:             0, // No timeout by default
		HandshakeRetries:         3,
		RetryBackoff:             1250 * time.Millisecond,
		EnableChaChaObfuscation:  true,
		MTU:                      1280, // IPv6 minimum
		MaxPacketSize:            1500, // Standard Ethernet
		EnableFragmentation:      false,
		PaddingEnabled:           true,
		MinPaddingSize:           0,
		MaxPaddingSize:           64,
		PaddingRatio:             1.0, // 100%
		ConnectionID:             0,   // Will be generated
		KeepaliveInterval:        15 * time.Second,
		IdleTimeout:              5 * time.Minute,
		FragmentTimeout:          10 * time.Second,
		TokenCacheMaxSize:        10000,
		GlobalTokenIssuanceRate:  40,
		GlobalTokenIssuanceBurst: 80,
		FirstSightRequired:       true,
		FirstSightWindow:         30 * time.Second,
		FirstSightMaxEntries:     50000,
		MaxSessions:              65536,
		DestroyTimeout:           11 * time.Second,  // Per spec §Termination: 11s (max RTO)
		MaxClockSkew:             120 * time.Second, // Per spec: ±120s skew tolerance (G-1)
		ReplayCacheTTL:           4 * time.Minute,
		ReceiveWindowSize:        256, // Configurable via WithReceiveWindowSize (M-3)
		RouterInfoValidator:      nil, // C-1: no default; callers must explicitly set via WithRouterInfoValidator
	}, nil
}
