package config

import (
	"crypto/subtle"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Default timeout values per the SSU2 specification.
const (
	// DefaultHandshakeTotalTimeout is the whole-handshake budget. ssu2.md
	// §"Handshake Retransmission" -> §"Total Timeout": "Recommended total
	// timeout for the handshake is 20 seconds."
	//
	// This is deliberately NOT the same number as the per-message timeouts
	// below: §"Session Request" and §"Token Request" each recommend "15 seconds
	// total" and §"Session Created" recommends "12 seconds total", and those
	// phases share one handshake. Using a single 15 s value as the total
	// truncated the recommended window and abandoned sessions that a compliant
	// peer (i2pd) would still be retransmitting.
	DefaultHandshakeTotalTimeout = 20 * time.Second

	// DefaultHandshakeTimeout is the per-message budget for the Session Request
	// and Session Confirmed phases. ssu2.md §"Handshake Retransmission" ->
	// §"Session Request": "Recommended timeout: 15 seconds total". It caps each
	// phase; DefaultHandshakeTotalTimeout caps the handshake as a whole.
	DefaultHandshakeTimeout = 15 * time.Second

	// DefaultSessionCreatedTimeout is the total budget for Bob waiting for the
	// Session Confirmed. ssu2.md §"Handshake Retransmission" -> §"Session
	// Created": "Recommended retransmission intervals: 1, 2, and 4 seconds (1,
	// 3, and 7 seconds after first sent). Recommended timeout: 12 seconds
	// total".
	DefaultSessionCreatedTimeout = 12 * time.Second

	// DefaultSessionRequestTimeout is the total budget for Alice waiting for the
	// Session Created / Retry. ssu2.md §"Handshake Retransmission" -> §"Session
	// Request": "Recommended retransmission intervals: 1.25, 2.5, and 5 seconds
	// … Recommended timeout: 15 seconds total".
	DefaultSessionRequestTimeout = 15 * time.Second

	// DefaultSessionConfirmedTimeout is the total budget for Alice's Session
	// Confirmed retransmissions before the session is abandoned. ssu2.md
	// §"Handshake Retransmission" -> §"Session Confirmed" gives the same
	// "1.25, 2.5, and 5 seconds" interval recommendation as Session Request.
	DefaultSessionConfirmedTimeout = 15 * time.Second
)

// DefaultRouterInfoValidator is the RouterInfo validation performed by a
// responder on the peer RouterInfo received in Session Confirmed.
//
// ssu2.md §"Session Confirmed" → §"Notes" enumerates the checks:
//
//   - "Bob must perform the usual Router Info validation. Ensure the signature
//     type is supported, verify the signature, verify the timestamp is within
//     bounds, and any other checks necessary."
//   - "Then he must search the Router Info for a NTCP or SSU2 Router Address
//     with a matching version (v) option. The static key (s) in the Router Info
//     must match the static key received in the first frame."
//   - "The introduction key "i" in the RI must be extracted and valid, to be
//     used in the data phase."
//
// So this validator parses the RouterInfo, verifies its signature and
// publication timestamp, then requires an SSU/SSU2 address advertising v=2
// whose "s" option matches the Noise-authenticated static key (constant-time
// compared) and whose "i" option is present and valid.
//
// §"Session Confirmed" → §"Notes" further requires: "On any error, including
// AEAD, RI, DH, timestamp, or key validation failure, Bob must halt further
// message processing and close the connection without responding." Returning a
// non-nil error is what triggers that teardown.
func DefaultRouterInfoValidator(routerInfo, authenticatedStaticKey []byte) error {
	flog("DefaultRouterInfoValidator", logger.Fields{"router_info_len": len(routerInfo), "static_key_len": len(authenticatedStaticKey)}).Debug("Validating router info against authenticated static key")
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

	ri, err := wire.ReadRouterInfo(routerInfo)
	if err != nil {
		return oops.Wrapf(err, "failed to parse peer RouterInfo")
	}

	// Signature type support, signature, timestamp bounds and structure.
	if err := wire.VerifyRouterInfoSignature(ri); err != nil {
		return oops.Wrapf(err, "peer RouterInfo failed validation")
	}

	// Version-scoped address lookup with mandatory s/i options.
	params, err := wire.ExtractSSU2AddressParams(ri)
	if err != nil {
		return oops.Wrapf(err, "peer RouterInfo has no usable SSU2 address")
	}

	if subtle.ConstantTimeCompare(params.StaticKey, authenticatedStaticKey) != 1 {
		return oops.
			Code("ROUTER_INFO_KEY_MISMATCH").
			In("ssu2").
			Errorf("no SSU2 address in RouterInfo contains the Noise-authenticated static key")
	}

	return nil
}

// NewSSU2Config creates a new SSU2Config with sensible defaults.
//
//   - routerHash is the local router identity hash.
//   - initiator indicates whether this connection will initiate the
//     handshake.
func NewSSU2Config(routerHash data.Hash, initiator bool) (*SSU2Config, error) {
	flog("NewSSU2Config", logger.Fields{"initiator": initiator}).Debug("Creating new SSU2Config")
	return &SSU2Config{
		Pattern:       "XK",
		Initiator:     initiator,
		AllowLoopback: true, // Default true for testing; adjust in production as needed
		RouterHash:    routerHash,
		BaseHandshakeConfig: baseconfig.BaseHandshakeConfig{
			HandshakeTimeout: DefaultHandshakeTimeout,
			ReadTimeout:      0, // No timeout by default
			WriteTimeout:     0, // No timeout by default
			HandshakeRetries: 3,
			RetryBackoff:     1250 * time.Millisecond,
		},
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
		DestroyTimeout:           11 * time.Second,   // ssu2.rst "Session Termination" leaves the closing period TBD; 11s matches i2pd
		NetworkID:                wire.MainNetworkID, // ssu2.md §"Header": 2 = main network
		MaxClockSkew:             120 * time.Second,  // Per spec: ±120s skew tolerance
		ReplayCacheTTL:           4 * time.Minute,
		ReceiveWindowSize:        256, // Configurable via WithReceiveWindowSize
		// ssu2.md §"Session Confirmed" -> §"Notes" makes RI validation mandatory
		// for a responder, so the compliant validator is the default rather than
		// an opt-in.
		RouterInfoValidator: DefaultRouterInfoValidator,
		// Left zero: the total is derived (see SSU2Config.HandshakeTotalTimeout),
		// so a caller that shortens HandshakeTimeout keeps fast-fail behavior
		// instead of being silently extended to 20 s.
		HandshakeTotalTimeout: 0,
		// ssu2.md §"Session Establishment" fast path requires somewhere to keep
		// the tokens peers send in New Token blocks, which §"Tokens" says "may be
		// used in a subsequent connection". Default-on so a plain config gets the
		// fast path; the listener replaces it with a socket-wide store.
		SessionTokens: wire.NewSessionTokenStore(0),
	}, nil
}
