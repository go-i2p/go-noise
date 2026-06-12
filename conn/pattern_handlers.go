package conn

import (
	"context"
	"sync"

	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// PatternHandlerFunc is the signature for a Noise handshake pattern handler.
// Consumers can implement custom patterns and register them via RegisterPattern.
//
// The handler receives a PatternContext interface that provides access to
// configuration, logging, and handshake message operations without exposing
// internal connection state. This allows third-party pattern implementations.
type PatternHandlerFunc func(pctx PatternContext, ctx context.Context) error

// patternMu guards concurrent access to initiatorHandlers and responderHandlers.
var patternMu sync.RWMutex

// initiatorHandlers maps pattern names to their initiator handshake implementations.
// Each handler is a closure over one of the six template functions in pattern_templates.go.
var initiatorHandlers = map[string]PatternHandlerFunc{
	"N":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayInitiator(ctx, "N") }),
	"K":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayInitiator(ctx, "K") }),
	"X":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayInitiator(ctx, "X") }),
	"NN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "NN") }),
	"NK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "NK") }),
	"NX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "NX") }),
	"KN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "KN") }),
	"KK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "KK") }),
	"KX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "KX") }),
	"IN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "IN") }),
	"IK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "IK") }),
	"IX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgInitiator(ctx, "IX") }),
	"XN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgInitiator(ctx, "XN") }),
	"XK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgInitiator(ctx, "XK") }),
	"XX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgInitiator(ctx, "XX") }),
}

// responderHandlers maps pattern names to their responder handshake implementations.
// Each handler is a closure over one of the six template functions in pattern_templates.go.
var responderHandlers = map[string]PatternHandlerFunc{
	"N":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayResponder(ctx, "N") }),
	"K":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayResponder(ctx, "K") }),
	"X":  wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performOnewayResponder(ctx, "X") }),
	"NN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "NN") }),
	"NK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "NK") }),
	"NX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "NX") }),
	"KN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "KN") }),
	"KK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "KK") }),
	"KX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "KX") }),
	"IN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "IN") }),
	"IK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "IK") }),
	"IX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performTwoMsgResponder(ctx, "IX") }),
	"XN": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgResponder(ctx, "XN") }),
	"XK": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgResponder(ctx, "XK") }),
	"XX": wrapConnHandler(func(nc *Conn, ctx context.Context) error { return nc.performThreeMsgResponder(ctx, "XX") }),
}

// wrapConnHandler adapts a *Conn method into a PatternHandlerFunc.
// This allows internal handlers to remain as methods while conforming
// to the public interface signature.
func wrapConnHandler(method func(*Conn, context.Context) error) PatternHandlerFunc {
	return func(pctx PatternContext, ctx context.Context) error {
		// The PatternContext is guaranteed to be a *Conn in our implementation,
		// so this type assertion is safe. External implementations would provide
		// their own PatternContext that doesn't depend on *Conn.
		nc, ok := pctx.(*Conn)
		if !ok {
			return oops.
				Code("INVALID_PATTERN_CONTEXT").
				In("noise").
				Errorf("pattern context must be *Conn for built-in handlers")
		}
		return method(nc, ctx)
	}
}

// normalizePattern extracts the short pattern name from a full Noise protocol
// name (e.g., "Noise_XK_25519_AESGCM_SHA256" → "XK") or returns short names unchanged.
func normalizePattern(pattern string) string {
	if hp, err := parseHandshakePattern(pattern); err == nil {
		return hp.Name
	}
	return pattern
}

// performHandshake is a generic handler that consults the appropriate map
// (initiator or responder) based on the role parameter and invokes the
// corresponding pattern handler.
func (nc *Conn) performHandshake(ctx context.Context, role string, handlers map[string]PatternHandlerFunc) error {
	pattern := nc.config.Pattern
	nc.logger.WithFields(i2plogger.Fields{
		"pkg":         "noise",
		"func":        "NoiseConn.performHandshake",
		"pattern":     pattern,
		"role":        role,
		"local_addr":  nc.LocalAddr().String(),
		"remote_addr": nc.RemoteAddr().String(),
	}).Debug("performing handshake as " + role)

	normalized := normalizePattern(pattern)
	patternMu.RLock()
	handler, ok := handlers[normalized]
	patternMu.RUnlock()
	if ok {
		return handler(nc, ctx)
	}
	return oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		Errorf("unsupported handshake pattern: %s", pattern)
}

// performInitiatorHandshake handles the initiator side of the handshake.
func (nc *Conn) performInitiatorHandshake(ctx context.Context) error {
	return nc.performHandshake(ctx, "initiator", initiatorHandlers)
}

// performResponderHandshake handles the responder side of the handshake.
func (nc *Conn) performResponderHandshake(ctx context.Context) error {
	return nc.performHandshake(ctx, "responder", responderHandlers)
}

// RegisterPattern registers custom initiator and responder handlers for the
// given Noise pattern name. Both handlers must be non-nil. RegisterPattern is
// safe to call concurrently with connection handshakes and is intended to be
// called once at program start (e.g., from an init() function).
func RegisterPattern(name string, initiator, responder PatternHandlerFunc) {
	if name == "" || initiator == nil || responder == nil {
		return
	}
	patternMu.Lock()
	initiatorHandlers[name] = initiator
	responderHandlers[name] = responder
	patternMu.Unlock()
}

// PATTERN PARSING
// ============================================================================

// parseHandshakePattern maps pattern name strings to go-i2p/noise HandshakePattern types.
// Accepts short names (e.g., "XX") and full Noise protocol names for both
// AESGCM and ChaChaPoly cipher suites (e.g., "Noise_XX_25519_ChaChaPoly_SHA256").
func parseHandshakePattern(patternName string) (noise.HandshakePattern, error) {
	switch patternName {
	case "Noise_NN_25519_AESGCM_SHA256", "Noise_NN_25519_ChaChaPoly_SHA256", "NN":
		return noise.HandshakeNN, nil
	case "Noise_NK_25519_AESGCM_SHA256", "Noise_NK_25519_ChaChaPoly_SHA256", "NK":
		return noise.HandshakeNK, nil
	case "Noise_NX_25519_AESGCM_SHA256", "Noise_NX_25519_ChaChaPoly_SHA256", "NX":
		return noise.HandshakeNX, nil
	case "Noise_XN_25519_AESGCM_SHA256", "Noise_XN_25519_ChaChaPoly_SHA256", "XN":
		return noise.HandshakeXN, nil
	case "Noise_XK_25519_AESGCM_SHA256", "Noise_XK_25519_ChaChaPoly_SHA256", "XK":
		return noise.HandshakeXK, nil
	case "Noise_XX_25519_AESGCM_SHA256", "Noise_XX_25519_ChaChaPoly_SHA256", "XX":
		return noise.HandshakeXX, nil
	case "Noise_KN_25519_AESGCM_SHA256", "Noise_KN_25519_ChaChaPoly_SHA256", "KN":
		return noise.HandshakeKN, nil
	case "Noise_KK_25519_AESGCM_SHA256", "Noise_KK_25519_ChaChaPoly_SHA256", "KK":
		return noise.HandshakeKK, nil
	case "Noise_KX_25519_AESGCM_SHA256", "Noise_KX_25519_ChaChaPoly_SHA256", "KX":
		return noise.HandshakeKX, nil
	case "Noise_IN_25519_AESGCM_SHA256", "Noise_IN_25519_ChaChaPoly_SHA256", "IN":
		return noise.HandshakeIN, nil
	case "Noise_IK_25519_AESGCM_SHA256", "Noise_IK_25519_ChaChaPoly_SHA256", "IK":
		return noise.HandshakeIK, nil
	case "Noise_IX_25519_AESGCM_SHA256", "Noise_IX_25519_ChaChaPoly_SHA256", "IX":
		return noise.HandshakeIX, nil
	case "Noise_N_25519_AESGCM_SHA256", "Noise_N_25519_ChaChaPoly_SHA256", "N":
		return noise.HandshakeN, nil
	case "Noise_K_25519_AESGCM_SHA256", "Noise_K_25519_ChaChaPoly_SHA256", "K":
		return noise.HandshakeK, nil
	case "Noise_X_25519_AESGCM_SHA256", "Noise_X_25519_ChaChaPoly_SHA256", "X":
		return noise.HandshakeX, nil
	default:
		return noise.HandshakePattern{}, oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			With("pattern", patternName).
			Errorf("unsupported handshake pattern: %s", patternName)
	}
}

// ValidateHandshakePattern reports whether pattern is a known Noise handshake
// pattern name. It accepts both short names ("XX") and full protocol names
// ("Noise_XX_25519_AESGCM_SHA256"). Returns a non-nil error if the pattern
// is unknown. This exported form allows sibling packages (e.g., noise/listener)
// to validate patterns without importing the unexported parseHandshakePattern.
func ValidateHandshakePattern(pattern string) error {
	_, err := parseHandshakePattern(pattern)
	return err
}
