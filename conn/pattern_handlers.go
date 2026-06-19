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

// Pattern group definitions for organizing Noise handshake pattern implementations.
var (
	// onewayPatterns are Noise patterns that complete in one message exchange.
	onewayPatterns = []string{"N", "K", "X"}
	// twoMessagePatterns are Noise patterns that complete in two message exchanges.
	twoMessagePatterns = []string{"NN", "NK", "NX", "KN", "KK", "KX", "IN", "IK", "IX"}
	// threeMessagePatterns are Noise patterns that complete in three message exchanges.
	threeMessagePatterns = []string{"XN", "XK", "XX"}
)

// initiatorHandlers maps pattern names to their initiator handshake implementations.
// Each handler is a closure over one of the six template functions in pattern_templates.go.
// Built by init() to reduce redundancy across the three pattern type categories.
var initiatorHandlers = buildInitiatorHandlers()

// responderHandlers maps pattern names to their responder handshake implementations.
// Each handler is a closure over one of the six template functions in pattern_templates.go.
// Built by init() to reduce redundancy across the three pattern type categories.
var responderHandlers = buildResponderHandlers()

type connPatternMethod func(*Conn, context.Context, string) error

type patternGroupSpec struct {
	patterns     []string
	messageCount int
}

var patternGroupSpecs = []patternGroupSpec{
	{patterns: onewayPatterns, messageCount: 1},
	{patterns: twoMessagePatterns, messageCount: 2},
	{patterns: threeMessagePatterns, messageCount: 3},
}

var handshakePatternsByName = buildHandshakePatternMap()

func addHandshakeAliases(m map[string]noise.HandshakePattern, pattern noise.HandshakePattern, short string) {
	m["Noise_"+short+"_25519_AESGCM_SHA256"] = pattern
	m["Noise_"+short+"_25519_ChaChaPoly_SHA256"] = pattern
	m[short] = pattern
}

func buildHandshakePatternMap() map[string]noise.HandshakePattern {
	patterns := make(map[string]noise.HandshakePattern, 45)
	addHandshakeAliases(patterns, noise.HandshakeNN, "NN")
	addHandshakeAliases(patterns, noise.HandshakeNK, "NK")
	addHandshakeAliases(patterns, noise.HandshakeNX, "NX")
	addHandshakeAliases(patterns, noise.HandshakeXN, "XN")
	addHandshakeAliases(patterns, noise.HandshakeXK, "XK")
	addHandshakeAliases(patterns, noise.HandshakeXX, "XX")
	addHandshakeAliases(patterns, noise.HandshakeKN, "KN")
	addHandshakeAliases(patterns, noise.HandshakeKK, "KK")
	addHandshakeAliases(patterns, noise.HandshakeKX, "KX")
	addHandshakeAliases(patterns, noise.HandshakeIN, "IN")
	addHandshakeAliases(patterns, noise.HandshakeIK, "IK")
	addHandshakeAliases(patterns, noise.HandshakeIX, "IX")
	addHandshakeAliases(patterns, noise.HandshakeN, "N")
	addHandshakeAliases(patterns, noise.HandshakeK, "K")
	addHandshakeAliases(patterns, noise.HandshakeX, "X")
	return patterns
}

func addPatternGroupHandlers(handlers map[string]PatternHandlerFunc, patterns []string, method connPatternMethod) {
	for _, pattern := range patterns {
		p := pattern // capture loop variable
		handlers[p] = wrapConnHandler(func(nc *Conn, ctx context.Context) error {
			return method(nc, ctx, p)
		})
	}
}

func buildHandlers(isInitiator bool) map[string]PatternHandlerFunc {
	handlers := make(map[string]PatternHandlerFunc)

	for _, group := range patternGroupSpecs {
		messageCount := group.messageCount
		method := func(nc *Conn, ctx context.Context, pattern string) error {
			return nc.performPatternTemplate(ctx, messageCount, isInitiator, pattern)
		}
		addPatternGroupHandlers(handlers, group.patterns, method)
	}

	return handlers
}

// buildInitiatorHandlers constructs the initiator handler map from pattern groups,
// reducing code duplication versus explicit map literals.
func buildInitiatorHandlers() map[string]PatternHandlerFunc {
	return buildHandlers(true)
}

// buildResponderHandlers constructs the responder handler map from pattern groups,
// reducing code duplication versus explicit map literals.
func buildResponderHandlers() map[string]PatternHandlerFunc {
	return buildHandlers(false)
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
	if pattern, ok := handshakePatternsByName[patternName]; ok {
		return pattern, nil
	}
	return noise.HandshakePattern{}, oops.
		Code("UNSUPPORTED_PATTERN").
		In("noise").
		With("pattern", patternName).
		Errorf("unsupported handshake pattern: %s", patternName)
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
