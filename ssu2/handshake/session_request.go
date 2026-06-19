package handshake

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// SessionRequestCreateOption configures optional behavior for
// CreateSessionRequest.
type SessionRequestCreateOption func(*sessionRequestCreateConfig) error

type sessionRequestCreateConfig struct {
	retryToken []byte
}

// WithSessionRequestRetryToken injects an 8-byte non-zero Retry token into
// bytes 24-31 of the SessionRequest header. When set, CreateSessionRequest
// automatically resets the Noise state for Retry and uses the tokened header.
func WithSessionRequestRetryToken(token []byte) SessionRequestCreateOption {
	return func(cfg *sessionRequestCreateConfig) error {
		if len(token) != 8 {
			return oops.Errorf("retry token must be exactly 8 bytes, got %d", len(token))
		}
		if isAllZeroToken(token) {
			return oops.Errorf("retry token must be nonzero per SSU2 spec")
		}
		cfg.retryToken = copyBytes(token)
		return nil
	}
}

func parseSessionRequestCreateOptions(opts ...SessionRequestCreateOption) (*sessionRequestCreateConfig, error) {
	cfg := &sessionRequestCreateConfig{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func isAllZeroToken(token []byte) bool {
	for _, b := range token {
		if b != 0 {
			return false
		}
	}
	return true
}

// CreateSessionRequest creates a SessionRequest message (Message 0, XK pattern message 1).
// This is the first handshake message sent by the initiator.
//
// SessionRequest contains:
// - Ephemeral key (32 bytes)
// - Encrypted static key (32 + 16 bytes MAC)
// - Encrypted blocks (DateTime, Options)
//
// XK pattern message 1: → e, es
//
// Optional behavior can be supplied via opts, e.g. Retry tokens.
func (h *HandshakeHandler) CreateSessionRequest(sourceConnID, destConnID uint64, opts ...SessionRequestCreateOption) (*SSU2Packet, error) {
	flog("CreateSessionRequest", logger.Fields{"sourceConnID": sourceConnID, "destConnID": destConnID}).Debug("Creating SessionRequest")
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionRequest")
	}

	cfg, err := parseSessionRequestCreateOptions(opts...)
	if err != nil {
		return nil, err
	}

	// Per SSU2 spec §Retry, tokened requests must start from a fresh
	// handshake state (message index 0 with fresh ephemeral key).
	if len(cfg.retryToken) == 8 {
		if err := h.ResetForRetry(); err != nil {
			return nil, oops.Wrapf(err, "failed to reset handshake state for Retry")
		}
	}

	// Create payload blocks for SessionRequest
	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	return h.buildHandshakePacket(blocks, MessageTypeSessionRequest, sourceConnID, destConnID, cfg.retryToken)
}

// CreateSessionRequestWithToken creates a SessionRequest with a Retry token
// inserted into header bytes 24-31. This is used when resending SessionRequest
// after receiving a Retry message from the responder.
//
// Per SSU2 spec §Retry, the handshake state must be reset before resending
// because the first SessionRequest already advanced the Noise state machine.
// This method calls ResetForRetry internally to create a fresh handshake state
// with a new ephemeral key and clean chaining key (C-3).
func (h *HandshakeHandler) CreateSessionRequestWithToken(sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	flog("CreateSessionRequestWithToken", logger.Fields{"sourceConnID": sourceConnID, "destConnID": destConnID, "tokenLen": len(token)}).Debug("Creating SessionRequest with retry token")
	return h.CreateSessionRequest(sourceConnID, destConnID, WithSessionRequestRetryToken(token))
}

// ResetForRetry recreates the internal Noise handshake state from scratch,
// preserving the static key, remote static key, and local options. This is
// required after receiving a Retry message because the original
// CreateSessionRequest already advanced the handshake state machine past
// message 1. Per SSU2 spec, the retried SessionRequest must use a fresh
// ephemeral key and start from a clean chaining key (C-3).
func (h *HandshakeHandler) ResetForRetry() error {
	flog("ResetForRetry").Debug("Resetting handshake state for retry")
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	pub, err := derivePublicKey(h.staticKey)
	if err != nil {
		return oops.Wrapf(err, "derive local static public key for retry")
	}
	config := noise.Config{
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    h.initiator,
		Prologue:     buildSSU2Prologue(),
		ProtocolName: []byte(SSU2ProtocolName),
		StaticKeypair: noise.DHKey{
			Private: copyBytes(h.staticKey),
			Public:  pub,
		},
	}
	if h.initiator && len(h.remoteStaticKey) == 32 {
		config.PeerStatic = copyBytes(h.remoteStaticKey)
	}
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return oops.Wrapf(err, "failed to recreate handshake state for retry")
	}
	// Zero the outgoing ephemeral private key before replacing the state.
	// LocalEphemeral returns a DHKey whose Private slice shares the underlying
	// array with the HandshakeState's internal field, so SecureZero clears it.
	// Note: the chaining key cannot be zeroed through the public API; it will
	// be collected by the GC when the old HandshakeState is no longer referenced.
	if h.handshakeState != nil {
		oldEphem := h.handshakeState.LocalEphemeral()
		securemem.SecureZero(oldEphem.Private)
	}
	h.handshakeState = hs
	h.sendCipher = nil
	h.recvCipher = nil
	h.sessCreateHeaderKey = nil
	h.sessionConfirmedHeaderKey = nil
	return nil
}

// ProcessSessionRequest processes a received SessionRequest message.
// This is called by the responder to process the initiator's first message.
//
// In the XK pattern, the initiator's static key is NOT transmitted in
// SessionRequest (message 1); it is sent encrypted in SessionConfirmed
// (message 3). This function therefore always returns (nil, nil) on success.
// The initiator's static key becomes available after a successful
// ProcessSessionConfirmed call via GetRemoteStaticKey(). Do NOT use the
// first return value of this function for authorization decisions.
func (h *HandshakeHandler) ProcessSessionRequest(packet *SSU2Packet) ([]byte, error) {
	flog("ProcessSessionRequest").Debug("Processing received SessionRequest")
	if h.initiator {
		return nil, oops.Errorf("initiator cannot process SessionRequest")
	}

	if packet.MessageType != MessageTypeSessionRequest {
		return nil, oops.Errorf("expected SessionRequest (type 0), got type %d", packet.MessageType)
	}

	if len(packet.EphemeralKey) != 32 {
		return nil, oops.Errorf("SessionRequest missing ephemeral key")
	}

	// Replay protection: hash the ephemeral key + payload as a unique message ID.
	// The ephemeral key is randomly generated per handshake attempt, so its
	// hash is a reliable replay detection key.
	if h.replayCache != nil {
		digest := sha256.Sum256(append(packet.EphemeralKey, packet.Payload...))
		if h.replayCache.CheckAndAdd(digest) {
			return nil, oops.Errorf("replayed SessionRequest detected")
		}
	}

	// MixHash(header) per SSU2 spec §KDF — binds the header into
	// the handshake hash before processing the Noise message.
	h.handshakeState.MixHash(packet.Header)

	// Reconstruct Noise message: ephemeral key + encrypted payload + MAC
	noiseMessage := append(append(copyBytes(packet.EphemeralKey), packet.Payload...), packet.MAC...)

	// Process handshake message using Noise protocol
	// ReadMessage will: receive ephemeral key, perform DH, decrypt payload
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to process SessionRequest handshake message")
	}

	// After processing message 1 (→ e, es), derive "SessCreateHeader" from
	// the intermediate chainKey per SSU2 spec §KDF for Session Request.
	h.sessCreateHeaderKey = deriveIntermediateHeaderKey(
		h.handshakeState.ChainingKey(), "SessCreateHeader",
	)

	// Store cipher states
	h.updateCipherStates(cs1, cs2)

	// Parse blocks from decrypted payload
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to deserialize SessionRequest blocks")
	}

	// Validate required blocks (DateTime, Options)
	if err := h.validateHandshakeBlocks(blocks, MessageTypeSessionRequest); err != nil {
		return nil, err
	}

	// Extract peer's Options block for padding negotiation (G-3).
	h.extractPeerOptions(blocks)

	// In the XK pattern, the initiator's static key is transmitted encrypted
	// in SessionConfirmed (message 3), not in SessionRequest (message 1).
	// Returning nil here is correct for XK; the static key will be available
	// via GetRemoteStaticKey() after ProcessSessionConfirmed succeeds.
	return nil, nil
}
