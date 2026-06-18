package handshake

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// CreateSessionCreated creates a SessionCreated message (Message 1, XK pattern message 2).
// This is the second handshake message sent by the responder.
//
// SessionCreated contains:
// - Ephemeral key (32 bytes)
// - Encrypted blocks (DateTime, Options)
//
// XK pattern: ← e, ee
func (h *HandshakeHandler) CreateSessionCreated(sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	flog("CreateSessionCreated", logger.Fields{"sourceConnID": sourceConnID, "destConnID": destConnID}).Debug("Creating SessionCreated")
	if h.initiator {
		return nil, oops.Errorf("only responder can create SessionCreated")
	}

	// Create payload blocks
	blocks := h.createHandshakeBlocks(MessageTypeSessionCreated)

	return h.buildHandshakePacket(blocks, MessageTypeSessionCreated, sourceConnID, destConnID, nil)
}

// ProcessSessionCreated processes a received SessionCreated message.
// This is called by the initiator to process the responder's response.
//
// After this, the handshake is complete and transport cipher states are available.
func (h *HandshakeHandler) ProcessSessionCreated(packet *SSU2Packet) error {
	flog("ProcessSessionCreated").Debug("Processing received SessionCreated")
	if !h.initiator {
		return oops.Errorf("responder cannot process SessionCreated")
	}

	if packet.MessageType != MessageTypeSessionCreated {
		return oops.Errorf("expected SessionCreated (type 1), got type %d", packet.MessageType)
	}

	if len(packet.EphemeralKey) != 32 {
		return oops.Errorf("SessionCreated missing ephemeral key")
	}

	// MixHash(header) per SSU2 spec §KDF — binds the header into
	// the handshake hash before processing the Noise message.
	h.handshakeState.MixHash(packet.Header)

	// Reconstruct Noise message: ephemeral key + encrypted payload + MAC
	noiseMessage := append(append(copyBytes(packet.EphemeralKey), packet.Payload...), packet.MAC...)

	// Process handshake message
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionCreated handshake message")
	}

	// After processing message 2 (← e, ee), derive "SessionConfirmed" from
	// the intermediate chainKey per SSU2 spec §KDF for Session Created.
	h.sessionConfirmedHeaderKey = deriveIntermediateHeaderKey(
		h.handshakeState.ChainingKey(), "SessionConfirmed",
	)

	// Store cipher states (handshake now complete)
	h.updateCipherStates(cs1, cs2)

	// Parse blocks
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return oops.Wrapf(err, "failed to deserialize SessionCreated blocks")
	}

	// Validate blocks
	if err := h.validateHandshakeBlocks(blocks, MessageTypeSessionCreated); err != nil {
		return err
	}

	// Extract peer's Options block for padding negotiation (G-3).
	h.extractPeerOptions(blocks)

	return nil
}
