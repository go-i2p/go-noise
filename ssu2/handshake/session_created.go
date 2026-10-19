package handshake

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// CreateSessionCreated creates a SessionCreated message (XK pattern
// message 2). This is the second handshake message, sent by the responder.
//
// SessionCreated contains:
//   - Ephemeral key (32 bytes)
//   - Encrypted blocks (DateTime, Options)
//
// XK pattern: ← e, ee
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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
// After this, the handshake is complete and transport cipher states are
// available.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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

	// MixHash(header) per ssu2.rst "KDF for Session Created and Session Confirmed part 1" — binds the header into
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
	// the intermediate chainKey per ssu2.rst "KDF for Session Created and Session Confirmed part 1".
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

	// Extract peer's Options block for padding negotiation.
	h.extractPeerOptions(blocks)

	return nil
}
