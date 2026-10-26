package handshake

import (
	"encoding/binary"

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

	// Verify the responder echoed our connection IDs back, swapped.
	//
	// Spec ref: ssu2.md §"Session Created" -> §"Notes": "Alice must drop the message
	// if the Destination and Source Connection IDs do not match the Source and
	// Destination Connection IDs of the Session Request." The header field table
	// defines Destination Connection ID as "The Source Connection ID received from
	// Alice in Session Request" and Source Connection ID as "The Destination
	// Connection ID received from Alice in Session Request".
	//
	// This is checked BEFORE MixHash(header): ssu2.md §"Duplicates and Error
	// Handling" requires that "Duplicates of the three Noise handshake messages ...
	// must be detected before MixHash() of the header", because once a corrupted or
	// bogus message has been hashed the transcript cannot be recovered even with
	// retransmission.
	if h.sessionRequestSent && len(packet.Header) >= 24 {
		gotDest := binary.BigEndian.Uint64(packet.Header[0:8])
		if gotDest != h.sentSourceConnID {
			return oops.
				Code("SESSION_CREATED_CONN_ID_MISMATCH").
				In("ssu2").
				With("dest_conn_id", gotDest).
				With("expected_dest_conn_id", h.sentSourceConnID).
				Errorf("SessionCreated destination connection ID %d does not match the source connection ID %d we sent in SessionRequest",
					gotDest, h.sentSourceConnID)
		}
		// The §Notes sentence pairs the above with "the Source Connection ID ...
		// [must] match the Destination Connection ID of the Session Request". The
		// responder now fills SessionCreated bytes 16-23 with Alice's own
		// SessionRequest destination ID (it adopts that value as its routing key in
		// ssu2/server/listener.go responderConnID), so the echo is enforced here too.
		gotSource := binary.BigEndian.Uint64(packet.Header[16:24])
		if gotSource != h.sentDestConnID {
			return oops.
				Code("SESSION_CREATED_CONN_ID_MISMATCH").
				In("ssu2").
				With("source_conn_id", gotSource).
				With("expected_source_conn_id", h.sentDestConnID).
				Errorf("SessionCreated source connection ID %d does not match the destination connection ID %d we sent in SessionRequest",
					gotSource, h.sentDestConnID)
		}
	}

	// Verify the message came from the endpoint we sent the Session Request to.
	//
	// Spec ref: ssu2.md §"Session Created" -> §"Notes": "Alice must drop the
	// message if the source IP and port do not match the destination IP and port
	// of the Session Request." The spec's §"Header Binding" rationale is that the
	// handshake pins a stable endpoint for its duration; an answer from anywhere
	// else means an off-path attacker injected a Session Created (or our own
	// outbound address was guessed), and accepting it would let that party drive
	// the transcript.
	//
	// Checked BEFORE MixHash(header) for the same reason as the connection-ID
	// checks above: ssu2.md §"Duplicates and Error Handling" requires rejection
	// before the header is folded into the transcript.
	if err := h.validatePeerAddress(packet); err != nil {
		return err
	}

	// Network ID check (proposal 147): a Session Created from another I2P
	// network must fail fast rather than continue a mismatched handshake.
	if err := h.validateNetworkID(packet); err != nil {
		return err
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

	// ssu2.md §"SessionCreated (Type 1)" -> §"Payload": "The minimum payload size is 8
	// bytes."
	if err := validatePayloadFloor(payload, MessageTypeSessionCreated); err != nil {
		return err
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
