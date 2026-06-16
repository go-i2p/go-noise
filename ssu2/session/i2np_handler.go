package session

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// handleI2NPMessage queues a complete I2NP message for delivery.
func (h *DataHandler) handleI2NPMessage(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleI2NPMessage", "dataLen": len(data)}).Debug("Queuing I2NP message for delivery")
	if len(data) == 0 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("I2NP message block is empty")
	}

	// Make defensive copy
	msg := make([]byte, len(data))
	copy(msg, data)

	// Try to queue message (non-blocking if full)
	select {
	case h.messageQueue <- msg:
		h.incrementStat(&h.stats.MessagesReceived)
		return nil
	default:
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("message queue full, dropping message")
	}
}

// === Block Type Handler Methods ===
// Each method handles a specific SSU2 block type, either directly
// or by delegating to registered callbacks.

// handleTermination processes a Termination block (Type 6).
// SSU2 spec format: validDataPacketsReceived (8 bytes, big-endian) + reason (1 byte) + additionalData (optional)
// Minimum length: 9 bytes.
func (h *DataHandler) handleTermination(data []byte) error {
	if len(data) < 9 {
		return oops.Errorf("Termination block too short: %d bytes, need at least 9", len(data))
	}

	validDataReceived := binary.BigEndian.Uint64(data[0:8])
	reason := data[8]
	additionalData := data[9:]

	log.WithFields(logger.Fields{
		"pkg":               "ssu2",
		"func":              "handleTermination",
		"validDataReceived": validDataReceived,
		"reason":            reason,
		"additionalDataLen": len(additionalData),
	}).Info("Received Termination block")

	cbs := h.getCallbacks()
	if cbs.OnTermination != nil {
		cbs.OnTermination(validDataReceived, reason, additionalData)
	}

	return nil
}

// handleNewToken processes a NewToken block (Type 17).
// NewToken format: Expires (4 bytes) + Token (8 bytes) = 12 bytes minimum
func (h *DataHandler) handleNewToken(data []byte) error {
	if len(data) < 12 {
		return oops.Errorf("NewToken block too short: %d bytes, need 12", len(data))
	}

	log.WithFields(logger.Fields{"pkg": "session", "func": "handleNewToken", "tokenLength": len(data)}).Debug("Received NewToken block")

	cbs := h.getCallbacks()
	if cbs.OnNewToken != nil {
		cbs.OnNewToken(data)
	}

	return nil
}

// handleNextNonce processes a NextNonce block (Type 11).
// NextNonce format: 8 bytes representing the new nonce value.
func (h *DataHandler) handleNextNonce(data []byte) error {
	if len(data) < 8 {
		return oops.Errorf("NextNonce block too short: %d bytes, need 8", len(data))
	}

	newNonce := binary.BigEndian.Uint64(data[0:8])

	log.WithFields(logger.Fields{"pkg": "session", "func": "handleNextNonce", "newNonce": newNonce}).Debug("Received NextNonce block")

	cbs := h.getCallbacks()
	if cbs.OnNextNonce != nil {
		return cbs.OnNextNonce(newNonce)
	}

	return nil
}

// handleFirstPacketNumber processes a FirstPacketNumber block (Type 14).
func (h *DataHandler) handleFirstPacketNumber(data []byte) error {
	if len(data) < 4 {
		return oops.Errorf("FirstPacketNumber block too short: %d bytes, need 4", len(data))
	}

	packetNumber := binary.BigEndian.Uint32(data[0:4])

	log.WithFields(logger.Fields{"pkg": "session", "func": "handleFirstPacketNumber", "packetNumber": packetNumber}).Debug("Received FirstPacketNumber block")

	cbs := h.getCallbacks()
	if cbs.OnFirstPacketNumber != nil {
		return cbs.OnFirstPacketNumber(packetNumber)
	}

	return nil
}

// handleCongestion processes a Congestion block (Type 20).
func (h *DataHandler) handleCongestion(data []byte) error {
	if len(data) < 1 {
		return oops.Errorf("Congestion block too short: %d bytes, need 1", len(data))
	}

	flags := data[0]

	log.WithFields(logger.Fields{"pkg": "session", "func": "handleCongestion", "flags": flags}).Debug("Received Congestion block")

	cbs := h.getCallbacks()
	if cbs.OnCongestion != nil {
		return cbs.OnCongestion(flags)
	}

	return nil
}

// handleSignedRelayBlock is the common handler for relay blocks that require
// unconditional signature verification: decode → check signature → verify → dispatch.
// Per SSU2 spec (G-2), if a signature is present, the verifier callback MUST be
// configured and must succeed. If the verifier is nil, the block is rejected to
// prevent fail-open authentication bypass (M-5).
func (h *DataHandler) handleSignedRelayBlock(
	block *SSU2Block,
	label string,
	decode func(*SSU2Block) ([]byte, error), // returns signature bytes
	verify func() error, // nil if no verifier wired
	dispatch func() error, // nil if no callback wired
) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleSignedRelayBlock", "dataLength": len(block.Data)}).Debug("Received " + label + " block")

	sig, err := decode(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode %s block", label)
	}

	if len(sig) == 0 {
		return oops.Code("MISSING_SIGNATURE").Errorf("%s block has no signature", label)
	}

	// Fail-closed (M-5): If signature is present, verifier MUST be configured.
	if verify == nil {
		return oops.Code("VERIFIER_MISSING").Errorf("%s block has signature but verifier callback is not configured", label)
	}
	if err := verify(); err != nil {
		return oops.Code("SIGNATURE_INVALID").Wrapf(err, "%s signature verification failed", label)
	}

	if dispatch != nil {
		return dispatch()
	}

	return nil
}

// handleRelayRequest processes a RelayRequest block (Type 7).
// Per SSU2 spec §Relay Request, signatures MUST be verified before acting (G-2).
func (h *DataHandler) handleRelayRequest(block *SSU2Block) error {
	cbs := h.getCallbacks()
	decoded, decErr := DecodeRelayRequest(block)
	return h.handleSignedRelayBlock(
		block, "RelayRequest",
		func(b *SSU2Block) ([]byte, error) {
			if decErr != nil {
				return nil, decErr
			}
			return decoded.Signature, nil
		},
		func() error {
			if cbs.VerifyRelayRequestSignature != nil {
				return cbs.VerifyRelayRequestSignature(decoded)
			}
			return nil
		},
		func() error {
			if cbs.OnRelayRequest != nil {
				return cbs.OnRelayRequest(block)
			}
			return nil
		},
	)
}

// handleRelayResponse processes a RelayResponse block (Type 8).
// Per SSU2 spec §Relay Response, signatures MUST be verified for
// accepted (code 0) and Charlie-rejected (code >= 64) responses (G-2).
func (h *DataHandler) handleRelayResponse(block *SSU2Block) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleRelayResponse", "dataLength": len(block.Data)}).Debug("Received RelayResponse block")

	cbs := h.getCallbacks()

	decoded, err := DecodeRelayResponse(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode RelayResponse block")
	}

	// Codes 0 (accepted) and >= 64 (Charlie rejection) carry signatures
	if decoded.Code == 0 || decoded.Code >= 64 {
		if len(decoded.Signature) == 0 {
			return oops.Code("MISSING_SIGNATURE").Errorf("RelayResponse (code %d) has no signature", decoded.Code)
		}
		// Fail-closed (M-5): If signature is present, verifier MUST be configured.
		if cbs.VerifyRelayResponseSignature == nil {
			return oops.Code("VERIFIER_MISSING").Errorf("RelayResponse (code %d) has signature but verifier callback is not configured", decoded.Code)
		}
		if err := cbs.VerifyRelayResponseSignature(decoded); err != nil {
			return oops.Code("SIGNATURE_INVALID").Wrapf(err, "RelayResponse signature verification failed")
		}
	}

	if cbs.OnRelayResponse != nil {
		return cbs.OnRelayResponse(block)
	}

	return nil
}

// handleRelayIntro processes a RelayIntro block (Type 9).
// Per SSU2 spec §Relay Intro, signatures MUST be verified before acting (G-2).
func (h *DataHandler) handleRelayIntro(block *SSU2Block) error {
	cbs := h.getCallbacks()
	decoded, decErr := DecodeRelayIntro(block)
	return h.handleSignedRelayBlock(
		block, "RelayIntro",
		func(b *SSU2Block) ([]byte, error) {
			if decErr != nil {
				return nil, decErr
			}
			return decoded.Signature, nil
		},
		func() error {
			if cbs.VerifyRelayIntroSignature != nil {
				return cbs.VerifyRelayIntroSignature(decoded)
			}
			return nil
		},
		func() error {
			if cbs.OnRelayIntro != nil {
				return cbs.OnRelayIntro(block)
			}
			return nil
		},
	)
}

// handleRelayTagRequest processes a RelayTagRequest block (Type 15).
func (h *DataHandler) handleRelayTagRequest(block *SSU2Block) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleRelayTagRequest", "dataLength": len(block.Data)}).Debug("Received RelayTagRequest block")

	cbs := h.getCallbacks()
	if cbs.OnRelayTagRequest != nil {
		return cbs.OnRelayTagRequest(block)
	}

	return nil
}

// handleRelayTag processes a RelayTag block (Type 16).
func (h *DataHandler) handleRelayTag(block *SSU2Block) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleRelayTag", "dataLength": len(block.Data)}).Debug("Received RelayTag block")

	cbs := h.getCallbacks()
	if cbs.OnRelayTag != nil {
		return cbs.OnRelayTag(block)
	}

	return nil
}

// handlePeerTest processes a PeerTest block (Type 10).
// Per SSU2 spec §Peer Test, signatures MUST be verified for messages 1-4 (G-2).
func (h *DataHandler) handlePeerTest(block *SSU2Block) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handlePeerTest", "dataLength": len(block.Data)}).Debug("Received PeerTest block")

	cbs := h.getCallbacks()

	decoded, err := DecodePeerTestBlock(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode PeerTest block")
	}

	// Messages 1-4 MUST carry signatures per spec
	if decoded.MessageCode >= PeerTestRequest && decoded.MessageCode <= PeerTestResult {
		if len(decoded.Signature) == 0 {
			return oops.Code("MISSING_SIGNATURE").Errorf("PeerTest message %d has no signature", decoded.MessageCode)
		}
		// Fail-closed (M-5): If signature is present, verifier MUST be configured.
		if cbs.VerifyPeerTestSignature == nil {
			return oops.Code("VERIFIER_MISSING").Errorf("PeerTest message %d has signature but verifier callback is not configured", decoded.MessageCode)
		}
		if err := cbs.VerifyPeerTestSignature(decoded); err != nil {
			return oops.Code("SIGNATURE_INVALID").Wrapf(err, "PeerTest message %d signature verification failed", decoded.MessageCode)
		}
	}

	if cbs.OnPeerTest != nil {
		return cbs.OnPeerTest(block)
	}

	return nil
}

// handlePathChallenge processes a PathChallenge block (Type 18).
func (h *DataHandler) handlePathChallenge(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handlePathChallenge", "dataLength": len(data)}).Debug("Received PathChallenge block")

	cbs := h.getCallbacks()
	if cbs.OnPathChallenge != nil {
		return cbs.OnPathChallenge(data)
	}

	return nil
}

// handlePathResponse processes a PathResponse block (Type 19).
func (h *DataHandler) handlePathResponse(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handlePathResponse", "dataLength": len(data)}).Debug("Received PathResponse block")

	cbs := h.getCallbacks()
	if cbs.OnPathResponse != nil {
		return cbs.OnPathResponse(data)
	}

	return nil
}

// handleDateTime processes a DateTime block (Type 0).
// DateTime format: Timestamp (4 bytes, seconds since epoch)
func (h *DataHandler) handleDateTime(data []byte) error {
	if len(data) < 4 {
		return oops.Errorf("DateTime block too short: %d bytes, need 4", len(data))
	}

	timestamp := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	cbs := h.getCallbacks()
	if cbs.OnDateTime != nil {
		return cbs.OnDateTime(timestamp)
	}

	return nil
}

// handleOptions processes an Options block (Type 1).
func (h *DataHandler) handleOptions(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleOptions", "dataLength": len(data)}).Debug("Received Options block")

	cbs := h.getCallbacks()
	if cbs.OnOptions != nil {
		return cbs.OnOptions(data)
	}

	return nil
}

// handleRouterInfo processes a RouterInfo block (Type 2).
func (h *DataHandler) handleRouterInfo(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleRouterInfo", "dataLength": len(data)}).Debug("Received RouterInfo block")

	cbs := h.getCallbacks()
	if cbs.OnRouterInfo != nil {
		return cbs.OnRouterInfo(data)
	}

	return nil
}

// handleAddress processes an Address block (Type 13).
// Address format: IP (4 or 16 bytes) + Port (2 bytes)
func (h *DataHandler) handleAddress(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleAddress", "dataLength": len(data)}).Debug("Received Address block")

	cbs := h.getCallbacks()
	if cbs.OnAddress != nil {
		return cbs.OnAddress(data)
	}

	return nil
}

// handleACK processes an ACK block (Type 12).
func (h *DataHandler) handleACK(block *SSU2Block) error {
	cbs := h.getCallbacks()
	if cbs.OnACK != nil {
		return cbs.OnACK(block)
	}

	// ACK blocks are typically handled by the ack_handler component
	return nil
}
