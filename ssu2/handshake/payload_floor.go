package handshake

import (
	"github.com/samber/oops"
)

// validatePayloadFloor enforces the SSU2 minimum payload size on a decrypted
// handshake message.
//
// ssu2.md states the floor for every handshake payload:
//   - §"SessionRequest (Type 0)" -> §"Payload": "The minimum payload size is 8 bytes.
//     Since the DateTime block is only 7 bytes, at least one other block must be
//     present."
//   - §"SessionCreated (Type 1)" -> §"Payload": "The minimum payload size is 8 bytes."
//   - §"SessionConfirmed (Type 2)" -> §"Payload": "The minimum payload size is 8 bytes."
//
// The floor is on the plaintext blocks (the ciphertext always clears it because
// of the 16-byte AEAD tag), so it is checked after ReadMessage decrypts and
// before the blocks are consumed. A peer that sends less is not following the
// spec; §"SessionRequest (Type 0)" -> §"Notes" and §"SessionCreated (Type 1)" -> §"Notes" both
// direct the receiver to drop/close on such errors.
func validatePayloadFloor(payload []byte, msgType uint8) error {
	if len(payload) < MinPayloadSize {
		return oops.
			Code("PAYLOAD_TOO_SMALL").
			In("ssu2").
			With("message_type", msgType).
			With("payload_len", len(payload)).
			With("min_payload", MinPayloadSize).
			Errorf("handshake message %d payload is %d bytes, below the %d-byte SSU2 minimum",
				msgType, len(payload), MinPayloadSize)
	}
	return nil
}
