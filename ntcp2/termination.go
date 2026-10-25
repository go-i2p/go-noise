package ntcp2

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// BuildTerminationBlock returns the plaintext payload of a NTCP2 Termination
// block: [blk:1=4][size:2=9][valid data frames received:8 BE][rsn:1].
//
// ntcp2.md §"Termination" (data phase block types):
//
//	blk :: 4
//	size :: 2 bytes, big endian, value = 9 or more
//	valid data frames received :: The number of valid AEAD data phase frames
//	    received (current receive nonce value); 0 if error occurs in handshake
//	    phase; 8 bytes, big endian
//	rsn :: reason, 1 byte: … 4: data phase AEAD failure … 7: clock skew …
//
// Reference: i2pd libi2pd/NTCP2.cpp:1664-1670 (SendTermination writes exactly
// [eNTCP2BlkTermination][0][9][8-byte BE m_ReceiveSequenceNumber][reason]);
// Java i2p.i2p NTCPConnection.java TerminationReason constants (same numbering).
func BuildTerminationBlock(reason byte, validFramesReceived uint64) []byte {
	block := make([]byte, BlockHeaderSize+TerminationBlockSize)
	block[0] = TerminationBlockType
	binary.BigEndian.PutUint16(block[1:3], TerminationBlockSize)
	binary.BigEndian.PutUint64(block[3:11], validFramesReceived)
	block[11] = reason
	return block
}

// sendTerminationBlock seals and writes one final data-phase frame containing a
// Termination block with the given reason code.
//
// ntcp2.md §"AEAD Error Handling": "After the read, or on read timeout, the
// recipient should send a payload with a termination block containing an 'AEAD
// failure' reason code, and close the connection." §"Clock Skew Guidelines":
// "If the adjusted clock skew exceeds the maximum, Bob should then reply with a
// Disconnect message containing a clock skew reason code, and close the
// connection."
//
// A failure to *decrypt* an inbound frame desynchronises only the receive
// state; the outbound cipher, write nonce and SipHash mask are still in sync,
// so one more properly-framed outbound message is valid and the peer can
// decrypt it (a raw socket write would not be — every data-phase message needs
// the SipHash-masked length prefix and AEAD).
//
// Unlike Conn.SendTerminationFrame, this internal variant does not require the
// established flag, because the clock-skew disconnect fires after message 3
// decrypted (data-phase keys exist) but before Handshake() completes. It does
// require the SipHash outbound state, and fails without it.
func (nc *Conn) sendTerminationBlock(reason byte) error {
	slm := nc.lengthObfuscator.Load()
	if slm == nil {
		return oops.
			Code("NO_SIPHASH_MODIFIER").
			In("ntcp2").
			Errorf("cannot seal termination frame without SipHash outbound state")
	}

	block := BuildTerminationBlock(reason, nc.readNonce)

	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()

	if err := nc.guardNonce(nc.writeNonce, "write"); err != nil {
		return err
	}

	toEncrypt, err := nc.applyOutboundModifier(block)
	if err != nil {
		return err
	}
	encrypted, err := nc.encryptFrame(toEncrypt)
	if err != nil {
		return err
	}
	frame, _, err := nc.buildWireFrameWithMask(encrypted, slm)
	if err != nil {
		return err
	}
	if _, err := nc.writeWireFrame(frame); err != nil {
		return err
	}
	nc.writeNonce++

	flog("NTCP2Conn.sendTerminationBlock", logger.Fields{
		"reason":          reason,
		"frames_received": nc.readNonce,
	}).Debug("NTCP2 termination block sent")
	return nil
}
