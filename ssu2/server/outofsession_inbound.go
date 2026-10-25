package server

import (
	"encoding/binary"
	"net"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// OutOfSessionMessage is an intro-key protected out-of-session SSU2 message
// that has been successfully de-obfuscated and AEAD-opened by the listener and
// is being handed to the transport layer.
type OutOfSessionMessage struct {
	// Type is the SSU2 message type byte (MessageTypePeerTest or
	// MessageTypeHolePunch).
	Type uint8

	// PacketNumber is the header packet number, also the AEAD nonce.
	PacketNumber uint32

	// DestConnID / SourceConnID are the header connection IDs. For Peer Test
	// messages 5/7 and Hole Punch these are derived from the test/relay nonce
	// (see wire.NonceConnectionIDs), which is how the receiver correlates the
	// message with the pending test.
	DestConnID   uint64
	SourceConnID uint64

	// Blocks is the decrypted payload block list.
	Blocks []*SSU2Block

	// From is the UDP source address of the datagram. Per ssu2.rst §"Relay
	// Process" this is authoritative for hole-punching: "Alice should check the
	// UDP source port of the Hole Punch message, and use that if it is different
	// than the reported port."
	From *net.UDPAddr
}

// outOfSessionHandler is the atomic box holding the registered callback.
type outOfSessionHandler struct {
	fn func(OutOfSessionMessage)
}

// SetOutOfSessionHandler registers the callback that receives intro-key
// protected out-of-session messages (Peer Test type 7, Hole Punch type 11)
// arriving on this listener's socket. Pass nil to unregister.
//
// The callback runs on a listener packet worker; it must not block for long.
func (l *SSU2Listener) SetOutOfSessionHandler(fn func(OutOfSessionMessage)) {
	if fn == nil {
		l.outOfSessionHandler.Store(nil)
		return
	}
	l.outOfSessionHandler.Store(&outOfSessionHandler{fn: fn})
}

// handleOutOfSessionIntroKeyMessage opens an intro-key protected message that
// could not be routed to a session and delivers it to the registered handler.
//
// The payload is AEAD-opened with OUR intro key, which is also what
// authenticates the sender's claim that this message was addressed to us: a
// spoofed or corrupted datagram fails the Poly1305 check and is dropped. Per
// ssu2.rst §"Peer Test" / §"Token Request" notes, on any error the message is
// dropped without responding, so that probing resistance is preserved.
func (l *SSU2Listener) handleOutOfSessionIntroKeyMessage(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	handler := l.outOfSessionHandler.Load()
	if handler == nil {
		return oops.
			Code("NO_OUT_OF_SESSION_HANDLER").
			In("ssu2").
			Errorf("no out-of-session handler registered for message type %d", packet.MessageType)
	}

	cfg := l.config.Load()
	if cfg == nil || len(cfg.IntroKey) != HeaderKeySize {
		return oops.
			Code("INTRO_KEY_MISSING").
			In("ssu2").
			Errorf("no intro key configured: cannot open out-of-session message")
	}
	if len(packet.Header) < LongHeaderSize {
		return oops.Errorf("out-of-session message requires a %d-byte long header", LongHeaderSize)
	}

	plaintext, err := DecryptIntroKeyAEAD(
		cfg.IntroKey,
		packet.Header[:LongHeaderSize],
		packet.Payload,
		packet.MAC,
		packet.PacketNumber,
	)
	if err != nil {
		return oops.Wrapf(err, "failed to open out-of-session message payload")
	}

	blocks, err := DeserializeBlocks(plaintext)
	if err != nil {
		return oops.Wrapf(err, "failed to deserialize out-of-session message blocks")
	}

	flog("handleOutOfSessionIntroKeyMessage", logger.Fields{
		"messageType": packet.MessageType,
		"packetNum":   packet.PacketNumber,
		"remote":      remoteAddr.String(),
		"blocks":      len(blocks),
	}).Debug("delivered out-of-session message")

	handler.fn(OutOfSessionMessage{
		Type:         packet.MessageType,
		PacketNumber: packet.PacketNumber,
		DestConnID:   binary.BigEndian.Uint64(packet.Header[0:8]),
		SourceConnID: binary.BigEndian.Uint64(packet.Header[16:24]),
		Blocks:       blocks,
		From:         remoteAddr,
	})
	return nil
}
