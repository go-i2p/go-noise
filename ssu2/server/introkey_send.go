package server

import (
	"net"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SendIntroKeyMessage builds and transmits an intro-key protected
// out-of-session SSU2 message (Peer Test, Hole Punch, Token Request) over the
// listener's socket to an arbitrary UDP address.
//
// These messages are not part of any session: per ssu2.rst §"Header Encryption
// Keys" their header and payload keys are the RECEIVER's introduction key, so
// the caller must supply that peer's intro key (typically extracted from the
// peer's RouterInfo NTCP2/SSU2 address "i" parameter). Construction and sealing
// are delegated to wire.BuildIntroKeyMessage, the single shared builder for the
// intro-key message family.
//
// Fails closed when the intro key is missing or malformed: an unsealed or
// cleartext-header variant is not a valid SSU2 message and would be dropped by
// every conformant peer, so it must never reach the wire.
func (l *SSU2Listener) SendIntroKeyMessage(introKey []byte, spec *IntroKeyMessageSpec, addr *net.UDPAddr) error {
	if addr == nil {
		return oops.Errorf("SendIntroKeyMessage: destination address is nil")
	}
	if len(introKey) != HeaderKeySize {
		flog("SendIntroKeyMessage", logger.Fields{
			"remote": addr.String(),
		}).Warn("receiver intro key unavailable: cannot send spec-compliant out-of-session message")
		return oops.
			Code("INTRO_KEY_MISSING").
			In("ssu2").
			Errorf("out-of-session message requires the receiver's %d-byte intro key", HeaderKeySize)
	}

	packet, packetNumber, err := BuildIntroKeyMessage(introKey, spec)
	if err != nil {
		return oops.Wrapf(err, "failed to build intro-key message")
	}

	if _, err := l.underlying.WriteTo(packet, addr); err != nil {
		return oops.Wrapf(err, "failed to write intro-key message to %s", addr.String())
	}

	flog("SendIntroKeyMessage", logger.Fields{
		"messageType": spec.MessageType,
		"packetNum":   packetNumber,
		"remote":      addr.String(),
		"size":        len(packet),
	}).Debug("sent intro-key protected message")
	return nil
}

// OpenIntroKeyMessage de-obfuscates and opens an intro-key protected
// out-of-session message (Peer Test, Hole Punch, Token Request) received on
// this listener, using our own intro key. The message type is discovered from
// the datagram itself, so the caller does not have to know it in advance.
//
// Returns the deserialized packet and its plaintext payload blocks. Any
// failure (short packet, header that does not de-obfuscate, AEAD verification
// failure) is returned as an error; callers must drop the message without
// responding, per the spec's probing-resistance rules.
func (l *SSU2Listener) OpenIntroKeyMessage(data []byte) (*SSU2Packet, []*SSU2Block, error) {
	cfg := l.config.Load()
	if cfg == nil || len(cfg.IntroKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("INTRO_KEY_MISSING").
			In("ssu2").
			Errorf("no intro key configured: cannot open intro-key protected message")
	}
	return OpenIntroKeyMessage(cfg.IntroKey, data)
}
