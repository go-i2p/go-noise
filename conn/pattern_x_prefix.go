package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// ============================================================================
// THREE-MESSAGE PATTERNS
// ============================================================================

// performXXInitiator handles XX pattern as initiator
func (nc *Conn) performXXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXXInitiator"}).Debug("starting XX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XX"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XX")
}

// performXXResponder handles XX pattern as responder
func (nc *Conn) performXXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXXResponder"}).Debug("starting XX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XX"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XX")
}

// performXNInitiator handles XN pattern as initiator (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *Conn) performXNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXNInitiator"}).Debug("starting XN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XN"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XN")
}

// performXNResponder handles XN pattern as responder (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *Conn) performXNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXNResponder"}).Debug("starting XN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XN"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XN")
}

// performXKInitiator handles XK pattern as initiator (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *Conn) performXKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXKInitiator"}).Debug("starting XK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first XK"); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second XK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third XK")
}

// performXKResponder handles XK pattern as responder (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *Conn) performXKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXKResponder"}).Debug("starting XK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first XK"); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second XK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third XK")
}

// ============================================================================
