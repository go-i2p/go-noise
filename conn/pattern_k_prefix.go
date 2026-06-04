package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// performKNInitiator handles KN pattern as initiator: → e, ← e, ee, se, es
func (nc *Conn) performKNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNInitiator"}).Debug("starting KN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKNResponder handles KN pattern as responder: → e, ← e, ee, se, es
func (nc *Conn) performKNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKNResponder"}).Debug("starting KN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KN")
}

// performKKInitiator handles KK pattern as initiator: → e, es, ss, ← e, ee, se
func (nc *Conn) performKKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKInitiator"}).Debug("starting KK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performKKResponder handles KK pattern as responder: → e, es, ss, ← e, ee, se
func (nc *Conn) performKKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKKResponder"}).Debug("starting KK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KK")
}

// performKXInitiator handles KX pattern as initiator (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *Conn) performKXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKXInitiator"}).Debug("starting KX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first KX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second KX")
}

// performKXResponder handles KX pattern as responder (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *Conn) performKXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKXResponder"}).Debug("starting KX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first KX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second KX")
}
