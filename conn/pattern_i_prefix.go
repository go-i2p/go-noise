package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// performINInitiator handles IN pattern as initiator: → e, s, ← e, ee, se, es
func (nc *Conn) performINInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINInitiator"}).Debug("starting IN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performINResponder handles IN pattern as responder: → e, s, ← e, ee, se, es
func (nc *Conn) performINResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performINResponder"}).Debug("starting IN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IN")
}

// performIKInitiator handles IK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *Conn) performIKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKInitiator"}).Debug("starting IK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIKResponder handles IK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *Conn) performIKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIKResponder"}).Debug("starting IK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IK")
}

// performIXInitiator handles IX pattern as initiator: → e, s, ← e, ee, se, s, es
func (nc *Conn) performIXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIXInitiator"}).Debug("starting IX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first IX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second IX")
}

// performIXResponder handles IX pattern as responder: → e, s, ← e, ee, se, s, es
func (nc *Conn) performIXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performIXResponder"}).Debug("starting IX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first IX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second IX")
}
