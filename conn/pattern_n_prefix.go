package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// TWO-MESSAGE INTERACTIVE PATTERNS
// ============================================================================

// performNNInitiator handles NN pattern as initiator
func (nc *Conn) performNNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNInitiator"}).Debug("starting NN pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNNResponder handles NN pattern as responder
func (nc *Conn) performNNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNNResponder"}).Debug("starting NN pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NN"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NN")
}

// performNKInitiator handles NK pattern as initiator: → e, es, ← e, ee
func (nc *Conn) performNKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKInitiator"}).Debug("starting NK pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNKResponder handles NK pattern as responder: → e, es, ← e, ee
func (nc *Conn) performNKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNKResponder"}).Debug("starting NK pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NK"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NK")
}

// performNXInitiator handles NX pattern as initiator: → e, ← e, ee, s, es
func (nc *Conn) performNXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXInitiator"}).Debug("starting NX pattern initiator")
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}

// performNXResponder handles NX pattern as responder: → e, ← e, ee, s, es
func (nc *Conn) performNXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNXResponder"}).Debug("starting NX pattern responder")
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first NX"); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second NX")
}
