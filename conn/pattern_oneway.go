package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// ============================================================================
// ONE-WAY PATTERNS (1 message)
// ============================================================================

// performNInitiator handles N pattern as initiator: → e, es
func (nc *Conn) performNInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNInitiator"}).Debug("starting N pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKInitiator handles K pattern as initiator: → e, es, ss
func (nc *Conn) performKInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKInitiator"}).Debug("starting K pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXInitiator handles X pattern as initiator: → e, es, s, ss
func (nc *Conn) performXInitiator(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXInitiator"}).Debug("starting X pattern initiator")
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// performNResponder handles N pattern as responder: → e, es
func (nc *Conn) performNResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performNResponder"}).Debug("starting N pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "N")
}

// performKResponder handles K pattern as responder: → e, es, ss
func (nc *Conn) performKResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performKResponder"}).Debug("starting K pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "K")
}

// performXResponder handles X pattern as responder: → e, es, s, ss
func (nc *Conn) performXResponder(ctx context.Context) error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.performXResponder"}).Debug("starting X pattern responder")
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "X")
}

// ============================================================================
