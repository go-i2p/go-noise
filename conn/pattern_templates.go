package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
)

// performOnewayInitiator handles any one-message Noise pattern as initiator.
// The initiator sends the single handshake message.
func (nc *Conn) performOnewayInitiator(ctx context.Context, label string) error {
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, label)
}

// performOnewayResponder handles any one-message Noise pattern as responder.
// The responder receives the single handshake message.
func (nc *Conn) performOnewayResponder(ctx context.Context, label string) error {
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, label)
}

// performTwoMsgInitiator handles any two-message Noise pattern as initiator.
// The initiator sends message 1 then receives message 2.
func (nc *Conn) performTwoMsgInitiator(ctx context.Context, p string) error {
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p)
}

// performTwoMsgResponder handles any two-message Noise pattern as responder.
// The responder receives message 1 then sends message 2.
func (nc *Conn) performTwoMsgResponder(ctx context.Context, p string) error {
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p)
}

// performThreeMsgInitiator handles any three-message Noise pattern as initiator.
// The initiator sends message 1, receives message 2, then sends message 3.
func (nc *Conn) performThreeMsgInitiator(ctx context.Context, p string) error {
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseFinal, "third "+p)
}

// performThreeMsgResponder handles any three-message Noise pattern as responder.
// The responder receives message 1, sends message 2, then receives message 3.
func (nc *Conn) performThreeMsgResponder(ctx context.Context, p string) error {
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third "+p)
}
