package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
)

// performOnewayInitiator handles any one-message Noise pattern as initiator.
// The initiator sends the single handshake message.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performOnewayInitiator(_ context.Context, label string) error {
	return nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, label)
}

// performOnewayResponder handles any one-message Noise pattern as responder.
// The responder receives the single handshake message.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performOnewayResponder(_ context.Context, label string) error {
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, label)
}

// performTwoMsgInitiator handles any two-message Noise pattern as initiator.
// The initiator sends message 1 then receives message 2.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performTwoMsgInitiator(_ context.Context, p string) error {
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p)
}

// performTwoMsgResponder handles any two-message Noise pattern as responder.
// The responder receives message 1 then sends message 2.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performTwoMsgResponder(_ context.Context, p string) error {
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	return nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p)
}

// performThreeMsgInitiator handles any three-message Noise pattern as initiator.
// The initiator sends message 1, receives message 2, then sends message 3.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performThreeMsgInitiator(_ context.Context, p string) error {
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
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performThreeMsgResponder(_ context.Context, p string) error {
	if err := nc.receiveNoiseHandshakeMsg(handshake.PhaseInitial, "first "+p); err != nil {
		return err
	}
	if err := nc.sendNoiseHandshakeMsg(handshake.PhaseExchange, "second "+p); err != nil {
		return err
	}
	return nc.receiveNoiseHandshakeMsg(handshake.PhaseFinal, "third "+p)
}
