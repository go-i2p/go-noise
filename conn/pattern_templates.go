package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
)

// MessageOp represents a single send or receive operation in a handshake.
type MessageOp struct {
	isSend bool // true for send, false for receive
	phase  handshake.HandshakePhase
	label  string
}

// performPatternMessages executes a sequence of handshake operations in order.
// Each operation is either a send or receive at a given handshake phase.
// Operations are executed sequentially; the first error is returned immediately.
func (nc *Conn) performPatternMessages(_ context.Context, ops []MessageOp) error {
	for _, op := range ops {
		var err error
		if op.isSend {
			err = nc.sendNoiseHandshakeMsg(op.phase, op.label)
		} else {
			err = nc.receiveNoiseHandshakeMsg(op.phase, op.label)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// performOnewayInitiator handles any one-message Noise pattern as initiator.
// The initiator sends the single handshake message.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performOnewayInitiator(ctx context.Context, label string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: true, phase: handshake.PhaseInitial, label: label},
	})
}

// performOnewayResponder handles any one-message Noise pattern as responder.
// The responder receives the single handshake message.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performOnewayResponder(ctx context.Context, label string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: false, phase: handshake.PhaseInitial, label: label},
	})
}

// performTwoMsgInitiator handles any two-message Noise pattern as initiator.
// The initiator sends message 1 then receives message 2.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performTwoMsgInitiator(ctx context.Context, p string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: true, phase: handshake.PhaseInitial, label: "first " + p},
		{isSend: false, phase: handshake.PhaseExchange, label: "second " + p},
	})
}

// performTwoMsgResponder handles any two-message Noise pattern as responder.
// The responder receives message 1 then sends message 2.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performTwoMsgResponder(ctx context.Context, p string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: false, phase: handshake.PhaseInitial, label: "first " + p},
		{isSend: true, phase: handshake.PhaseExchange, label: "second " + p},
	})
}

// performThreeMsgInitiator handles any three-message Noise pattern as initiator.
// The initiator sends message 1, receives message 2, then sends message 3.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performThreeMsgInitiator(ctx context.Context, p string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: true, phase: handshake.PhaseInitial, label: "first " + p},
		{isSend: false, phase: handshake.PhaseExchange, label: "second " + p},
		{isSend: true, phase: handshake.PhaseFinal, label: "third " + p},
	})
}

// performThreeMsgResponder handles any three-message Noise pattern as responder.
// The responder receives message 1, sends message 2, then receives message 3.
// Note: context is accepted for API compatibility but is not directly used here.
// The context deadline is enforced at the socket level by executeRoleBasedHandshake().
func (nc *Conn) performThreeMsgResponder(ctx context.Context, p string) error {
	return nc.performPatternMessages(ctx, []MessageOp{
		{isSend: false, phase: handshake.PhaseInitial, label: "first " + p},
		{isSend: true, phase: handshake.PhaseExchange, label: "second " + p},
		{isSend: false, phase: handshake.PhaseFinal, label: "third " + p},
	})
}
