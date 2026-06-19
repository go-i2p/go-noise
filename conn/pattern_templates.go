package conn

import (
	"context"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// MessageOp represents a single send or receive operation in a handshake.
type MessageOp struct {
	isSend bool // true for send, false for receive
	phase  handshake.HandshakePhase
	label  string
}

type templateStep struct {
	phase          handshake.HandshakePhase
	initiatorSends bool
	labelPrefix    string
}

var patternTemplateSteps = map[int][]templateStep{
	1: {
		{phase: handshake.PhaseInitial, initiatorSends: true, labelPrefix: ""},
	},
	2: {
		{phase: handshake.PhaseInitial, initiatorSends: true, labelPrefix: "first "},
		{phase: handshake.PhaseExchange, initiatorSends: false, labelPrefix: "second "},
	},
	3: {
		{phase: handshake.PhaseInitial, initiatorSends: true, labelPrefix: "first "},
		{phase: handshake.PhaseExchange, initiatorSends: false, labelPrefix: "second "},
		{phase: handshake.PhaseFinal, initiatorSends: true, labelPrefix: "third "},
	},
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

func buildPatternMessageOps(messageCount int, isInitiator bool, patternLabel string) ([]MessageOp, error) {
	steps, ok := patternTemplateSteps[messageCount]
	if !ok {
		return nil, oops.
			Code("UNSUPPORTED_TEMPLATE").
			In("noise").
			With("message_count", messageCount).
			Errorf("unsupported message template count: %d", messageCount)
	}

	ops := make([]MessageOp, 0, len(steps))
	for _, step := range steps {
		label := patternLabel
		if step.labelPrefix != "" {
			label = step.labelPrefix + patternLabel
		}
		op := MessageOp{
			isSend: step.initiatorSends == isInitiator,
			phase:  step.phase,
			label:  label,
		}
		ops = append(ops, op)
	}

	return ops, nil
}

// performPatternTemplate executes one of the metadata-defined handshake
// templates (1, 2, or 3 messages) for either role.
func (nc *Conn) performPatternTemplate(ctx context.Context, messageCount int, isInitiator bool, patternLabel string) error {
	ops, err := buildPatternMessageOps(messageCount, isInitiator, patternLabel)
	if err != nil {
		return err
	}
	return nc.performPatternMessages(ctx, ops)
}
