package handshake

import (
	"errors"
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface check: ModifierChain must implement HandshakeModifier.
var _ HandshakeModifier = (*ModifierChain)(nil)

// ModifierChain applies several [HandshakeModifier]s in sequence.
//
// On the way out, modifiers run in the order they were added (first to last).
// On the way in, they run in reverse order (last to first). This keeps the
// transformations balanced: if modifier A wraps modifier B's output, inbound
// unwraps B first, then A.
//
// Example:
//
//	chain := NewModifierChain("chain", xor, padding)
//	// Outbound: data -> xor -> padding
//	// Inbound:  data -> padding -> xor
//
// Thread-safety: a chain is safe for concurrent use after it is built. The
// list of modifiers is copied at construction time and never changed, so
// concurrent ModifyOutbound/ModifyInbound calls need no extra synchronisation.
// Do not call Close() at the same time as other methods (Close is not
// re-entrant).
type ModifierChain struct {
	modifiers []HandshakeModifier
	name      string
}

// NewModifierChain creates a new modifier chain with the given modifiers.
// Modifiers are applied in the order they are provided.
// Nil modifiers are silently filtered out to prevent runtime panics.
func NewModifierChain(name string, modifiers ...HandshakeModifier) *ModifierChain {
	// Filter nil entries and copy to prevent external modification
	chain := make([]HandshakeModifier, 0, len(modifiers))
	for _, m := range modifiers {
		if m != nil {
			chain = append(chain, m)
		}
	}

	flog("NewModifierChain", logger.Fields{"name": name, "modifier_count": len(chain)}).Debug("Creating modifier chain")
	return &ModifierChain{
		modifiers: chain,
		name:      name,
	}
}

// logModifyStart emits a debug trace at the start of an Modify* operation.
func (mc *ModifierChain) logModifyStart(direction string, phase HandshakePhase, dataLen int) {
	flog("ModifierChain."+direction, logger.Fields{"chain": mc.name, "phase": phase.String(), "data_len": dataLen}).Debug("Applying modifier chain " + direction)
}

// wrapModifierError wraps a modifier failure with standardised context.
// direction must be either "ModifyOutbound" or "ModifyInbound".
func (mc *ModifierChain) wrapModifierError(direction string, modifier HandshakeModifier, index int, phase HandshakePhase, err error) error {
	flog("ModifierChain."+direction, logger.Fields{"chain": mc.name, "modifier": modifier.Name(), "index": index}).WithError(err).Error("Modifier chain " + direction + " failed")
	const outboundMsg = "modifier chain outbound processing failed"
	const inboundMsg = "modifier chain inbound processing failed"
	msg := outboundMsg
	if direction == "ModifyInbound" {
		msg = inboundMsg
	}
	return oops.
		Code("MODIFIER_CHAIN_ERROR").
		In("handshake").
		With("chain_name", mc.name).
		With("modifier_name", modifier.Name()).
		With("modifier_index", index).
		With("phase", phase.String()).
		Wrap(fmt.Errorf("%s: %w", msg, err))
}

// ModifyOutbound runs every modifier in the chain over outbound data, in the
// order the modifiers were added. It returns the transformed data, or an error
// naming the modifier that failed.
func (mc *ModifierChain) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	mc.logModifyStart("ModifyOutbound", phase, len(data))
	result := data

	for i, modifier := range mc.modifiers {
		modified, err := modifier.ModifyOutbound(phase, result)
		if err != nil {
			return nil, mc.wrapModifierError("ModifyOutbound", modifier, i, phase, err)
		}
		result = modified
	}

	return result, nil
}

// ModifyInbound runs every modifier in the chain over inbound data, in reverse
// order, to undo the transformations applied during outbound processing. It
// returns the recovered data, or an error naming the modifier that failed.
func (mc *ModifierChain) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	mc.logModifyStart("ModifyInbound", phase, len(data))
	result := data

	// Apply modifiers in reverse order for inbound data
	for i := len(mc.modifiers) - 1; i >= 0; i-- {
		modifier := mc.modifiers[i]
		modified, err := modifier.ModifyInbound(phase, result)
		if err != nil {
			return nil, mc.wrapModifierError("ModifyInbound", modifier, i, phase, err)
		}
		result = modified
	}

	return result, nil
}

// Name returns the name of the modifier chain for logging and debugging.
func (mc *ModifierChain) Name() string {
	return mc.name
}

// Count returns the number of modifiers in the chain.
func (mc *ModifierChain) Count() int {
	return len(mc.modifiers)
}

// IsEmpty returns true if the chain contains no modifiers.
func (mc *ModifierChain) IsEmpty() bool {
	return len(mc.modifiers) == 0
}

// ModifierNames returns the names of all modifiers in the chain.
func (mc *ModifierChain) ModifierNames() []string {
	names := make([]string, len(mc.modifiers))
	for i, modifier := range mc.modifiers {
		names[i] = modifier.Name()
	}
	return names
}

// Close calls Close() on every modifier in the chain, collecting all errors.
// All members are closed regardless of intermediate errors; the aggregated
// error (via errors.Join) is returned so callers can inspect all failures.
// Callers should not call Close() concurrently with ModifyOutbound or
// ModifyInbound.
func (mc *ModifierChain) Close() error {
	flog("ModifierChain.Close", logger.Fields{"chain": mc.name}).Debug("Closing modifier chain")
	var errs []error
	for _, m := range mc.modifiers {
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
