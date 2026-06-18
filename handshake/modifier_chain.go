package handshake

import (
	"errors"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface check: ModifierChain must implement HandshakeModifier.
var _ HandshakeModifier = (*ModifierChain)(nil)

// ModifierChain represents a chain of HandshakeModifier instances that are
// applied in sequence. The chain ensures that modifiers are applied in the
// correct order and provides error handling for the entire chain.
// Moved from: handshake/chain.go
//
// Thread-safety: ModifierChain is safe for concurrent use after construction.
// The internal modifiers slice is immutable (copied at construction time and never
// written afterwards). PaddingModifier uses crypto/rand (goroutine-safe);
// XORModifier is read-only after construction. Callers do not need additional
// synchronisation for concurrent ModifyOutbound/ModifyInbound calls, but must not
// call Close() concurrently with other methods (Close() is not re-entrant).
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

// ModifyOutbound applies all modifiers in the chain to outbound data.
// Modifiers are applied in the order they were added to the chain.
func (mc *ModifierChain) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifierChain.ModifyOutbound", logger.Fields{"chain": mc.name, "phase": phase.String(), "data_len": len(data)}).Debug("Applying modifier chain outbound")
	result := data

	for i, modifier := range mc.modifiers {
		modified, err := modifier.ModifyOutbound(phase, result)
		if err != nil {
			flog("ModifierChain.ModifyOutbound", logger.Fields{"chain": mc.name, "modifier": modifier.Name(), "index": i}).WithError(err).Error("Modifier chain outbound failed")
			return nil, oops.
				Code("MODIFIER_CHAIN_ERROR").
				In("handshake").
				With("chain_name", mc.name).
				With("modifier_name", modifier.Name()).
				With("modifier_index", i).
				With("phase", phase.String()).
				Wrapf(err, "modifier chain outbound processing failed")
		}
		result = modified
	}

	return result, nil
}

// ModifyInbound applies all modifiers in the chain to inbound data.
// Modifiers are applied in reverse order to undo the transformations
// applied during outbound processing.
func (mc *ModifierChain) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	flog("ModifierChain.ModifyInbound", logger.Fields{"chain": mc.name, "phase": phase.String(), "data_len": len(data)}).Debug("Applying modifier chain inbound")
	result := data

	// Apply modifiers in reverse order for inbound data
	for i := len(mc.modifiers) - 1; i >= 0; i-- {
		modifier := mc.modifiers[i]
		modified, err := modifier.ModifyInbound(phase, result)
		if err != nil {
			flog("ModifierChain.ModifyInbound", logger.Fields{"chain": mc.name, "modifier": modifier.Name(), "index": i}).WithError(err).Error("Modifier chain inbound failed")
			return nil, oops.
				Code("MODIFIER_CHAIN_ERROR").
				In("handshake").
				With("chain_name", mc.name).
				With("modifier_name", modifier.Name()).
				With("modifier_index", i).
				With("phase", phase.String()).
				Wrapf(err, "modifier chain inbound processing failed")
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
