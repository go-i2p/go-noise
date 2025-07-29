package handshake

import (
	"github.com/samber/oops"
)

// ModifierChain represents a chain of HandshakeModifier instances that are
// applied in sequence. The chain ensures that modifiers are applied in the
// correct order and provides error handling for the entire chain.
// Moved from: handshake/chain.go
type ModifierChain struct {
	modifiers []HandshakeModifier
	name      string
}

// NewModifierChain creates a new modifier chain with the given modifiers.
// Modifiers are applied in the order they are provided.
func NewModifierChain(name string, modifiers ...HandshakeModifier) *ModifierChain {
	// Make a copy to prevent external modification
	chain := make([]HandshakeModifier, len(modifiers))
	copy(chain, modifiers)

	return &ModifierChain{
		modifiers: chain,
		name:      name,
	}
}

// ModifyOutbound applies all modifiers in the chain to outbound data.
// Modifiers are applied in the order they were added to the chain.
func (mc *ModifierChain) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	result := data

	for i, modifier := range mc.modifiers {
		modified, err := modifier.ModifyOutbound(phase, result)
		if err != nil {
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
	result := data

	// Apply modifiers in reverse order for inbound data
	for i := len(mc.modifiers) - 1; i >= 0; i-- {
		modifier := mc.modifiers[i]
		modified, err := modifier.ModifyInbound(phase, result)
		if err != nil {
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
