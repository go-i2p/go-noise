package handshake

// HandshakeModifier is the interface every handshake modifier implements.
// A modifier transforms data on its way out (outbound) and undoes that
// transformation on its way in (inbound).
//
// Each method takes the current [HandshakePhase] so the modifier can decide
// whether to act. For example, the built-in modifiers only transform data
// during the handshake phases and pass data-phase messages through unchanged.
//
// Implementations must be safe for concurrent calls to ModifyOutbound and
// ModifyInbound from separate goroutines (for example, the read and write
// pumps of the same connection). A modifier with no mutable state is safe by
// construction; a stateful one must protect its mutable fields with a mutex.
type HandshakeModifier interface {
	// ModifyOutbound transforms data being sent during any phase of the
	// connection. It returns the transformed data, or an error.
	ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)

	// ModifyInbound undoes the outbound transformation on data being received
	// during any phase of the connection. It returns the recovered data, or an
	// error.
	ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)

	// Name returns a short name for the modifier, used in logs and error
	// messages.
	Name() string

	// Close releases any resources the modifier holds and zeroes sensitive key
	// material. Call it when the connection is torn down. A modifier that holds
	// no key material should return nil. [ModifierChain.Close] calls Close on
	// every modifier in the chain.
	Close() error
}

// ModifierCloner is an optional interface a HandshakeModifier can implement to
// support deep copying. If a modifier holds mutable state (for example,
// configuration or statistics), it should implement Clone to return an
// independent copy. Config.Clone() deep-copies modifiers that implement this
// interface; otherwise the same modifier is shared between the original config
// and the clone.
type ModifierCloner interface {
	HandshakeModifier
	Clone() HandshakeModifier
}
