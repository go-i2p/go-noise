package handshake

// HandshakeModifier defines the interface for modifying handshake data
// for obfuscation and padding purposes. Modifiers can be chained to create
// complex transformations while maintaining Noise protocol security.
type HandshakeModifier interface {
	// ModifyOutbound modifies data being sent during handshake
	ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)

	// ModifyInbound modifies data being received during handshake
	ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)

	// Name returns the modifier name for logging and debugging
	Name() string
}
