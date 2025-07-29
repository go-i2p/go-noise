package handshake

// HandshakePhase represents the phase of the handshake process
type HandshakePhase int

const (
	// PhaseInitial represents the initial phase of the handshake
	PhaseInitial HandshakePhase = iota
	// PhaseExchange represents the message exchange phase
	PhaseExchange
	// PhaseFinal represents the final phase of the handshake
	PhaseFinal
)

// String returns the string representation of the handshake phase
func (p HandshakePhase) String() string {
	switch p {
	case PhaseInitial:
		return "initial"
	case PhaseExchange:
		return "exchange"
	case PhaseFinal:
		return "final"
	default:
		return "unknown"
	}
}
