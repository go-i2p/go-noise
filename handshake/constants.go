package handshake

// HandshakePhase names the phase of a Noise connection that a message is in.
// The first three phases are the Noise handshake messages; the last is the
// data phase that follows once the handshake is done.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// The numeric values of these constants are part of a stability contract.
// Downstream packages rely on the ordering
// PhaseInitial < PhaseExchange < PhaseFinal < PhaseData. In particular, guards
// of the form "phase >= PhaseFinal" (ssu2/wire) are used to match both
// PhaseFinal and PhaseData, while "phase > PhaseFinal" (ntcp2) matches only
// PhaseData. New phase constants MUST NOT be inserted between PhaseFinal and
// PhaseData; add them after PhaseData or before PhaseInitial instead.
type HandshakePhase int

const (
	// PhaseInitial is the first handshake message (message 1, sent by the
	// initiator to the responder).
	PhaseInitial HandshakePhase = iota
	// PhaseExchange is the second handshake message (message 2, sent by the
	// responder to the initiator).
	PhaseExchange
	// PhaseFinal is the third handshake message (message 3, sent by the
	// initiator to the responder, when the Noise pattern requires it).
	PhaseFinal
	// PhaseData is the post-handshake data transport phase. It keeps ongoing
	// data exchange distinct from the final handshake message, so
	// protocol-specific modifiers can treat them differently (for example,
	// SSU2).
	//
	// Stability: PhaseData MUST stay strictly greater than PhaseFinal. The
	// ssu2 package uses "phase >= PhaseFinal" guards (and ntcp2 uses "phase >
	// PhaseFinal") that depend on this ordering. Inserting a new constant
	// between PhaseFinal and PhaseData will silently break those modifiers.
	PhaseData
)

// String returns the phase as a short lowercase word, such as "initial" or
// "data". Unknown phases return "unknown".
func (p HandshakePhase) String() string {
	switch p {
	case PhaseInitial:
		return "initial"
	case PhaseExchange:
		return "exchange"
	case PhaseFinal:
		return "final"
	case PhaseData:
		return "data"
	default:
		return "unknown"
	}
}
