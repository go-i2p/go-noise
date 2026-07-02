package server

import (
	"github.com/samber/oops"
)

// initHeaderProtection initializes the inbound HeaderProtector when an
// IntroKey is configured. See the field documentation on SSU2Listener and
// AUDIT C-1 for the rationale.
//
// When config.IntroKey is set (32 bytes), the listener creates a HeaderProtector
// that can decrypt header protection applied by spec-compliant SSU2 initiators.
// The initiator obfuscates header bytes 0-15 (and, for long headers, bytes 16-63)
// using ChaCha20 keyed on the receiver's intro key.
//
// If IntroKey is not set or is the wrong length, this is a no-op and the listener
// assumes all inbound packets have plaintext headers (test/legacy mode).
func (l *SSU2Listener) initHeaderProtection(config *SSU2Config) error {
	if len(config.IntroKey) != 32 {
		return nil
	}
	hp, err := NewHeaderProtectorFromIntroKey(config.IntroKey, HeaderTypeSessionRequest)
	if err != nil {
		return oops.Wrapf(err, "failed to build inbound header protector")
	}
	l.introHeaderProtector = hp
	return nil
}

// parseInboundPacket attempts to deserialize a received datagram. It first tries
// the plaintext interpretation (used by internal tests and legacy peers that do
// not apply header protection). If that fails and the listener has an inbound
// HeaderProtector configured, it falls back to header-protection decryption on
// a defensive copy and re-tries Deserialize. Returns (packet, true) on success
// or (nil, false) when the packet should be silently dropped.
//
// AUDIT C-1 & AUDIT 1.2: This four-stage parse accommodates:
//  1. Plaintext (testing/legacy)
//  2. Header-protected SessionRequest/TokenRequest (intro key)
//  3. Outbound session replies (SessionCreated/Retry) via trial-deobfuscation
//  4. Inbound SessionConfirmed/Data for accepted/established sessions via
//     AcceptedSessionRegistry trial-deobfuscation
//
// For cases 3 and 4 the raw dest conn ID (bytes 0–7) CANNOT be used as a lookup
// key because header protection XOR-masks those bytes.  TrialDeobfuscate tries
// every registered session's protectors in turn and accepts the first whose
// decrypted dest conn ID matches the session's own conn ID.
func (l *SSU2Listener) parseInboundPacket(data []byte) (*SSU2Packet, bool) {
	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err == nil {
		return packet, true
	}

	// Try intro-key (new sessions)
	if l.introHeaderProtector != nil {
		decrypted := make([]byte, len(data))
		copy(decrypted, data)
		if err := l.introHeaderProtector.DecryptHeader(decrypted); err == nil {
			packet = &SSU2Packet{}
			if err := packet.Deserialize(decrypted); err == nil {
				return packet, true
			}
		}
	}

	// Try outbound session header protectors (replies to our dials).
	// We cannot read bytes 0–7 in the clear: they are XOR-masked by header
	// protection.  TrialDeobfuscate iterates all pending sessions and tries
	// each one's SessionCreated protector (then Retry protector) on a
	// defensive copy, accepting the first whose decrypted dest conn ID
	// matches the session's source conn ID.
	if conn, deobfuscated, err := l.pendingOutbound.TrialDeobfuscate(data); err == nil && conn != nil && deobfuscated != nil {
		packet = &SSU2Packet{}
		if err := packet.Deserialize(deobfuscated); err == nil {
			return packet, true
		}
	}

	// Try per-session inbound protectors for accepted/established sessions.
	// Covers:
	//   - SessionConfirmed (responder receives; k_header_2 = sessionConfirmedHeader2)
	//   - Data (all roles; k_header_2 = recvDataHeader2)
	// Both use KDF-derived keys that differ per session and are unknown to the
	// listener until the session's Handshake goroutine derives and notifies them.
	if conn, deobfuscated, err := l.acceptedSessions.TrialDeobfuscate(data); err == nil && conn != nil && deobfuscated != nil {
		packet = &SSU2Packet{}
		if err := packet.Deserialize(deobfuscated); err == nil {
			return packet, true
		}
	}

	return nil, false
}
