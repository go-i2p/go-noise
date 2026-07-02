package server

import (
	"encoding/binary"

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
// AUDIT C-1 & AUDIT 1.2: This two-stage parse accommodates:
// 1. Plaintext (testing/legacy)
// 2. Header-protected SessionRequest/TokenRequest (intro key)
// 3. Outbound session replies (SessionCreated/Retry) with temporary header protectors
//
// The fallback path for outbound replies operates on a defensive copy because
// DecryptHeader mutates the buffer in place, and the inbound buffer may be reused.
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

	// Try outbound session header protectors (replies to our dials)
	// Extract destination ConnID to look up pending outbound session
	if len(data) >= ShortHeaderSize {
		// Extract destination ConnID from packet header bytes 0-7
		destConnID := binary.BigEndian.Uint64(data[0:8])

		// Look up pending outbound session by source ConnID (the destination in the reply)
		conn, deobfuscated, err := l.pendingOutbound.LookupAndDeobfuscate(destConnID, data)
		if err == nil && conn != nil && deobfuscated != nil {
			// Successfully deobfuscated; parse the result
			packet = &SSU2Packet{}
			if err := packet.Deserialize(deobfuscated); err == nil {
				return packet, true
			}
		}
	}

	return nil, false
}
