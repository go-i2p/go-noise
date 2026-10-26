package server

import (
	"net"

	"github.com/samber/oops"
)

// initHeaderProtection initializes the inbound HeaderProtector when an
// IntroKey is configured. See the field documentation on SSU2Listener for
// the rationale.
//
// When config.IntroKey is set (32 bytes), the listener creates a HeaderProtector
// that can decrypt header protection applied by spec-compliant SSU2 initiators.
// The initiator obfuscates header bytes 0-15 (and, for long headers, bytes 16-63)
// using ChaCha20 keyed on the receiver's intro key.
//
// If IntroKey is not set or is the wrong length, this is a no-op: the protected
// stages in parseInboundPacket then have no key to try, and only the out-of-session
// message types the spec permits without header protection are accepted.
func (l *SSU2Listener) initHeaderProtection(config *SSU2Config) error {
	if len(config.IntroKey) != 32 {
		return nil
	}
	hp, err := NewHeaderProtectorFromIntroKey(config.IntroKey, HeaderTypeSessionRequest)
	if err != nil {
		return oops.Wrapf(err, "failed to build inbound header protector")
	}
	l.introHeaderProtector.Store(hp)
	return nil
}

// parseInboundPacket attempts to deserialize a received datagram. It first
// tries each header-protection strategy, then reads the header unprotected for
// the out-of-session message types the spec allows there. Returns (packet, true)
// on success or (nil, false) when
// the packet should be silently dropped.
//
// ssu2.md §"Header Validation" requires the receiver to remove header
// protection BEFORE reading the message type ("Decrypting the next 8 bytes of
// the header will then reveal the message type and be able to determine if it
// is a short or long header"), and §"Header Encryption" states that in
// production "connection IDs in the headers are always header-encrypted". The
// de-obfuscation stages are therefore attempted first; the plaintext parse is
// the final fallback.
//
// Attempting plaintext first would mis-interpret a header-protected packet
// whenever its masked type byte (offset 12, XOR-masked by protection) happens
// to decode to a short-header type (SessionConfirmed=2 or Data=6): short-header
// parsing skips the long-header version/network-ID self-validation, so the
// garbage would be accepted instead of falling through to the correct
// de-obfuscation stage.
//
// The de-obfuscation stages are:
//  1. Intro-key (new sessions and out-of-session intro-key messages:
//     TokenRequest, PeerTest, HolePunch, Retry)
//  2. Outbound session replies (SessionCreated/Retry) via trial-deobfuscation
//  3. Inbound SessionConfirmed/Data for accepted/established sessions via
//     AcceptedSessionRegistry trial-deobfuscation
//  4. Unprotected header read, out-of-session types only (spec step 2)
//
// For cases 2 and 3 the raw dest conn ID (bytes 0–7) CANNOT be used as a lookup
// key because header protection XOR-masks those bytes.  TrialDeobfuscate tries
// every registered session's protectors in turn and accepts the first whose
// decrypted dest conn ID matches the session's own conn ID.
// parseInboundPacket de-obfuscates and parses one received datagram, stamping
// the peer's actual source address and address family onto the returned packet.
//
// The source stamp is not cosmetic: ssu2.md §"Session Created" -> §"Notes"
// requires Alice to "drop the message if the source IP and port do not match the
// destination IP and port of the Session Request", and the family selects the
// legal datagram budget (§"Max I2NP Message Size": IPv4 MTU - 28, IPv6
// MTU - 48). Both are only checkable while the datagram's origin is known, so
// the listener — which shares one socket across many sessions — must carry it
// through to the session, exactly as the dedicated-socket read path does in
// ssu2/session/conn_read.go.
func (l *SSU2Listener) parseInboundPacket(data []byte, from *net.UDPAddr) (*SSU2Packet, bool) {
	stamp := func(packet *SSU2Packet) *SSU2Packet {
		packet.Source = from
		packet.IsIPv4 = IsIPv4Addr(from)
		return packet
	}

	// Try intro-key (new sessions and out-of-session intro-key messages:
	// TokenRequest, PeerTest, HolePunch, Retry).
	if hp := l.introHeaderProtector.Load(); hp != nil {
		decrypted := make([]byte, len(data))
		copy(decrypted, data)
		// DecryptHeaderForPacket derives the extension span from the type byte
		// the masks reveal, so one protector covers every intro-key family
		// member. DecryptHeader would instead apply the protector's own
		// configured type, which is SessionRequest here and would over-decrypt
		// bytes 16-63 of any TokenRequest/PeerTest/HolePunch longer than 64
		// bytes (those obfuscate only bytes 16-31).
		if err := hp.DecryptHeaderForPacket(decrypted); err == nil {
			packet := &SSU2Packet{}
			if err := packet.Deserialize(decrypted); err == nil &&
				isIntroKeyMessageType(packet.MessageType) {
				return stamp(packet), true
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
		packet := &SSU2Packet{}
		if err := packet.Deserialize(deobfuscated); err == nil {
			return stamp(packet), true
		}
	}

	// Try per-session inbound protectors for accepted/established sessions.
	// Covers:
	//   - SessionConfirmed (responder receives; k_header_2 = sessionConfirmedHeader2)
	//   - Data (all roles; k_header_2 = recvDataHeader2)
	// Both use KDF-derived keys that differ per session and are unknown to the
	// listener until the session's Handshake goroutine derives and notifies them.
	if conn, deobfuscated, err := l.acceptedSessions.TrialDeobfuscate(data); err == nil && conn != nil && deobfuscated != nil {
		packet := &SSU2Packet{}
		if err := packet.Deserialize(deobfuscated); err == nil {
			return stamp(packet), true
		}
	}

	// Final stage: read the header without any header-protection operation.
	//
	// ssu2.md §"Header Protection" -> §"Recommended processing steps", step 2:
	// "If the connection ID does not match a current session: Check the
	// plaintext header at bytes 8-15 are valid (without doing any header
	// protection operation). Verify the net ID and protocol version are valid,
	// and the message type is Session Request, or other message type allowed
	// out-of-session."
	//
	// This stage therefore covers only out-of-session message types. A Session
	// Confirmed or Data packet is never sent with an unprotected header (its
	// header keys come from the session KDF), so accepting one here would let an
	// attacker forge an unprotected in-session packet past the classifier — the
	// Java reference implementation rejects exactly that
	// (PacketHandler.receiveSSU2Packet: "can't have session confirmed with null
	// state"). It also covers a listener whose IntroKey is not configured yet,
	// for which the protected stages above have no key to try.
	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err == nil && isIntroKeyMessageType(packet.MessageType) {
		return stamp(packet), true
	}

	return nil, false
}

// isIntroKeyMessageType reports whether messageType belongs to the out-of-session
// family protected with the intro key (SessionRequest, SessionCreated, Retry,
// TokenRequest, PeerTest, HolePunch). SessionConfirmed and Data use per-session
// KDF-derived header keys and are never protected with the intro key, so a header
// that resolves to one of those short-header types under the intro key is a false
// match and must fall through to the per-session stages — and must be rejected
// outright by the unprotected stage.
func isIntroKeyMessageType(messageType uint8) bool {
	return messageType != MessageTypeSessionConfirmed && messageType != MessageTypeData
}
