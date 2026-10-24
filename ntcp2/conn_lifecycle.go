package ntcp2

import (
	"errors"
	"net"
	"time"

	"github.com/go-i2p/go-noise/internal/cryptorand"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// guardNonce rejects read or write operations when the nonce counter has
// reached MaxNonce. Per the spec: "Connection must be dropped and restarted
// after it reaches that value." direction should be "read" or "write".
func (nc *Conn) guardNonce(nonce uint64, direction string) error {
	if nonce >= MaxNonce {
		nc.broken.Store(true)
		flog("NTCP2Conn.guardNonce", logger.Fields{direction + "_nonce": nonce}).Error(direction + " nonce exhausted, connection must be terminated")
		return oops.
			Code("NONCE_EXHAUSTED").
			In("ntcp2").
			With(direction+"_nonce", nonce).
			With("max_nonce", MaxNonce).
			Errorf("%s nonce exhausted (reached %d), connection must be terminated", direction, nonce)
	}
	return nil
}

// handshakeErrorCodes are the oops codes that ntcp2.rst §"Session Request" /
// §"Session Created" group under "any error, including AEAD, DH, timestamp,
// apparent replay, or key validation failure", for which Bob (or Alice) "must
// halt further message processing and close the connection without responding.
// This should be an abnormal close (TCP RST)."
//
// I/O and timeout codes (MSG1_READ_FAILED, MSG1_PAD_READ_FAILED,
// MSG3_READ_FAILED, MSG2_NO_BYTES, MSG2_PARTIAL, …) are deliberately absent:
// those are not protocol violations, and a peer that simply went away needs no
// probing resistance. Sending our own message (MSG*_SEND/WRITE_FAILED) is also
// excluded — the socket is already broken in that case. The MSG*_SIZE_MISMATCH
// codes are excluded for the same reason: they are self-checks on a message we
// are about to write, not a violation the peer committed.
var handshakeErrorCodes = map[string]bool{
	// AEAD / DH failures while decrypting a handshake message
	"MSG1_PROCESS_FAILED": true,
	"MSG2_PROCESS_FAILED": true,
	"MSG3_PROCESS_FAILED": true,

	// Key validation failures
	"INVALID_CURVE25519_KEY": true, // X[31] & 0x80 != 0; spec: probe as for AEAD
	// The RouterInfo we received does not advertise the static key the peer
	// proved possession of. (The ROUTER_INFO_KEY_MISMATCH code is a *local*
	// config error on our own outbound RouterInfo, not a peer violation, so it
	// is deliberately not listed here.)
	"PEER_ROUTER_INFO_KEY_MISMATCH": true,

	// Apparent replay
	"MSG1_REPLAY": true,

	// Timestamp failures are deliberately excluded. ntcp2.rst §"Clock Skew
	// Guidelines" requires Bob to answer with a Session Created "even if the
	// maximum skew is exceeded, rather than simply closing the connection. This
	// allows Alice to get Bob's timestamp and calculate the skew." An immediate
	// RST (SetLinger(0) + Close) can discard the Session Created that is still
	// in flight, defeating the very purpose of sending it, so the skew path
	// closes gracefully instead.

	// Message-1 / message-2 field violations
	"MSG1_NETID_MISMATCH":    true,
	"MSG1_VERSION_MISMATCH":  true,
	"MSG1_OPTIONS_TOO_SHORT": true,
	"MSG1_PADDING_TOO_LARGE": true,
	"MSG2_OPTIONS_TOO_SHORT": true,

	// Message 3 part 2 frame violations
	"MSG3_PART2_TOO_LARGE":        true,
	"MSG3_PART2_TOO_SMALL":        true,
	"MSG3_PART2_TOO_SHORT":        true,
	"MSG3_PART2_TRUNCATED_HEADER": true,
	"MSG3_PART2_BLOCK_TYPE":       true,
	"MSG3_PART2_BLOCK_ORDER":      true,
	"MSG3_PART2_BLOCK_OVERRUN":    true,
	"MSG3_PART2_NO_ROUTER_INFO":   true,

	// "Bob/Alice must fail the connection if any incoming data remains"
	"MSG_EXTRA_DATA": true,
}

// isHandshakeProtocolError reports whether err carries one of the oops codes
// that the NTCP2 spec classifies as a handshake failure requiring an abnormal
// close.
func isHandshakeProtocolError(err error) bool {
	var oopsErr oops.OopsError
	if !errors.As(err, &oopsErr) {
		return false
	}
	// Code() is `any` and reports the deepest code in the chain, so a wrapped
	// protocol error still resolves to its original code.
	code, ok := oopsErr.Code().(string)
	if !ok {
		return false
	}
	return handshakeErrorCodes[code]
}

// closeHandshakeError applies the spec's error action for a handshake failure.
//
// ntcp2.rst §"Session Request": "On any error, including AEAD, DH, timestamp,
// apparent replay, or key validation failure, Bob must halt further message
// processing and close the connection without responding. This should be an
// abnormal close (TCP RST)." After an AEAD failure the same section adds that
// Bob "should set a random timeout ... and then read a random number of bytes
// ... before closing the socket" — the probing-resistance delay that
// handleAEADError already implements.
//
// Reusing handleAEADError for every protocol error is intentional: a bad
// transcript, a forbidden block type and a failed timestamp are all things an
// attacker probes for, so they must be indistinguishable on the wire.
func (nc *Conn) closeHandshakeError(err error, underlying net.Conn) {
	if err == nil || !isHandshakeProtocolError(err) {
		return
	}
	// sendTermination=false: the spec requires closing "without responding", and
	// the data-phase keys do not exist yet, so a Termination block cannot be
	// sealed.
	nc.applyProbingResistance(underlying, false)
}

// applyProbingResistance performs the spec's error action: mark the connection
// broken, read a random number of junk bytes over a random timeout, optionally
// let the transport layer emit a Termination block, then RST the socket.
//
// When sendTermination is false the OnAEADError hook is skipped. That is the
// required behaviour for handshake failures: ntcp2.rst §"Session Request" says
// Bob must "close the connection without responding", and the data-phase keys
// are not established until the handshake completes, so a Termination block
// could not be sealed anyway.
func (nc *Conn) applyProbingResistance(underlying net.Conn, sendTermination bool) {
	flog("NTCP2Conn.applyProbingResistance").Warn("authentication/protocol error detected, applying probing-resistance behaviour")
	nc.broken.Store(true)

	// Generate a random byte count in [0, AEADErrorMaxJunkBytes) to read before
	// returning. RandInRange uses rejection sampling so there is no modulo bias.
	junkLenRand, err := cryptorand.RandInRange(0, int64(AEADErrorMaxJunkBytes-1))
	if err != nil {
		nc.sendTCPRST(underlying)
		return // best effort
	}
	junkLen := int(junkLenRand)
	if junkLen > 0 {
		// Randomize the timeout duration within [AEADErrorTimeoutMin, AEADErrorTimeoutMax]
		// to avoid creating a timing fingerprint (per spec: "random timeout").
		timeout := randomAEADTimeout()
		// Best-effort probing resistance: deadline failures do not change the
		// required close-on-auth-failure outcome, so the error is intentionally ignored.
		underlying.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
		junk := make([]byte, junkLen)
		// Best-effort junk read: if the peer closes or the deadline fires, the
		// connection is still marked broken and RST below.
		underlying.Read(junk) //nolint:errcheck // best effort
	}

	// If the router transport layer registered a hook, let it send a termination
	// block (type 4, reason 4 = "AEAD failure") before we RST the socket.
	// Per the spec Data Phase / AEAD Error Handling sections: "the recipient should send a payload with a termination block
	// containing an 'AEAD failure' reason code, and close the connection."
	if sendTermination && nc.OnAEADError != nil {
		nc.OnAEADError(underlying)
	}

	// Per the spec: "This should be an abnormal close (TCP RST)"
	nc.sendTCPRST(underlying)
}

// handleAEADError implements probing-resistance behaviour on AEAD authentication
// failure. Per the NTCP2 spec, the receiver should:
//  1. Read a random number of junk bytes for a random duration.
//  2. Send a TCP RST (abnormal close) rather than a graceful FIN.
//  3. Mark the connection as broken.
//
// Termination blocks (reason code 4 = AEAD failure) are handled by the
// router transport layer (go-i2p/go-i2p/lib/transport/ntcp).
func (nc *Conn) handleAEADError(underlying net.Conn) {
	nc.applyProbingResistance(underlying, true)
}

// randomAEADTimeout returns a uniformly random duration in the range
// [AEADErrorTimeoutMin, AEADErrorTimeoutMax] for probing-resistance delays.
// The spec says "random timeout (range TBD)" — we randomize to avoid creating
// a timing fingerprint that would allow an attacker to identify AEAD failures.
func randomAEADTimeout() time.Duration {
	spread := AEADErrorTimeoutMax - AEADErrorTimeoutMin
	n, err := cryptorand.RandInRange(0, int64(spread))
	if err != nil {
		// Fallback to midpoint on entropy failure (best effort)
		return AEADErrorTimeoutMin + spread/2
	}
	return AEADErrorTimeoutMin + time.Duration(n)
}

// sendTCPRST sends a TCP RST by setting SO_LINGER to 0 (immediate close without
// FIN handshake) and then closing the connection. Per the NTCP2 spec, AEAD failures
// should result in an abnormal close. If the underlying connection is not a
// *net.TCPConn, falls back to a normal Close().
//
// Sets underlyingClosed so that the subsequent NTCP2Conn.Close() call skips a
// second close of the same socket, avoiding an fd-reuse double-close race.
func (nc *Conn) sendTCPRST(conn net.Conn) {
	flog("NTCP2Conn.sendTCPRST").Debug("Sending TCP RST (abnormal close) per NTCP2 spec")
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// These are best-effort cleanup calls. Any failure still leaves the
		// socket on the path toward close, and the caller treats this as terminal.
		tcpConn.SetLinger(0) //nolint:errcheck
		tcpConn.Close()      //nolint:errcheck
	} else {
		// Same best-effort cleanup semantics for non-TCP connections.
		conn.Close() //nolint:errcheck
	}
	// Store the flag AFTER the close operations so that a panic between
	// the store and the close cannot permanently prevent a subsequent
	// Close() call from closing the fd. Between this store and the Close()
	// call above, a concurrent Close() goroutine may also call
	// noiseConn.Close() — but noiseConn.Close() on an already-closed socket
	// merely returns an error that is suppressed by the nc.broken.Load()
	// check in Close().
	nc.underlyingClosed.Store(true)
}
