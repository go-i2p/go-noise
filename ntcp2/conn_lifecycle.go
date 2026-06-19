package ntcp2

import (
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

// handleAEADError implements probing-resistance behaviour on AEAD authentication
// failure. Per the NTCP2 spec, the receiver should:
//  1. Read a random number of junk bytes for a random duration.
//  2. Send a TCP RST (abnormal close) rather than a graceful FIN.
//  3. Mark the connection as broken.
//
// Termination blocks (reason code 4 = AEAD failure) are handled by the
// router transport layer (go-i2p/go-i2p/lib/transport/ntcp).
func (nc *Conn) handleAEADError(underlying net.Conn) {
	flog("NTCP2Conn.handleAEADError").Warn("AEAD error detected, applying probing-resistance behaviour")
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
	// Per spec §4: "the recipient should send a payload with a termination block
	// containing an 'AEAD failure' reason code, and close the connection."
	if nc.OnAEADError != nil {
		nc.OnAEADError(underlying)
	}

	// Per the spec: "This should be an abnormal close (TCP RST)"
	nc.sendTCPRST(underlying)
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
	// BUG-RC-4: store flag AFTER the close operations so that a panic between
	// the store and the close cannot permanently prevent a subsequent Close()
	// call from closing the fd. Between this store and the Close() call above,
	// a concurrent Close() goroutine may also call noiseConn.Close() — but
	// noiseConn.Close() on an already-closed socket merely returns an error
	// that is suppressed by the nc.broken.Load() check in Close().
	nc.underlyingClosed.Store(true)
}
