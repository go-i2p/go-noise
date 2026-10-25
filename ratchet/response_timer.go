package ratchet

// This file implements the ratchet layer's response obligations and the timers
// that discharge them.
//
// ecies.md §"Retransmissions and State Transistions" -> §"Ratchet-layer
// Responses":
//
//	"Receipt of NS and NSR messages require a response; receipt of ACK Request
//	 and Next Key blocks also require a response.
//	 Implementations should start a timer when one of these messages is received
//	 which requires a response, and generate an 'empty' (no Garlic Clove block)
//	 response at the ECIES layer if no reverse traffic is sent in a short period
//	 of time (e.g. 1 second).
//	 It may also be appropriate for an even shorter timeout for responses to NS
//	 and NSR messages, to shift the traffic to the efficient ES messages as soon
//	 as possible."
//
// and §"Multiple NSR Messages": "Once Alice receives an NSR, Alice does a split()
// to derive the ES session keys. Alice should set a timer, and send an empty ES
// message if the higher layer does not send any traffic, typically within one
// second."
//
// Java I2P implements the same obligations with a real timer inside the ratchet
// layer (net.i2p.router.crypto.ratchet.ACKTimer, scheduled by RatchetSKM, which
// calls back into ECIESAEADEngine to emit the empty message).
//
// This package is a library with no socket of its own - the host (the datagram or
// streaming layer) owns the write path - so the obligation is exposed as data
// rather than acted on internally:
//
//   - decrypting an NS / NSR / AckRequest / NextKey marks the session as owing a
//     response and records a deadline;
//   - any real outbound ES or NSR the host sends clears it, because that traffic
//     already carries the queued control blocks;
//   - [SessionManager.SweepResponses] returns the sessions whose deadline has
//     passed, and the host sends an empty payload for each via
//     [SessionManager.EncryptGarlicMessage].
//
// A host that ignores the API still works for bidirectional traffic (the
// piggy-backed blocks go out with the next real message); the timers are what make
// unidirectional and low-bandwidth flows complete, which is exactly the case the
// spec calls out.

import (
	"time"

	"github.com/go-i2p/logger"
)

// Response timers per ecies.md §"Ratchet-layer Responses" ("e.g. 1 second"),
// with a shorter value for the NS/NSR handshake.
//
// Java I2P: ECIESAEADEngine uses a 1 s ES-response timer and a shorter ACK timer;
// i2pd ECIESX25519AEADRatchetSession.h uses ECIESX25519_DEFAULT_ACK_REQUEST_INTERVAL
// and drives empty payloads off ECIESX25519_SEND_INACTIVITY_TIMEOUT = 5000 ms.
const (
	// responseTimerES is the deadline for an ES-layer response (Ack / NextKey
	// acknowledgement). Spec: "typically within one second".
	responseTimerES = 1 * time.Second

	// responseTimerHandshake is the deadline for the response to an NS or NSR.
	// Spec: "an even shorter timeout ... to shift the traffic to the efficient ES
	// messages as soon as possible".
	responseTimerHandshake = 500 * time.Millisecond

	// ackResponseDelay is how long to wait before sending an explicit ACK, so a
	// real reply can carry it instead. Spec §"Message ACKs": "wait a short time
	// (perhaps a hundred ms) before sending an explicit ACK".
	ackResponseDelay = 100 * time.Millisecond
)

// responseOwed records that this session must produce a message at the ECIES
// layer, even an empty one, unless real traffic beats the deadline.
type responseOwed struct {
	// deadline is when the response must go out. Zero means nothing is owed.
	deadline time.Time
	// kinds lists every receipt that is still unanswered. One message discharges
	// them all, because any outbound ES carries every queued Ack / NextKey block.
	kinds []string
}

// oweResponse marks a response as due at deadline.
//
// The EARLIEST deadline is kept, so a short handshake timer is never pushed out by
// a later, longer ES timer. Every reason is accumulated rather than overwritten, so
// the host can see everything a single send is answering for.
//
// Must be called with session.mu held.
func (s *Session) oweResponse(kind string, delay time.Duration) {
	deadline := time.Now().Add(delay)
	if s.response.deadline.IsZero() || deadline.Before(s.response.deadline) {
		s.response.deadline = deadline
	}
	for _, existing := range s.response.kinds {
		if existing == kind {
			return
		}
	}
	s.response.kinds = append(s.response.kinds, kind)
}

// fulfillResponse clears the obligation because real traffic (which carries any
// queued control blocks) has gone out.
//
// Must be called with session.mu held.
func (s *Session) fulfillResponse() {
	s.response = responseOwed{}
}

// responseDue reports whether a response obligation exists and has expired.
func (s *Session) responseDue(now time.Time) bool {
	return !s.response.deadline.IsZero() && !now.Before(s.response.deadline)
}

// ResponseOwed describes an outstanding ratchet-layer response obligation.
type ResponseOwed struct {
	// SessionTag identifies the session the host must send on.
	SessionTag [8]byte
	// Kinds lists every unanswered receipt, for logging.
	Kinds []string
	// OverdueBy is how far past the deadline the obligation is.
	OverdueBy time.Duration
}

// SweepResponses returns the sessions whose response deadline has passed, so the
// host can send an empty ECIES-layer message for each.
//
// Spec ref: ecies.md §"Ratchet-layer Responses" - "generate an 'empty' (no Garlic
// Clove block) response at the ECIES layer if no reverse traffic is sent in a
// short period of time".
//
// The obligation is NOT cleared here: the host only discharges it once the send
// succeeds, and a send failure must leave it pending so the response is retried.
// Sending through [SessionManager.EncryptGarlicMessage] clears it automatically,
// since that is real outbound traffic.
func (sm *SessionManager) SweepResponses() []ResponseOwed {
	now := time.Now()
	var due []ResponseOwed

	sm.mu.RLock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.mu.RUnlock()

	for _, session := range sessions {
		session.mu.Lock()
		if session.responseDue(now) {
			tag := session.recvTagForResponse()
			due = append(due, ResponseOwed{
				SessionTag: tag,
				Kinds:      append([]string(nil), session.response.kinds...),
				OverdueBy:  now.Sub(session.response.deadline),
			})
		}
		session.mu.Unlock()
	}

	if len(due) > 0 {
		flog("SweepResponses", logger.Fields{"due": len(due)}).Debug("Ratchet-layer responses are overdue")
	}
	return due
}

// recvTagForResponse returns a tag the host can use to address this session. The
// ratchet layer indexes inbound tags, so any currently-advertised tag identifies
// the session to the peer's own decrypt path; the host normally already holds the
// session's outbound addressing.
//
// Must be called with session.mu held.
func (s *Session) recvTagForResponse() [8]byte {
	if len(s.pendingTags) > 0 {
		return s.pendingTags[0]
	}
	return [8]byte{}
}
