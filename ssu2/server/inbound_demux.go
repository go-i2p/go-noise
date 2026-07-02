package server

import (
	"sync"
	"time"

	"github.com/go-i2p/go-noise/ssu2/session"
	"github.com/samber/oops"
)

// AcceptedSession holds demux state for a responder-role (or listener-dialed
// initiator-role) session that shares the listener socket.  Both SessionConfirmed
// (responder only) and inbound Data packets are header-protected with per-session
// KDF-derived keys, so a trial-deobfuscation registry analogous to
// PendingOutboundRegistry is required to decode them before the packet can be
// routed to the connection.
//
// Key observations:
//   - For inbound SessionConfirmed (responder receives):
//     k_header_1 = listener's intro key
//     k_header_2 = KDF-derived sessionConfirmedHeader2
//   - For inbound Data (both roles):
//     k_header_1 = our intro key (receiver)
//     k_header_2 = KDF-derived recvDataHeader2
//
// Both protectors are registered asynchronously via notification channels
// because the keys are only derived during the Handshake() goroutine.
type AcceptedSession struct {
	// connID is the responder's own connection ID, which equals the
	// destination connection ID in all inbound packets for this session.
	connID uint64

	// conn is the SSU2Conn being demultiplexed.
	conn *session.SSU2Conn

	// sessionConfirmedProtector decrypts header protection on inbound
	// SessionConfirmed packets.  Nil until notified from
	// createAndSendSessionCreated (responder only).
	sessionConfirmedProtector *HeaderProtector

	// dataInboundProtector decrypts header protection on inbound Data packets.
	// Nil until notified from deriveDataPhaseKeys (both roles).
	dataInboundProtector *HeaderProtector

	// createdAt tracks when this entry was registered.
	createdAt time.Time
}

// AcceptedSessionRegistry manages the set of sessions that share the listener
// socket and need per-session header-protector trial-deobfuscation.  It mirrors
// PendingOutboundRegistry for the inbound / responder direction.
//
// Thread Safety: All methods are thread-safe via mu.
type AcceptedSessionRegistry struct {
	// sessions maps connID → AcceptedSession
	sessions map[uint64]*AcceptedSession

	// mu protects the sessions map
	mu sync.RWMutex

	// maxSessions caps the number of entries (0 = no cap).
	maxSessions int
}

// NewAcceptedSessionRegistry creates a registry with an optional capacity cap.
// maxSessions ≤ 0 means no cap (caller should pass config.MaxSessions * 2 or similar).
func NewAcceptedSessionRegistry(maxSessions int) *AcceptedSessionRegistry {
	return &AcceptedSessionRegistry{
		sessions:    make(map[uint64]*AcceptedSession),
		maxSessions: maxSessions,
	}
}

// Register adds a new accepted session to the registry.
// Protectors are initially nil and filled in later via SetSessionConfirmedProtector
// and SetDataPhaseProtector.
// Returns error if capacity is exceeded or connID is already registered.
func (r *AcceptedSessionRegistry) Register(connID uint64, conn *session.SSU2Conn) error {
	flog("AcceptedSessionRegistry.Register").Debug("Registering accepted session for inbound demux")
	if conn == nil {
		return oops.
			Code("INVALID_SESSION").
			In("accepted_session_registry").
			Errorf("connection cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxSessions > 0 && len(r.sessions) >= r.maxSessions {
		return oops.
			Code("ACCEPTED_CAPACITY_EXCEEDED").
			In("accepted_session_registry").
			With("max", r.maxSessions).
			With("current", len(r.sessions)).
			Errorf("accepted session registry capacity exceeded")
	}

	if _, exists := r.sessions[connID]; exists {
		return oops.
			Code("DUPLICATE_CONN_ID").
			In("accepted_session_registry").
			With("conn_id", connID).
			Errorf("connection ID already registered in accepted session registry")
	}

	r.sessions[connID] = &AcceptedSession{
		connID:    connID,
		conn:      conn,
		createdAt: time.Now(),
	}
	return nil
}

// SetSessionConfirmedProtector installs the header protector used to deobfuscate
// inbound SessionConfirmed packets for this session.
// Returns error if the session is not registered.
func (r *AcceptedSessionRegistry) SetSessionConfirmedProtector(connID uint64, protector *HeaderProtector) error {
	flog("AcceptedSessionRegistry.SetSessionConfirmedProtector").Debug("Installing SessionConfirmed inbound protector")
	if protector == nil {
		return oops.
			Code("INVALID_PROTECTOR").
			In("accepted_session_registry").
			Errorf("protector cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.sessions[connID]
	if !ok {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("accepted_session_registry").
			With("conn_id", connID).
			Errorf("session not found in accepted registry for SessionConfirmed protector update")
	}
	entry.sessionConfirmedProtector = protector
	return nil
}

// SetDataPhaseProtector installs the header protector used to deobfuscate
// inbound Data packets for this session.
// Returns error if the session is not registered.
func (r *AcceptedSessionRegistry) SetDataPhaseProtector(connID uint64, protector *HeaderProtector) error {
	flog("AcceptedSessionRegistry.SetDataPhaseProtector").Debug("Installing data-phase inbound protector")
	if protector == nil {
		return oops.
			Code("INVALID_PROTECTOR").
			In("accepted_session_registry").
			Errorf("protector cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.sessions[connID]
	if !ok {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("accepted_session_registry").
			With("conn_id", connID).
			Errorf("session not found in accepted registry for data-phase protector update")
	}
	entry.dataInboundProtector = protector
	return nil
}

// TrialDeobfuscate attempts header-protection removal on packetData against
// every registered session's available protectors (SessionConfirmed and/or
// data-phase inbound).  Because bytes 0–7 are XOR-masked, the dest conn ID
// cannot be read before deobfuscation; this method tries each candidate in
// turn, accepting the first whose decrypted bytes 0–7 equal that session's
// connID.
//
// Returns (conn, deobfuscated, nil) on the first match.
// Returns (nil, nil, nil) when no session matches.
func (r *AcceptedSessionRegistry) TrialDeobfuscate(packetData []byte) (*session.SSU2Conn, []byte, error) {
	flog("AcceptedSessionRegistry.TrialDeobfuscate").Debug("Trial-deobfuscating against accepted sessions")
	if len(packetData) < 8 {
		return nil, nil, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, entry := range r.sessions {
		if conn, data := trialDeobfuscateWithProtector(entry.sessionConfirmedProtector, entry.conn, entry.connID, packetData); conn != nil {
			return conn, data, nil
		}
		if conn, data := trialDeobfuscateWithProtector(entry.dataInboundProtector, entry.conn, entry.connID, packetData); conn != nil {
			return conn, data, nil
		}
	}
	return nil, nil, nil
}

// Remove unregisters an accepted session from the registry.
// Safe to call multiple times (idempotent).
func (r *AcceptedSessionRegistry) Remove(connID uint64) {
	flog("AcceptedSessionRegistry.Remove").Debug("Removing accepted session from inbound registry")
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, connID)
}

// Count returns the number of registered accepted sessions.
func (r *AcceptedSessionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
