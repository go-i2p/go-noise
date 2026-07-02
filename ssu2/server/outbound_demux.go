package server

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/ssu2/session"
	"github.com/samber/oops"
)

// PendingOutboundSession holds state for an outbound session awaiting its
// SessionCreated/Retry reply. Maintained in the listener to enable demultiplexing
// handshake replies over the listener's shared socket.
//
// Design rationale:
//   - Outbound replies (SessionCreated, Retry) are header-protected with keys
//     derived from the handshake, not the listener's intro key
//   - The listener needs these keys to deobfuscate replies and route them
//   - This struct holds the temporary header protector + connection reference
//   - On handshake completion, the session moves to the normal PacketRouter
//   - On handshake failure or timeout, the session is cleaned up
type PendingOutboundSession struct {
	// sourceConnID is the initiator's source connection ID
	sourceConnID uint64

	// conn is the SSU2Conn in handshaking state
	conn *session.SSU2Conn

	// headerProtector is the SessionCreated protector derived from SessCreateHeaderKey.
	// Installed via SetProtector after sendSessionRequest derives the key.
	// Nil until the key is available.
	headerProtector *HeaderProtector

	// retryProtector is the header protector for Retry packets, keyed on
	// the responder's intro key (known at connection creation time).
	// Nil if the remote intro key was not provided.
	retryProtector *HeaderProtector

	// createdAt tracks when this pending session was registered
	createdAt time.Time

	// handshakeDoneOnce ensures cleanup happens exactly once
	handshakeDoneOnce sync.Once
}

// PendingOutboundRegistry manages pending outbound sessions registered on a listener.
// It provides thread-safe registration, lookup, and cleanup of outbound sessions
// awaiting their SessionCreated/Retry replies.
//
// Thread Safety: All methods are thread-safe via registry.mu.
type PendingOutboundRegistry struct {
	// sessions maps source connection ID to pending session state
	sessions map[uint64]*PendingOutboundSession

	// mu protects the sessions map
	mu sync.RWMutex

	// maxPending caps the number of simultaneous pending outbound sessions
	// (optional; 0 = no limit). Prevents memory exhaustion from stalled dials.
	maxPending int

	// cleanupTimeout is how long to wait before removing a stale pending session
	// (optional; 0 = no timeout). Prevents memory leaks from interrupted dials.
	cleanupTimeout time.Duration

	// stopChan signals cleanup goroutine to exit (lifecycle management)
	stopChan chan struct{}

	// wg waits for cleanup goroutine
	wg sync.WaitGroup
}

// NewPendingOutboundRegistry creates a new registry for pending outbound sessions.
//
// Parameters:
//   - maxPending: Maximum concurrent pending sessions (0 = unlimited)
//   - cleanupTimeout: How long before removing stale sessions (0 = no timeout)
//
// Returns a new registry ready to use.
func NewPendingOutboundRegistry(maxPending int, cleanupTimeout time.Duration) *PendingOutboundRegistry {
	return &PendingOutboundRegistry{
		sessions:       make(map[uint64]*PendingOutboundSession),
		maxPending:     maxPending,
		cleanupTimeout: cleanupTimeout,
		stopChan:       make(chan struct{}),
	}
}

// Register adds a pending outbound session to the registry.
// Returns error if the session ID is already registered or capacity is exceeded.
//
// Parameters:
//   - sourceConnID: The initiator's source connection ID (routing key)
//   - conn: The SSU2Conn in handshaking state
//   - retryProtector: Header protector for Retry replies (built from remote intro
//     key, available at registration time). May be nil when the remote intro key
//     is not yet known.
//
// The SessionCreated protector is installed separately via SetProtector once
// SessCreateHeaderKey is derived inside Handshake.
//
// Returns error if registration fails.
func (r *PendingOutboundRegistry) Register(sourceConnID uint64, conn *session.SSU2Conn, retryProtector *HeaderProtector) error {
	flog("Register").Debug("Registering pending outbound session")
	if conn == nil {
		return oops.
			Code("INVALID_SESSION").
			In("pending_outbound").
			Errorf("connection cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check capacity
	if r.maxPending > 0 && len(r.sessions) >= r.maxPending {
		return oops.
			Code("PENDING_CAPACITY_EXCEEDED").
			In("pending_outbound").
			With("max_pending", r.maxPending).
			With("current", len(r.sessions)).
			Errorf("pending outbound session capacity exceeded")
	}

	// Check for duplicate
	if _, exists := r.sessions[sourceConnID]; exists {
		return oops.
			Code("DUPLICATE_SOURCE_CONN_ID").
			In("pending_outbound").
			With("source_conn_id", sourceConnID).
			Errorf("source connection ID already registered")
	}

	r.sessions[sourceConnID] = &PendingOutboundSession{
		sourceConnID:   sourceConnID,
		conn:           conn,
		retryProtector: retryProtector,
		createdAt:      time.Now(),
	}

	return nil
}

// GetSessionBySourceConnID retrieves a pending outbound session by its source connection ID.
// Returns nil if not found.
// This is used for routing incoming replies to pending outbound sessions.
//
// Parameters:
//   - sourceConnID: The source connection ID to look up
//
// Returns the SSU2Conn, or nil if not found.
func (r *PendingOutboundRegistry) GetSessionBySourceConnID(sourceConnID uint64) *session.SSU2Conn {
	flog("GetSessionBySourceConnID").Debug("Looking up session by source ConnID")

	r.mu.RLock()
	defer r.mu.RUnlock()

	pending := r.sessions[sourceConnID]
	if pending != nil {
		return pending.conn
	}
	return nil
}

// LookupAndDeobfuscate searches for a pending outbound session by source connection ID
// and attempts to deobfuscate the packet header using its stored SessionCreated protector.
// Returns (connection, deobfuscated_packet, error).
//
// NOTE: This method is keyed on the raw (possibly masked) dest conn ID; use
// TrialDeobfuscate when the header bytes may be XOR-masked.  LookupAndDeobfuscate
// is kept for post-parse routing where the conn ID is already decrypted.
//
// On success, the caller must manually remove the session from the registry when
// the handshake completes (to transition it to the normal session router).
//
// Parameters:
//   - sourceConnID: The source connection ID to look up
//   - packetData: The encrypted packet (will be deobfuscated in place if found)
//
// Returns (conn, deobfuscated_data, nil) if found and deobfuscation succeeds,
// or (nil, nil, nil) if not found, or (nil, nil, error) if deobfuscation fails.
func (r *PendingOutboundRegistry) LookupAndDeobfuscate(sourceConnID uint64, packetData []byte) (*session.SSU2Conn, []byte, error) {
	flog("LookupAndDeobfuscate").Debug("Looking up pending outbound session")

	r.mu.RLock()
	pending := r.sessions[sourceConnID]
	r.mu.RUnlock()

	if pending == nil {
		return nil, nil, nil
	}

	if pending.headerProtector == nil {
		// SessionCreated protector not yet installed (SessCreateHeaderKey not yet
		// derived).  Return an error so the caller can distinguish "found but
		// undeobfuscatable" from "not found", preventing silent plaintext passthrough.
		return nil, nil, oops.
			Code("MISSING_HEADER_PROTECTOR").
			In("pending_outbound").
			With("source_conn_id", sourceConnID).
			Errorf("SessionCreated header protector not yet installed for pending session")
	}

	// Work on a defensive copy (deobfuscation mutates in place)
	deobfuscated := make([]byte, len(packetData))
	copy(deobfuscated, packetData)

	if err := pending.headerProtector.DecryptHeader(deobfuscated); err != nil {
		return nil, nil, oops.Wrapf(err, "failed to deobfuscate outbound reply")
	}

	return pending.conn, deobfuscated, nil
}

// SetProtector installs or updates the SessionCreated header protector for a
// registered pending session.  DialSSU2ViaListener calls this once
// SessCreateHeaderKey is derived (signalled via SetListenerKeyNotify).
//
// Parameters:
//   - sourceConnID: The source connection ID of the pending session to update
//   - protector: The HeaderProtector built from the derived SessCreateHeaderKey
//
// Returns error if the session is not registered.
func (r *PendingOutboundRegistry) SetProtector(sourceConnID uint64, protector *HeaderProtector) error {
	flog("SetProtector").Debug("Installing SessionCreated protector for pending outbound session")
	if protector == nil {
		return oops.
			Code("INVALID_PROTECTOR").
			In("pending_outbound").
			Errorf("protector cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pending, ok := r.sessions[sourceConnID]
	if !ok {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("pending_outbound").
			With("source_conn_id", sourceConnID).
			Errorf("pending session not found for protector update")
	}
	pending.headerProtector = protector
	return nil
}

// TrialDeobfuscate attempts deobfuscation of packetData against every registered
// pending outbound session's available protectors (SessionCreated and/or Retry).
// Because header bytes 0–7 are XOR-masked, the dest conn ID cannot be read in
// the clear before deobfuscation; this method tries each candidate in turn.
//
// For each session it tries:
//  1. headerProtector (for SessionCreated)
//  2. retryProtector (for Retry)
//
// A candidate succeeds when DecryptHeader leaves bytes 0–7 equal to that
// session's sourceConnID.  The first matching deobfuscated copy is returned.
//
// Returns (conn, deobfuscated, nil) on match, (nil, nil, nil) when no session
// matches (packet belongs to a different context).
func (r *PendingOutboundRegistry) TrialDeobfuscate(packetData []byte) (*session.SSU2Conn, []byte, error) {
	flog("TrialDeobfuscate").Debug("Trial-deobfuscating against pending outbound sessions")
	if len(packetData) < 8 {
		return nil, nil, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, pending := range r.sessions {
		if conn, data := trialDeobfuscateWithProtector(pending.headerProtector, pending.conn, pending.sourceConnID, packetData); conn != nil {
			return conn, data, nil
		}
		if conn, data := trialDeobfuscateWithProtector(pending.retryProtector, pending.conn, pending.sourceConnID, packetData); conn != nil {
			return conn, data, nil
		}
	}
	return nil, nil, nil
}

// trialDeobfuscateWithProtector tries to deobfuscate packetData with protector
// and checks whether the decrypted dest conn ID (bytes 0–7) matches expectedID.
// Returns (conn, decrypted) on success, (nil, nil) on nil protector or mismatch.
func trialDeobfuscateWithProtector(protector *HeaderProtector, conn *session.SSU2Conn, expectedID uint64, packetData []byte) (*session.SSU2Conn, []byte) {
	if protector == nil || conn == nil {
		return nil, nil
	}
	candidate := make([]byte, len(packetData))
	copy(candidate, packetData)
	if err := protector.DecryptHeader(candidate); err != nil {
		return nil, nil
	}
	if len(candidate) < 8 {
		return nil, nil
	}
	decryptedDestID := binary.BigEndian.Uint64(candidate[0:8])
	if decryptedDestID != expectedID {
		return nil, nil
	}
	return conn, candidate
}

// Remove unregisters a pending outbound session from the registry.
// Safe to call multiple times (idempotent).
//
// Parameters:
//   - sourceConnID: The source connection ID to remove
func (r *PendingOutboundRegistry) Remove(sourceConnID uint64) {
	flog("Remove").Debug("Removing pending outbound session")

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sessions, sourceConnID)
}

// RemoveAndGetConn removes a pending session and returns its connection,
// or nil if not found. Useful for cleanup on handshake completion.
//
// Parameters:
//   - sourceConnID: The source connection ID to remove
//
// Returns the SSU2Conn, or nil if not found.
func (r *PendingOutboundRegistry) RemoveAndGetConn(sourceConnID uint64) *session.SSU2Conn {
	flog("RemoveAndGetConn").Debug("Removing and returning connection")

	r.mu.Lock()
	defer r.mu.Unlock()

	pending := r.sessions[sourceConnID]
	if pending != nil {
		delete(r.sessions, sourceConnID)
		return pending.conn
	}
	return nil
}

// Count returns the current number of pending outbound sessions.
func (r *PendingOutboundRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// String returns a debug representation of the registry state.
func (r *PendingOutboundRegistry) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("PendingOutboundRegistry{sessions=%d, maxPending=%d}", len(r.sessions), r.maxPending)
}

// StartCleanup launches the stale-session cleanup goroutine.
// It is a no-op when cleanupTimeout is zero.
// Call StopCleanup (or close the listener) to terminate it.
func (r *PendingOutboundRegistry) StartCleanup() {
	if r.cleanupTimeout <= 0 {
		return
	}
	r.wg.Add(1)
	go r.cleanupLoop()
}

// StopCleanup signals the cleanup goroutine to exit and waits for it.
func (r *PendingOutboundRegistry) StopCleanup() {
	select {
	case <-r.stopChan:
		// Already stopped
	default:
		close(r.stopChan)
	}
	r.wg.Wait()
}

// cleanupLoop periodically removes sessions that have been pending longer
// than cleanupTimeout, preventing memory leaks from stalled dials.
func (r *PendingOutboundRegistry) cleanupLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cleanupTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.removeStale()
		}
	}
}

// removeStale purges sessions older than cleanupTimeout.
func (r *PendingOutboundRegistry) removeStale() {
	cutoff := time.Now().Add(-r.cleanupTimeout)
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		if s.createdAt.Before(cutoff) {
			delete(r.sessions, id)
		}
	}
}

// AUDIT 1.2: Single-reader invariant preservation.
// The pending outbound registry does NOT spawn a read loop on the listener socket.
// All reads remain in the listener's exclusive receiveLoop goroutine.
// Outbound sessions register only a temporary header protector for demultiplexing
// during the handshake phase; they do not attempt concurrent reads.
// Once the handshake completes, the session transitions to the normal PacketRouter
// and the temporary protector is discarded.
//
// This design maintains the strict single-reader guarantee while enabling
// multiplexed outbound dials over the listener socket.
