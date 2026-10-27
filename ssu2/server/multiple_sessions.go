package server

import (
	"fmt"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// Multiple sessions with the same peer.
//
// ssu2.md §"Multiple Sessions":
//
//	"Peers should not establish multiple sessions with the same peer, whether SSU 1
//	or 2, or with the same or different IP addresses. However, this could happen,
//	either due to bugs, or a previous session termination message being lost, or in
//	a race where the termination message has not arrived yet.
//
//	If Bob has an existing session with Alice, when Bob receives the Session
//	Confirmed from Alice, completing the handshake and establishing a new session,
//	Bob should:
//	  - Migrate any unsent or unacknowledged outbound I2NP messages from the old
//	    session to the new one
//	  - Send a termination with reason code 22 on the old session
//	  - Remove the old session and replace it with the new one"
//
// Sessions are indexed by connection ID for packet routing, which cannot answer the
// question this section asks — "do I already have a session with *this peer*?" — so
// the listener keeps a second index keyed on the peer's router hash. The hash is
// only trustworthy once the handshake has authenticated the peer's static key and
// the RouterInfo has been validated, which is exactly the moment §"Multiple
// Sessions" names, so the index is written from the established hook rather than at
// session creation.

// peerKeyOf returns the index key for a session: the peer's router hash.
func peerKeyOf(conn *SSU2Conn) data.Hash {
	addr := conn.GetSSU2Addr()
	if addr == nil {
		return data.Hash{}
	}
	return addr.RouterHash()
}

// supersedePeerSession enforces §"Multiple Sessions" for a session whose handshake
// just completed, and records it in the peer index.
//
// It is called from the established hook, inline with handshake finalization, so
// every action here is non-blocking: the old session's Termination (reason 22) is
// handed to CloseWithReason running on its own goroutine, and the message migration
// is a queue write.
func (l *SSU2Listener) supersedePeerSession(conn *SSU2Conn) {
	key := peerKeyOf(conn)
	if key.IsZero() {
		// No authenticated peer identity to index on; nothing to dedup against.
		return
	}

	connID := conn.GetSSU2Addr().ConnectionID()

	l.sessionMutex.Lock()
	previousID, hadPrevious := l.sessionsByPeer[key]
	l.sessionsByPeer[key] = connID
	l.sessionMutex.Unlock()

	if !hadPrevious || previousID == connID {
		return
	}

	old := l.router.GetSession(previousID)
	if old == nil || old == conn {
		// The old session is already gone (its own teardown removed it); the index
		// entry was simply stale.
		return
	}

	flog("supersedePeerSession", logger.Fields{
		"peer":        logRouterHash(key),
		"old_conn_id": previousID,
		"new_conn_id": connID,
	}).Info("peer established a second session; replacing the older one per ssu2.md §\"Multiple Sessions\"")

	// Bullet 1: migrate unsent or unacknowledged outbound I2NP messages.
	migrated := conn.MigrateFrom(old.MigrationTracker())

	// Bullets 2 and 3: termination reason 22 on the old session, then remove it.
	// CloseWithReason sends the Termination block and runs the closing phase; its
	// close hook deregisters it from the routing maps. It blocks for the destroy
	// window, so it goes on its own goroutine.
	go func() {
		if err := old.CloseWithReason(TerminationReplacedByNewSession, nil); err != nil {
			flog("supersedePeerSession", logger.Fields{
				"old_conn_id": previousID,
				"error":       err.Error(),
			}).Debug("closing the superseded session")
		}
	}()

	flog("supersedePeerSession", logger.Fields{
		"old_conn_id": previousID,
		"migrated":    migrated,
		"reason":      TerminationReplacedByNewSession,
	}).Debug("older session replaced")
}

// unindexPeerSession drops a closed session from the peer index, but only if the
// index still points at it: a session that was superseded must not delete its
// replacement's entry when its own teardown finally runs.
func (l *SSU2Listener) unindexPeerSession(conn *SSU2Conn) {
	key := peerKeyOf(conn)
	if key.IsZero() {
		return
	}
	connID := conn.GetSSU2Addr().ConnectionID()

	l.sessionMutex.Lock()
	defer l.sessionMutex.Unlock()
	if current, ok := l.sessionsByPeer[key]; ok && current == connID {
		delete(l.sessionsByPeer, key)
	}
}

// logRouterHash formats a router hash for logs without dumping the whole value.
func logRouterHash(hash data.Hash) string {
	const prefix = 8
	if len(hash) < prefix {
		return fmt.Sprintf("%x", hash[:])
	}
	return fmt.Sprintf("%x...", hash[:prefix])
}

// peerSessionCount reports how many peers are indexed (test and diagnostics seam).
func (l *SSU2Listener) peerSessionCount() int {
	l.sessionMutex.RLock()
	defer l.sessionMutex.RUnlock()
	return len(l.sessionsByPeer)
}
