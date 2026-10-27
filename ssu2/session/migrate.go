package session

import (
	"sync"

	"github.com/go-i2p/logger"
)

// Outbound I2NP migration for a superseded session.
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
// The first bullet is the one that needs per-session state: I2NP messages Bob
// queued on the old session are his own outbound data — tunnel builds, garlic,
// replies — and would be lost when that session is removed. To keep them, a
// responder session remembers the outbound packets that carried I2NP material and
// have not been acknowledged, and hands them to the replacement session, which
// replays them as new Data packets.
//
// Tracking is armed for responder sessions only, because §"Multiple Sessions"
// assigns the whole procedure to Bob. An initiator's unacknowledged messages are
// not at risk in the same way: Alice drives her own retransmissions and, when she
// builds a second session, she is the one that knows the first was replaced.

// i2npBlockTypes are the blocks that carry I2NP material per ssu2.md §"Blocks":
// the single-packet I2NP message and the two fragment types that split a message
// too large for one packet.
var i2npBlockTypes = map[uint8]struct{}{
	BlockTypeI2NPMessage:      {},
	BlockTypeFirstFragment:    {},
	BlockTypeFollowOnFragment: {},
}

// maxMigratedMessages bounds the state one session retains for migration. A router
// under load can have far more outstanding I2NP than a replacement session is
// worth carrying, and I2NP messages expire on their own, so the oldest are dropped
// past this cap.
const maxMigratedMessages = 256

// migratedMessage is one unacknowledged outbound I2NP packet.
type migratedMessage struct {
	packetNumber uint32
	blocks       []*SSU2Block
}

// migrationTracker records the outbound I2NP packets of one session so a
// replacement session can adopt them. It is safe for concurrent use.
type migrationTracker struct {
	mu       sync.Mutex
	pending  map[uint32]migratedMessage
	order    []uint32
	dropped  int
	capacity int
}

func newMigrationTracker() *migrationTracker {
	return &migrationTracker{
		pending:  make(map[uint32]migratedMessage),
		capacity: maxMigratedMessages,
	}
}

// note records a payload that carried I2NP material, keyed by the packet number it
// went out on so a later ACK can retire it.
func (m *migrationTracker) note(packetNumber uint32, payload []byte) {
	if m == nil || len(payload) == 0 {
		return
	}
	blocks, err := DeserializeBlocks(payload)
	if err != nil || len(blocks) == 0 {
		return
	}
	if !blocksCarryI2NP(blocks) {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.pending[packetNumber]; exists {
		return
	}
	if len(m.order) >= m.capacity {
		// Drop the oldest rather than the newest: a backlog this deep means the
		// peer is not acknowledging, and the front of the queue is the stalest.
		oldest := m.order[0]
		m.order = m.order[1:]
		delete(m.pending, oldest)
		m.dropped++
	}
	m.pending[packetNumber] = migratedMessage{packetNumber: packetNumber, blocks: blocks}
	m.order = append(m.order, packetNumber)
}

// retire drops the packets the peer acknowledged, so they are not sent twice.
func (m *migrationTracker) retire(numbers []uint32) {
	if m == nil || len(numbers) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, num := range numbers {
		if _, ok := m.pending[num]; !ok {
			continue
		}
		delete(m.pending, num)
		for i, candidate := range m.order {
			if candidate == num {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
}

// take removes and returns every recorded message in send order.
func (m *migrationTracker) take() []migratedMessage {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]migratedMessage, 0, len(m.order))
	for _, num := range m.order {
		if msg, ok := m.pending[num]; ok {
			out = append(out, msg)
		}
	}
	clear(m.pending)
	m.order = nil
	return out
}

// pendingCount reports how many messages are recorded.
func (m *migrationTracker) pendingCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}

// blocksCarryI2NP reports whether any block in the list carries I2NP material.
func blocksCarryI2NP(blocks []*SSU2Block) bool {
	for _, b := range blocks {
		if b == nil {
			continue
		}
		if _, ok := i2npBlockTypes[b.Type]; ok {
			return true
		}
	}
	return false
}

// TrackOutboundI2NP arms migration tracking for this session's outbound I2NP
// messages and returns the tracker they are recorded on.
//
// The router calls this when it accepts a responder session, and later passes the
// tracker to the replacement session via [SSU2Conn.MigrateFrom] when ssu2.md
// §"Multiple Sessions" requires the old session to be superseded. Returns nil for a
// session that does not track (an initiator), which makes [SSU2Conn.MigrateFrom] a
// no-op on it.
func (h *SSU2Conn) TrackOutboundI2NP() *MigrationTracker {
	if h.initiator {
		return nil
	}
	h.migrationMutex.Lock()
	defer h.migrationMutex.Unlock()
	if h.migration == nil {
		h.migration = newMigrationTracker()
	}
	return &MigrationTracker{tracker: h.migration}
}

// SetEstablishedHook installs the callback that runs when this session's handshake
// completes. The SSU2 listener uses it to enforce ssu2.md §"Multiple Sessions";
// the hook runs inline with finalization, so it must not block.
//
// Setting it after the handshake has completed means the callback never fires.
func (h *SSU2Conn) SetEstablishedHook(hook func(*SSU2Conn)) {
	h.establishedHookMu.Lock()
	h.establishedHook = hook
	h.establishedHookMu.Unlock()
}

// MigrationTracker is the handle a router holds on one session's unacknowledged
// outbound I2NP messages, so it can move them to a replacement session.
type MigrationTracker struct {
	tracker *migrationTracker
}

// Pending returns the messages recorded for migration, oldest first. It drains the
// tracker: a second call returns nothing, so a message cannot be migrated twice.
func (t *MigrationTracker) Pending() []*SSU2Block {
	if t == nil {
		return nil
	}
	var out []*SSU2Block
	for _, msg := range t.tracker.take() {
		out = append(out, msg.blocks...)
	}
	return out
}

// Len reports how many unacknowledged I2NP packets are recorded.
func (t *MigrationTracker) Len() int {
	if t == nil {
		return 0
	}
	return t.tracker.pendingCount()
}

// MigrationTracker returns the handle on this session's unacknowledged outbound
// I2NP messages, or nil if tracking was never armed. The listener uses it to move
// those messages to a replacement session per ssu2.md §"Multiple Sessions".
func (h *SSU2Conn) MigrationTracker() *MigrationTracker {
	h.migrationMutex.Lock()
	tracker := h.migration
	h.migrationMutex.Unlock()
	if tracker == nil {
		return nil
	}
	return &MigrationTracker{tracker: tracker}
}

// MigrateFrom re-sends the I2NP blocks a superseded session had queued or left
// unacknowledged, per ssu2.md §"Multiple Sessions": "Migrate any unsent or
// unacknowledged outbound I2NP messages from the old session to the new one."
//
// Returns the number of blocks replayed. A block that this session cannot send (an
// error from the write path) is dropped and logged rather than retried, since the
// peer's message-level expiry will handle it.
func (h *SSU2Conn) MigrateFrom(old *MigrationTracker) int {
	if old == nil {
		return 0
	}
	blocks := old.Pending()
	if len(blocks) == 0 {
		return 0
	}

	moved := 0
	for _, block := range blocks {
		if err := h.writeBlock(block); err != nil {
			flog("MigrateFrom", logger.Fields{
				"block_type": block.Type,
				"error":      err.Error(),
			}).Debug("could not migrate an I2NP block to the replacement session")
			continue
		}
		moved++
	}

	flog("MigrateFrom", logger.Fields{
		"migrated": moved,
		"total":    len(blocks),
	}).Info("migrated outbound I2NP messages from a replaced session")
	return moved
}
