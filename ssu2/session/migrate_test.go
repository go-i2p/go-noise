package session

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationResponderConn returns an established responder session writing to a
// mock socket, with a send cipher so outbound packets seal.
func migrationResponderConn(t *testing.T) (*SSU2Conn, *mockPacketConn) {
	t.Helper()

	initConn, _, initPriv, _, respPriv, respPub := setupConnPair(t)
	config := createTestConfig(t)
	config.DestroyTimeout = 0

	conn, err := NewSSU2Conn(
		initConn,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001},
		config,
		false, // responder: Bob is the role §"Multiple Sessions" addresses
		respPriv,
		respPub,
	)
	require.NoError(t, err)
	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()
	conn.cipherMutex.Lock()
	conn.sendCipher = newTestSendCipher(t)
	conn.cipherMutex.Unlock()
	conn.remoteConnectionID.Store(0x1122334455667788)

	t.Cleanup(func() { conn.SetOwnsUnderlying(false); initConn.Close(); _ = initPriv })
	return conn, initConn
}

func i2npPayload(t *testing.T, data string) []byte {
	t.Helper()
	payload, err := SerializeBlocks([]*SSU2Block{{
		Type: BlockTypeI2NPMessage,
		Data: []byte(data),
	}})
	require.NoError(t, err)
	return payload
}

// TestMigrationTracker_RecordsOnlyI2NP covers ssu2.md §"Multiple Sessions" bullet
// one: what must survive a replaced session is "unsent or unacknowledged outbound
// I2NP messages" — an ACK packet carries nothing to migrate.
func TestMigrationTracker_RecordsOnlyI2NP(t *testing.T) {
	tracker := newMigrationTracker()

	tracker.note(1, i2npPayload(t, "hello i2np"))
	assert.Equal(t, 1, tracker.pendingCount(), "an I2NP message must be recorded")

	ackPayload, err := SerializeBlocks([]*SSU2Block{ackOnlyBlock()})
	require.NoError(t, err)
	tracker.note(2, ackPayload)
	assert.Equal(t, 1, tracker.pendingCount(), "an ACK-only payload carries nothing to migrate")

	tracker.note(3, nil)
	assert.Equal(t, 1, tracker.pendingCount(), "an empty payload is not a message")
}

func TestMigrationTracker_FragmentsAreRecorded(t *testing.T) {
	tracker := newMigrationTracker()

	payload, err := SerializeBlocks([]*SSU2Block{{
		Type: BlockTypeFirstFragment,
		Data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 'x'},
	}})
	require.NoError(t, err)

	tracker.note(7, payload)
	assert.Equal(t, 1, tracker.pendingCount(),
		"a fragmented message is still outbound I2NP material")
}

// TestMigrationTracker_RetireOnAck: an acknowledged message reached the peer, so
// replaying it on the replacement session would duplicate tunnel data.
func TestMigrationTracker_RetireOnAck(t *testing.T) {
	tracker := newMigrationTracker()

	tracker.note(1, i2npPayload(t, "first"))
	tracker.note(2, i2npPayload(t, "second"))
	tracker.note(3, i2npPayload(t, "third"))

	tracker.retire([]uint32{2})
	assert.Equal(t, 2, tracker.pendingCount())

	remaining := tracker.take()
	require.Len(t, remaining, 2)
	assert.Equal(t, uint32(1), remaining[0].packetNumber, "messages must be taken in send order")
	assert.Equal(t, uint32(3), remaining[1].packetNumber)
	assert.Zero(t, tracker.pendingCount(), "take drains the tracker")
}

func TestMigrationTracker_CapDropsOldest(t *testing.T) {
	tracker := newMigrationTracker()
	tracker.capacity = 4

	for i := uint32(0); i < 10; i++ {
		tracker.note(i, i2npPayload(t, "message"))
	}

	assert.Equal(t, 4, tracker.pendingCount(), "the backlog is bounded")
	remaining := tracker.take()
	require.Len(t, remaining, 4)
	assert.Equal(t, uint32(6), remaining[0].packetNumber, "the oldest messages are dropped first")
}

// TestTrackOutboundI2NP_ResponderOnly: §"Multiple Sessions" assigns the migration
// procedure to Bob, so only a responder session tracks.
func TestTrackOutboundI2NP_ResponderOnly(t *testing.T) {
	responder, _ := migrationResponderConn(t)
	require.NotNil(t, responder.TrackOutboundI2NP(),
		"a responder must track its outbound I2NP for migration")

	initiator, _ := establishedConnForTermination(t)
	assert.Nil(t, initiator.TrackOutboundI2NP(),
		"an initiator drives its own retransmission and must not track")
}

// TestSendPacketDirect_TracksI2NPPackets proves the write path records at seal time
// and that an ACK retires the record.
func TestSendPacketDirect_TracksI2NPPackets(t *testing.T) {
	conn, _ := migrationResponderConn(t)
	conn.TrackOutboundI2NP()

	// Send through the same sealing path the send loop uses: the write queue needs
	// a running loop, and tracking happens at seal time either way.
	payload, err := SerializeBlocks([]*SSU2Block{i2npBlock()})
	require.NoError(t, err)
	packet := conn.newDataPacket()
	packet.Payload = payload
	require.NoError(t, conn.sendPacketDirect(packet))

	assert.Equal(t, 1, conn.migration.pendingCount(),
		"an outbound I2NP packet must be recorded for migration")

	conn.retireAckedPackets([]uint32{packet.PacketNumber})
	assert.Zero(t, conn.migration.pendingCount(),
		"an acknowledged message must not be migrated")
}

// TestMigrateFrom_ReplaysBlocks moves the old session's messages onto a new one.
func TestMigrateFrom_ReplaysBlocks(t *testing.T) {
	old, _ := migrationResponderConn(t)
	tracker := old.TrackOutboundI2NP()
	require.NotNil(t, tracker)

	old.migration.note(1, i2npPayload(t, "alpha"))
	old.migration.note(2, i2npPayload(t, "bravo"))
	require.Equal(t, 2, old.migration.pendingCount())

	fresh, sock := migrationResponderConn(t)
	moved := fresh.MigrateFrom(tracker)

	assert.Equal(t, 2, moved, "both I2NP messages must be replayed on the new session")
	assert.Zero(t, tracker.Len(), "the old session's backlog is drained")

	// A second migration has nothing left to move: a message must not be sent twice.
	assert.Zero(t, fresh.MigrateFrom(tracker))

	// MigrateFrom enqueues through the write path; drain the queue and verify the
	// messages reached the socket.
	for i := 0; i < 2; i++ {
		select {
		case packet := <-fresh.sendQueue:
			require.NoError(t, fresh.sendPacketDirect(packet))
		case <-time.After(time.Second):
			t.Fatalf("migration enqueued fewer than %d packets", i+1)
		}
	}
	sent := 0
	for i := 0; i < 2; i++ {
		select {
		case <-sock.writeChan:
			sent++
		case <-time.After(time.Second):
		}
	}
	assert.Equal(t, 2, sent, "migrated messages must be sent on the new session")
}

// TestEstablishedHook_NotFiredBeforeFinalize: the hook is the §"Multiple Sessions"
// trigger, so it must not run while the handshake is still in progress — firing
// early would index a session whose peer identity is not yet authenticated.
func TestEstablishedHook_NotFiredBeforeFinalize(t *testing.T) {
	conn, _ := migrationResponderConn(t)

	fired := false
	conn.SetEstablishedHook(func(*SSU2Conn) { fired = true })

	// A handshake packet arriving before completion must not fire it.
	conn.processHandshakePacket(&SSU2Packet{
		MessageType: MessageTypeSessionConfirmed,
		Header:      make([]byte, ShortHeaderSize),
	})
	assert.False(t, fired, "the established hook runs only at handshake completion")
}
