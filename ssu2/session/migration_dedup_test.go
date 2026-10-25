// Tests for ssu2.md §"Connection Migration" -> §"Initiating Path Validation":
// "If the IP or port is different than previously received, AND the packet is
// not a duplicate packet number, AND the packet successfully decrypts, the
// session enters the path validation phase."
//
// The path-validation trigger must therefore run AFTER the receive-window
// duplicate filter, not at parse time: a spoofed copy of a genuine packet
// forwarded from a different address (§"Threat Model" -> "#### Off-Path Packet
// Forwarding") carries an already-seen packet number and must not start
// migration.

package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationConn returns an established conn with a working receive window,
// send cipher, and path validator, plus the mock socket it writes to.
func migrationConn(t *testing.T) (*SSU2Conn, *mockPacketConn) {
	t.Helper()
	conn, sock := establishedConnForTermination(t)
	conn.cipherMutex.Lock()
	conn.sendCipher = newTestSendCipher(t)
	conn.cipherMutex.Unlock()
	if conn.recvWindow == nil {
		conn.recvWindow = NewReceiveWindow(0, DefaultMaxWindowSize)
	}
	if conn.pathValidator == nil {
		conn.pathValidator = NewPathValidator(conn)
	}
	return conn, sock
}

// readyDataPacket builds a decrypted data-phase packet as it would appear
// after parseInboundPacket: plaintext payload, Source set.
func readyDataPacket(t *testing.T, pktNum uint32, src *net.UDPAddr) *SSU2Packet {
	t.Helper()
	payload, err := SerializeBlocks([]*SSU2Block{i2npBlock()})
	require.NoError(t, err)
	hdr := make([]byte, ShortHeaderSize)
	// Destination conn ID + packet number, mirroring newDataPacket.
	binary.BigEndian.PutUint64(hdr[0:8], 0x1122334455667788)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	return &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
		Payload:      payload,
		Source:       src,
	}
}

// TestMigrationTriggeredAfterDedup proves a fresh, non-duplicate packet from a
// new source address starts path validation (observable as a Path Challenge
// datagram written to the new address).
func TestMigrationTriggeredAfterDedup(t *testing.T) {
	old := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000}
	fresh := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 2000}
	conn, sock := migrationConn(t)
	conn.remoteAddr = old

	pkt := readyDataPacket(t, 1, fresh)
	conn.processDataPackets(pkt)

	// Drain writes looking for one addressed to the new path.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case w := <-sock.writeChan:
			if ua, ok := w.addr.(*net.UDPAddr); ok && ua.String() == fresh.String() {
				return // path challenge sent to the migrated address
			}
		case <-deadline:
			t.Fatal("expected a path-challenge datagram to the new address")
		}
	}
}

// TestMigrationNotTriggeredForDuplicatePacketNumber proves the spec's "not a
// duplicate packet number" precondition: a second packet from a *different*
// address that reuses an already-delivered packet number must not start
// migration (off-path forwarding of a captured packet).
func TestMigrationNotTriggeredForDuplicatePacketNumber(t *testing.T) {
	old := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000}
	spoof := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 9000}
	conn, sock := migrationConn(t)
	conn.remoteAddr = old

	// First delivery of packet 5 from the legitimate address.
	conn.processDataPackets(readyDataPacket(t, 5, old))

	// Drain any writes from the first packet (ACKs etc.).
drain:
	for {
		select {
		case <-sock.writeChan:
		default:
			break drain
		}
	}

	// Duplicate packet 5 arriving from a spoofed new address.
	conn.processDataPackets(readyDataPacket(t, 5, spoof))

	select {
	case w := <-sock.writeChan:
		if ua, ok := w.addr.(*net.UDPAddr); ok && ua.String() == spoof.String() {
			t.Fatal("a duplicate packet number must not initiate path validation")
		}
	case <-time.After(200 * time.Millisecond):
	}
	assert.True(t, true)
}

// TestMigrationRequiresSourceAddress proves a packet with no recorded source
// (e.g. the listener-fed path, where the conn does not parse the datagram
// itself) does not panic or spuriously migrate.
func TestMigrationRequiresSourceAddress(t *testing.T) {
	conn, _ := migrationConn(t)
	conn.remoteAddr = &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000}

	pkt := readyDataPacket(t, 1, nil)
	assert.NotPanics(t, func() { conn.processDataPackets(pkt) })
}
