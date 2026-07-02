package server

import (
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// incomingPacket holds a received packet and its source address for worker processing.
type incomingPacket struct {
	data       []byte
	remoteAddr *net.UDPAddr
}

// packetWorkers is the number of goroutines in the packet processing pool.
const packetWorkers = 8

// packetQueueSize is the buffer size for the incoming packet channel.
// Packets arriving when the queue is full are dropped.
const packetQueueSize = 256

// receiveLoop continuously reads packets from the underlying connection
// and routes them to appropriate sessions or creates new sessions.
// M-2: Blocking ReadFrom is used instead of 100ms deadline polling.
// The loop exits when the underlying connection is closed by Close().
//
// Design:
// - Reads UDP datagrams from the underlying PacketConn
// - Copies each datagram into the packet queue for worker pool processing
// - Implements exponential backoff on ReadFrom errors to prevent CPU spin
// - Drops packets silently when the queue is full (tracked in droppedPackets)
//
// Thread safety: This is the sole goroutine reading from the underlying socket.
func (l *SSU2Listener) receiveLoop() {
	flog("receiveLoop").Debug("receiveLoop: starting packet receive loop")
	defer l.wg.Done()

	buf := make([]byte, MaxPacketSizeIPv4)

	const (
		backoffMin = 5 * time.Millisecond
		backoffMax = time.Second
	)
	backoff := backoffMin

	for {
		n, remoteAddr, err := l.underlying.ReadFrom(buf)
		if err != nil {
			// Check if we're shutting down
			select {
			case <-l.shutdownChan:
				return
			default:
			}
			// Log non-shutdown errors and apply exponential backoff to
			// prevent CPU-spin when the socket enters a persistent error state.
			flog("receiveLoop").
				WithError(err).Warn("receiveLoop: ReadFrom error; backing off")
			select {
			case <-l.shutdownChan:
				return
			case <-time.After(backoff):
			}
			if backoff < backoffMax {
				backoff *= 2
				if backoff > backoffMax {
					backoff = backoffMax
				}
			}
			continue
		}
		// Reset backoff on successful read.
		backoff = backoffMin

		udpAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		select {
		case l.packetQueue <- incomingPacket{data: packetData, remoteAddr: udpAddr}:
		default:
			// packetQueue is full - drop packet and warn
			atomic.AddUint64(&l.droppedPackets, 1)
			flog("receiveLoop", logger.Fields{"remoteAddr": udpAddr.String(), "dropped": atomic.LoadUint64(&l.droppedPackets)}).Warn("packetQueue full, dropping packet")
		}
	}
}

// packetWorker drains the packet queue and processes packets.
// Multiple workers run concurrently as a bounded pool.
//
// Design:
// - Each worker runs in its own goroutine (pool size = packetWorkers)
// - Workers block on packetQueue until a packet arrives or shutdown is signaled
// - Packet processing is delegated to handleIncomingPacket
//
// Thread safety: Multiple workers run concurrently; packet processing must be safe.
func (l *SSU2Listener) packetWorker() {
	flog("packetWorker").Debug("packetWorker: starting packet processing worker")
	defer l.wg.Done()

	for {
		select {
		case pkt, ok := <-l.packetQueue:
			if !ok {
				return
			}
			l.handleIncomingPacket(pkt.data, pkt.remoteAddr)
		case <-l.shutdownChan:
			return
		}
	}
}

// handleIncomingPacket processes a received packet and routes it appropriately.
// This is called in a goroutine for each received packet.
//
// AUDIT C-1 & AUDIT 1.2: The listener attempts multiple header-protection strategies:
// 1. Plaintext (testing/legacy)
// 2. Intro-key (SessionRequest/TokenRequest)
// 3. Outbound session protectors (SessionCreated/Retry replies)
//
// Design:
// - Attempts to parse the packet with all available protectors
// - For outbound replies, routes directly to the pending session
// - For new sessions, routes via PacketRouter
// - For TokenRequest, processes directly if routing fails
// - All other routing failures are silently ignored
func (l *SSU2Listener) handleIncomingPacket(data []byte, remoteAddr *net.UDPAddr) {
	flog("handleIncomingPacket", logger.Fields{"remote_addr": remoteAddr.String(), "data_len": len(data)}).Debug("handleIncomingPacket: processing received packet")
	packet, ok := l.parseInboundPacket(data)
	if !ok {
		return
	}

	// Check if this packet belongs to a pending outbound session.
	// Extract destination ConnID from packet header (already decrypted at this point).
	if len(packet.Header) >= 8 {
		destConnID := binary.BigEndian.Uint64(packet.Header[0:8])
		if conn := l.pendingOutbound.GetSessionBySourceConnID(destConnID); conn != nil {
			// This is a reply to one of our outbound dials.
			// Deliver it directly to the outbound session (no router needed).
			conn.ProcessInboundPacket(packet)
			return
		}
	}

	// Route packet to appropriate handler via the normal router
	if err := l.router.RoutePacket(packet, remoteAddr); err != nil {
		// Routing failed, check if this is a token request
		if packet.MessageType == MessageTypeTokenRequest {
			if err := l.processTokenRequest(packet, remoteAddr); err != nil {
				// Gate rejections (NO_TOKEN_ISSUED) are already logged at Debug
				// inside processTokenRequest — only surface genuine failures
				// (WriteTo error, token generation failure) at WARN. BUG-RL-3.
				var oopsErr oops.OopsError
				if !errors.As(err, &oopsErr) || oopsErr.Code() != "NO_TOKEN_ISSUED" {
					atomic.AddUint64(&l.routingErrors, 1)
					flog("handleIncomingPacket", logger.Fields{"remote_addr": remoteAddr.String()}).WithError(err).Warn("token request processing failed")
				}
			}
			return
		}
		atomic.AddUint64(&l.routingErrors, 1)
		// AUDIT 5.1: Handshake-type packets (SessionRequest) that fail to
		// route indicate a session-creation error — these must be visible
		// even without debug logging so operators can detect when 100 % of
		// inbound sessions are failing.  Data packets that fail routing are
		// typically late arrivals for a closed session and are expected; log
		// those at Debug to avoid production noise.
		logEntry := flog("handleIncomingPacket", logger.Fields{"remote_addr": remoteAddr.String(), "message_type": packet.MessageType, "routing_errors": atomic.LoadUint64(&l.routingErrors)}).WithError(err)
		if l.router.IsHandshakePacket(packet.MessageType) {
			logEntry.Warn("handshake packet routing failed")
		} else {
			logEntry.Debug("data packet routing failed (likely late arrival)")
		}
	}
}

// Stats returns observability counters for the listener: the number of
// packets dropped because the worker queue was full, the number of
// packets that failed to route to a session (AUDIT 5.1, M-7), and
// whether the OS read buffer could not be sized as requested (BUG-PB-2).
func (l *SSU2Listener) Stats() map[string]uint64 {
	readBufferFailed := uint64(0)
	if l.readBufferFailed.Load() {
		readBufferFailed = 1
	}
	return map[string]uint64{
		"dropped_packets":    atomic.LoadUint64(&l.droppedPackets),
		"routing_errors":     atomic.LoadUint64(&l.routingErrors),
		"read_buffer_failed": readBufferFailed,
	}
}
