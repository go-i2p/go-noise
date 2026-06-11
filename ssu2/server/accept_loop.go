package server

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "receiveLoop"}).Debug("receiveLoop: starting packet receive loop")
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
			log.WithFields(logger.Fields{"pkg": "server", "func": "receiveLoop"}).
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
			log.WithFields(logger.Fields{
				"pkg":        "server",
				"func":       "receiveLoop",
				"remoteAddr": udpAddr.String(),
				"dropped":    atomic.LoadUint64(&l.droppedPackets),
			}).Warn("packetQueue full, dropping packet")
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "packetWorker"}).Debug("packetWorker: starting packet processing worker")
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
// AUDIT C-1: If plaintext Deserialize fails and an inbound HeaderProtector is
// configured (i.e. config.IntroKey was set), the listener performs an in-place
// header-protection decryption attempt before discarding the packet. This is
// the receiver-side counterpart to spec-compliant SSU2 senders that obfuscate
// header bytes 0-15 (and, for long headers, bytes 16-63) using ChaCha20 keyed
// on the receiver's intro key.
//
// Design:
// - Attempts to parse the packet (plaintext first, then header-protected)
// - Routes the packet to an existing session via PacketRouter
// - If routing fails and packet is a TokenRequest, processes it directly
// - All other routing failures are silently ignored
func (l *SSU2Listener) handleIncomingPacket(data []byte, remoteAddr *net.UDPAddr) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "handleIncomingPacket", "remote_addr": remoteAddr.String(), "data_len": len(data)}).Debug("handleIncomingPacket: processing received packet")
	packet, ok := l.parseInboundPacket(data)
	if !ok {
		return
	}

	// Route packet to appropriate handler
	if err := l.router.RoutePacket(packet, remoteAddr); err != nil {
		// Routing failed, check if this is a token request
		if packet.MessageType == MessageTypeTokenRequest {
			_ = l.processTokenRequest(packet, remoteAddr)
			return
		}
		atomic.AddUint64(&l.routingErrors, 1)
		// AUDIT 5.1: Handshake-type packets (SessionRequest) that fail to
		// route indicate a session-creation error — these must be visible
		// even without debug logging so operators can detect when 100 % of
		// inbound sessions are failing.  Data packets that fail routing are
		// typically late arrivals for a closed session and are expected; log
		// those at Debug to avoid production noise.
		logEntry := log.WithFields(logger.Fields{
			"pkg":            "server",
			"func":           "handleIncomingPacket",
			"remote_addr":    remoteAddr.String(),
			"message_type":   packet.MessageType,
			"routing_errors": atomic.LoadUint64(&l.routingErrors),
		}).WithError(err)
		if l.router.IsHandshakePacket(packet.MessageType) {
			logEntry.Warn("handshake packet routing failed")
		} else {
			logEntry.Debug("data packet routing failed (likely late arrival)")
		}
	}
}

// Stats returns observability counters for the listener: the number of
// packets dropped because the worker queue was full and the number of
// packets that failed to route to a session (AUDIT 5.1, M-7).
func (l *SSU2Listener) Stats() map[string]uint64 {
	return map[string]uint64{
		"dropped_packets": atomic.LoadUint64(&l.droppedPackets),
		"routing_errors":  atomic.LoadUint64(&l.routingErrors),
	}
}
