package session

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/go-noise/internal/iobuf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// validateReadyForIO checks that the connection is in the Established state
// and ready for read/write operations.
func (h *SSU2Conn) validateReadyForIO() error {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()
	flog("validateReadyForIO", logger.Fields{"state": state}).Debug("checking connection state")

	if state != StateEstablished {
		return oops.Errorf("connection not established: %s", state)
	}
	return nil
}

// Read implements net.Conn.Read.
// Reads data from the connection, reassembling I2NP messages from Data packets.
// Blocks until data is available, the read deadline expires, or the connection closes.
//
// If a previous Read call did not consume a complete message (because the caller's
// buffer was too small), this Read returns the remainder of that message first
// before fetching a new one from the DataHandler.
func (h *SSU2Conn) Read(b []byte) (int, error) {
	flog("Read", logger.Fields{"buf_len": len(b)}).Debug("waiting for inbound data")
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	h.readMutex.Lock()
	defer h.readMutex.Unlock()

	// Enforce mutual exclusivity of Read and MessageChan delivery paths (MEDIUM-1, LOW-3).
	// Use a single atomic CompareAndSwap on readDeliveryMode to atomically check that
	// the mode is Unset and set it to Read in one operation. This prevents TOCTOU races
	// where both Read and MessageChan could observe the mode as unset concurrently.
	if !h.readDeliveryMode.CompareAndSwap(int32(ReadDeliveryModeUnset), int32(ReadDeliveryModeRead)) {
		// Mode is already set to something (either Read or Chan).
		// If it's Read, allow it (concurrent Read calls are OK).
		// If it's Chan, return an error.
		mode := h.readDeliveryMode.Load()
		if mode != int32(ReadDeliveryModeRead) {
			return 0, oops.Errorf("Read() called after MessageChan(); these delivery paths are mutually exclusive")
		}
	}

	// Check if we have a pending message from a previous truncated Read.
	// This mirrors the buffering in conn.Conn.pendingPlaintext.
	if n, drained := iobuf.DrainPendingBuffer(&h.pendingMessage, b, true); drained || n > 0 {
		flog("Read", logger.Fields{"copied_len": n, "remaining": len(h.pendingMessage)}).Debug("Data read from pending message buffer")
		return n, nil
	}

	// Block until a message arrives, the connection closes, or the deadline expires.
	// Use a stoppable timer (rather than time.After) so the timer is released
	// promptly instead of lingering until it fires (AUDIT 4.4).
	var deadlineCh <-chan time.Time
	if timer := h.getReadDeadlineTimer(); timer != nil {
		defer timer.Stop()
		deadlineCh = timer.C
	}
	var msg []byte
	select {
	case msg = <-h.dataHandler.MessageChan():
		// Message received
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-deadlineCh:
		return 0, oops.Errorf("read deadline exceeded")
	}

	// Copy message to buffer
	n := copy(b, msg)
	if n < len(msg) {
		// Buffer was too small. Store the unread remainder for the next Read call
		// instead of silently dropping it. See MEDIUM-1 audit finding.
		h.pendingMessage = make([]byte, len(msg)-n)
		copy(h.pendingMessage, msg[n:])
		flog("Read", logger.Fields{"needed": len(msg), "got": len(b), "buffered": len(h.pendingMessage)}).Debug("Buffer too small; buffering message remainder")
		// The remainder is preserved in h.pendingMessage and will be returned on
		// the next Read, so this is a successful partial read, not an error.
		// Returning a non-nil error here would violate the io.Reader/net.Conn
		// contract and cause io.Copy/bufio.Reader/io.ReadFull to abort despite
		// no data loss. Mirrors conn.Conn.Read. See MED-1 audit finding.
		return n, nil
	}

	return n, nil
}

// readOnePacket attempts to parse and process a single inbound packet from the given buffer and address.
// Returns true if the packet was valid (parsed) or false if it should be dropped.
func (h *SSU2Conn) readOnePacket(buf []byte, addr net.Addr) bool {
	packet := h.parseInboundPacket(buf, addr)
	if packet != nil {
		flog("readOnePacket", logger.Fields{"type": packet.MessageType, "pktnum": packet.PacketNumber}).Debug("Parsed inbound packet")
		h.processInboundPacket(packet)
		return true
	}
	flog("readOnePacket").Debug("Inbound packet dropped (parse returned nil)")
	return false
}

// recvLoop handles inbound packet reception.
func (h *SSU2Conn) recvLoop() {
	defer h.wg.Done()

	// Buffer must hold any valid SSU2 packet; use MaxPacketSizeIPv4 so we
	// never truncate legitimate packets regardless of the configured MTU.
	buf := make([]byte, MaxPacketSizeIPv4)
	for {
		// BUG-TO-1: For sessions that own the underlying socket (DialSSU2),
		// block directly on ReadFrom. CloseWithReason closes the socket after
		// signalling closeChan, which unblocks ReadFrom. This eliminates the
		// 100 ms CPU wakeup cycle for dial sessions.
		// For shared-socket sessions (ownsUnderlying=false), fall back to the
		// 100 ms poll so the loop can still exit when closeChan fires.
		if h.ownsUnderlying {
			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				select {
				case <-h.closeChan:
					return
				default:
				}
				h.readErrors.Add(1)
				continue
			}
			flog("recvLoop", logger.Fields{"bytes": n, "from": addr}).Debug("Received UDP packet")
			h.readOnePacket(buf[:n], addr)
		} else {
			// Shared socket path: this connection does not own the PacketConn but
			// is its sole reader (DialSSU2WithConn contract). We cannot block
			// indefinitely on ReadFrom because that would prevent closeChan from
			// being checked. Use a 100 ms read deadline on this socket to achieve
			// periodic wakeup.
			//
			// NOTE: SetReadDeadline here is safe because the DialSSU2WithConn API
			// contract guarantees this connection is the SOLE reader of the socket.
			// Listener-accepted connections never enter this branch because
			// readsOwnSocket is false for them, so recvLoop is never started.
			// If a future use case shares this socket with other readers, this
			// branch must be revisited (RACE-4).
			select {
			case <-h.closeChan:
				return
			default:
			}
			_ = h.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				// Non-timeout error: check if we're closing before counting it.
				select {
				case <-h.closeChan:
					return
				default:
				}
				h.readErrors.Add(1)
				continue
			}

			flog("recvLoop", logger.Fields{"bytes": n, "from": addr}).Debug("Received UDP packet")
			h.readOnePacket(buf[:n], addr)
		}
	}
}

// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
// Supports connection migration: if a packet from a new address passes AEAD
// verification, the remote address is updated (per spec §Connection Migration).
func (h *SSU2Conn) parseInboundPacket(data []byte, addr net.Addr) *SSU2Packet {
	flog("parseInboundPacket", logger.Fields{"data_len": len(data), "from": addr}).Debug("parsing inbound UDP datagram")
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	// Check if the source address has changed (requires lock to read remoteAddr).
	// Per spec §Connection Migration: packets from a new address require path
	// validation before accepting the address change.
	h.remoteAddrLock.RLock()
	addrChanged := !udpAddr.IP.Equal(h.remoteAddr.IP) || udpAddr.Port != h.remoteAddr.Port
	h.remoteAddrLock.RUnlock()

	// Decrypt header protection before parsing
	if h.headerProtector != nil {
		hType := h.expectedInboundHeaderType()
		if err := h.headerProtector.DecryptInboundHeader(data, hType); err != nil {
			h.parseErrors.Add(1)
			return nil
		}
	}

	// H-1 fix: SSU2 has no data-phase length-obfuscation field. Header bytes
	// 14-15 are the spec's "moreflags" (unused, set to 0), already covered by
	// ChaCha20 header protection above. The datagram length is the message
	// length (parsed by Deserialize from the UDP payload size), so there is
	// nothing to deobfuscate here. The bytes are zeroed before AEAD below.

	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err != nil {
		h.parseErrors.Add(1)
		return nil
	}

	h.cipherMutex.Lock()
	cipher := h.recvCipher
	if cipher != nil && packet.MessageType == MessageTypeData && len(packet.Payload) > 0 {
		// Per SSU2 spec: nonce is the packet number, AD is the 16-byte header.
		// Bytes 14-15 must be zeroed before AEAD decryption because the sender
		// encrypts with bytes 14-15 = 0 (they are set to the obfuscated length
		// only AFTER encryption). Without this, the AD mismatch causes every
		// data packet to fail AEAD verification.
		binary.BigEndian.PutUint16(packet.Header[14:16], 0)
		cipher.SetNonce(uint64(packet.PacketNumber))
		decrypted, err := cipher.Decrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
		if err != nil {
			h.cipherMutex.Unlock()
			h.decryptErrors.Add(1)
			return nil
		}
		packet.Payload = decrypted
	}
	h.cipherMutex.Unlock()

	// If the address changed but AEAD passed, initiate path validation (G-7).
	// Per spec §Connection Migration: packets from a new address require
	// path validation before accepting the address change.
	if addrChanged && h.pathValidator != nil {
		if _, err := h.pathValidator.InitiatePathValidation(udpAddr); err != nil {
			// Do not silently swallow: a failure to start validation means
			// the address migration is not being verified (AUDIT 5.2).
			flog("parseInboundPacket", logger.Fields{"new_addr": udpAddr.String()}).WithError(err).Warn("failed to initiate path validation for migrated address")
		}
	}

	h.updateActivity()
	return packet
}

// keepaliveLoop manages connection keepalive.
func (h *SSU2Conn) keepaliveLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.lastActivityLock.RLock()
			timeSinceActivity := time.Since(h.lastActivity)
			h.lastActivityLock.RUnlock()

			// Check if we need to send keepalive
			if timeSinceActivity >= h.config.KeepaliveInterval {
				// Send ACK-only packet as keepalive per spec §Keepalive (M-3)
				h.sendImmediateACK()
			}

			// Check for timeout (M-2: configurable idle timeout)
			idleTimeout := h.config.IdleTimeout
			if idleTimeout <= 0 {
				idleTimeout = 5 * time.Minute
			}
			if timeSinceActivity >= idleTimeout {
				h.closeMutex.Lock()
				h.closeErr = oops.Errorf("idle timeout")
				h.closeMutex.Unlock()
				// H-3: Run close in a separate goroutine to avoid deadlock.
				// keepaliveLoop is counted in h.wg, so if we call h.Close() directly,
				// it will call h.wg.Wait() and deadlock waiting for this goroutine to finish.
				go h.Close()
				return
			}
		case <-h.closeChan:
			return
		}
	}
}

// processInboundPacket processes a received packet.
func (h *SSU2Conn) processInboundPacket(packet *SSU2Packet) {
	switch packet.MessageType {
	case MessageTypeData:
		// Enforce receive window: reject duplicate, old, and out-of-window packets
		var readyPackets []*SSU2Packet
		if h.recvWindow != nil {
			var err error
			readyPackets, err = h.recvWindow.Insert(packet)
			if err != nil {
				return // silently drop
			}
		} else {
			// No receive window; treat this packet as immediately ready
			readyPackets = []*SSU2Packet{packet}
		}

		// Process all ready packets (including the current one and any that were buffered)
		for _, readyPacket := range readyPackets {
			h.validDataPacketsReceived.Add(1)

			// Record for ACK only after window acceptance
			if readyPacket.PacketNumber > 0 {
				h.ackHandler.RecordReceived(readyPacket.PacketNumber)

				// H-2: Check if a delayed ACK should be sent immediately.
				// If ShouldSendACK returns true (threshold met or delay elapsed), send ACK.
				// Otherwise, rely on timer or next batch of packets (see H-2 TODO).
				rtt := h.rttEstimator.GetSmoothedRTT()
				if rtt == 0 {
					rtt = 50 * time.Millisecond // Default if not yet measured
				}
				if h.ackHandler.ShouldSendACK(rtt) {
					h.sendImmediateACK()
				}
			}

			// Check immediate-ack flag: header byte 13, bit 0 (M-5: this is also
			// checked via CongestionFlagRequestACK in the Congestion block handler,
			// providing redundant but harmless ACK triggering)
			if len(readyPacket.Header) > 13 && readyPacket.Header[13]&0x01 != 0 {
				h.sendImmediateACK()
			}
			h.processDataPacket(readyPacket)
		}
	case MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypeSessionConfirmed:
		// Handshake packets bypass receive window
		if packet.PacketNumber > 0 {
			h.ackHandler.RecordReceived(packet.PacketNumber)
		}
		// Handshake packets are scarce and progress the state machine; dropping
		// one forces reliance on the (slow) retransmit schedule and inflates
		// handshake latency. Briefly block to enqueue rather than dropping on a
		// transiently-full queue, but bound the wait so a stalled handshake
		// reader cannot pin this worker indefinitely (AUDIT 4.2).
		select {
		case h.recvQueue <- packet:
		case <-h.closeChan:
		default:
			timer := time.NewTimer(handshakeEnqueueTimeout)
			select {
			case h.recvQueue <- packet:
			case <-h.closeChan:
			case <-timer.C:
				flog("processInboundPacket", logger.Fields{"msg_type": packet.MessageType}).Warn("recvQueue full; dropped handshake packet after enqueue timeout")
			}
			timer.Stop()
		}
	}
}

// processDataPacket handles a data-phase packet: parses blocks and retires ACKed packets.
func (h *SSU2Conn) processDataPacket(packet *SSU2Packet) {
	flog("processDataPacket", logger.Fields{"pkt_num":     packet.PacketNumber, "payload_len": len(packet.Payload)}).Debug("processing")
	blocks, err := h.dataHandler.ProcessDataPacket(packet)
	if err != nil {
		flog("processDataPacket", logger.Fields{"error": err.Error()}).Debug("ProcessDataPacket error")
		return
	}
	flog("processDataPacket", logger.Fields{"num_blocks": len(blocks)}).Debug("processed blocks")

	// Process ACK blocks
	for _, block := range blocks {
		if block.Type == BlockTypeACK {
			ackedNums, _ := h.ackHandler.ProcessACK(block)
			// Remove acknowledged packets from pending queue
			h.pendingMutex.Lock()
			for _, num := range ackedNums {
				delete(h.pendingPackets, num)
			}
			h.pendingMutex.Unlock()
		}
	}
}

// handlePeerNextNonce is the OnNextNonce callback wired in installCipherStates.
// When the peer sends us a NextNonce, we rekey the *receive* cipher to match.
func (h *SSU2Conn) handlePeerNextNonce(newNonce uint64) error {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.recvCipher == nil {
		return oops.Errorf("receive cipher not initialized")
	}

	// Derive new recv cipher key per SSU2 spec §NextNonce:
	// newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32) (G-5).
	newKey, err := deriveRekeyKey(h.recvCipher)
	if err != nil {
		return oops.Wrapf(err, "failed to derive rekey for recv cipher")
	}
	h.recvCipher.UnsafeSetKey(newKey)
	h.recvCipher.SetNonce(newNonce)

	flog("handlePeerNextNonce", logger.Fields{"newNonce": newNonce}).Info("Applied peer NextNonce rekey on receive cipher")
	return nil
}

// getReadDeadlineTimer returns a *time.Timer that fires at the read deadline,
// or nil if no deadline is set. Callers MUST Stop() the returned timer when
// done to release it promptly; a previous implementation used time.After,
// which leaks an unstoppable timer on every Read until it fires (AUDIT 4.4).
func (h *SSU2Conn) getReadDeadlineTimer() *time.Timer {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.readDeadline.IsZero() {
		return nil
	}
	return time.NewTimer(time.Until(h.readDeadline))
}

// MessageChan returns a receive-only channel of complete I2NP messages.
// This is an alternative delivery path to Read(); both paths consume from
// the same underlying channel, so they are mutually exclusive. Using both
// concurrently will cause messages to race to whichever receiver is ready,
// resulting in silent message loss.
//
// IMPORTANT: Do not use MessageChan() and Read() concurrently on the same
// connection. This method returns a closed channel (panic-free sentinel) if
// Read() has already been called, enforcing mutual exclusivity. See MEDIUM-1.
func (h *SSU2Conn) MessageChan() <-chan []byte {
	// Enforce mutual exclusivity of MessageChan and Read delivery paths (MEDIUM-1, LOW-3).
	// Use a single atomic CompareAndSwap on readDeliveryMode to atomically check that
	// the mode is Unset and set it to Chan in one operation. This prevents TOCTOU races
	// where both Read and MessageChan could observe the mode as unset concurrently.
	if !h.readDeliveryMode.CompareAndSwap(int32(ReadDeliveryModeUnset), int32(ReadDeliveryModeChan)) {
		// Mode is already set to something (either Read or Chan).
		// If it's Chan, allow it (concurrent MessageChan calls are OK).
		// If it's Read, return a closed channel as a panic-free sentinel.
		mode := h.readDeliveryMode.Load()
		if mode != int32(ReadDeliveryModeChan) {
			flog("MessageChan").Error(
				"MessageChan called after Read; returning closed channel - these delivery paths are mutually exclusive",
			)
			return h.closedMessageChan
		}
	}
	return h.dataHandler.MessageChan()
}
