package session

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// validateReadyForIO checks that the connection is in the Established state
// and ready for read/write operations.
func (h *SSU2Conn) validateReadyForIO() error {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()
	log.WithFields(logger.Fields{"pkg": "session", "func": "validateReadyForIO", "state": state}).Debug("checking connection state")

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
	log.WithFields(logger.Fields{"pkg": "session", "func": "Read", "buf_len": len(b)}).Debug("waiting for inbound data")
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	h.readMutex.Lock()
	defer h.readMutex.Unlock()

	// Enforce mutual exclusivity of Read and MessageChan delivery paths (MEDIUM-1).
	// The first call to Read sets readModeCalled; if MessageChan was already called,
	// we return an error to prevent message splitting across both paths.
	if !h.readModeCalled.CompareAndSwap(false, true) {
		// readModeCalled was already true; this is OK, just another Read call
	} else if h.messageChanModeCalled.Load() {
		// MessageChan was called first; return a hard error to enforce the contract
		return 0, oops.Errorf("Read() called after MessageChan(); these delivery paths are mutually exclusive")
	}

	// Check if we have a pending message from a previous truncated Read.
	// This mirrors the buffering in conn.Conn.pendingPlaintext.
	if len(h.pendingMessage) > 0 {
		n := copy(b, h.pendingMessage)
		h.pendingMessage = h.pendingMessage[n:]
		// Zero the consumed portion if fully drained
		if len(h.pendingMessage) == 0 {
			h.pendingMessage = nil
		}
		log.WithFields(logger.Fields{
			"pkg": "session", "func": "Read",
			"copied_len": n, "remaining": len(h.pendingMessage),
		}).Debug("Data read from pending message buffer")
		return n, nil
	}

	// Block until a message arrives, the connection closes, or the deadline expires
	var msg []byte
	select {
	case msg = <-h.dataHandler.MessageChan():
		// Message received
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-h.getReadDeadline():
		return 0, oops.Errorf("read deadline exceeded")
	}

	// Copy message to buffer
	n := copy(b, msg)
	if n < len(msg) {
		// Buffer was too small. Store the unread remainder for the next Read call
		// instead of silently dropping it. See MEDIUM-1 audit finding.
		h.pendingMessage = make([]byte, len(msg)-n)
		copy(h.pendingMessage, msg[n:])
		log.WithFields(logger.Fields{
			"pkg": "session", "func": "Read",
			"needed": len(msg), "got": len(b), "buffered": len(h.pendingMessage),
		}).Debug("Buffer too small; buffering message remainder")
		// The remainder is preserved in h.pendingMessage and will be returned on
		// the next Read, so this is a successful partial read, not an error.
		// Returning a non-nil error here would violate the io.Reader/net.Conn
		// contract and cause io.Copy/bufio.Reader/io.ReadFull to abort despite
		// no data loss. Mirrors conn.Conn.Read. See MED-1 audit finding.
		return n, nil
	}

	return n, nil
}

// recvLoop handles inbound packet reception.
func (h *SSU2Conn) recvLoop() {
	defer h.wg.Done()

	// Buffer must hold any valid SSU2 packet; use MaxPacketSizeIPv4 so we
	// never truncate legitimate packets regardless of the configured MTU.
	buf := make([]byte, MaxPacketSizeIPv4)
	for {
		select {
		case <-h.closeChan:
			return
		default:
			_ = h.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				h.readErrors.Add(1)
				continue
			}

			log.WithFields(logger.Fields{"pkg": "session", "func": "recvLoop", "bytes": n, "from": addr}).Debug("Received UDP packet")
			if packet := h.parseInboundPacket(buf[:n], addr); packet != nil {
				log.WithFields(logger.Fields{"pkg": "session", "func": "recvLoop", "type": packet.MessageType, "pktnum": packet.PacketNumber}).Debug("Parsed inbound packet")
				h.processInboundPacket(packet)
			} else {
				log.WithFields(logger.Fields{"pkg": "session", "func": "recvLoop"}).Debug("Inbound packet dropped (parse returned nil)")
			}
		}
	}
}

// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
// Supports connection migration: if a packet from a new address passes AEAD
// verification, the remote address is updated (per spec §Connection Migration).
func (h *SSU2Conn) parseInboundPacket(data []byte, addr net.Addr) *SSU2Packet {
	log.WithFields(logger.Fields{"pkg": "session", "func": "parseInboundPacket", "data_len": len(data), "from": addr}).Debug("parsing inbound UDP datagram")
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

	// SipHash length deobfuscation: recover the data length from header
	// bytes 14-15 per spec §Data Phase Length Obfuscation (G-2).
	if mod := h.sipHashModifier.Load(); mod != nil && len(data) >= ShortHeaderSize {
		mask := mod.NextInboundMask()
		obfuscated := binary.BigEndian.Uint16(data[14:16])
		binary.BigEndian.PutUint16(data[14:16], obfuscated^mask)
	}

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
		_, _ = h.pathValidator.InitiatePathValidation(udpAddr)
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
		select {
		case h.recvQueue <- packet:
		default:
		}
	}
}

// processDataPacket handles a data-phase packet: parses blocks and retires ACKed packets.
func (h *SSU2Conn) processDataPacket(packet *SSU2Packet) {
	log.WithFields(logger.Fields{
		"pkg":         "ssu2",
		"func":        "processDataPacket",
		"pkt_num":     packet.PacketNumber,
		"payload_len": len(packet.Payload),
	}).Debug("processing")
	blocks, err := h.dataHandler.ProcessDataPacket(packet)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "processDataPacket", "error": err.Error()}).Debug("ProcessDataPacket error")
		return
	}
	log.WithFields(logger.Fields{"pkg": "session", "func": "processDataPacket", "num_blocks": len(blocks)}).Debug("processed blocks")

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

	log.WithFields(logger.Fields{"pkg": "session", "func": "handlePeerNextNonce", "newNonce": newNonce}).Info("Applied peer NextNonce rekey on receive cipher")
	return nil
}

// getReadDeadline returns a channel that closes at read deadline.
func (h *SSU2Conn) getReadDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.readDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.readDeadline))
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
	// Enforce mutual exclusivity of MessageChan and Read delivery paths (MEDIUM-1).
	// If MessageChan is called after Read, we return a closed channel instead of
	// allowing message splitting.
	if !h.messageChanModeCalled.CompareAndSwap(false, true) {
		// messageChanModeCalled was already true; this is OK, just another call
	} else if h.readModeCalled.Load() {
		// Read was called first; return a closed channel as a panic-free sentinel
		log.WithFields(logger.Fields{"pkg": "session", "func": "MessageChan"}).Error(
			"MessageChan called after Read; returning closed channel - these delivery paths are mutually exclusive",
		)
		return h.closedMessageChan
	}
	return h.dataHandler.MessageChan()
}
