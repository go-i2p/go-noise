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

	// Enforce mutual exclusivity of Read and MessageChan delivery paths.
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

	if n, drained := h.readFromPendingMessage(b); drained || n > 0 {
		return n, nil
	}

	msg, err := h.waitForInboundMessage()
	if err != nil {
		return 0, err
	}

	return h.copyInboundMessageToBuffer(b, msg)
}

func (h *SSU2Conn) readFromPendingMessage(b []byte) (int, bool) {
	// Check if we have a pending message from a previous truncated Read.
	// This mirrors the buffering in conn.Conn.pendingPlaintext.
	n, drained := iobuf.DrainPendingBuffer(&h.pendingMessage, b, true)
	if drained || n > 0 {
		flog("Read", logger.Fields{"copied_len": n, "remaining": len(h.pendingMessage)}).Debug("Data read from pending message buffer")
	}
	return n, drained
}

func (h *SSU2Conn) waitForInboundMessage() ([]byte, error) {
	// Block until a message arrives, the connection closes, or the deadline expires.
	// Use a stoppable timer (rather than time.After) so the timer is released
	// promptly instead of lingering until it fires.
	var deadlineCh <-chan time.Time
	if timer := h.getReadDeadlineTimer(); timer != nil {
		defer timer.Stop()
		deadlineCh = timer.C
	}
	select {
	case msg := <-h.dataHandler.MessageChan():
		return msg, nil
	case <-h.closeChan:
		return nil, oops.Errorf("connection closed")
	case <-deadlineCh:
		return nil, oops.Errorf("read deadline exceeded")
	}
}

func (h *SSU2Conn) copyInboundMessageToBuffer(b, msg []byte) (int, error) {
	// Copy message to buffer
	n := copy(b, msg)
	if n < len(msg) {
		// Buffer was too small. Store the unread remainder for the next Read call
		// instead of silently dropping it.
		h.pendingMessage = make([]byte, len(msg)-n)
		copy(h.pendingMessage, msg[n:])
		flog("Read", logger.Fields{"needed": len(msg), "got": len(b), "buffered": len(h.pendingMessage)}).Debug("Buffer too small; buffering message remainder")
		// The remainder is preserved in h.pendingMessage and will be returned on
		// the next Read, so this is a successful partial read, not an error.
		// Returning a non-nil error here would violate the io.Reader/net.Conn
		// contract and cause io.Copy/bufio.Reader/io.ReadFull to abort despite
		// no data loss. Mirrors conn.Conn.Read.
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

	// Exponential backoff on persistent ReadFrom errors (own-socket path) to
	// avoid a CPU-spin busy loop when the socket enters a persistent error
	// state (e.g. transient network-down conditions). Mirrors the backoff
	// strategy used by SSU2Listener.receiveLoop (ssu2/server/accept_loop.go).
	const (
		backoffMin = 5 * time.Millisecond
		backoffMax = time.Second
	)
	backoff := backoffMin

	for {
		n, addr, stop, err := h.readInboundDatagram(buf)
		if stop {
			return
		}
		if err != nil {
			flog("recvLoop", logger.Fields{"error": err}).Warn("recvLoop: ReadFrom error; backing off")
			select {
			case <-h.closeChan:
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
		backoff = backoffMin
		flog("recvLoop", logger.Fields{"bytes": n, "from": addr}).Debug("Received UDP packet")
		h.readOnePacket(buf[:n], addr)
	}
}

func (h *SSU2Conn) readInboundDatagram(buf []byte) (int, net.Addr, bool, error) {
	if h.ownsUnderlying {
		// BUG-TO-1: For sessions that own the underlying socket (DialSSU2),
		// block directly on ReadFrom. CloseWithReason closes the socket after
		// signalling closeChan, which unblocks ReadFrom. This eliminates the
		// 100 ms CPU wakeup cycle for dial sessions.
		n, addr, err := h.underlying.ReadFrom(buf)
		if err != nil {
			select {
			case <-h.closeChan:
				return 0, nil, true, nil
			default:
			}
			h.readErrors.Add(1)
			return 0, nil, false, err
		}
		return n, addr, false, nil
	}

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
		return 0, nil, true, nil
	default:
	}
	_ = h.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	n, addr, err := h.underlying.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return 0, nil, false, nil
		}
		// Non-timeout error: check if we're closing before counting it.
		select {
		case <-h.closeChan:
			return 0, nil, true, nil
		default:
		}
		h.readErrors.Add(1)
		return 0, nil, false, err
	}

	return n, addr, false, nil
}

// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
// Supports connection migration: if a packet from a new address passes AEAD
// verification, the remote address is updated (per spec §Connection Migration).
func (h *SSU2Conn) parseInboundPacket(data []byte, addr net.Addr) *SSU2Packet {
	flog("parseInboundPacket", logger.Fields{"data_len": len(data), "from": addr}).Debug("parsing inbound UDP datagram")
	udpAddr := h.asUDPAddr(addr)
	if udpAddr == nil {
		return nil
	}

	// Decrypt header protection before parsing
	if h.headerProtector != nil {
		if !h.decryptInboundHeader(data) {
			return nil
		}
	}

	// SSU2 has no data-phase length-obfuscation field. Header bytes
	// 14-15 are the spec's "moreflags" (unused, set to 0), already covered by
	// ChaCha20 header protection above. The datagram length is the message
	// length (parsed by Deserialize from the UDP payload size), so there is
	// nothing to deobfuscate here. The bytes are zeroed before AEAD below.

	packet := &SSU2Packet{}
	if !h.deserializeInboundPacket(packet, data) {
		return nil
	}

	if !h.decryptInboundPayload(packet) {
		return nil
	}

	// Carry the source address on the packet. Connection migration is NOT
	// triggered here: ssu2.md §"Connection Migration" -> §"Initiating Path
	// Validation" requires the packet to also "not [be] a duplicate packet
	// number", which is only known after the receive-window dedup in
	// processDataPackets. The trigger therefore happens in handleReadyDataPacket
	// (post-dedup, post-decrypt). Handshake packets ignore Source: migration is
	// "defined only for the data phase" and the handshake address is pinned.
	packet.Source = udpAddr

	h.updateActivity()
	return packet
}

func (h *SSU2Conn) asUDPAddr(addr net.Addr) *net.UDPAddr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}
	return udpAddr
}

func (h *SSU2Conn) decryptInboundHeader(data []byte) bool {
	hType := h.expectedInboundHeaderType()
	if err := h.headerProtector.DecryptInboundHeader(data, hType); err != nil {
		h.parseErrors.Add(1)
		return false
	}
	return true
}

func (h *SSU2Conn) deserializeInboundPacket(packet *SSU2Packet, data []byte) bool {
	if err := packet.Deserialize(data); err != nil {
		h.parseErrors.Add(1)
		return false
	}
	return true
}

func (h *SSU2Conn) decryptInboundPayload(packet *SSU2Packet) bool {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	cipher := h.recvCipher
	if cipher == nil || packet.MessageType != MessageTypeData || len(packet.Payload) == 0 {
		return true
	}

	// The AEAD nonce is the packet number and the associated data is the
	// 16-byte short header. Bytes 14-15 are the "moreflags" field, which
	// ssu2.rst (Messages, data message) defines as "2 bytes, unused, set to 0
	// for future compatibility" -- SSU2 has no data-phase length-obfuscation
	// field, so both peers use zero here. Zero them defensively so the AD
	// matches what the sender encrypted.
	binary.BigEndian.PutUint16(packet.Header[14:16], 0)
	cipher.SetNonce(uint64(packet.PacketNumber))
	decrypted, err := cipher.Decrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
	if err != nil {
		h.decryptErrors.Add(1)
		return false
	}
	packet.Payload = decrypted

	// ssu2.rst (Messages): "The minimum payload size is 8 bytes ... If the
	// requirement is not met, a Padding block must be included." Now that the
	// AEAD tag is stripped, the plaintext blocks must clear the floor; a peer
	// that sends less is not following the spec.
	if len(packet.Payload) < MinPayloadSize {
		flog("decryptInboundPayload", logger.Fields{
			"pktNum":     packet.PacketNumber,
			"payloadLen": len(packet.Payload),
			"minimum":    MinPayloadSize,
		}).Warn("inbound payload below the SSU2 minimum payload size")
		return false
	}
	return true
}

func (h *SSU2Conn) shouldValidateMigratedAddress(udpAddr *net.UDPAddr) bool {
	h.remoteAddrLock.RLock()
	addrChanged := !udpAddr.IP.Equal(h.remoteAddr.IP) || udpAddr.Port != h.remoteAddr.Port
	h.remoteAddrLock.RUnlock()
	return addrChanged && h.pathValidator != nil
}

func (h *SSU2Conn) initiatePathValidation(udpAddr *net.UDPAddr) {
	if _, err := h.pathValidator.InitiatePathValidation(udpAddr); err != nil {
		// Do not silently swallow: a failure to start validation means
		// the address migration is not being verified.
		flog("parseInboundPacket", logger.Fields{"new_addr": udpAddr.String()}).WithError(err).Warn("failed to initiate path validation for migrated address")
	}
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
				// Send an ACK-only packet as keepalive. ssu2.rst has no
				// dedicated keepalive section; ACKs are described under
				// "Congestion Control".
				h.sendImmediateACK()
			}

			// Check for timeout (configurable idle timeout).
			idleTimeout := h.config.IdleTimeout
			if idleTimeout <= 0 {
				idleTimeout = 5 * time.Minute
			}
			if timeSinceActivity >= idleTimeout {
				h.closeMutex.Lock()
				h.closeErr = oops.Errorf("idle timeout")
				h.closeMutex.Unlock()
				// Run close in a separate goroutine to avoid deadlock.
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

// ProcessInboundPacket processes a received packet by routing it to the appropriate
// handler based on message type. Handshake packets are enqueued to the receive queue
// for the initiator/responder handshake logic to consume. Data packets pass through
// the packet-number filter for duplicate detection and are then processed in arrival
// order; SSU2 does not reorder them.
//
// This method is exported to support cross-package delivery of packets from
// the listener to pending outbound sessions during handshake demultiplexing,
// preserving the single-reader invariant and the pending outbound registry.
//
// Parameters:
//   - packet: The parsed SSU2Packet to process
func (h *SSU2Conn) ProcessInboundPacket(packet *SSU2Packet) {
	switch packet.MessageType {
	case MessageTypeData:
		h.processDataPackets(packet)
	case MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypeSessionConfirmed:
		h.processHandshakePacket(packet)
	}
}

// processInboundPacket (deprecated) is kept for backwards compatibility.
// New code should use ProcessInboundPacket.
func (h *SSU2Conn) processInboundPacket(packet *SSU2Packet) {
	h.ProcessInboundPacket(packet)
}

func (h *SSU2Conn) processDataPackets(packet *SSU2Packet) {
	// Filter duplicate and too-old packet numbers. SSU2 provides no in-order
	// delivery (ssu2.rst §"Delivery Guarantees"), so an accepted packet goes
	// straight to the data path in arrival order rather than to a reordering
	// buffer.
	readyPackets := h.collectReadyDataPackets(packet)
	for _, readyPacket := range readyPackets {
		h.handleReadyDataPacket(readyPacket)
	}
}

func (h *SSU2Conn) collectReadyDataPackets(packet *SSU2Packet) []*SSU2Packet {
	if h.recvWindow == nil {
		// No receive window; treat this packet as immediately ready
		return []*SSU2Packet{packet}
	}
	readyPackets, err := h.recvWindow.Insert(packet)
	if err != nil {
		return nil // silently drop
	}
	return readyPackets
}

func (h *SSU2Conn) handleReadyDataPacket(readyPacket *SSU2Packet) {
	h.validDataPacketsReceived.Add(1)

	// Connection migration: this packet has now successfully decrypted
	// (decryptInboundPayload) and passed the receive-window duplicate filter
	// (collectReadyDataPackets), satisfying both spec preconditions in
	// ssu2.md §"Connection Migration" -> §"Initiating Path Validation". Only
	// then do we check for a changed source address and start validation.
	if udpAddr := h.asUDPAddr(readyPacket.Source); udpAddr != nil &&
		h.shouldValidateMigratedAddress(udpAddr) {
		h.initiatePathValidation(udpAddr)
	}

	// Process the packet first, then decide about the ACK. ssu2.md §"ACK
	// Frequency" allows exactly this: "A receiver may process multiple available
	// packets before determining whether to send an ACK block in response."
	// Processing also yields the block list, which the ack-eliciting
	// classification below needs.
	blocks := h.processDataPacket(readyPacket)

	// Record for ACK only after window acceptance, and only for ack-eliciting
	// packets.
	//
	// ssu2.md §"Generating ACKs": "In-session data packets containing any block
	// EXCEPT for the following are ack-eliciting: ACK block / Address block /
	// DateTime block / Padding block / Termination block", and "Routers
	// acknowledge all packets they receive and process. However, only
	// ack-eliciting packets cause an ACK block to be sent within the maximum ack
	// delay. Packets that are not ack-eliciting are only acknowledged when an ACK
	// block is sent for other reasons."
	//
	// Non-ack-eliciting packets are therefore still carried by any ACK that goes
	// out for another reason (GenerateACK acks the whole received set), but they
	// do not by themselves push the receiver over the two-packet threshold.
	//
	// Every data-phase packet number is meaningful and must be ackable, including
	// 0: §"Packet Numbering" gives Bob packet 0 for the Session Confirmed ACK.
	var types []uint8
	for _, b := range blocks {
		if b != nil {
			types = append(types, b.Type)
		}
	}
	if len(blocks) == 0 || IsAckEliciting(types) {
		h.ackHandler.RecordReceived(readyPacket.PacketNumber)
	}

	// Check if a delayed ACK should be sent immediately.
	// If ShouldSendACK returns true (threshold met or delay elapsed), send ACK.
	// Otherwise, rely on the timer or the next batch of packets.
	rtt := h.rttEstimator.GetSmoothedRTT()
	if rtt == 0 {
		rtt = 50 * time.Millisecond // Default if not yet measured
	}
	if h.ackHandler.ShouldSendACK(rtt) {
		h.sendImmediateACK()
	}

	// Check immediate-ack flag: header byte 13, bit 0. This is also
	// checked via CongestionFlagRequestACK in the Congestion block handler,
	// providing redundant but harmless ACK triggering.
	if len(readyPacket.Header) > 13 && readyPacket.Header[13]&0x01 != 0 {
		h.sendImmediateACK()
	}
}

func (h *SSU2Conn) processHandshakePacket(packet *SSU2Packet) {
	// Handshake packets bypass receive window.
	//
	// ssu2.rst §"Packet Numbering": Session Request, Session Created, Token
	// Request, Retry, Peer Test and Hole Punch carry a *random* packet number
	// that is ignored, so recording those would pollute the ACK set with
	// numbers the peer never assigned. Session Confirmed is the exception: for
	// Alice "outbound packet numbering starts at 0 with Session Confirmed",
	// and Bob must acknowledge that packet 0.
	if packet.MessageType == MessageTypeSessionConfirmed {
		h.ackHandler.RecordReceived(packet.PacketNumber)
	}
	// Handshake packets are scarce and progress the state machine; dropping
	// one forces reliance on the (slow) retransmit schedule and inflates
	// handshake latency. Briefly block to enqueue rather than dropping on a
	// transiently-full queue, but bound the wait so a stalled handshake
	// reader cannot pin this worker indefinitely.
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

// processDataPacket handles a data-phase packet: parses blocks and retires ACKed
// packets. It returns the parsed blocks (nil on failure) so the caller can apply
// the ack-eliciting classification from ssu2.md §"Generating ACKs".
func (h *SSU2Conn) processDataPacket(packet *SSU2Packet) []*SSU2Block {
	flog("processDataPacket", logger.Fields{"pkt_num": packet.PacketNumber, "payload_len": len(packet.Payload)}).Debug("processing")
	blocks, err := h.dataHandler.ProcessDataPacket(packet)
	if err != nil {
		flog("processDataPacket", logger.Fields{"error": err.Error()}).Debug("ProcessDataPacket error")
		return nil
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
	return blocks
}

// handlePeerNextNonce is the OnNextNonce callback wired in installCipherStates.
// When the peer sends us a NextNonce, we rekey the *receive* cipher to match.
func (h *SSU2Conn) handlePeerNextNonce(newNonce uint64) error {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.recvCipher == nil {
		return oops.Errorf("receive cipher not initialized")
	}

	// Derive new recv cipher key: newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
	// The ssu2.rst "NextNonce" section is "TODO" with contents "TBD", so this
	// derivation follows the i2pd reference implementation, not the spec text.
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
// which leaks an unstoppable timer on every Read until it fires.
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
// Read() has already been called, enforcing mutual exclusivity.
func (h *SSU2Conn) MessageChan() <-chan []byte {
	// Enforce mutual exclusivity of MessageChan and Read delivery paths.
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
