package session

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Write implements net.Conn.Write.
// Writes data to the connection. If the data exceeds the per-packet payload
// capacity (determined by MTU), it is automatically split into FirstFragment
// and FollowOnFragment blocks per SSU2 spec §FirstFragment/§FollowOnFragment.
//
// For unfragmented messages, b is sent as-is in a BlockTypeI2NPMessage block.
// Per the SSU2 spec, block type 3 (I2NP) data must already contain the 9-byte
// I2NP short header: [I2NPType:1][MessageID:4][ShortExpiry:4] followed by the
// message body. The caller is responsible for prepending this header.
//
// For fragmented messages, the implementation generates its own MessageID and
// ShortExpiry for the FirstFragment/FollowOnFragment blocks, treating b[0] as
// the I2NP type byte and the rest as body data.
func (h *SSU2Conn) Write(b []byte) (int, error) {
	flog("Write", logger.Fields{"dataLen": len(b)}).Debug("sending data")
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	// Maximum block data that fits in a single Data packet.
	// Available = MTU - IP(40) - UDP(8) - SSU2_header(16) - AEAD_MAC(16) - block_TLV(3)
	const blockHdrSize = 3 // wire.minBlockHeaderSize: Type(1)+Length(2)
	maxBlockData := h.config.MTU - 80 - blockHdrSize

	if len(b) <= maxBlockData {
		// Fits in a single I2NP message block
		block := &SSU2Block{
			Type: BlockTypeI2NPMessage,
			Data: append([]byte(nil), b...),
		}
		if err := h.writeBlock(block); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	// Fragment the message using FirstFragment + FollowOnFragment blocks.
	blocks, err := h.buildI2NPFragmentBlocks(b, maxBlockData)
	if err != nil {
		return 0, oops.Wrapf(err, "failed to build I2NP fragment blocks")
	}

	if err := h.WriteBlocks(blocks); err != nil {
		return 0, err
	}
	return len(b), nil
}

// buildI2NPFragmentBlocks splits a large I2NP message into FirstFragment and
// FollowOnFragment blocks per SSU2 spec.
//
// FirstFragment (type 4): I2NPType(1) + MessageID(4) + ShortExpiry(4) + data
// FollowOnFragment (type 5): FragInfo(1) + MessageID(4) + data
//
// The follow-on fragment number is a 7-bit field, allowing at most 127 follow-on
// fragments. Combined with the first fragment (number 0), the maximum total is 128.
func (h *SSU2Conn) buildI2NPFragmentBlocks(data []byte, maxBlockData int) ([]*SSU2Block, error) {
	flog("buildI2NPFragmentBlocks", logger.Fields{"dataLen": len(data), "maxBlockData": maxBlockData}).Debug("fragmenting I2NP message")
	const (
		firstFragHeaderSize       = 9   // type(1) + msgID(4) + shortExpiry(4)
		followOnFragHeaderSize    = 5   // fragInfo(1) + msgID(4)
		maxFollowOnFragmentNumber = 127 // 7-bit field: 0-127, but first fragment is 0, so max follow-on is 127
	)

	// Generate a random message ID for fragment correlation.
	var msgIDBuf [4]byte
	if _, err := rand.Read(msgIDBuf[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate fragment message ID")
	}
	messageID := binary.BigEndian.Uint32(msgIDBuf[:])

	// I2NP type: use first byte if present, else 0.
	var i2npType uint8
	if len(data) > 0 {
		i2npType = data[0]
	}
	// Short expiration: current time + 120 seconds, in seconds since epoch.
	shortExpiry := uint32(time.Now().Unix()) + 120

	maxFirstData := maxBlockData - firstFragHeaderSize
	if maxFirstData <= 0 {
		return nil, oops.Errorf("MTU too small for fragmentation")
	}

	end := maxFirstData
	if end > len(data) {
		end = len(data)
	}

	// Build FirstFragment block.
	firstData := make([]byte, firstFragHeaderSize+end)
	firstData[0] = i2npType
	binary.BigEndian.PutUint32(firstData[1:5], messageID)
	binary.BigEndian.PutUint32(firstData[5:9], shortExpiry)
	copy(firstData[9:], data[:end])

	blocks := []*SSU2Block{{Type: BlockTypeFirstFragment, Data: firstData}}
	offset := end

	maxFollowData := maxBlockData - followOnFragHeaderSize

	// Validate fragment count: calculate total fragments needed and check against maximum
	remainingData := len(data) - offset
	followOnFragmentsNeeded := (remainingData + maxFollowData - 1) / maxFollowData // ceiling division
	if followOnFragmentsNeeded > int(maxFollowOnFragmentNumber) {
		return nil, oops.Errorf("message requires %d follow-on fragments, exceeds maximum of %d; use a smaller MTU or smaller message", followOnFragmentsNeeded, maxFollowOnFragmentNumber)
	}

	fragNum := uint8(1)
	for offset < len(data) {
		fEnd := offset + maxFollowData
		if fEnd > len(data) {
			fEnd = len(data)
		}
		isLast := fEnd == len(data)
		fragInfo := fragNum << 1
		if isLast {
			fragInfo |= 0x01
		}

		followData := make([]byte, followOnFragHeaderSize+(fEnd-offset))
		followData[0] = fragInfo
		binary.BigEndian.PutUint32(followData[1:5], messageID)
		copy(followData[5:], data[offset:fEnd])

		blocks = append(blocks, &SSU2Block{Type: BlockTypeFollowOnFragment, Data: followData})
		offset = fEnd
		fragNum++
	}

	return blocks, nil
}

// WriteBlocks sends the provided SSU2 blocks as individual Data packets (one
// packet per block). Unlike Write, this bypasses the BlockTypeI2NPMessage
// wrapper and sends pre-built blocks directly. Use this to send fragment
// blocks (BlockTypeFirstFragment / BlockTypeFollowOnFragment) for large I2NP
// messages.
func (h *SSU2Conn) WriteBlocks(blocks []*SSU2Block) error {
	flog("WriteBlocks", logger.Fields{"blockCount": len(blocks)}).Debug("sending blocks")
	if err := h.validateReadyForIO(); err != nil {
		return err
	}
	for _, block := range blocks {
		if err := h.writeBlock(block); err != nil {
			return err
		}
	}
	return nil
}

// newDataPacket allocates a fresh SSU2 Data packet with the next sequence
// number and a populated short header (connID + pktNum).
func (h *SSU2Conn) newDataPacket() *SSU2Packet {
	flog("newDataPacket").Debug("allocating data packet")
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID.Load())
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	return &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
}

// writeBlock sends a single SSU2Block as a Data packet.
func (h *SSU2Conn) writeBlock(block *SSU2Block) error {
	flog("writeBlock", logger.Fields{"blockType": block.Type}).Debug("sending block")

	// AUDIT 2.2: Check write deadline BEFORE consuming sequence number to avoid
	// wasting sequence numbers on writes that will be rejected by deadline anyway.
	// This prevents sequence number gaps that cause unnecessary peer retransmissions.
	select {
	case <-h.getWriteDeadline():
		return oops.Errorf("write deadline exceeded")
	case <-h.closeChan:
		return oops.Errorf("connection closed")
	default:
		// Deadline not yet expired, safe to proceed
	}

	packet := h.newDataPacket()

	// Serialize block into payload
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "failed to serialize block")
	}
	packet.Payload = payload

	// Enqueue for sending
	select {
	case h.sendQueue <- packet:
		return nil
	case <-h.closeChan:
		return oops.Errorf("connection closed")
	case <-h.getWriteDeadline():
		return oops.Errorf("write deadline exceeded")
	}
}

// sendLoop handles outbound packet transmission.
func (h *SSU2Conn) sendLoop() {
	flog("sendLoop").Debug("starting outbound packet transmission loop")
	defer h.wg.Done()

	for {
		select {
		case packet := <-h.sendQueue:
			if err := h.sendPacketDirect(packet); err != nil {
				h.writeErrors.Add(1)
				flog("sendLoop", logger.Fields{"pktNum": packet.PacketNumber, "error":  err}).Error("UDP write failed")
				continue
			}
		case <-h.closeChan:
			return
		}
	}
}

// retransmitLoop periodically scans pendingPackets for RTO expiry and
// re-enqueues expired packets. Packets exceeding maxPacketRetries are dropped.
func (h *SSU2Conn) retransmitLoop() {
	flog("retransmitLoop").Debug("starting retransmit loop")
	defer h.wg.Done()

	ticker := time.NewTicker(retransmitInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.retransmitExpired()
		case <-h.closeChan:
			return
		}
	}
}

// retransmitExpired checks all pending packets and retransmits those that
// have exceeded their NextRetry deadline.
func (h *SSU2Conn) retransmitExpired() {
	flog("retransmitExpired").Debug("checking pending packets for retransmission")
	now := time.Now()
	rto := h.rttEstimator.GetRTO()

	h.pendingMutex.Lock()
	defer h.pendingMutex.Unlock()

	for pn, pp := range h.pendingPackets {
		if now.Before(pp.NextRetry) {
			continue
		}

		if pp.Retries >= maxPacketRetries {
			delete(h.pendingPackets, pn)
			continue
		}

		pp.Retries++
		// Exponential backoff: double the RTO for each retry
		backoff := rto * time.Duration(1<<pp.Retries)
		pp.NextRetry = now.Add(backoff)

		// Per spec: retransmissions must use a fresh packet number.
		newPacket := h.newDataPacket()
		newPacket.Payload = make([]byte, len(pp.PlaintextPayload))
		copy(newPacket.Payload, pp.PlaintextPayload)

		// Remove old entry; sendPacketDirect will track the new one.
		delete(h.pendingPackets, pn)

		// Best-effort re-enqueue; drop if sendQueue is full
		select {
		case h.sendQueue <- newPacket:
		default:
		}
	}
}

// sendPacketDirect sends a packet directly to the peer.
// For data packets in the established state, the payload is encrypted with AEAD.
func (h *SSU2Conn) sendPacketDirect(packet *SSU2Packet) error {
	flog("sendPacketDirect", logger.Fields{"pktNum": packet.PacketNumber, "msgType": packet.MessageType}).Debug("sending packet")
	plaintextPayload, err := h.encryptDataPayload(packet)
	if err != nil {
		return err
	}

	h.applyDataHeaderMoreFlags(packet)

	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet")
	}

	if err := h.applyOutboundHeaderProtection(data, packet.MessageType); err != nil {
		return err
	}

	h.remoteAddrLock.RLock()
	_, err = h.underlying.WriteTo(data, h.remoteAddr)
	h.remoteAddrLock.RUnlock()
	if err != nil {
		return oops.Wrapf(err, "failed to write to UDP")
	}

	if packet.MessageType == MessageTypeData {
		h.validDataPacketsSent.Add(1)
	}
	h.updateActivity()
	h.trackPendingPacket(packet, plaintextPayload)

	return nil
}

// encryptDataPayload encrypts the payload for data packets using AEAD.
// Returns a copy of the plaintext payload for potential retransmit.
func (h *SSU2Conn) encryptDataPayload(packet *SSU2Packet) ([]byte, error) {
	flog("encryptDataPayload", logger.Fields{"pktNum": packet.PacketNumber, "payloadLen": len(packet.Payload)}).Debug("encrypting payload")
	var plaintextPayload []byte

	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	cipher := h.sendCipher
	if cipher == nil || packet.MessageType != MessageTypeData || len(packet.Payload) == 0 {
		return nil, nil
	}

	plaintextPayload = make([]byte, len(packet.Payload))
	copy(plaintextPayload, packet.Payload)

	packet.Header[12] = packet.MessageType
	cipher.SetNonce(uint64(packet.PacketNumber))
	encrypted, err := cipher.Encrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt payload")
	}
	packet.Payload = encrypted
	return plaintextPayload, nil
}

// applyDataHeaderMoreFlags sets the data-phase short-header "moreflags" field
// (bytes 14-15) to zero, as mandated by the SSU2 spec (§Messages, Data Message
// Type 6: "moreflags :: 2 bytes, unused, set to 0 for future compatibility").
//
// H-1 fix: SSU2 has NO data-phase length-obfuscation field. Each UDP datagram
// contains exactly one message and "the length of the datagram ... is the length
// of the message"; header confidentiality is provided solely by ChaCha20 header
// protection over bytes 0-15. The prior implementation XOR-ed an obfuscated length
// (via a stateful per-direction SipHash chain) into bytes 14-15. That construct is
// not part of SSU2: it placed non-spec bytes in the moreflags field on the wire
// (wire-incompatible with Java I2P / i2pd) and the recovered value was discarded
// before AEAD on the receive side, so it was functionally inert for our own
// decryption while still risking a desync on UDP loss/reorder. We now keep the
// field at the spec-mandated zero.
func (h *SSU2Conn) applyDataHeaderMoreFlags(packet *SSU2Packet) {
	flog("applyDataHeaderMoreFlags", logger.Fields{"msgType": packet.MessageType}).Debug("zeroing data header moreflags per SSU2 spec")
	if packet.MessageType == MessageTypeData && len(packet.Header) >= ShortHeaderSize {
		binary.BigEndian.PutUint16(packet.Header[14:16], 0)
	}
}

// applyOutboundHeaderProtection encrypts the outbound header if protection is enabled.
func (h *SSU2Conn) applyOutboundHeaderProtection(data []byte, messageType uint8) error {
	flog("applyOutboundHeaderProtection", logger.Fields{"msgType": messageType}).Debug("encrypting header")
	if h.headerProtector == nil {
		return nil
	}
	hType := messageTypeToHeaderType(messageType)
	if err := h.headerProtector.EncryptOutboundHeader(data, hType); err != nil {
		return oops.Wrapf(err, "failed to encrypt header")
	}
	return nil
}

// trackPendingPacket records a sent data packet for potential retransmission.
func (h *SSU2Conn) trackPendingPacket(packet *SSU2Packet, plaintext []byte) {
	flog("trackPendingPacket", logger.Fields{"pktNum": packet.PacketNumber}).Debug("recording packet for retransmission")
	if packet.MessageType != MessageTypeData || packet.PacketNumber == 0 {
		return
	}
	h.pendingMutex.Lock()
	h.pendingPackets[packet.PacketNumber] = &PendingPacket{
		Packet:           packet,
		PlaintextPayload: plaintext,
		SentTime:         time.Now(),
		Retries:          0,
		NextRetry:        time.Now().Add(h.rttEstimator.GetRTO()),
	}
	h.pendingMutex.Unlock()
}

// sendImmediateACK generates and sends an ACK packet without delay, honoring
// the immediate-ack flag (header byte 13 bit 0) from the peer.
func (h *SSU2Conn) sendImmediateACK() {
	flog("sendImmediateACK").Debug("generating and sending immediate ACK")
	ack, err := h.ackHandler.GenerateACK()
	if err != nil || ack == nil {
		return
	}
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID.Load())
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
	payload, _ := SerializeBlocks([]*SSU2Block{ack})
	packet.Payload = payload
	_ = h.sendPacketDirect(packet)
}

// handleCongestionBlock processes a received Congestion block (G-6).
// If the RequestACK flag (bit 0) is set, triggers an immediate ACK per spec.
// If the ECN flag (bit 1) is set, signals the congestion controller.
func (h *SSU2Conn) handleCongestionBlock(flags uint8) error {
	flog("handleCongestionBlock", logger.Fields{"flags": flags}).Debug("processing congestion block")
	if flags&CongestionFlagRequestACK != 0 {
		h.sendImmediateACK()
	}
	if flags&CongestionFlagECN != 0 && h.congestionController != nil {
		h.congestionController.OnECN()
	}
	return nil
}

// handlePathChallengeData wraps PathValidator.HandlePathChallenge for the DataHandler callback (G-7).
func (h *SSU2Conn) handlePathChallengeData(data []byte) error {
	flog("handlePathChallengeData", logger.Fields{"dataLen": len(data)}).Debug("processing path challenge")
	block := &SSU2Block{Type: BlockTypePathChallenge, Data: data}
	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	return h.pathValidator.HandlePathChallenge(block, addr)
}

// handlePathResponseData wraps PathValidator.HandlePathResponse for the DataHandler callback (G-7).
func (h *SSU2Conn) handlePathResponseData(data []byte) error {
	flog("handlePathResponseData", logger.Fields{"dataLen": len(data)}).Debug("processing path response")
	block := &SSU2Block{Type: BlockTypePathResponse, Data: data}
	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	return h.pathValidator.HandlePathResponse(block, addr)
}

// handleAddressBlock processes an Address block (Type 13) for passive NAT
// detection (G-6). The block contains the sender's view of our IP and port.
// Format: IP (4 or 16 bytes) + Port (2 bytes big-endian).
func (h *SSU2Conn) handleAddressBlock(data []byte) error {
	if len(data) != 6 && len(data) != 18 {
		return oops.Errorf("Address block invalid length: %d (expected 6 or 18)", len(data))
	}
	portOffset := len(data) - 2
	ip := net.IP(data[:portOffset])
	port := binary.BigEndian.Uint16(data[portOffset:])

	localAddr := h.LocalAddr()
	if udp, ok := localAddr.(*net.UDPAddr); ok {
		if !udp.IP.Equal(ip) || udp.Port != int(port) {
			flog("handleAddressBlock", logger.Fields{"reportedIP":   ip.String(), "reportedPort": port, "localIP":      udp.IP.String(), "localPort":    udp.Port}).Info("Address block reports different address (possible NAT)")
		}
	}
	return nil
}

// nextSendSequence returns the next packet sequence number.
// When the sequence crosses rekeyThreshold, it fires a one-shot
// NextNonce rekey so the cipher is refreshed before the 32-bit
// counter wraps. Per SSU2 spec, the packet number must not wrap
// around to zero (G-1); if the counter reaches 0xFFFFFFFF the
// connection is closed.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
func (h *SSU2Conn) nextSendSequence() uint32 {
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()

	// Hard reject: do not wrap past 0xFFFFFFFF (G-1).
	if h.sendSequence == 0xFFFFFFFF {
		flog("nextSendSequence").Error("packet number exhausted (0xFFFFFFFF): closing connection per SSU2 spec")
		go h.Close()
		return 0xFFFFFFFF
	}

	seq := h.sendSequence
	h.sendSequence++

	// Trigger rekey exactly once when we cross the threshold,
	// but only if NextNonce is enabled via config (G-1).
	if h.config.EnableNextNonce && seq >= rekeyThreshold && !h.rekeyInFlight.Load() {
		if h.rekeyInFlight.CompareAndSwap(false, true) {
			go h.initiateRekey()
		}
	}
	return seq
}

// initiateRekey sends a NextNonce block to the peer, then rekeys the local
// send cipher and resets the send sequence counter.
//
// The NextNonce block MUST be encrypted with the OLD key so the receiver can
// decrypt it and learn about the rekey. Only after the NextNonce packet is
// fully encrypted and transmitted do we switch to the new key.
//
// This function bypasses the normal sendQueue path and sends inline under
// cipherMutex to guarantee atomic key transition: no packet can be encrypted
// between NextNonce send and the key switch.
func (h *SSU2Conn) initiateRekey() {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.sendCipher == nil {
		return
	}

	flog("initiateRekey").Warn("initiating NextNonce rekey (unfinalized spec area — interoperability not guaranteed)")

	// Derive new send cipher key per SSU2 spec §NextNonce:
	// newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
	newKey, err := deriveRekeyKey(h.sendCipher)
	if err != nil {
		flog("initiateRekey", logger.Fields{"error": err}).Error("failed to derive rekey for send cipher")
		return
	}

	// Send NextNonce block encrypted with the OLD key before rekeying.
	if err := h.sendNextNonceInline(); err != nil {
		flog("initiateRekey", logger.Fields{"error": err}).Error("failed to send NextNonce block")
		return
	}

	// NOW rekey the cipher to the new key.
	h.sendCipher.UnsafeSetKey(newKey)
	h.sendCipher.SetNonce(0)

	// Reset send sequence so new packets start at 0.
	h.sendSeqMutex.Lock()
	h.sendSequence = 0
	h.sendSeqMutex.Unlock()
}

// sendNextNonceInline builds, encrypts, and sends a NextNonce block directly,
// bypassing the sendQueue. Must be called while holding cipherMutex so the
// packet is encrypted with the current (old) key atomically.
func (h *SSU2Conn) sendNextNonceInline() error {
	flog("sendNextNonceInline").Debug("building and sending NextNonce block")
	// Allocate packet number from the current sequence counter.
	h.sendSeqMutex.Lock()
	pktNum := h.sendSequence
	h.sendSequence++
	h.sendSeqMutex.Unlock()

	// Build NextNonce block with new starting nonce (0).
	var nonceBuf [8]byte
	block := &SSU2Block{Type: BlockTypeNextNonce, Data: nonceBuf[:]}

	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "serialize NextNonce block")
	}

	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID.Load())
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	hdr[12] = MessageTypeData

	// Encrypt with the current (OLD) key.
	h.sendCipher.SetNonce(uint64(pktNum))
	encrypted, err := h.sendCipher.Encrypt(nil, hdr[:ShortHeaderSize], payload)
	if err != nil {
		return oops.Wrapf(err, "encrypt NextNonce block")
	}

	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		Payload:      encrypted,
		MAC:          make([]byte, MACSize),
	}

	// Data-phase moreflags (header bytes 14-15) are set to 0 per SSU2 spec.
	// SSU2 has no length-obfuscation field; see applyDataHeaderMoreFlags (H-1).
	binary.BigEndian.PutUint16(packet.Header[14:16], 0)

	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "serialize NextNonce packet")
	}

	if h.headerProtector != nil {
		hType := messageTypeToHeaderType(packet.MessageType)
		_ = h.headerProtector.EncryptOutboundHeader(data, hType)
	}

	h.remoteAddrLock.RLock()
	_, err = h.underlying.WriteTo(data, h.remoteAddr)
	h.remoteAddrLock.RUnlock()
	if err != nil {
		return oops.Wrapf(err, "send NextNonce packet")
	}

	h.updateActivity()
	return nil
}

// updateActivity updates the last activity timestamp.
func (h *SSU2Conn) updateActivity() {
	h.lastActivityLock.Lock()
	defer h.lastActivityLock.Unlock()
	h.lastActivity = time.Now()
}

// getWriteDeadline returns a channel that closes at write deadline.
func (h *SSU2Conn) getWriteDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.writeDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.writeDeadline))
}
