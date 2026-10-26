package session

import (
	"encoding/binary"
	"github.com/go-i2p/crypto/rand"
	"net"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Write implements net.Conn.Write.
// Writes data to the connection. If the data exceeds the per-packet payload
// capacity (determined by MTU), it is automatically split into FirstFragment
// and FollowOnFragment blocks per ssu2.rst "First Fragment"/"Follow-on Fragment".
//
// For unfragmented messages, b is sent as-is in a BlockTypeI2NPMessage block.
// i2npBlockBudget returns the data-phase payload budget in bytes for the peer's
// address family, per ssu2.md §"MTU" -> §"Max I2NP Message Size": MTU - 60 for
// IPv4 and MTU - 80 for IPv6. An unknown or dual-stack-wildcard peer falls back
// to the smaller IPv6 budget, so the conservative case is never exceeded.
func (h *SSU2Conn) i2npBlockBudget() int {
	mtu := h.config.MTU
	if h.peerIsIPv4() {
		return mtu - 60
	}
	return mtu - 80
}

// peerIsIPv4 reports whether the session's remote address is an IPv4 (or
// IPv4-mapped) address.
func (h *SSU2Conn) peerIsIPv4() bool {
	h.remoteAddrLock.RLock()
	remote := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	if remote == nil || remote.IP == nil {
		return false
	}
	return remote.IP.To4() != nil
}

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
	//
	// ssu2.md §"MTU" -> §"Max I2NP Message Size" gives a per-family budget:
	//   "IPv4: ... Max message size is MTU - 28. Data phase header is 16 bytes
	//    and MAC is 16 bytes, totaling 32 bytes. Payload size is MTU - 60.
	//    Max data phase payload is 1440 for a max 1500 MTU. Max data phase
	//    payload is 1220 for a min 1280 MTU."
	//   "IPv6: ... Max message size is MTU - 48. ... Payload size is MTU - 80.
	//    Max data phase payload is 1420 for a max 1500 MTU. Max data phase
	//    payload is 1200 for a min 1280 MTU."
	//
	// The block TLV header is then subtracted from that payload budget. Using the
	// IPv6 figure for IPv4 peers under-sizes every IPv4 message by 20 bytes.
	const blockHdrSize = 3 // wire.minBlockHeaderSize: Type(1)+Length(2)
	maxBlockData := h.i2npBlockBudget() - blockHdrSize

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
//
// To obtain the assigned packet numbers for ACK correlation, use
// WriteBlocksWithNumbers instead.
func (h *SSU2Conn) WriteBlocks(blocks []*SSU2Block) error {
	_, err := h.WriteBlocksWithNumbers(blocks)
	return err
}

// WriteBlocksWithNumbers sends the provided SSU2 blocks as individual Data
// packets (one packet per block) and returns the packet number assigned to
// each block in the same order. The returned slice has the same length as
// blocks; element i is the packet number of the packet carrying blocks[i].
//
// Packet numbers are allocated at enqueue time, before the packet reaches the
// wire. Callers can use the returned numbers to deterministically correlate
// explicit ACK blocks received from the peer to the exact packets they sent,
// enabling spec-correct delivery confirmation without heuristic retirement.
//
// On the first error the function stops and returns the packet numbers
// allocated so far (which may be fewer than len(blocks)) together with the
// error. Numbers already allocated to enqueued packets remain in flight.
func (h *SSU2Conn) WriteBlocksWithNumbers(blocks []*SSU2Block) ([]uint32, error) {
	flog("WriteBlocksWithNumbers", logger.Fields{"blockCount": len(blocks)}).Debug("sending blocks with packet-number tracking")
	if err := h.validateReadyForIO(); err != nil {
		return nil, err
	}
	nums := make([]uint32, 0, len(blocks))
	for _, block := range blocks {
		pktNum, err := h.writeBlockWithNumber(block)
		if err != nil {
			return nums, err
		}
		nums = append(nums, pktNum)
	}
	return nums, nil
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
// It is a convenience wrapper around writeBlockWithNumber that discards the
// assigned packet number.
func (h *SSU2Conn) writeBlock(block *SSU2Block) error {
	_, err := h.writeBlockWithNumber(block)
	return err
}

// writeBlockWithNumber sends a single SSU2Block as a Data packet and returns
// the packet number assigned to that packet.  The number is allocated before
// the packet is enqueued so that callers receive a stable identifier even
// before the packet reaches the wire.
func (h *SSU2Conn) writeBlockWithNumber(block *SSU2Block) (uint32, error) {
	flog("writeBlockWithNumber", logger.Fields{"blockType": block.Type}).Debug("sending block")

	// Check write deadline BEFORE consuming sequence number to avoid
	// wasting sequence numbers on writes that will be rejected by deadline anyway.
	// This prevents sequence number gaps that cause unnecessary peer retransmissions.
	select {
	case <-h.getWriteDeadline():
		return 0, oops.Errorf("write deadline exceeded")
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	default:
		// Deadline not yet expired, safe to proceed
	}

	packet := h.newDataPacket()

	// Serialize block into payload
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return 0, oops.Wrapf(err, "failed to serialize block")
	}
	packet.Payload = payload

	// Enqueue for sending
	select {
	case h.sendQueue <- packet:
		return packet.PacketNumber, nil
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-h.getWriteDeadline():
		return 0, oops.Errorf("write deadline exceeded")
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
				flog("sendLoop", logger.Fields{"pktNum": packet.PacketNumber, "error": err}).Error("UDP write failed")
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

	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()

	_, plaintextPayload, err := h.sealPacket(packet, addr)
	if err != nil {
		return err
	}

	if packet.MessageType == MessageTypeData {
		h.validDataPacketsSent.Add(1)
	}
	h.updateActivity()
	h.trackPendingPacket(packet, plaintextPayload)

	return nil
}

// sealPacket applies the full outbound protection pipeline to a packet and
// writes the resulting datagram to addr:
//
//  1. AEAD-seal the payload (data-phase keys, nonce = packet number,
//     associated data = the cleartext header)
//  2. zero the header's unused moreflags field
//  3. serialize header || payload || MAC
//  4. apply header protection (ChaCha20 masks/extension)
//  5. write the datagram to the underlying socket
//
// Returns the wire bytes and the plaintext payload (needed for retransmission
// tracking). A packet whose payload cannot be sealed is never written: an
// unencrypted Data packet is not a valid SSU2 message and would be dropped by
// any conformant peer, so sealPacket fails closed instead.
func (h *SSU2Conn) sealPacket(packet *SSU2Packet, addr *net.UDPAddr) ([]byte, []byte, error) {
	plaintextPayload, err := h.encryptDataPayload(packet)
	if err != nil {
		return nil, nil, err
	}

	h.applyDataHeaderMoreFlags(packet)

	// The destination family selects the outbound datagram budget: ssu2.md
	// §"Max I2NP Message Size" allows MTU - 28 on IPv4 but only MTU - 48 on
	// IPv6, so a 1453-1472 byte packet is legal over IPv4 and must not be
	// refused.
	packet.IsIPv4 = IsIPv4Addr(addr)

	data, err := packet.Serialize()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to serialize packet")
	}

	if err := h.applyOutboundHeaderProtection(data, packet.MessageType); err != nil {
		return nil, nil, err
	}

	if addr == nil {
		return nil, nil, oops.Errorf("no destination address for packet")
	}
	if _, err := h.underlying.WriteTo(data, addr); err != nil {
		return nil, nil, oops.Wrapf(err, "failed to write to UDP")
	}
	return data, plaintextPayload, nil
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

	// ssu2.rst (Messages): "The minimum payload size is 8 bytes ... If the
	// requirement is not met, a Padding block must be included." The floor is on
	// the plaintext blocks, so it must be enforced here, before the AEAD tag is
	// added (ciphertext always clears 16 bytes) and before the padded plaintext
	// is stored for retransmission.
	if len(packet.Payload) < MinPayloadSize {
		padded, err := PadPayloadToMin(packet.Payload)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to pad payload to minimum size")
		}
		packet.Payload = padded
	}

	plaintextPayload = make([]byte, len(packet.Payload))
	copy(plaintextPayload, packet.Payload)

	// ssu2.md §"Congestion Control" -> §"Immediate ACK Flag": the sender sets
	// the data-header flag byte bit 0 (header[13] & 0x01) to request that the
	// peer ACK within min(rtt/16, 5) ms instead of the normal delayed ACK.
	// The flag must be applied before sealing because the cleartext header is
	// the AEAD associated data.
	//
	// Strategy (per the strategies the spec lists, matching Java
	// PeerState2.getFlags()/PeerState.shouldRequestImmediateAck(), which sets
	// 0x01 when the send window is over 2/3 full): set it when the congestion
	// window is more than two-thirds consumed, and only on packets carrying
	// I2NP messages or fragments, since the spec says "Immediate ACK flags
	// should only be necessary on data packets containing I2NP messages or
	// message fragments."
	if wire.ContainsI2NPBlocks(plaintextPayload) && h.shouldRequestImmediateAck() {
		packet.Header[13] |= 0x01
	}

	packet.Header[12] = packet.MessageType
	cipher.SetNonce(uint64(packet.PacketNumber))
	encrypted, err := cipher.Encrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt payload")
	}
	packet.Payload = encrypted
	return plaintextPayload, nil
}

// shouldRequestImmediateAck reports whether outbound I2NP data packets
// should request an immediate ACK from the peer.
//
// ssu2.md §"Congestion Control" -> §"Immediate ACK Flag" lists several valid
// sender strategies; Java I2P (PeerState.shouldRequestImmediateAck(), used by
// PeerState2.getFlags()) sets the flag when the send window is over 2/3 full,
// i.e. remaining < window/3. We mirror that: remaining = CWND - bytesInFlight.
// A zero window (slow-start edge) never requests.
func (h *SSU2Conn) shouldRequestImmediateAck() bool {
	cc := h.congestionController
	if cc == nil {
		return false
	}
	cwnd := cc.GetCWND()
	if cwnd <= 0 {
		return false
	}
	return cc.AvailableWindow() < cwnd/3
}

// applyDataHeaderMoreFlags sets the data-phase short-header "moreflags" field
// (bytes 14-15) to zero, as mandated by the SSU2 spec (§Messages, Data Message
// Type 6: "moreflags :: 2 bytes, unused, set to 0 for future compatibility").
//
// SSU2 has no data-phase length-obfuscation field. Each UDP datagram contains
// exactly one message and "the length of the datagram ... is the length of the
// message"; header confidentiality is provided solely by ChaCha20 header
// protection over bytes 0-15. The moreflags field is therefore kept at the
// spec-mandated zero.
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
//
// Every Data packet number is tracked, including 0: ssu2.rst §"Packet Numbering"
// gives the responder packet 0 for its first Data packet, so 0 is a legitimate
// data-phase number and must not be treated as "not yet in the data phase".
func (h *SSU2Conn) trackPendingPacket(packet *SSU2Packet, plaintext []byte) {
	flog("trackPendingPacket", logger.Fields{"pktNum": packet.PacketNumber}).Debug("recording packet for retransmission")
	if packet.MessageType != MessageTypeData {
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
	payload, err := SerializeBlocks([]*SSU2Block{ack})
	if err != nil {
		flog("sendImmediateACK", logger.Fields{"error": err}).Warn("failed to serialize ACK block")
		return
	}
	packet.Payload = payload
	if err := h.sendPacketDirect(packet); err != nil {
		flog("sendImmediateACK", logger.Fields{"error": err}).Warn("failed to send immediate ACK packet")
	}
}

// handleCongestionBlock processes a received Congestion block.
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

// handlePathChallengeData wraps PathValidator.HandlePathChallenge for the DataHandler callback.
func (h *SSU2Conn) handlePathChallengeData(data []byte) error {
	flog("handlePathChallengeData", logger.Fields{"dataLen": len(data)}).Debug("processing path challenge")
	block := &SSU2Block{Type: BlockTypePathChallenge, Data: data}
	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	return h.pathValidator.HandlePathChallenge(block, addr)
}

// handlePathResponseData wraps PathValidator.HandlePathResponse for the DataHandler callback.
func (h *SSU2Conn) handlePathResponseData(data []byte) error {
	flog("handlePathResponseData", logger.Fields{"dataLen": len(data)}).Debug("processing path response")
	block := &SSU2Block{Type: BlockTypePathResponse, Data: data}
	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	return h.pathValidator.HandlePathResponse(block, addr)
}

// handleAddressBlock processes an Address block (Type 13) for passive NAT
// detection. The block contains the sender's view of our IP and port.
//
// Wire format per ssu2.rst "Address": port (2 bytes, big endian) followed by
// the IP address (4 bytes IPv4 or 16 bytes IPv6, network byte order). Parsing
// is delegated to wire.DecodeAddressBlock so there is exactly one decoder for
// this block.
func (h *SSU2Conn) handleAddressBlock(data []byte) error {
	blk, err := wire.DecodeAddressBlock(wire.NewSSU2Block(wire.BlockTypeAddress, data))
	if err != nil {
		return oops.Wrapf(err, "failed to decode Address block")
	}
	ip := blk.IP
	port := blk.Port

	localAddr := h.LocalAddr()
	if udp, ok := localAddr.(*net.UDPAddr); ok {
		if !udp.IP.Equal(ip) || udp.Port != int(port) {
			flog("handleAddressBlock", logger.Fields{"reportedIP": ip.String(), "reportedPort": port, "localIP": udp.IP.String(), "localPort": udp.Port}).Info("Address block reports different address (possible NAT)")
		}
	}
	return nil
}

// nextSendSequence returns the next packet sequence number.
// When the sequence crosses rekeyThreshold, it fires a one-shot
// NextNonce rekey so the cipher is refreshed before the 32-bit
// counter wraps. Per SSU2 spec, the packet number must not wrap
// around to zero; if the counter reaches 0xFFFFFFFF the
// connection is closed.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
func (h *SSU2Conn) nextSendSequence() uint32 {
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()

	// Hard reject: do not wrap past 0xFFFFFFFF.
	if h.sendSequence == 0xFFFFFFFF {
		flog("nextSendSequence").Error("packet number exhausted (0xFFFFFFFF): closing connection per SSU2 spec")
		go h.Close()
		return 0xFFFFFFFF
	}

	seq := h.sendSequence
	h.sendSequence++

	// Trigger rekey exactly once when we cross the threshold,
	// but only if NextNonce is enabled via config.
	if !h.config.EnableNextNonce || seq < rekeyThreshold || h.rekeyInFlight.Load() {
		return seq
	}

	if h.rekeyInFlight.CompareAndSwap(false, true) {
		go h.initiateRekey()
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
	// Always re-arm rekeyInFlight when this attempt finishes, whether it
	// succeeds or fails, so a transient failure doesn't permanently disable
	// all future rekeys for the life of the connection, and a success
	// correctly re-arms the mechanism for a later rekey in a long-lived
	// connection.
	defer h.rekeyInFlight.Store(false)

	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.sendCipher == nil {
		return
	}

	flog("initiateRekey").Warn("initiating NextNonce rekey (unfinalized spec area — interoperability not guaranteed)")

	// Derive new send cipher key: newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
	// The ssu2.rst "NextNonce" section is "TODO" with contents "TBD", so this
	// derivation follows the i2pd reference implementation, not the spec text.
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

	// Meet the 8-byte minimum payload rule (ssu2.rst Messages). This path
	// encrypts inline instead of going through encryptDataPayload.
	payload, err = PadPayloadToMin(payload)
	if err != nil {
		return oops.Wrapf(err, "pad NextNonce payload")
	}

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
	// SSU2 has no length-obfuscation field; see applyDataHeaderMoreFlags.
	binary.BigEndian.PutUint16(packet.Header[14:16], 0)

	h.remoteAddrLock.RLock()
	packet.IsIPv4 = IsIPv4Addr(h.remoteAddr)
	h.remoteAddrLock.RUnlock()

	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "serialize NextNonce packet")
	}

	if err := h.applyOutboundHeaderProtection(data, packet.MessageType); err != nil {
		return oops.Wrapf(err, "encrypt NextNonce header")
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
