package handshake

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SessionConfirmed fragmentation constants per SSU2 spec.
const (
	// sessionConfirmedMinMTU is the IPv6 minimum MTU used for conservative sizing.
	sessionConfirmedMinMTU = 1280

	// sessionConfirmedPerPacketOverhead = IP(40) + UDP(8) + SSU2 header(16).
	sessionConfirmedPerPacketOverhead = 64

	// sessionConfirmedMaxPerPacket is the maximum ciphertext bytes per fragment.
	sessionConfirmedMaxPerPacket = sessionConfirmedMinMTU - sessionConfirmedPerPacketOverhead

	// sessionConfirmedMaxFragments is the maximum fragment count (4-bit field).
	sessionConfirmedMaxFragments = 15
)

// CreateSessionConfirmed creates a SessionConfirmed message (XK pattern message 3).
// This is the third handshake message sent by the initiator.
//
// SessionConfirmed uses a short header (16 bytes) and contains no ephemeral key.
// It contains the initiator's RouterInfo block so the responder can learn the
// initiator's identity. routerInfo may be nil for testing.
// This message completes the XK handshake (→ s, se) and produces transport cipher states.
func (h *HandshakeHandler) CreateSessionConfirmed(connID uint64, packetNumber uint32, routerInfo []byte) (*SSU2Packet, error) {
	flog("CreateSessionConfirmed", logger.Fields{"connID": connID, "packetNumber": packetNumber}).Debug("Creating SessionConfirmed")
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return nil, oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// SessionConfirmed must contain initiator's RouterInfo per SSU2 spec
	var blocks []*SSU2Block
	if len(routerInfo) > 0 {
		blocks = append(blocks, NewSSU2Block(BlockTypeRouterInfo, routerInfo))
	}

	// Serialize blocks (may be empty)
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}

	// Build the 16-byte short header before encrypting so it can be
	// mixed into the handshake hash per SSU2 spec §KDF.
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[0:8], connID)
	binary.BigEndian.PutUint32(header[8:12], packetNumber)
	header[12] = MessageTypeSessionConfirmed
	// frag field: bits 7-4 = fragment number (0), bits 3-0 = total fragments (1)
	header[13] = 0x01

	// Check that the encrypted payload fits in a single packet.
	// Total data size = static key (32) + payload + 2 MACs (32) = payload + 64.
	// Available space per packet = MTU - IP header (40 IPv6 worst case) - UDP (8) - SSU2 header (16) = MTU - 64.
	// Use conservative default MTU of 1280 (IPv6 minimum).
	totalDataSize := len(payload) + 64 // static key + two MACs
	if totalDataSize > sessionConfirmedMaxPerPacket {
		return nil, oops.Errorf("SessionConfirmed payload too large for single packet (%d bytes, max %d); use CreateSessionConfirmedFragments instead", totalDataSize, sessionConfirmedMaxPerPacket)
	}

	// MixHash(header) binds the header into the handshake hash.
	h.handshakeState.MixHash(header)

	// Write 3rd XK handshake message through Noise state machine (→ s, se).
	// This completes the handshake and returns transport cipher states.
	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionConfirmed handshake message")
	}

	// Store cipher states (handshake now complete)
	h.updateCipherStates(cs1, cs2)

	// Separate MAC (last 16 bytes) from payload
	var pktPayload, mac []byte
	if len(ciphertext) >= 16 {
		pktPayload = ciphertext[:len(ciphertext)-16]
		mac = ciphertext[len(ciphertext)-16:]
	} else {
		pktPayload = ciphertext
		mac = make([]byte, 16)
	}

	// Create packet with 16-byte short header
	packet := &SSU2Packet{
		Header:       make([]byte, 16),
		EphemeralKey: nil, // No ephemeral key in SessionConfirmed
		Payload:      pktPayload,
		MAC:          mac,
		MessageType:  MessageTypeSessionConfirmed,
		PacketNumber: packetNumber,
	}

	// Header already built above for MixHash; assign it to packet.
	packet.Header = header

	return packet, nil
}

// ProcessSessionConfirmed processes a received SessionConfirmed message.
// This is called by the responder to complete the XK handshake (→ s, se).
//
// After this, both sides have completed the handshake and can send Data messages.
func (h *HandshakeHandler) ProcessSessionConfirmed(packet *SSU2Packet) error {
	flog("ProcessSessionConfirmed").Debug("Processing received SessionConfirmed")
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}

	if packet.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed (type 2), got type %d", packet.MessageType)
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// MixHash(header) per SSU2 spec §KDF — binds the short header into
	// the handshake hash before processing the Noise message.
	//
	// Check frag field (byte 13): bits 7-4 = fragment number, bits 3-0 = total fragments.
	// For fragmented messages, use ProcessSessionConfirmedFragments instead.
	if len(packet.Header) >= 14 {
		fragByte := packet.Header[13]
		totalFrags := fragByte & 0x0F
		fragNum := (fragByte >> 4) & 0x0F
		if totalFrags > 1 || fragNum > 0 {
			return oops.Errorf("fragmented SessionConfirmed: use ProcessSessionConfirmedFragments (fragment %d of %d)", fragNum, totalFrags)
		}
	}

	h.handshakeState.MixHash(packet.Header)

	// Reconstruct Noise handshake message from payload + MAC
	noiseMessage := append(copyBytes(packet.Payload), packet.MAC...)

	return h.finalizeSessionConfirmed(noiseMessage)
}

// finalizeSessionConfirmed reads the handshake message, updates cipher states,
// captures the peer's static key, and extracts the RouterInfo payload.
func (h *HandshakeHandler) finalizeSessionConfirmed(noiseMessage []byte) error {
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionConfirmed handshake message")
	}

	h.updateCipherStates(cs1, cs2)

	if ps := h.handshakeState.PeerStatic(); len(ps) > 0 {
		h.remoteStaticKey = copyBytes(ps)
	}

	if err := h.extractPeerRouterInfo(payload); err != nil {
		return err
	}
	if err := h.verifyPeerRouterInfoStaticKey(); err != nil {
		return err
	}
	return nil
}

// CreateSessionConfirmedFragments creates one or more SessionConfirmed packets.
// When the payload fits in a single packet, it returns a slice of length 1
// (identical to CreateSessionConfirmed). When the Noise ciphertext exceeds
// the per-packet limit, it splits the ciphertext across multiple fragments
// using the frag field at header byte 13 (bits 7-4 = fragment number,
// bits 3-0 = total fragments) per SSU2 spec §Session Confirmed.
//
// Only the first fragment's header is MixHash'd into the handshake. Subsequent
// fragment headers carry the same connection ID with incrementing packet numbers.
func (h *HandshakeHandler) CreateSessionConfirmedFragments(connID uint64, packetNumber uint32, routerInfo []byte) ([]*SSU2Packet, error) {
	flog("CreateSessionConfirmedFragments", logger.Fields{"connID": connID, "packetNumber": packetNumber}).Debug("Creating SessionConfirmed with fragmentation")
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}
	if h.handshakeState.MessageIndex() != 2 {
		return nil, oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	payload, err := h.serializeConfirmedPayload(routerInfo)
	if err != nil {
		return nil, err
	}

	totalFrags, err := computeFragmentCount(len(payload) + 64)
	if err != nil {
		return nil, err
	}

	header := buildSessionConfirmedHeader(connID, packetNumber, 0, totalFrags)
	h.handshakeState.MixHash(header)

	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionConfirmed handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	packets := buildFragmentPackets(ciphertext, connID, packetNumber, totalFrags)
	packets[0].Header = header

	return packets, nil
}

// serializeConfirmedPayload serializes the RouterInfo block for SessionConfirmed.
func (h *HandshakeHandler) serializeConfirmedPayload(routerInfo []byte) ([]byte, error) {
	flog("serializeConfirmedPayload", logger.Fields{"routerInfoLen": len(routerInfo)}).Debug("Serializing RouterInfo block")
	var blocks []*SSU2Block
	if len(routerInfo) > 0 {
		blocks = append(blocks, NewSSU2Block(BlockTypeRouterInfo, routerInfo))
	}
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}
	return payload, nil
}

// computeFragmentCount returns the number of fragments needed for the given ciphertext size.
func computeFragmentCount(ciphertextSize int) (int, error) {
	flog("computeFragmentCount", logger.Fields{"ciphertextSize": ciphertextSize}).Debug("Calculating fragment count")
	totalFrags := (ciphertextSize + sessionConfirmedMaxPerPacket - 1) / sessionConfirmedMaxPerPacket
	if totalFrags < 1 {
		totalFrags = 1
	}
	if totalFrags > sessionConfirmedMaxFragments {
		return 0, oops.Errorf("SessionConfirmed requires %d fragments, max %d", totalFrags, sessionConfirmedMaxFragments)
	}
	return totalFrags, nil
}

// buildSessionConfirmedHeader builds a 16-byte SessionConfirmed short header.
func buildSessionConfirmedHeader(connID uint64, packetNumber uint32, fragNum, totalFrags int) []byte {
	flog("buildSessionConfirmedHeader", logger.Fields{"connID": connID, "fragNum": fragNum, "totalFrags": totalFrags}).Debug("Building short header")
	header := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], connID)
	binary.BigEndian.PutUint32(header[8:12], packetNumber)
	header[12] = MessageTypeSessionConfirmed
	header[13] = byte(fragNum<<4) | byte(totalFrags)
	return header
}

// buildFragmentPackets splits ciphertext into fragment packets.
func buildFragmentPackets(ciphertext []byte, connID uint64, packetNumber uint32, totalFrags int) []*SSU2Packet {
	flog("buildFragmentPackets", logger.Fields{"ciphertextLen": len(ciphertext), "totalFrags": totalFrags}).Debug("Splitting ciphertext into fragments")
	packets := make([]*SSU2Packet, 0, totalFrags)
	offset := 0
	for i := 0; i < totalFrags; i++ {
		end := offset + sessionConfirmedMaxPerPacket
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk := ciphertext[offset:end]
		fragHeader := buildSessionConfirmedHeader(connID, packetNumber, i, totalFrags)

		var pktPayload, mac []byte
		if i == totalFrags-1 && len(chunk) >= MACSize {
			pktPayload = chunk[:len(chunk)-MACSize]
			mac = chunk[len(chunk)-MACSize:]
		} else {
			pktPayload = chunk
			mac = make([]byte, MACSize)
		}

		packets = append(packets, &SSU2Packet{
			Header:       fragHeader,
			EphemeralKey: nil,
			Payload:      pktPayload,
			MAC:          mac,
			MessageType:  MessageTypeSessionConfirmed,
			PacketNumber: packetNumber,
		})
		offset = end
	}
	return packets
}

// ProcessSessionConfirmedFragments reassembles and processes a fragmented
// SessionConfirmed message. The packets slice must contain all fragments
// ordered by fragment number (0 .. totalFrags-1).
//
// For a single-fragment message, this behaves identically to ProcessSessionConfirmed.
func (h *HandshakeHandler) ProcessSessionConfirmedFragments(packets []*SSU2Packet) error {
	flog("ProcessSessionConfirmedFragments", logger.Fields{"fragmentCount": len(packets)}).Debug("Processing SessionConfirmed fragments")
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}
	if len(packets) == 0 {
		return oops.Errorf("no SessionConfirmed fragments provided")
	}
	if h.handshakeState.MessageIndex() != 2 {
		return oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	if err := h.validateFragmentOrdering(packets); err != nil {
		return err
	}

	// MixHash(header) — only the first fragment's header is mixed.
	h.handshakeState.MixHash(packets[0].Header)

	noiseMessage := reassembleFragments(packets)

	return h.finalizeSessionConfirmed(noiseMessage)
}

// validateFragmentOrdering checks that the fragment ordering and completeness
// is correct for a set of SessionConfirmed packets.
func (h *HandshakeHandler) validateFragmentOrdering(packets []*SSU2Packet) error {
	flog("validateFragmentOrdering", logger.Fields{"packetCount": len(packets)}).Debug("Checking fragment ordering")
	totalFrags := int(packets[0].Header[13] & 0x0F)
	if totalFrags < 1 {
		totalFrags = 1
	}
	if len(packets) != totalFrags {
		return oops.Errorf("expected %d fragments, got %d", totalFrags, len(packets))
	}
	for i, pkt := range packets {
		if pkt.MessageType != MessageTypeSessionConfirmed {
			return oops.Errorf("fragment %d: expected SessionConfirmed (type 2), got type %d", i, pkt.MessageType)
		}
		fragNum := int((pkt.Header[13] >> 4) & 0x0F)
		if fragNum != i {
			return oops.Errorf("fragment %d: unexpected fragment number %d", i, fragNum)
		}
	}
	return nil
}

// reassembleFragments concatenates payload data from ordered fragments into a
// single Noise ciphertext. The last fragment's MAC is appended.
func reassembleFragments(packets []*SSU2Packet) []byte {
	flog("reassembleFragments", logger.Fields{"fragmentCount": len(packets)}).Debug("Concatenating fragment payloads")
	totalSize := 0
	for _, pkt := range packets {
		totalSize += len(pkt.Payload)
	}
	totalSize += len(packets[len(packets)-1].MAC)

	noiseMessage := make([]byte, 0, totalSize)
	for i, pkt := range packets {
		noiseMessage = append(noiseMessage, pkt.Payload...)
		if i == len(packets)-1 {
			noiseMessage = append(noiseMessage, pkt.MAC...)
		}
	}
	return noiseMessage
}
