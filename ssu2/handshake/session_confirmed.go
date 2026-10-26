package handshake

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SessionConfirmed fragmentation constants per SSU2 spec.
const (
	// sessionConfirmedMinMTU is the IPv6 minimum MTU, used when the session has
	// not told us its MTU. ssu2.md §"MTU": "The minimum SSU2 MTU is 1280".
	sessionConfirmedMinMTU = 1280

	// Per-packet overhead, from ssu2.md §"Session Confirmed Fragmentation":
	// "Calculate the space available in each packet, which is the MTU minus the
	// IP header (20 or 40), minus the UDP header (8), minus the SSU2 short
	// header (16). Total per-packet overhead is 44 (IPv4) or 64 (IPv6)."
	sessionConfirmedOverheadIPv4 = 44
	sessionConfirmedOverheadIPv6 = 64

	// sessionConfirmedJumboOverhead is the part of the jumbo payload that is not
	// the encrypted payload: "Calculate the total data size (not including the
	// header), which is the payload size + 64 bytes for the static key and two
	// MACs."
	sessionConfirmedJumboOverhead = 64

	// sessionConfirmedMaxFragments is the maximum fragment count: §"Header"
	// short header "bits 3-0: total fragments 1-15".
	sessionConfirmedMaxFragments = 15
)

// SetFragmentMTU configures the MTU and address family the Session Confirmed
// fragments are sized for. The caller (the session) passes the effective MTU —
// the smaller of its own configured MTU and the MTU the peer published — and
// whether the peer address is IPv4.
//
// Without this, fragmentation is always sized for the most conservative case
// (1280-byte IPv6), which sends more fragments than a compliant peer expects
// when the path allows a larger MTU. Zero/unset keeps the 1280 minimum.
func (h *HandshakeHandler) SetFragmentMTU(mtu int, ipv4 bool) {
	if mtu < sessionConfirmedMinMTU {
		mtu = sessionConfirmedMinMTU
	}
	h.fragMTU = mtu
	h.fragIPv4 = ipv4
}

// fragmentCapacity returns the maximum number of jumbo-payload bytes that fit
// in one Session Confirmed packet for this session's MTU and address family.
// ssu2.md §"Session Confirmed Fragmentation": per-packet overhead is 44 (IPv4)
// or 64 (IPv6).
func (h *HandshakeHandler) fragmentCapacity() int {
	mtu := h.fragMTU
	if mtu < sessionConfirmedMinMTU {
		mtu = sessionConfirmedMinMTU
	}
	overhead := sessionConfirmedOverheadIPv6
	if h.fragIPv4 {
		overhead = sessionConfirmedOverheadIPv4
	}
	return mtu - overhead
}

// CreateSessionConfirmed creates a SessionConfirmed message (XK pattern
// message 3). This is the third handshake message, sent by the initiator.
//
// SessionConfirmed uses a short header (16 bytes) and contains no ephemeral
// key. It carries the initiator's RouterInfo block so the responder can learn
// the initiator's identity. routerInfo may be nil for testing.
//
// This message completes the XK handshake (→ s, se) and produces the
// transport cipher states.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
func (h *HandshakeHandler) CreateSessionConfirmed(connID uint64, packetNumber uint32, routerInfo []byte) (*SSU2Packet, error) {
	flog("CreateSessionConfirmed", logger.Fields{"connID": connID, "packetNumber": packetNumber}).Debug("Creating SessionConfirmed")
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return nil, oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// SessionConfirmed must carry the initiator's full signed RouterInfo; see
	// serializeConfirmedPayload for the spec basis.
	payload, err := h.serializeConfirmedPayload(routerInfo)
	if err != nil {
		return nil, err
	}

	// Build the 16-byte short header before encrypting so it can be
	// mixed into the handshake hash per ssu2.rst "KDF for Session Confirmed part 2".
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[0:8], connID)
	binary.BigEndian.PutUint32(header[8:12], packetNumber)
	header[12] = MessageTypeSessionConfirmed
	// frag field: bits 7-4 = fragment number (0), bits 3-0 = total fragments (1)
	header[13] = 0x01

	// Check that the encrypted payload fits in a single packet.
	// Total data size = static key (32) + payload + 2 MACs (32) = payload + 64,
	// per ssu2.md §"Session Confirmed Fragmentation". The capacity is the
	// session's MTU minus its per-packet overhead (44 IPv4 / 64 IPv6).
	maxPerPacket := h.fragmentCapacity()
	totalDataSize := len(payload) + sessionConfirmedJumboOverhead
	if totalDataSize > maxPerPacket {
		return nil, oops.Errorf("SessionConfirmed payload too large for single packet (%d bytes, max %d); use CreateSessionConfirmedFragments instead", totalDataSize, maxPerPacket)
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
// After this, both sides have completed the handshake and can send Data
// messages.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
func (h *HandshakeHandler) ProcessSessionConfirmed(packet *SSU2Packet) error {
	flog("ProcessSessionConfirmed").Debug("Processing received SessionConfirmed")
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}
	if packet == nil {
		return oops.Errorf("SessionConfirmed packet is nil")
	}

	if packet.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed (type 2), got type %d", packet.MessageType)
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// MixHash(header) per ssu2.rst "KDF for Session Confirmed part 2" — binds the short header into
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

	// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload": "The minimum payload size is 8
	// bytes. Since the RouterInfo block will be well more than that, the
	// requirement is met with only that block."
	if err := validatePayloadFloor(payload, MessageTypeSessionConfirmed); err != nil {
		return err
	}

	h.updateCipherStates(cs1, cs2)

	if ps := h.handshakeState.PeerStatic(); len(ps) > 0 {
		h.remoteStaticKey = copyBytes(ps)
	}

	// Validate the block set before consuming any of it.
	//
	// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload" enumerates exactly what
	// the frame may carry and fixes the first block: "RouterInfo block (must be
	// the first block) / Options block (optional) / New Token block (optional) /
	// Relay Request block (optional) / Peer Test block (optional) / First Packet
	// Number block (optional) / I2NP, First Fragment, or Follow-on Fragment
	// blocks (optional, but probably no room) / Padding block (optional)". The
	// §Notes list adds the sender-side rule for the equivalent NTCP2 frame,
	// "This frame must never contain any other block type."
	//
	// Without this check a peer could smuggle a Termination, Address, ACK or
	// Relay Tag block into the handshake, which the data-phase handler would act
	// on once the session opened.
	if err := validateSessionConfirmedBlocks(payload); err != nil {
		return err
	}

	if err := h.extractPeerRouterInfo(payload); err != nil {
		return err
	}
	if err := h.verifyPeerRouterInfoStaticKey(); err != nil {
		return err
	}
	return nil
}

// CreateSessionConfirmedFragments creates one or more SessionConfirmed
// packets. When the payload fits in a single packet, it returns a slice of
// length 1 (identical to CreateSessionConfirmed). When the Noise ciphertext
// exceeds the per-packet limit, it splits the ciphertext across multiple
// fragments using the frag field at header byte 13 (bits 7-4 = fragment
// number, bits 3-0 = total fragments) per SSU2 spec §Session Confirmed.
//
// Only the first fragment's header is MixHash'd into the handshake.
// Subsequent fragment headers carry the same connection ID with incrementing
// packet numbers.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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

	totalFrags, err := computeFragmentCount(len(payload)+sessionConfirmedJumboOverhead, h.fragmentCapacity())
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

	packets := buildFragmentPackets(ciphertext, connID, packetNumber, totalFrags, h.fragmentCapacity())
	packets[0].Header = header

	return packets, nil
}

// serializeConfirmedPayload serializes the RouterInfo block for SessionConfirmed.
// serializeConfirmedPayload builds the Session Confirmed payload: the mandatory
// RouterInfo block, followed by the Options block the spec asks for.
//
// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload": "RouterInfo block (must be
// the first block) / Options block (optional) / …", and §"Notes": "Options
// should be included, to specify padding parameters." §"Session Confirmed
// Fragmentation" adds: "The Session Confirmed message must contain the full
// signed Router Info from Alice so that Bob may perform several required checks"
// — the static key "s", the introduction key "i", and the RI signature.
// Reference: Java InboundEstablishState2.java:977 throws "No RI in Session
// Confirmed".
//
// A missing RouterInfo fails closed rather than emitting a message that no
// conformant responder can validate: a bare RouterHash carries neither an "s"
// nor an "i" parameter.
func (h *HandshakeHandler) serializeConfirmedPayload(routerInfo []byte) ([]byte, error) {
	flog("serializeConfirmedPayload", logger.Fields{"routerInfoLen": len(routerInfo)}).Debug("Serializing SessionConfirmed payload")
	if len(routerInfo) == 0 {
		return nil, oops.
			Code("MISSING_LOCAL_ROUTER_INFO").
			In("ssu2").
			Errorf("Session Confirmed must carry the full signed local RouterInfo (ssu2.md Session Confirmed Fragmentation); set SSU2Config.LocalRouterInfo via WithLocalRouterInfo")
	}

	// The block requires the mandatory flag+frag prefix (see
	// EncodeRouterInfoBlock); flood is not requested and the RI is sent
	// uncompressed, matching the NTCP2 handshake RI handling.
	riBlock, err := EncodeRouterInfoBlock(routerInfo, false, false)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encode RouterInfo block")
	}
	blocks := []*SSU2Block{riBlock}

	// Options block: the same negotiated padding parameters this handler sends in
	// Session Created, so the responder can apply them at the start of the data
	// phase (ssu2.md §"Session Confirmed" -> §"Notes").
	blocks = append(blocks, h.optionsBlockOrEmpty())

	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}
	// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload": "The minimum payload
	// size is 8 bytes." The RI block clears the floor on its own; the pad is a
	// no-op for every realistic RouterInfo.
	payload, err = PadPayloadToMin(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to pad SessionConfirmed payload")
	}
	return payload, nil
}

// minFragmentTail is the smallest legal amount of data in the LAST fragment of a
// fragmented Session Confirmed.
//
// ssu2.md §"Session Confirmed Fragmentation": "Calculate the size of the data in
// the last packet. It must be greater than or equal to 24 bytes, so that header
// encryption will work. If it is too small, either add a padding block, OR
// increase the size of the padding block if already present, OR reduce the size
// of one of the other packets so that the last packet will be big enough."
//
// 24 is the header-protection IV: §"KDF for Session Confirmed" takes the IV from
// "the last 24 bytes of the packet", and every packet ends with the 16-byte
// AEAD tag, so the tail fragment needs 24 bytes total (8 payload + 16 tag) to
// carry that sample.
const minFragmentTail = 24

// computeFragmentCount returns the number of fragments needed for the given
// jumbo size at the given per-packet capacity.
func computeFragmentCount(ciphertextSize, maxPerPacket int) (int, error) {
	flog("computeFragmentCount", logger.Fields{"ciphertextSize": ciphertextSize}).Debug("Calculating fragment count")
	totalFrags := (ciphertextSize + maxPerPacket - 1) / maxPerPacket
	if totalFrags < 1 {
		totalFrags = 1
	}
	if totalFrags > sessionConfirmedMaxFragments {
		return 0, oops.Errorf("SessionConfirmed requires %d fragments, max %d", totalFrags, sessionConfirmedMaxFragments)
	}
	return totalFrags, nil
}

// fragmentSizes returns the per-fragment byte sizes for a ciphertext of the given
// length, honouring both the per-packet capacity and the spec's 24-byte minimum
// tail.
//
// A naive split leaves the last fragment with ciphertextSize mod maxPerPacket
// bytes, which for remainders of 1..23 produces a fragment that a conformant
// receiver cannot header-decrypt (and that this package's own validate() rejects
// as below MinPacketSize, aborting the whole Session Confirmed send). The spec's
// third remedy — "reduce the size of one of the other packets so that the last
// packet will be big enough" — is applied here: the tail is topped up to 24
// bytes by shortening the preceding fragment.
func fragmentSizes(ciphertextSize, maxPerPacket int) []int {
	totalFrags, err := computeFragmentCount(ciphertextSize, maxPerPacket)
	if err != nil || totalFrags <= 1 {
		return []int{ciphertextSize}
	}

	// Greedy fill: every fragment takes as much as the capacity allows.
	sizes := make([]int, totalFrags)
	remaining := ciphertextSize
	for i := range sizes {
		n := remaining
		if n > maxPerPacket {
			n = maxPerPacket
		}
		sizes[i] = n
		remaining -= n
	}

	// Rebalance the tail if greedy left it under the floor.
	if tail := sizes[totalFrags-1]; tail < minFragmentTail {
		need := minFragmentTail - tail
		sizes[totalFrags-2] -= need
		sizes[totalFrags-1] += need
	}
	return sizes
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
func buildFragmentPackets(ciphertext []byte, connID uint64, packetNumber uint32, totalFrags, maxPerPacket int) []*SSU2Packet {
	flog("buildFragmentPackets", logger.Fields{"ciphertextLen": len(ciphertext), "totalFrags": totalFrags}).Debug("Splitting ciphertext into fragments")
	// Sizes come from fragmentSizes, which shortens the second-to-last fragment
	// when needed so the final fragment keeps the spec's 24-byte minimum. The
	// per-fragment byte count is the ciphertext slice it carries, MAC included:
	// only the last fragment's MAC is real ciphertext, and the synthetic MAC
	// field of the earlier fragments is metadata that never enters the jumbo
	// message (reassembleFragments concatenates payload fields plus the final
	// MAC only).
	sizes := fragmentSizes(len(ciphertext), maxPerPacket)
	if len(sizes) != totalFrags {
		totalFrags = len(sizes)
	}
	packets := make([]*SSU2Packet, 0, totalFrags)
	offset := 0
	for i := 0; i < totalFrags; i++ {
		end := offset + sizes[i]
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
// For a single-fragment message, this behaves identically to
// ProcessSessionConfirmed.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
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
//
// Every packets[i].Header is bounds-checked (>= 14 bytes) before indexing
// Header[13], so this function is safe to call in isolation.
func (h *HandshakeHandler) validateFragmentOrdering(packets []*SSU2Packet) error {
	flog("validateFragmentOrdering", logger.Fields{"packetCount": len(packets)}).Debug("Checking fragment ordering")
	if len(packets) == 0 {
		return oops.Errorf("no fragments to validate")
	}
	for i, pkt := range packets {
		if pkt == nil {
			return oops.Errorf("fragment %d is nil", i)
		}
	}
	if len(packets[0].Header) < 14 {
		return oops.Errorf("fragment 0: header too short (%d bytes, need at least 14)", len(packets[0].Header))
	}
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
		if len(pkt.Header) < 14 {
			return oops.Errorf("fragment %d: header too short (%d bytes, need at least 14)", i, len(pkt.Header))
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

// validateSessionConfirmedBlocks enforces the Session Confirmed payload block
// set and ordering.
//
// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload":
//
//	RouterInfo block (must be the first block)
//	Options block (optional)
//	New Token block (optional)
//	Relay Request block (optional)
//	Peer Test block (optional)
//	First Packet Number block (optional)
//	I2NP, First Fragment, or Follow-on Fragment blocks (optional, but probably no room)
//	Padding block (optional)
//
// Any other block type is illegal in this frame ("This frame must never contain
// any other block type"), and the data-phase ordering rules apply on top:
// Padding must be last, and Termination — which is not in the list at all — must
// never appear (Java throws "Termination block in Session Confirmed",
// InboundEstablishState2.java:972).
func validateSessionConfirmedBlocks(payload []byte) error {
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return oops.Wrapf(err, "SessionConfirmed payload is not a valid block sequence")
	}
	if len(blocks) == 0 {
		return oops.Errorf("SessionConfirmed payload contains no blocks; RouterInfo is required and must be first")
	}

	if blocks[0].Type != BlockTypeRouterInfo {
		return oops.
			Code("SESSION_CONFIRMED_FIRST_BLOCK").
			In("ssu2").
			With("first_block_type", blocks[0].Type).
			Errorf("SessionConfirmed first block is type %d, but the RouterInfo block (type %d) must be first (ssu2.md §\"SessionConfirmed\" -> §\"Payload\")",
				blocks[0].Type, BlockTypeRouterInfo)
	}

	for i, block := range blocks {
		if !isSessionConfirmedBlockType(block.Type) {
			return oops.
				Code("SESSION_CONFIRMED_ILLEGAL_BLOCK").
				In("ssu2").
				With("block_type", block.Type).
				With("index", i).
				Errorf("SessionConfirmed contains block type %d, which is not one of the payload types the spec allows (ssu2.md §\"SessionConfirmed\" -> §\"Payload\")",
					block.Type)
		}
		if block.Type == BlockTypePadding && i != len(blocks)-1 {
			return oops.
				Code("SESSION_CONFIRMED_PADDING_NOT_LAST").
				In("ssu2").
				Errorf("SessionConfirmed Padding block at index %d of %d must be the last block", i, len(blocks))
		}
	}
	return nil
}

// isSessionConfirmedBlockType reports whether t is one of the eight block types
// ssu2.md §"SessionConfirmed (Type 2)" -> §"Payload" permits.
func isSessionConfirmedBlockType(t uint8) bool {
	switch t {
	case BlockTypeRouterInfo,
		BlockTypeOptions,
		BlockTypeNewToken,
		BlockTypeRelayRequest,
		BlockTypePeerTest,
		BlockTypeFirstPacketNumber,
		BlockTypeI2NPMessage,
		BlockTypeFirstFragment,
		BlockTypeFollowOnFragment,
		BlockTypePadding:
		return true
	default:
		return false
	}
}
