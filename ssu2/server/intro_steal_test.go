package server

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-noise/ssu2/session"
	"github.com/go-i2p/go-noise/ssu2/wire"
)

// A Session Confirmed is protected with k_header_1 = OUR OWN introduction key and
// k_header_2 = a per-session KDF key (ssu2.md §"Header Protection" -> §"Header
// keys"; ssu2/wire/header_keys.go keysForKDFProtected). The listener's intro-key
// protector therefore holds the right key for bytes 0-7 and the wrong key for
// bytes 8-15, so its decode recovers the destination connection ID perfectly and
// turns the type, version, net ID and flag bytes into uniform noise.
//
// Noise that happens to look like a long header used to be enough to claim the
// datagram: isIntroKeyMessageType only excluded types 2 and 6, so 254 of 256
// possible type bytes passed, and Deserialize's version check cost another 1/256.
// Measured over 20000 fresh random payloads the false-claim rate was 73, or
// 0.365% per Session Confirmed datagram. Once claimed, the packet was classified
// as a long header, its ciphertext byte 14 was read as a network ID, and the
// datagram was dropped as cross-network traffic — which is what the field logs
// showed as "dropping packet from a different I2P network got_netid=223
// our_netid=2". Handshake retransmits are byte-identical, so a single false claim
// killed the whole handshake rather than costing one datagram.
//
// isIntroKeyHeader now validates the whole fixed-field set of a genuine long
// header instead of just the type, which drops the rate to about one datagram in
// 1.4e7. These tests pin both halves of that: the discriminator itself, and the
// end-to-end routing of a real Session Confirmed the intro stage can no longer
// steal.

// introStageSees replays stage 1 of parseInboundPacket in isolation: decode the
// datagram with the listener's intro-key protector and deserialize it, exactly as
// the intro stage does, so a test can inspect what that stage makes of it.
func introStageSees(t *testing.T, l *SSU2Listener, datagram []byte) (*SSU2Packet, bool) {
	t.Helper()

	hp := l.introHeaderProtector.Load()
	require.NotNil(t, hp)

	decrypted := make([]byte, len(datagram))
	copy(decrypted, datagram)
	if err := hp.DecryptHeaderForPacket(decrypted); err != nil {
		return nil, false
	}
	packet := &SSU2Packet{}
	if err := packet.Deserialize(decrypted); err != nil {
		return nil, false
	}
	return packet, true
}

// sessionConfirmedDatagram builds a real Session Confirmed for destConnID,
// header-protected the way an initiator protects it for us: k_header_1 is our
// introduction key, k_header_2 is the session's sessionConfirmedHeader2, which
// only the peer and the owning session hold.
func sessionConfirmedDatagram(t *testing.T, introKey, headerKey2 []byte, destConnID uint64) []byte {
	t.Helper()

	pkt := make([]byte, wire.ShortHeaderSize+200)
	binary.BigEndian.PutUint64(pkt[0:8], destConnID)
	binary.BigEndian.PutUint32(pkt[8:12], 7) // packet number
	pkt[12] = MessageTypeSessionConfirmed
	pkt[13] = 0x01 // frag 0 of 1
	// The masks are drawn from the datagram's last 24 bytes, so the body has to be
	// fresh randomness on every call: a fixed body would make every "different"
	// datagram produce the identical mask, and a loop over it would sample one
	// value repeatedly instead of measuring anything.
	_, err := rand.Read(pkt[wire.ShortHeaderSize:])
	require.NoError(t, err)

	hp, err := wire.NewHeaderProtector(introKey, headerKey2, wire.HeaderTypeSessionConfirmed)
	require.NoError(t, err)
	require.NoError(t, hp.EncryptHeader(pkt))

	return pkt
}

// TestIsIntroKeyHeaderRejectsMaskedNoise is the deterministic half: it pins the
// closed set of accepted types and the three fixed fields, so no future widening
// of the predicate can silently reopen the hole.
func TestIsIntroKeyHeaderRejectsMaskedNoise(t *testing.T) {
	long := func(typ, ver, netid, flag byte) *SSU2Packet {
		h := make([]byte, LongHeaderSize)
		h[12] = typ
		h[13] = ver
		h[14] = netid
		h[15] = flag
		return &SSU2Packet{Header: h, MessageType: typ, NetworkID: netid}
	}
	// A well-formed header of the given type: the type alone decides acceptance.
	genuine := func(typ byte) *SSU2Packet {
		return long(typ, SSU2ProtocolVersion, MainNetworkID, 0)
	}

	for _, typ := range []uint8{
		MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypePeerTest,
		MessageTypeRetry, MessageTypeTokenRequest, MessageTypeHolePunch,
	} {
		require.True(t, isIntroKeyHeader(genuine(typ)), "type %d is in the intro-key family", typ)
	}

	// The two short-header types, and every type the spec does not define: a
	// masked byte 12 lands in all of these, and none may be claimed.
	for _, typ := range []uint8{
		MessageTypeSessionConfirmed, MessageTypeData, 3, 4, 5, 8, 12, 13, 200, 255,
	} {
		require.False(t, isIntroKeyHeader(genuine(typ)), "type %d is not in the intro-key family", typ)
	}

	require.False(t, isIntroKeyHeader(long(MessageTypeSessionRequest, SSU2ProtocolVersion+1, MainNetworkID, 0)),
		"wrong protocol version")
	require.False(t, isIntroKeyHeader(long(MessageTypeSessionRequest, SSU2ProtocolVersion, 0, 0)),
		"netid 0 is not a network any deployment uses")
	require.False(t, isIntroKeyHeader(long(MessageTypeSessionRequest, SSU2ProtocolVersion, MainNetworkID, 1)),
		"the unused flag byte must be 0")

	// A short header never carries the version, netid or flag fields, so it can
	// never satisfy the long-header shape.
	require.False(t, isIntroKeyHeader(&SSU2Packet{
		Header:      make([]byte, ShortHeaderSize),
		MessageType: MessageTypeSessionRequest,
	}))
	require.False(t, isIntroKeyHeader(&SSU2Packet{MessageType: MessageTypeSessionRequest}),
		"packet with no header at all")
}

// TestParseInboundPacket_SessionConfirmedNeverStolenByIntroStage is the
// end-to-end half, and the regression test for the handshake-killing drop.
//
// It does not rely on getting unlucky: it searches fresh random Session Confirmed
// datagrams until it finds one whose intro-stage decode yields a header the old
// type-only predicate would have accepted and the new one rejects, then proves the
// datagram is delivered to its session as a Session Confirmed instead. Run against
// the previous predicate, the final assertion fails.
func TestParseInboundPacket_SessionConfirmedNeverStolenByIntroStage(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0x5151515151515151)

	headerKey2 := randomKey(t)
	scProtector, err := wire.NewHeaderProtector(introKey, headerKey2, wire.HeaderTypeSessionConfirmed)
	require.NoError(t, err)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), false)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))
	require.NoError(t, l.acceptedSessions.SetSessionConfirmedProtector(connID, scProtector))

	var stolen *SSU2Packet
	var stolenDatagram []byte
	const attempts = 20000
	for i := 0; i < attempts; i++ {
		datagram := sessionConfirmedDatagram(t, introKey, headerKey2, connID)
		packet, ok := introStageSees(t, l, datagram)
		if !ok {
			continue
		}
		// Look for a decode the OLD predicate would have accepted and the new one
		// rejects: that is exactly the datagram that used to be stolen.
		oldPredicate := packet.MessageType != MessageTypeSessionConfirmed &&
			packet.MessageType != MessageTypeData
		if oldPredicate && !isIntroKeyHeader(packet) {
			stolen, stolenDatagram = packet, datagram
			break
		}
	}
	require.NotNil(t, stolen,
		"a wrongly-keyed decode must produce a plausible-looking long header at least once in %d tries, "+
			"or this test proves nothing", attempts)

	// The datagram the intro stage must now decline is a genuine Session Confirmed,
	// so its own stage claims it and the session gets the right message.
	packet, ok := l.parseInboundPacket(stolenDatagram, testPeerAddr())
	require.True(t, ok, "a Session Confirmed whose protector is installed must be parsed, not dropped")
	require.Equal(t, MessageTypeSessionConfirmed, packet.MessageType,
		"the intro stage must not hand over a mis-typed header for a Session Confirmed")
	require.Len(t, packet.Header, ShortHeaderSize,
		"a Session Confirmed has the 16-byte short header; a 32-byte one means the intro stage stole it")
	require.Equal(t, connID, binary.BigEndian.Uint64(packet.Header[0:8]))
}

// TestParseInboundPacket_SessionConfirmedDeliveredAcrossManyDatagrams runs the
// delivery over enough fresh datagrams that the pre-fix false-claim rate could not
// hide: at 0.365% per datagram, 2000 of them failed to be delivered about 99.997%
// of the time.
func TestParseInboundPacket_SessionConfirmedDeliveredAcrossManyDatagrams(t *testing.T) {
	l, introKey := newParseTestListener(t)
	const connID = uint64(0x0B0B0B0B0B0B0B0B)

	headerKey2 := randomKey(t)
	scProtector, err := wire.NewHeaderProtector(introKey, headerKey2, wire.HeaderTypeSessionConfirmed)
	require.NoError(t, err)

	conn := session.NewHandshakingMockSSU2ConnForTest(connID, completeInitiatorHandler(t), false)
	require.NoError(t, l.acceptedSessions.Register(connID, conn))
	require.NoError(t, l.acceptedSessions.SetSessionConfirmedProtector(connID, scProtector))

	for i := 0; i < 2000; i++ {
		datagram := sessionConfirmedDatagram(t, introKey, headerKey2, connID)
		packet, ok := l.parseInboundPacket(datagram, testPeerAddr())
		require.Truef(t, ok, "datagram %d was dropped", i)
		require.Equalf(t, MessageTypeSessionConfirmed, packet.MessageType, "datagram %d was mis-typed", i)
		require.Lenf(t, packet.Header, ShortHeaderSize, "datagram %d was claimed by the intro stage", i)
	}
}

// TestParseInboundPacket_GenuineIntroKeyMessagesStillClaimed guards the other
// direction: tightening the predicate must not cost the listener the messages it
// exists to receive. A Session Request protected with the intro key for both halves
// still decodes and is still claimed by the intro stage.
func TestParseInboundPacket_GenuineIntroKeyMessagesStillClaimed(t *testing.T) {
	l, introKey := newParseTestListener(t)

	datagram := make([]byte, LongHeaderSize+64+16)
	binary.BigEndian.PutUint64(datagram[0:8], 0x1122334455667788)
	binary.BigEndian.PutUint32(datagram[8:12], 99)
	datagram[12] = MessageTypeSessionRequest
	datagram[13] = SSU2ProtocolVersion
	datagram[14] = l.networkID()
	datagram[15] = 0
	binary.BigEndian.PutUint64(datagram[16:24], 0xAABBCCDDEEFF0011)
	for i := 32; i < len(datagram)-1; i++ {
		datagram[i] = byte(i * 3)
	}

	hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NoError(t, hp.EncryptHeader(datagram))

	packet, ok := l.parseInboundPacket(datagram, testPeerAddr())
	require.True(t, ok, "a genuine Session Request must still be parsed")
	require.Equal(t, MessageTypeSessionRequest, packet.MessageType)
	require.Len(t, packet.Header, LongHeaderSize)
	require.Equal(t, uint64(0x1122334455667788), binary.BigEndian.Uint64(packet.Header[0:8]))
	require.Equal(t, l.networkID(), packet.NetworkID)
}
