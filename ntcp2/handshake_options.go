package ntcp2

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2 handshake options-block field validation.
//
// The spec defines the message 1 and message 2 options blocks in the
// SessionRequest and SessionCreated sections and attaches mandatory ("must")
// validation requirements to several of their fields:
//
//   - id (network ID): "If this field is nonzero, and does not match Bob's
//     network ID, Bob should disconnect and block future connections."
//   - ver: "Implementation should verify compatibility, including multiple
//     versions if a comma is present."
//   - tsA / tsB: "Bob must reject connections where the timestamp value is too
//     far off from the current time. Call the maximum delta time 'D'." (and the
//     mirror requirement for Alice). Per Clock Skew Guidelines: "A clock skew
//     between two peers of greater than +/- 60 seconds is generally fatal."
//   - trailing bytes: "Bob must fail the connection if any incoming data
//     remains after validating message 1 and reading in the padding." (and the
//     mirror requirement for Alice after message 2).
//
// Message 2's options block carries no id or ver field (its first two bytes are
// reserved), so network-ID and version validation applies to message 1 only.

// Options block field offsets. Message 1 layout (16 bytes, big endian):
//
//	byte  0     id
//	byte  1     ver
//	bytes 2-3   padLen
//	bytes 4-5   m3p2Len
//	bytes 6-7   Rsvd (0)
//	bytes 8-11  tsA
//	bytes 12-15 Reserved (0)
//
// Message 2 uses the same padLen and timestamp offsets, with id/ver replaced by
// two reserved bytes.
const (
	optsNetIDOffset     = 0
	optsVerOffset       = 1
	optsPadLenOffset    = 2
	optsM3P2LenOffset   = 4
	optsTimestampOffset = 8
)

// maxMsg1TotalSize is the message 1 size cap that applies when the responder is
// published as "NTCP" (NTCP and NTCP2 sharing one port): "Alice must limit the
// maximum size of this message, including padding, to 287 bytes or less. This
// facilitates automatic protocol identification by Bob." When published as
// "NTCP2" there is no such restriction, so this bound governs outbound padding
// generation and is not used to reject inbound messages.
const maxMsg1TotalSize = 287

// maxMsg1OutboundPaddingBytes is the largest padding this implementation may add
// to message 1 while still honouring the 287-byte coexistence cap. The default
// padding distribution (see randomNTCP2PaddingLength) stays within it.
const maxMsg1OutboundPaddingBytes = maxMsg1TotalSize - msg1Size // 223

// validateMessage1Options checks the network ID, version and timestamp fields of
// a decrypted message 1 options block. padLen and m3p2Len are returned for the
// caller's own bounds checks; the spec lets a responder reject excessive padding
// but sets no numeric limit, so no padding cap is applied here.
//
// An out-of-tolerance timestamp is reported through clockSkew rather than err.
// The Clock Skew Guidelines section requires that Bob "reply with a Session
// Created even if the maximum skew is exceeded, rather than simply closing the
// connection. This allows Alice to get Bob's timestamp and calculate the skew,
// and take action if necessary." Every other failure is a hard error, for which
// the spec requires an immediate silent close (TCP RST).
func validateMessage1Options(opts []byte, netID uint8, maxSkew time.Duration) (padLen int, m3p2Len uint16, clockSkew bool, err error) {
	if len(opts) < ntcp2OptionsSize {
		return 0, 0, false, oops.
			Code("MSG1_OPTIONS_TOO_SHORT").
			In("ntcp2").
			With("length", len(opts)).
			With("need", ntcp2OptionsSize).
			Errorf("message 1 options too short: got %d, need %d", len(opts), ntcp2OptionsSize)
	}

	// Network ID. A zero value is accepted for compatibility with routers
	// predating proposal 147, per "If this field is nonzero, and does not match
	// Bob's network ID".
	if id := opts[optsNetIDOffset]; id != 0 && id != netID {
		return 0, 0, false, oops.
			Code("MSG1_NETID_MISMATCH").
			In("ntcp2").
			With("remote_netid", id).
			With("local_netid", netID).
			Errorf("message 1 network ID %d does not match local network ID %d", id, netID)
	}

	// Protocol version. NTCP2 is version 2; the on-wire field is a single byte,
	// so any other value is incompatible.
	if ver := opts[optsVerOffset]; ver != ntcp2Ver {
		return 0, 0, false, oops.
			Code("MSG1_VERSION_MISMATCH").
			In("ntcp2").
			With("remote_version", ver).
			With("expected_version", ntcp2Ver).
			Errorf("message 1 protocol version %d unsupported (expected %d)", ver, ntcp2Ver)
	}

	padLen = int(binary.BigEndian.Uint16(opts[optsPadLenOffset : optsPadLenOffset+2]))
	m3p2Len = binary.BigEndian.Uint16(opts[optsM3P2LenOffset : optsM3P2LenOffset+2])

	if maxSkew > 0 {
		ts := binary.BigEndian.Uint32(opts[optsTimestampOffset : optsTimestampOffset+4])
		if _, ok := clockSkewWithinTolerance(uint64(ts), maxSkew); !ok {
			return padLen, m3p2Len, true, nil
		}
	}

	return padLen, m3p2Len, false, nil
}

// validateMessage2Options checks the timestamp field of a decrypted message 2
// options block and returns its padding length. Unlike the responder, the spec
// requires Alice to "halt further message processing and close the connection
// without responding" on any message 2 error including a timestamp failure, so
// an excessive skew is returned as an error here.
func validateMessage2Options(opts []byte, maxSkew time.Duration) (padLen int, err error) {
	if len(opts) < ntcp2OptionsSize {
		return 0, oops.
			Code("MSG2_OPTIONS_TOO_SHORT").
			In("ntcp2").
			With("length", len(opts)).
			Errorf("message 2 options too short: got %d, need %d", len(opts), ntcp2OptionsSize)
	}

	padLen = int(binary.BigEndian.Uint16(opts[optsPadLenOffset : optsPadLenOffset+2]))

	if maxSkew > 0 {
		ts := binary.BigEndian.Uint32(opts[optsTimestampOffset : optsTimestampOffset+4])
		if skew, ok := clockSkewWithinTolerance(uint64(ts), maxSkew); !ok {
			return padLen, oops.
				Code("MSG2_CLOCK_SKEW").
				In("ntcp2").
				With("skew", skew.String()).
				With("max_skew", maxSkew.String()).
				Errorf("message 2 timestamp skew %s exceeds tolerance %s", skew, maxSkew)
		}
	}

	return padLen, nil
}

// clockSkewWithinTolerance returns the absolute delta between a peer's Unix
// seconds timestamp and the local clock, and whether that delta is within
// maxSkew. The comparison is unsigned and symmetric, matching the spec's
// "+/- 60 seconds" guidance.
func clockSkewWithinTolerance(ts uint64, maxSkew time.Duration) (skew time.Duration, ok bool) {
	now := uint64(time.Now().Unix())
	var delta uint64
	if ts >= now {
		delta = ts - now
	} else {
		delta = now - ts
	}
	skew = time.Duration(delta) * time.Second
	return skew, skew <= maxSkew
}

// recheckClockSkewAfterConfirm performs the responder's post-SessionConfirmed
// clock-skew recheck, closing the connection with a clock-skew termination
// block when the RTT-adjusted skew exceeds the maximum D.
//
// ntcp2.md §"Clock Skew Guidelines": "If Alice does reply with Session
// Confirmed (probably because the skew is very close to the 60s limit, and the
// Alice and Bob calculations are not exactly the same due to RTT), Bob should
// adjust the calculated clock skew by subtracting half the RTT. If the adjusted
// clock skew exceeds the maximum, Bob should then reply with a Disconnect
// message containing a clock skew reason code, and close the connection."
//
// Reference: Java i2p.i2p InboundEstablishState.java (verifyInbound(), called
// after message 3 / RouterInfo receipt):
//
//	long rtt = _context.clock().now() - _con.getCreated();
//	_peerSkew -= ((rtt / 2) + 500) / 1000;
//	long diff = 1000*Math.abs(_peerSkew);
//	boolean skewOK = diff < Router.CLOCK_FUDGE_FACTOR;   // 1*60*1000 ms
//	→ fail(NTCPConnection.REASON_SKEW)                  // reason 7
//
// The initial `_peerSkew` is set at message-1 arrival to (now - tsA); we
// reproduce it from cfg.msg1ReceivedAt and cfg.peerTimestampSecs, and the RTT
// as (msg3 arrival - msg1 arrival) — Java measures from connection creation,
// the same interval in practice for an inbound NTCP2 connection. Java rounds
// each term to whole seconds (+500 ms); we keep full duration precision, which
// only makes the boundary decision slightly more accurate.
//
// The tolerance comparison uses `<= maxSkew` (pass), matching this package's
// message-1/message-2 checks in clockSkewWithinTolerance, so a connection that
// passed the initial check at exactly D does not fail here for a zero-RTT peer.
//
// i2pd has no handshake-phase recheck — it re-validates DateTime-block
// timestamps in the data phase instead (libi2pd/NTCP2.cpp ProcessPacket
// DateTime handling) — so the dev spec's explicit requirement and Java decide.
//
// On failure the spec's "Disconnect message" is a data-phase Termination block
// (§"Termination": "rsn :: reason, 1 byte: … 7: clock skew"; reference i2pd
// libi2pd/NTCP2.h NTCP2TerminationReason eNTCP2BlkTermination reason 7 /
// SendTermination), sealed here with the just-derived data-phase keys and sent
// via sendTerminationBlock, followed by a graceful close so the frame flushes.
// A failure to seal or write the frame falls back to the abnormal close.
func (c *Conn) recheckClockSkewAfterConfirm(cfg *Config, raw net.Conn) error {
	msg3At := cfg.msg3ReceivedAt
	if msg3At.IsZero() {
		// Defensive: if the responder path did not record msg3 arrival, the
		// recheck runs immediately after it, so "now" is the arrival time.
		msg3At = time.Now()
	}

	// Signed peer skew at message-1 arrival: (our clock) - tsA.
	skew := cfg.msg1ReceivedAt.Sub(time.Unix(int64(cfg.peerTimestampSecs), 0))
	rtt := msg3At.Sub(cfg.msg1ReceivedAt)
	if rtt < 0 {
		rtt = 0
	}
	adjusted := skew - rtt/2
	if adjusted < 0 {
		adjusted = -adjusted
	}

	maxSkew := cfg.maxClockSkew()
	if adjusted <= maxSkew {
		return nil
	}

	flog("recheckClockSkewAfterConfirm", logger.Fields{
		"remote":   raw.RemoteAddr().String(),
		"skew":     skew.String(),
		"rtt":      rtt.String(),
		"adj_skew": adjusted.String(),
		"max_skew": maxSkew.String(),
	}).Warn("NTCP2 responder: RTT-adjusted clock skew exceeds maximum after SessionConfirmed")

	// Spec: reply with the disconnect (termination) message, then close.
	if err := c.sendTerminationBlock(TerminationReasonClockSkew); err != nil {
		flog("recheckClockSkewAfterConfirm", logger.Fields{"error": err.Error()}).
			Debug("could not seal clock-skew termination frame; using abnormal close")
		c.broken.Store(true)
		c.sendTCPRST(raw)
	} else {
		c.broken.Store(true)
		c.gracefulClose(raw)
	}

	return oops.
		Code("MSG3_CLOCK_SKEW_RECHECK").
		In("ntcp2").
		With("adjusted_skew", adjusted.String()).
		With("max_skew", maxSkew.String()).
		Errorf("RTT-adjusted clock skew %s exceeds tolerance %s after SessionConfirmed (termination block sent, reason %d)",
			adjusted, maxSkew, TerminationReasonClockSkew)
}

// probeNoMoreData verifies that the peer sent nothing beyond the end of a
// handshake message, as required after message 1 ("Bob must fail the connection
// if any incoming data remains after validating message 1 and reading in the
// padding") and after message 2 (the mirror requirement for Alice).
//
// Detection is a single-byte read bounded by a short probe window: a byte
// arriving inside that window means the peer sent more than the message. A
// conforming peer stays silent until it receives our reply, so a timeout is the
// expected outcome.
//
// restoreDeadline is the deadline the surrounding handshake flow had installed
// (zero for none) and is re-applied before returning, so the probe can neither
// widen the handshake timeout nor leave the socket without its slowloris
// deadline.
func probeNoMoreData(conn net.Conn, restoreDeadline time.Time) error {
	if err := conn.SetReadDeadline(time.Now().Add(extraHandshakeProbeWindow)); err != nil {
		// The connection does not support deadlines; the probe is unavailable
		// and skipping it keeps such transports working.
		return nil
	}
	defer conn.SetReadDeadline(restoreDeadline) //nolint:errcheck // best-effort restore

	var b [1]byte
	n, err := conn.Read(b[:])
	if n > 0 {
		return oops.
			Code("MSG_EXTRA_DATA").
			In("ntcp2").
			With("extra_bytes", n).
			Errorf("unexpected data after handshake message: peer must not send before our reply")
	}
	if err == nil {
		return oops.
			Code("MSG_EXTRA_DATA").
			In("ntcp2").
			Errorf("unexpected data after handshake message: peer must not send before our reply")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// No extra byte within the window: conforming behaviour.
		return nil
	}
	if err == io.EOF {
		return oops.
			Code("MSG_PEER_CLOSED").
			In("ntcp2").
			Errorf("peer closed connection before handshake reply")
	}
	return oops.Wrapf(err, "probe read after handshake message failed")
}

// extraHandshakeProbeWindow bounds the single-byte probe used to detect
// unexpected trailing data after handshake messages 1 and 2. It is short enough
// to add negligible latency yet long enough to catch a peer that flushes extra
// bytes with or immediately after the message.
const extraHandshakeProbeWindow = 10 * time.Millisecond

// msg3Part2BlockOrder is the block sequence the SessionConfirmed section
// requires for message 3 part 2:
//
//	"The frame must contain 1 to 3 blocks in the following order:
//	 1) Alice's Router Info block (required)
//	 2) Options block (optional)
//	 3) Padding block (optional)
//	 This frame must never contain any other block type."
var msg3Part2BlockOrder = []byte{RouterInfoBlockType, OptionsBlockType, PaddingBlockType}

// blockTypeRank returns the position of blockType in the message 3 part 2
// ordering rules, or -1 when the type is not permitted in that frame.
func blockTypeRank(blockType byte) int {
	for i, t := range msg3Part2BlockOrder {
		if t == blockType {
			return i
		}
	}
	return -1
}

// validateMsg3Part2Blocks enforces the message 3 part 2 block whitelist and
// ordering rules, and verifies that each block's declared size stays within the
// frame so that reading one block cannot overrun into the next.
func validateMsg3Part2Blocks(frame []byte) error {
	if len(frame) < BlockHeaderSize {
		return oops.
			Code("MSG3_PART2_TOO_SHORT").
			In("ntcp2").
			With("length", len(frame)).
			Errorf("message 3 part 2 frame too short for a block header: %d bytes", len(frame))
	}

	lastRank := -1
	sawRouterInfo := false
	next := 0
	for next < len(frame) {
		if len(frame)-next < BlockHeaderSize {
			return oops.
				Code("MSG3_PART2_TRUNCATED_HEADER").
				In("ntcp2").
				With("remaining", len(frame)-next).
				Errorf("message 3 part 2 truncated mid-block-header at offset %d", next)
		}
		blockType := frame[next]
		rank := blockTypeRank(blockType)
		if rank < 0 {
			return oops.
				Code("MSG3_PART2_BLOCK_TYPE").
				In("ntcp2").
				With("block_type", blockType).
				With("offset", next).
				Errorf("message 3 part 2 contains forbidden block type %d (only RouterInfo, Options and Padding are allowed)", blockType)
		}
		if rank <= lastRank {
			return oops.
				Code("MSG3_PART2_BLOCK_ORDER").
				In("ntcp2").
				With("block_type", blockType).
				With("offset", next).
				With("previous_type", msg3Part2BlockOrder[lastRank]).
				Errorf("message 3 part 2 block type %d out of order (must be RouterInfo, then Options, then Padding)", blockType)
		}
		if rank == 0 {
			sawRouterInfo = true
		}
		size := int(binary.BigEndian.Uint16(frame[next+1 : next+3]))
		end := next + BlockHeaderSize + size
		if end > len(frame) {
			return oops.
				Code("MSG3_PART2_BLOCK_OVERRUN").
				In("ntcp2").
				With("block_type", blockType).
				With("block_size", size).
				With("frame_len", len(frame)).
				Errorf("message 3 part 2 block %d declares %d bytes, overrunning the %d-byte frame", blockType, size, len(frame))
		}
		lastRank = rank
		next = end
	}

	// The RouterInfo block is required (not optional): an empty frame, or one
	// carrying only Options and/or Padding, is non-conforming even though those
	// blocks appear in the correct relative order.
	if !sawRouterInfo {
		return oops.
			Code("MSG3_PART2_NO_ROUTER_INFO").
			In("ntcp2").
			Errorf("message 3 part 2 is missing the required RouterInfo block")
	}
	return nil
}
