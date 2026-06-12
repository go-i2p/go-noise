package ntcp2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/cryptorand"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"

	i2pbase64 "github.com/go-i2p/common/base64"
)

// NTCP2 handshake wire-format constants.
const (
	// msg1Size is the fixed size of NTCP2 message 1 AEAD frame (before cleartext padding).
	// 32 bytes (AES-obfuscated ephemeral key) + 16 bytes (encrypted options) + 16 bytes (Poly1305 tag).
	msg1Size = 64

	// msg2Size is the fixed size of NTCP2 message 2 AEAD frame (before cleartext padding).
	msg2Size = 64

	// msg3Part1Size is the fixed size of NTCP2 message 3 part 1.
	// 32 bytes (encrypted static key) + 16 bytes (Poly1305 tag).
	msg3Part1Size = 48

	// ntcp2NetID is the I2P network ID (value 2 for the main network).
	ntcp2NetID = 0x02

	// ntcp2Ver is the NTCP2 protocol version field value.
	ntcp2Ver = 0x02

	// ntcp2OptionsSize is the fixed size of the options block in bytes.
	ntcp2OptionsSize = 16

	// routerInfoBlockType is the NTCP2 block type for RouterInfo (type 2).
	routerInfoBlockType = 0x02
)

// Handshake performs the NTCP2 XK three-way handshake with correct wire framing.
//
// The standard Noise framing adds a 2-byte length prefix to every handshake
// message. The NTCP2 spec explicitly forbids length prefixes on messages 1, 2,
// and 3.  This method writes and reads raw Noise bytes directly over the TCP
// socket to produce the correct on-wire format:
//
//   - Message 1 (64 bytes): [AES-obfuscated e (32B)] [EncryptAndHash(options) (16B)] [tag (16B)]
//   - Message 2 (64 bytes): [AES-obfuscated e (32B)] [EncryptAndHash(options) (16B)] [tag (16B)]
//   - Message 3 (48 + m3p2Len bytes): [EncryptAndHash(s) (48B)] [EncryptAndHash(RI block) (m3p2Len B)]
//
// Cleartext padding: Alice sends none (padLen=0). Bob's padding is read,
// MixHash'd, and discarded per the NTCP2 spec §4.4.
//
// Handshake must not be called concurrently on the same connection.
func (c *Conn) Handshake(ctx context.Context) (retErr error) {
	cfg := c.ntcp2Config.Load()
	if cfg == nil {
		return oops.
			Code("MISSING_NTCP2_CONFIG").
			In("ntcp2").
			Errorf("NTCP2Config not set; call SetNTCP2Config before Handshake")
	}

	nc := c.UnderlyingConn()
	nc.StartHandshake()

	// Apply a handshake deadline to the underlying TCP connection so that
	// blocking Read/Write calls in performInitiatorHandshake / performResponderHandshake
	// are bounded. Without this, a misbehaving peer can cause the handshake to block
	// indefinitely (the ctx was previously accepted but never used).
	raw := nc.Underlying()
	hsCtx := ctx
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		// AUDIT 4.1: never allow an unbounded handshake. If no timeout is
		// configured and the caller's context carries no deadline, fall back
		// to the default so a peer that completes the TCP connect but stalls
		// the Noise exchange cannot pin this goroutine (and, for serial
		// AcceptWithHandshake callers, the whole accept loop) forever.
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			timeout = DefaultHandshakeTimeoutSeconds * time.Second
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var deadlineSet bool
	if deadline, ok := hsCtx.Deadline(); ok {
		// BUG-RC-2 / BUG-SM-2: if Accept() already set an authoritative deadline,
		// use the EARLIER of the two so a caller delay between Accept and Handshake
		// cannot extend the total window beyond one HandshakeTimeout.
		if !c.handshakeDeadline.IsZero() && c.handshakeDeadline.Before(deadline) {
			deadline = c.handshakeDeadline
		}
		if err := raw.SetDeadline(deadline); err != nil {
			nc.FailHandshake()
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("ntcp2").
				Wrapf(err, "failed to set handshake deadline on underlying connection")
		}
		deadlineSet = true
	} else if !c.handshakeDeadline.IsZero() {
		// No ctx deadline but Accept set one — honour it (BUG-RC-2 / BUG-SM-2).
		if err := raw.SetDeadline(c.handshakeDeadline); err != nil {
			nc.FailHandshake()
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("ntcp2").
				Wrapf(err, "failed to set handshake deadline on underlying connection")
		}
		deadlineSet = true
	}
	if deadlineSet {
		// BUG-SM-1: clear the deadline only on success. On failure the caller
		// should close the connection immediately, so lifting the deadline would
		// leave a brief window with no deadline before Close(). Keying off
		// retErr (named return) ensures the defer runs the clear only when the
		// handshake completes without error.
		defer func() {
			if retErr == nil {
				_ = raw.SetDeadline(time.Time{})
			}
		}()
	}

	var err error
	var msg3Payload []byte
	if cfg.Initiator {
		if len(cfg.LocalRouterInfo) == 0 {
			nc.FailHandshake()
			return oops.
				Code("MISSING_LOCAL_ROUTER_INFO").
				In("ntcp2").
				Errorf("LocalRouterInfo must be set in NTCP2Config for outbound connections")
		}
		err = performInitiatorHandshake(cfg, nc)
	} else {
		msg3Payload, err = performResponderHandshake(cfg, nc)
	}
	if err != nil {
		nc.FailHandshake()
		return err
	}

	// On the responder side, store Alice's decrypted message-3 part-2 payload
	// (the I2NP block frame containing her RouterInfo) so the router transport
	// layer can parse it via PeerMessage3Payload() / PeerRouterInfoBytes().
	// Without this, the OBEP/responder has no way to learn Alice's NTCP2
	// address for direct delivery of replies (e.g. ShortTunnelBuildReply).
	if msg3Payload != nil {
		buf := make([]byte, len(msg3Payload))
		copy(buf, msg3Payload)
		c.peerMsg3Payload.Store(&buf)
	}

	// Run the PostHandshakeHook to derive SipHash keys from the ASK master and h.
	if err := nc.RunPostHandshakeHook(); err != nil {
		nc.FailHandshake()
		return oops.
			Code("POST_HANDSHAKE_HOOK_FAILED").
			In("ntcp2").
			Wrapf(err, "post-handshake hook failed after NTCP2 handshake")
	}

	nc.CompleteHandshake()

	// Copy the derived SipHash modifier from the config into the connection's
	// data-phase length obfuscator (mirrors the standard handshake path).
	if err := c.PropagateSipHash(); err != nil {
		return oops.
			Code("SIPHASH_PROPAGATION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to propagate SipHash modifier after handshake")
	}

	// STATE-1 / RACE-3: mark the connection as fully established only after the
	// SipHash keys are installed. Read() and Write() gate on this flag.
	c.established.Store(true)

	return nil
}

// performInitiatorHandshake executes the three-message NTCP2 XK exchange.
// Each phase is delegated to sendInitiatorMsg1, receiveResponderMsg2, and
// sendInitiatorMsg3 so each step can be tested independently.
func performInitiatorHandshake(cfg *Config, nc *noise.NoiseConn) error {
	riBytes := cfg.LocalRouterInfo
	// m3p2Len includes the block header (3B), flag byte (1B), RouterInfo bytes, and the AEAD tag (16B).
	// Per the NTCP2 spec, the RouterInfo block (type 2) data starts with a 1-byte flag field.
	m3p2Len := uint16(BlockHeaderSize + 1 + len(riBytes) + Poly1305Overhead)

	// Defense-in-depth: verify the public key derived from our Noise static
	// private key actually appears in the LocalRouterInfo we are about to
	// send inside msg3. i2pd silently terminates the TCP connection (no
	// termination frame) if the static public key it received in msg1 does
	// not appear as the `s=` option of any NTCP2 address in the RouterInfo
	// we send in msg3 (libi2pd/NTCP2.cpp:690, RouterInfo.cpp:838). The
	// observable symptom is "frame #0 EOF" in the data phase. We log a
	// warning here so the misconfiguration is visible in production logs;
	// the authoritative fix lives in the caller (go-i2p/go-i2p) — see
	// PROMPT.md in this repo. Logging (not erroring) keeps existing tests
	// that use synthetic RouterInfo bytes working.
	if err := verifyLocalRouterInfoMatchesStaticKey(cfg.StaticKey, riBytes); err != nil {
		if cfg.StrictRouterInfoVerification {
			return oops.
				Code("ROUTER_INFO_KEY_MISMATCH").
				In("ntcp2").
				Wrapf(err, "LocalRouterInfo does not advertise the static key (strict mode enabled; see PROMPT.md)")
		}
		log.WithFields(logger.Fields{
			"pkg":   "ntcp2",
			"func":  "performInitiatorHandshake",
			"event": "static_key_ri_mismatch",
			"err":   err.Error(),
		}).Warn("LocalRouterInfo does not advertise the static key we will send in the Noise handshake; i2pd peers will silently close the TCP connection after msg3 (frame #0 EOF). See PROMPT.md.")
	}

	if err := sendInitiatorMsg1(cfg, nc, m3p2Len); err != nil {
		return err
	}
	if err := receiveResponderMsg2(cfg, nc); err != nil {
		return err
	}
	return sendInitiatorMsg3(cfg, nc, riBytes, m3p2Len)
}

// sendInitiatorMsg1 builds and sends the NTCP2 message 1 (AES-obfuscation step),
// followed by the randomly-generated cleartext padding bytes. The padding length
// is randomized in the range [0, 223] per the NTCP2 spec §4.3, matching the
// i2pd/Java I2P padding distribution to prevent passive wire fingerprinting.
//
// opts construction, Noise WriteHandshakeMsg, size check, dump, wire write, and
// padding send are kept together so this step can be unit-tested with a mock NoiseConn.
func sendInitiatorMsg1(cfg *Config, nc *noise.NoiseConn, m3p2Len uint16) error {
	opts1, padLen, err := buildMessage1Options(m3p2Len)
	if err != nil {
		return err // already wrapped by buildMessage1Options
	}
	msg1, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseInitial, opts1)
	if err != nil {
		return oops.Code("MSG1_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 1")
	}
	if len(msg1) != msg1Size {
		return oops.Code("MSG1_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 1 to be %d bytes, got %d", msg1Size, len(msg1))
	}
	raw := nc.Underlying()
	dumpMsg1IfEnabled(cfg, raw, opts1, msg1)
	if _, err := raw.Write(msg1); err != nil {
		return oops.Code("MSG1_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 1")
	}

	// Send the cleartext padding bytes (if padLen > 0) and MixHash them into
	// the handshake state. The padding content is random per the spec to prevent
	// plaintext fingerprinting. This matches i2pd's CreateSessionRequestMessage.
	if padLen > 0 {
		pad, err := cryptorand.RandomBytes(padLen)
		if err != nil {
			return oops.Code("MSG1_PAD_GEN_FAILED").In("ntcp2").
				Wrapf(err, "failed to generate %d padding bytes for message 1", padLen)
		}
		if _, err := raw.Write(pad); err != nil {
			return oops.Code("MSG1_PAD_SEND_FAILED").In("ntcp2").
				Wrapf(err, "failed to send %d padding bytes after message 1", padLen)
		}
		nc.MixHashData(pad)
	}
	return nil
}

// receiveResponderMsg2 reads and processes the NTCP2 message 2 (Noise exchange step).
// It uses a 1-byte probe read to distinguish early peer-close from partial
// msg2, then MixHashes Bob's cleartext padding into the handshake state.
func receiveResponderMsg2(cfg *Config, nc *noise.NoiseConn) error {
	raw := nc.Underlying()
	// Split the read into a 1-byte probe + the remaining 63 bytes so we can
	// distinguish "peer rejected msg1 (closed before writing any byte)" from
	// "peer started msg2 then aborted (partial write)". This is critical
	// interop diagnostic info: the first case points at TCP-reachability or
	// msg1-AEAD problems, the second at msg2 framing on the responder side.
	buf2 := make([]byte, msg2Size)
	n1, err := io.ReadFull(raw, buf2[:1])
	if err != nil {
		classifyMsg2ReadFailure(cfg, raw, 0, err)
		return oops.Code("MSG2_NO_BYTES").In("ntcp2").
			With("bytes_read", 0).
			Wrapf(err, "peer closed connection without sending any msg2 bytes (msg1 likely rejected)")
	}
	if n2, err := io.ReadFull(raw, buf2[1:]); err != nil {
		classifyMsg2ReadFailure(cfg, raw, n1+n2, err)
		return oops.Code("MSG2_PARTIAL").In("ntcp2").
			With("bytes_read", n1+n2).
			With("bytes_expected", msg2Size).
			Wrapf(err, "peer started msg2 but closed after %d bytes", n1+n2)
	}
	bobOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseExchange, buf2)
	if err != nil {
		return oops.Code("MSG2_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 2")
	}
	// Read and MixHash Bob's cleartext padding (bytes 2-3 of his options = padLen).
	// i2pd ALWAYS sends a random number of padding bytes (0..222) after msg2 and
	// MixHashes them into h before decrypting m3p1. We MUST mirror that or
	// m3p1 AEAD verification on i2pd's side fails, causing silent terminate.
	var bobPadLen int
	if len(bobOpts) >= ntcp2OptionsSize {
		bobPadLen = int(binary.BigEndian.Uint16(bobOpts[2:4]))
		_ = hex.EncodeToString(bobOpts[:ntcp2OptionsSize]) // bobOpts available for debug
		if bobPadLen > 0 {
			pad := make([]byte, bobPadLen)
			if _, err := io.ReadFull(raw, pad); err != nil {
				return oops.Code("MSG2_PAD_READ_FAILED").In("ntcp2").
					Wrapf(err, "failed to read %d cleartext padding bytes after message 2", bobPadLen)
			}
			nc.MixHashData(pad)
		}
	}
	// Debug-level breadcrumb for interop diagnostics. Redacted for anonymity.
	log.WithFields(logger.Fields{
		"pkg":          "ntcp2",
		"func":         "receiveResponderMsg2",
		"event":        "msg2_processed",
		"bob_padlen":   bobPadLen,
		"bob_opts_len": len(bobOpts),
	}).Debug("NTCP2 msg2 processed; bob padlen extracted")
	return nil
}

// sendInitiatorMsg3 builds and sends the NTCP2 message 3 (RouterInfo framing step).
// It wraps the local RouterInfo in the NTCP2 block frame, encrypts it via the
// Noise PhaseFinal WriteHandshakeMsg, validates the wire length, and writes it.
func sendInitiatorMsg3(cfg *Config, nc *noise.NoiseConn, riBytes []byte, m3p2Len uint16) error {
	msg3Payload := buildMsg3Part2Payload(riBytes)
	msg3, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseFinal, msg3Payload)
	if err != nil {
		return oops.Code("MSG3_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 3")
	}
	expectedLen := msg3Part1Size + int(m3p2Len)
	if len(msg3) != expectedLen {
		return oops.Code("MSG3_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 3 to be %d bytes, got %d", expectedLen, len(msg3))
	}
	raw := nc.Underlying()
	dumpMsg3IfEnabled(cfg, raw, msg3, riBytes, m3p2Len)
	if _, err := raw.Write(msg3); err != nil {
		return oops.Code("MSG3_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 3")
	}
	// Emit a Warn-level breadcrumb at msg3 send so we can correlate with the
	// data-phase reader's "frame #0 EOF" warning. If the two warnings are
	// adjacent in the log, the peer rejected msg3 immediately (silent
	// Terminate after AEAD/block check). If they are seconds apart, the peer
	// accepted msg3 and closed later for an unrelated reason. See
	// libi2pd/NTCP2.cpp:634 (HandleSessionConfirmedReceived).
	log.WithFields(logger.Fields{
		"pkg":      "ntcp2",
		"func":     "sendInitiatorMsg3",
		"event":    "msg3_sent",
		"msg3_len": len(msg3),
		"m3p1_len": msg3Part1Size,
		"m3p2_len": int(m3p2Len),
		"ri_len":   len(riBytes),
	}).Debug("NTCP2 msg3 written to wire; awaiting first data-phase frame")
	return nil
}

// performResponderHandshake executes the three-message NTCP2 XK exchange
// from the responder's (Bob's) perspective. On success it returns the
// decrypted message-3 part-2 plaintext, which is the I2NP block frame
// containing Alice's RouterInfo (and any optional padding/options blocks
// per the NTCP2 spec). The caller is responsible for parsing and storing
// it for the router transport layer.
// missingReplayWarnOnce ensures the "no replay detector" warning (AUDIT 5.3)
// is emitted at most once per process rather than on every inbound handshake.
var missingReplayWarnOnce sync.Once

// warnMissingReplayDetector logs a one-time warning that the responder is
// running without NTCP2 message-1 replay protection.
func warnMissingReplayDetector() {
	missingReplayWarnOnce.Do(func() {
		log.WithFields(logger.Fields{
			"pkg":  "ntcp2",
			"func": "performResponderHandshake",
		}).Warn("no ReplayDetector configured: NTCP2 message-1 replay protection is DISABLED; set one via WithReplayDetector")
	})
}

func performResponderHandshake(cfg *Config, nc *noise.NoiseConn) ([]byte, error) {
	raw := nc.Underlying()

	// === Message 1 (Alice -> Bob) ============================================
	buf1 := make([]byte, msg1Size)
	if _, err := io.ReadFull(raw, buf1); err != nil {
		return nil, oops.Code("MSG1_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 1")
	}
	aliceOpts, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseInitial, buf1)
	if err != nil {
		dumpInboundMsg1IfEnabled(cfg, raw, buf1, nil, err)
		return nil, oops.Code("MSG1_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 1")
	}
	dumpInboundMsg1IfEnabled(cfg, raw, buf1, aliceOpts, nil)

	// Replay detection: check if the ephemeral key X has been seen before.
	// Per the I2P NTCP2 spec, Bob must maintain a cache of previously-used
	// ephemeral keys (the first 32 bytes of message 1, the AES-obfuscated X)
	// and reject duplicates within the freshness window (±ClockSkewTolerance).
	// The encrypted-but-deterministic form is sufficient as a replay key
	// because the same plaintext X always produces the same ciphertext when
	// obfuscated with the same RH_B and IV.
	if cfg.ReplayDetector != nil {
		var ephemeralKey [32]byte
		copy(ephemeralKey[:], buf1[:32])
		if cfg.ReplayDetector.CheckAndAdd(ephemeralKey) {
			return nil, oops.
				Code("MSG1_REPLAY").
				In("ntcp2").
				With("remote", raw.RemoteAddr().String()).
				Errorf("replay detected: ephemeral key has been seen before within TTL window")
		}
	} else {
		// AUDIT 5.3: replay protection is opt-in. A responder with no
		// ReplayDetector silently accepts replayed message-1 ephemerals,
		// contrary to the NTCP2 spec's requirement. Warn once so operators
		// notice the missing protection rather than running unprotected
		// without any signal.
		warnMissingReplayDetector()
	}

	// Parse Alice's options to extract padLen (bytes 2-3) and m3p2Len (bytes 4-5).
	if len(aliceOpts) < ntcp2OptionsSize {
		return nil, oops.Code("MSG1_OPTIONS_TOO_SHORT").In("ntcp2").
			Errorf("message 1 options too short: got %d, need %d", len(aliceOpts), ntcp2OptionsSize)
	}
	alicePadLen := int(binary.BigEndian.Uint16(aliceOpts[2:4]))
	m3p2Len := binary.BigEndian.Uint16(aliceOpts[4:6])

	// Validate alicePadLen to prevent unbounded allocation DoS.
	// Per spec §4.3, padding is "0..223 bytes" in practice. We enforce
	// a conservative limit to prevent an attacker from forcing the responder
	// to allocate 64 KiB per connection and blocking on io.ReadFull.
	if alicePadLen > MaxNTCP2HandshakePadding {
		return nil, oops.
			Code("MSG1_PADDING_TOO_LARGE").
			In("ntcp2").
			With("padLen", alicePadLen).
			With("max", MaxNTCP2HandshakePadding).
			Errorf("message 1 padding too large: %d > %d", alicePadLen, MaxNTCP2HandshakePadding)
	}

	// Validate m3p2Len to prevent unbounded allocation DoS.
	// Per spec, RouterInfo is typically < 2 KB. We enforce a conservative
	// limit to prevent an attacker from forcing the responder to allocate
	// excessive memory (up to 64 KiB with uint16 max) per connection.
	if m3p2Len > MaxNTCP2Message3Part2Len {
		return nil, oops.
			Code("MSG3_PART2_TOO_LARGE").
			In("ntcp2").
			With("m3p2Len", m3p2Len).
			With("max", MaxNTCP2Message3Part2Len).
			Errorf("message 3 part 2 too large: %d > %d", m3p2Len, MaxNTCP2Message3Part2Len)
	}

	// Read and MixHash Alice's cleartext padding after message 1.
	// Per NTCP2 spec §4.1: "padding MUST be mixed into the handshake hash"
	// even when padLen is 0 (no bytes to read, no MixHash needed).
	if alicePadLen > 0 {
		pad := make([]byte, alicePadLen)
		if _, err := io.ReadFull(raw, pad); err != nil {
			return nil, oops.Code("MSG1_PAD_READ_FAILED").In("ntcp2").
				Wrapf(err, "failed to read %d cleartext padding bytes after message 1", alicePadLen)
		}
		nc.MixHashData(pad)
	}

	// === Message 2 (Bob -> Alice) ============================================
	opts2, bobPadLen, err := buildMessage2Options()
	if err != nil {
		return nil, err // already wrapped by buildMessage2Options
	}
	msg2, err := nc.WriteHandshakeMsgToBytes(handshake.PhaseExchange, opts2)
	if err != nil {
		return nil, oops.Code("MSG2_WRITE_FAILED").In("ntcp2").
			Wrapf(err, "failed to build NTCP2 message 2")
	}
	if len(msg2) != msg2Size {
		return nil, oops.Code("MSG2_SIZE_MISMATCH").In("ntcp2").
			Errorf("expected message 2 to be %d bytes, got %d", msg2Size, len(msg2))
	}
	if _, err := raw.Write(msg2); err != nil {
		return nil, oops.Code("MSG2_SEND_FAILED").In("ntcp2").
			Wrapf(err, "failed to send NTCP2 message 2")
	}

	// Send the cleartext padding bytes (if bobPadLen > 0) and MixHash them into
	// the handshake state. The padding content is random per the spec to prevent
	// plaintext fingerprinting. This matches i2pd's CreateSessionCreatedMessage.
	if bobPadLen > 0 {
		pad, err := cryptorand.RandomBytes(bobPadLen)
		if err != nil {
			return nil, oops.Code("MSG2_PAD_GEN_FAILED").In("ntcp2").
				Wrapf(err, "failed to generate %d padding bytes for message 2", bobPadLen)
		}
		if _, err := raw.Write(pad); err != nil {
			return nil, oops.Code("MSG2_PAD_SEND_FAILED").In("ntcp2").
				Wrapf(err, "failed to send %d padding bytes after message 2", bobPadLen)
		}
		nc.MixHashData(pad)
	}

	// === Message 3 (Alice -> Bob) ============================================
	msg3Len := msg3Part1Size + int(m3p2Len)
	buf3 := make([]byte, msg3Len)
	if _, err := io.ReadFull(raw, buf3); err != nil {
		return nil, oops.Code("MSG3_READ_FAILED").In("ntcp2").
			Wrapf(err, "failed to read NTCP2 message 3 (%d bytes)", msg3Len)
	}
	payload, err := nc.ReadHandshakeMsgFromBytes(handshake.PhaseFinal, buf3)
	if err != nil {
		return nil, oops.Code("MSG3_PROCESS_FAILED").In("ntcp2").
			Wrapf(err, "failed to process NTCP2 message 3")
	}

	// Return the decrypted message-3 part-2 plaintext to the caller. This is
	// the I2NP block frame containing Alice's RouterInfo (block type 2) and
	// any optional padding/options blocks. The router transport layer needs
	// this to learn Alice's NTCP2 address for direct reply delivery (e.g.
	// ShortTunnelBuildReply for 1-hop outbound tunnels).
	return payload, nil
}

// buildMessage2Options constructs the 16-byte options block sent as the
// AEAD payload in NTCP2 message 2 (Bob -> Alice), and returns the options
// and a randomly-generated padding length in the range [0, 223].
//
// Wire layout (all fields big-endian) — spec: https://spec.i2p.net/ntcp2#options:
//
//	bytes 0-1  : Reserved = 0   (NOT id/ver — those fields are message 1 only)
//	bytes 2-3  : padLen         (cleartext padding length, randomized 0-223)
//	bytes 4-7  : Reserved = 0
//	bytes 8-11 : tsB            (Bob's Unix timestamp, big-endian uint32)
//	bytes 12-15: Reserved = 0
//
// The padLen value is randomized to match the i2pd/Java I2P padding distribution
// (0-223 bytes) per the NTCP2 spec §4.3, preventing passive wire fingerprinting.
// The actual padding bytes are generated separately by the caller and sent
// after the 64-byte AEAD frame.
func buildMessage2Options() ([]byte, int, error) {
	// Generate random padding length [0, 223] per i2pd distribution.
	// i2pd's CreateSessionCreatedMessage uses rand()%(287-64) which is 0-222,
	// but the spec says 0-223, so we use 223 as the max.
	const maxPadLen = 223 // per NTCP2 spec §4.3
	padLen, err := randomPaddingLength(maxPadLen)
	if err != nil {
		return nil, 0, oops.Code("RAND_PAD_FAILED").In("ntcp2").
			Wrapf(err, "failed to generate random padding length for message 2")
	}

	opts := make([]byte, ntcp2OptionsSize)
	// opts[0:2] = Reserved = 0 (Message 2 has no id/ver)
	binary.BigEndian.PutUint16(opts[2:4], uint16(padLen))
	// opts[4:8] = Reserved = 0
	binary.BigEndian.PutUint32(opts[8:12], uint32(time.Now().Unix()))
	// opts[12:16] = Reserved = 0
	return opts, padLen, nil
}

// buildMessage1Options constructs the 16-byte options block sent as the
// AEAD payload in NTCP2 message 1 (Alice -> Bob), and returns the options
// and a randomly-generated padding length in the range [0, 223].
//
// Wire layout (all fields big-endian):
//
//	byte 0     : id     = 0x02  (network ID)
//	byte 1     : ver    = 0x02  (NTCP2 protocol version)
//	bytes 2-3  : padLen         (cleartext padding length, randomized 0-223)
//	bytes 4-5  : m3p2Len        (message-3 part-2 size, including AEAD tag)
//	bytes 6-7  : Rsvd   = 0
//	bytes 8-11 : tsA            (Alice's Unix timestamp, big-endian uint32)
//	bytes 12-15: Reserved = 0
//
// The padLen value is randomized to match the i2pd/Java I2P padding distribution
// (0-223 bytes) per the NTCP2 spec §4.3, preventing passive wire fingerprinting.
// The actual padding bytes are generated separately by the caller and sent
// after the 64-byte AEAD frame.
func buildMessage1Options(m3p2Len uint16) ([]byte, int, error) {
	// Generate random padding length [0, 223] per i2pd distribution.
	// Use rejection sampling from a single random byte to ensure uniform distribution.
	const maxPadLen = 223 // per NTCP2 spec §4.3 and i2pd CreateSessionRequestMessage
	padLen, err := randomPaddingLength(maxPadLen)
	if err != nil {
		return nil, 0, oops.Code("RAND_PAD_FAILED").In("ntcp2").
			Wrapf(err, "failed to generate random padding length for message 1")
	}

	opts := make([]byte, ntcp2OptionsSize)
	opts[0] = ntcp2NetID
	opts[1] = ntcp2Ver
	binary.BigEndian.PutUint16(opts[2:4], uint16(padLen))
	binary.BigEndian.PutUint16(opts[4:6], m3p2Len)
	// opts[6:8] = Rsvd = 0
	binary.BigEndian.PutUint32(opts[8:12], uint32(time.Now().Unix()))
	// opts[12:16] = Reserved = 0
	return opts, padLen, nil
}

// buildMsg3Part2Payload wraps raw RouterInfo bytes in the NTCP2 block frame
// (type 2) that becomes the plaintext payload of Noise message 3.
//
// Per the NTCP2 spec, the RouterInfo block data starts with a 1-byte flag field:
//   - bit 0: if set, request peer to flood the RouterInfo
//
// Wire layout:
//
//	byte 0    : block type = 0x02 (RouterInfo)
//	bytes 1-2 : block size = 1 + len(routerInfoBytes) (big-endian uint16)
//	byte 3    : flag = 0x00 (no flood request)
//	bytes 4+  : routerInfoBytes
//
// Performance note: The make() call zero-initializes the buffer even though
// we immediately overwrite all bytes. A micro-optimization would use unsafe
// or a slice of an uninitialized backing array. This is not pursued because:
//   - Called once per connection (not a hot path)
//   - Allocation cost is dominated by the Noise AEAD that immediately follows
//   - Zero-init provides defense-in-depth against partial-write bugs
func buildMsg3Part2Payload(routerInfoBytes []byte) []byte {
	payload := make([]byte, BlockHeaderSize+1+len(routerInfoBytes))
	payload[0] = routerInfoBlockType
	binary.BigEndian.PutUint16(payload[1:3], uint16(1+len(routerInfoBytes)))
	payload[3] = 0x00 // flag byte: no flood request
	copy(payload[4:], routerInfoBytes)
	return payload
}

// verifyLocalRouterInfoMatchesStaticKey is a defense-in-depth check that
// verifies the public key derived from staticPriv (32-byte Curve25519 scalar)
// is actually advertised in riBytes (a serialized RouterInfo).
//
// The check is intentionally cheap: it derives the public key, encodes it
// using i2p-base64 (the encoding used in RouterAddress option mappings),
// and substring-scans riBytes for that 43-character text.
//
// This avoids depending on the full RouterInfo parser (which would create a
// dep cycle: go-noise is below go-i2p in the layer stack). The trade-off is
// that this can produce a false negative if i2p-base64 substring happens to
// appear elsewhere in the RI by coincidence (probability ≈ 2^-258, ignorable).
//
// staticPriv == nil or len != 32 returns nil (no-op): the caller is responsible
// for static-key length validation elsewhere; this helper exists only to
// catch the specific mismatch failure mode and not to second-guess validation.
//
// riBytes == nil or len == 0 also returns nil: caller checks for that
// (msg3 will fail later with a clearer error).
func verifyLocalRouterInfoMatchesStaticKey(staticPriv, riBytes []byte) error {
	if len(staticPriv) != StaticKeySize {
		return nil
	}
	if len(riBytes) == 0 {
		return nil
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return oops.Wrapf(err, "failed to derive Curve25519 public key from static private key")
	}
	pubB64 := i2pbase64.EncodeToString(pub)
	if bytes.Contains(riBytes, []byte(pubB64)) {
		return nil
	}
	return oops.
		With("derived_public_key_b64", pubB64).
		With("ri_bytes_len", len(riBytes)).
		Errorf("derived public key from live NTCP2 static private key does not " +
			"appear in serialized LocalRouterInfo (no NTCP2 address publishes " +
			"this key as its `s=` option)")
}

// randomPaddingLength generates a cryptographically secure random integer in the
// range [0, max] inclusive using rejection sampling to avoid modulo bias.
// This function is used to generate randomized handshake padding lengths that
// match the i2pd/Java I2P distribution per NTCP2 spec §4.3.
//
// Returns an error only if the underlying CSPRNG fails (extremely rare). If max
// is 0, always returns 0 without error.
func randomPaddingLength(max int) (int, error) {
	if max == 0 {
		return 0, nil
	}
	if max < 0 || max > 255 {
		return 0, oops.Code("INVALID_PAD_MAX").In("ntcp2").
			Errorf("randomPaddingLength: max must be in range [0, 255], got %d", max)
	}

	// Use rejection sampling with a single byte to ensure uniform distribution.
	// Find the largest multiple of (max+1) that fits in a byte.
	limit := 256 - (256 % (max + 1))

	for {
		buf, err := cryptorand.RandomBytes(1)
		if err != nil {
			return 0, oops.Code("RAND_FAILED").In("ntcp2").
				Wrapf(err, "cryptorand.RandomBytes failed during padding length generation")
		}
		val := int(buf[0])
		if val < limit {
			return val % (max + 1), nil
		}
		// val >= limit: reject and retry to avoid modulo bias
	}
}
