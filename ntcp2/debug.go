//go:build ntcp2_debug

package ntcp2

// debug.go — NTCP2 wire-dump and interop-diagnostic helpers.
//
// These functions are activated only when the NTCP2_DUMP_MSG1 or
// NTCP2_DUMP_MSG3 environment variables are set to a positive integer N.
// They emit one-shot structured-log dumps for the first N handshakes, then
// become no-ops. They are intentionally separated from handshake.go so that
// the protocol logic is not obscured by instrumentation code.

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
)

// msg1WireDumpRemaining is decremented each time we hex-dump a msg1 wire
// payload. When NTCP2_DUMP_MSG1=N is set in the environment, the first N
// initiator handshakes will emit a one-shot hex dump of the AES key,
// AES IV, full 64-byte msg1, and the 16-byte cleartext options that were
// AEAD-encrypted into bytes 32-63. This is intended for one-shot
// interop debugging against i2pd / Java I2P; it is a no-op when the
// env var is unset or its budget is exhausted.
var (
	msg1WireDumpRemaining atomic.Int32
	msg3WireDumpRemaining atomic.Int32
)

func init() {
	if v := os.Getenv("NTCP2_DUMP_MSG1"); v != "" {
		var n int32
		for _, c := range v {
			if c < '0' || c > '9' {
				return
			}
			n = n*10 + int32(c-'0')
			if n > 1000 {
				n = 1000
				break
			}
		}
		msg1WireDumpRemaining.Store(n)
	}
	if v := os.Getenv("NTCP2_DUMP_MSG3"); v != "" {
		var n int32
		for _, c := range v {
			if c < '0' || c > '9' {
				return
			}
			n = n*10 + int32(c-'0')
			if n > 1000 {
				n = 1000
				break
			}
		}
		msg3WireDumpRemaining.Store(n)
	}
}

// dumpMsg1IfEnabled emits a one-shot hex dump of every cryptographic input
// to NTCP2 message 1 plus the final 64-byte wire payload. It is intended for
// interop debugging against i2pd / Java I2P when peers reject our message 1.
//
// Activation: set NTCP2_DUMP_MSG1=N (positive integer) in the environment.
// The next N initiator handshakes will dump; subsequent handshakes are silent.
//
// Output goes through the structured logger at Info level. The dump exposes
// the peer's published router hash and IV (both already public via netDb)
// and the encrypted msg1 bytes (visible on the wire). It does NOT expose any
// private key material.
func dumpMsg1IfEnabled(cfg *Config, raw interface{}, opts1, msg1 []byte) {
	if msg1WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg1WireDumpRemaining.Add(-1) < 0 {
		return
	}
	fields := logger.Fields{
		"pkg":           "ntcp2",
		"func":          "dumpMsg1IfEnabled",
		"aes_key":       hex.EncodeToString(cfg.BobRouterHash[:]),
		"aes_iv":        hex.EncodeToString(cfg.ObfuscationIV),
		"remote_s":      hex.EncodeToString(cfg.RemoteStaticKey),
		"opts_clear":    hex.EncodeToString(opts1),
		"msg1_wire":     hex.EncodeToString(msg1),
		"msg1_x_obf":    hex.EncodeToString(msg1[:32]),
		"msg1_aead_ct":  hex.EncodeToString(msg1[32:]),
		"local_ri_len":  len(cfg.LocalRouterInfo),
		"protocol_name": NTCP2ProtocolName,
	}
	if nc, ok := raw.(net.Conn); ok && nc != nil {
		if a := nc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := nc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Info("NTCP2 msg1 wire dump (one-shot interop debug)")
}

// dumpInboundMsg1IfEnabled emits a one-shot hex dump of an inbound NTCP2
// message 1 from the responder's perspective. Useful for diagnosing rejected
// peer connections (where decryptedOpts is nil and decryptErr is set) or
// confirming what i2pd actually sends. Shares the NTCP2_DUMP_MSG1 budget
// with the initiator-side dumper.
func dumpInboundMsg1IfEnabled(cfg *Config, raw interface{}, buf1, decryptedOpts []byte, decryptErr error) {
	if msg1WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg1WireDumpRemaining.Add(-1) < 0 {
		return
	}
	fields := logger.Fields{
		"pkg":       "ntcp2",
		"func":      "dumpInboundMsg1IfEnabled",
		"aes_key":   hex.EncodeToString(cfg.BobRouterHash[:]),
		"aes_iv":    hex.EncodeToString(cfg.ObfuscationIV),
		"msg1_wire": hex.EncodeToString(buf1),
	}
	if len(decryptedOpts) > 0 {
		fields["opts_clear"] = hex.EncodeToString(decryptedOpts)
		fields["status"] = "decrypted_ok"
	}
	if decryptErr != nil {
		fields["status"] = "decrypt_failed"
		fields["err"] = decryptErr.Error()
	}
	if nc, ok := raw.(net.Conn); ok && nc != nil {
		if a := nc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := nc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Info("NTCP2 inbound msg1 wire dump (one-shot interop debug)")
}

// classifyMsg2ReadFailure logs a structured classification of a failed
// msg2 read so we can distinguish between three interop failure modes:
//
//  1. bytes_read == 0 + io.EOF:         peer accepted TCP but rejected msg1
//     silently (most likely AEAD failure
//     on their side, or msg1 framing bug).
//  2. bytes_read == 0 + ECONNRESET:     peer sent RST without writing
//     (firewall, banlist, version policy).
//  3. bytes_read in 1..63 + EOF/RST:    peer started msg2 then aborted
//     (msg2 construction bug on their side
//     or our side closing prematurely).
//
// Always logged (not gated by NTCP2_DUMP_MSG1) because it is cheap and the
// most actionable signal for live interop debugging.
func classifyMsg2ReadFailure(cfg *Config, raw interface{}, bytesRead int, err error) {
	var category string
	switch {
	case bytesRead == 0 && errors.Is(err, io.EOF):
		category = "peer_closed_silently_after_msg1"
	case bytesRead == 0:
		category = "peer_reset_after_msg1"
	case bytesRead < msg2Size:
		category = "peer_truncated_msg2"
	default:
		category = "unknown"
	}
	fields := logger.Fields{
		"pkg":        "ntcp2",
		"func":       "classifyMsg2ReadFailure",
		"event":      "msg2_read_failure",
		"category":   category,
		"bytes_read": bytesRead,
		"bytes_want": msg2Size,
		"err":        err.Error(),
	}
	if cfg != nil && cfg.RemoteRouterHash != nil {
		fields["peer_hash_b64"] = base64.StdEncoding.EncodeToString(cfg.RemoteRouterHash[:])
	}
	if nc, ok := raw.(net.Conn); ok && nc != nil {
		if a := nc.RemoteAddr(); a != nil {
			fields["peer"] = a.String()
		}
		if a := nc.LocalAddr(); a != nil {
			fields["local"] = a.String()
		}
	}
	log.WithFields(fields).Warn("NTCP2 msg2 read failed (interop diagnostic)")
}

// dumpMsg3IfEnabled emits a one-shot hex dump of the NTCP2 message 3 wire
// payload (m3p1 + m3p2) plus the inner RouterInfo bytes that were just
// AEAD-encrypted into m3p2. Activation: NTCP2_DUMP_MSG3=N. The dump exposes
// only data already on the wire (after AEAD encryption) and the local
// RouterInfo bytes (which we publish to the netDb anyway). It does NOT
// expose any private key material or the data-phase keys.
func dumpMsg3IfEnabled(cfg *Config, raw interface{}, msg3, riBytes []byte, m3p2Len uint16) {
	if msg3WireDumpRemaining.Load() <= 0 {
		return
	}
	if msg3WireDumpRemaining.Add(-1) < 0 {
		return
	}
	var remote, local string
	if nc, ok := raw.(net.Conn); ok {
		if a := nc.RemoteAddr(); a != nil {
			remote = a.String()
		}
		if a := nc.LocalAddr(); a != nil {
			local = a.String()
		}
	}
	m3p1End := msg3Part1Size
	if m3p1End > len(msg3) {
		m3p1End = len(msg3)
	}
	flog("dumpMsg3IfEnabled", logger.Fields{"event": "ntcp2_msg3_wire_dump", "remote": remote, "local": local, "msg3_len": len(msg3), "m3p1_len": msg3Part1Size, "m3p2_len": int(m3p2Len), "ri_len": len(riBytes), "m3p1_hex": hex.EncodeToString(msg3[:m3p1End]), "m3p2_hex": hex.EncodeToString(msg3[m3p1End:]), "ri_hex": hex.EncodeToString(riBytes), "sent_ns": time.Now().UnixNano()}).Info("NTCP2 msg3 hex dump (wire bytes about to be written)")
	_ = cfg
}
