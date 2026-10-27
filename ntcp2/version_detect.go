package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP/NTCP2 version detection.
//
// ntcp2.md §"Version Detection":
//
//	"When published as \"NTCP\", the router must automatically detect the
//	protocol version for incoming connections."
//
//	"To detect the version of an incoming NTCP connection, Bob proceeds as follows:
//	 - Wait for at least 64 bytes (minimum NTCP2 message 1 size)
//	 - If the initial received data is 288 or more bytes, the incoming connection is version 1.
//	 - If less than 288 bytes, either
//	     - Wait for a short time for more data ... if at least 288 total received, it's NTCP 1.
//	     - Try the first stages of decoding as version 2, if it fails, wait a short
//	       time for more data
//	         - Decrypt the first 32 bytes (the X key) of the SessionRequest packet
//	           using AES-256 with key RH_B.
//	         - Verify a valid point on the curve. If it fails, wait a short time for
//	           more data for NTCP 1
//	         - Verify the AEAD frame. If it fails, wait a short time for more data
//	           for NTCP 1"
//
// A router published as plain "NTCP" listens for NTCP version 1 and NTCP2 on the
// same TCP port, so a responder cannot simply run the NTCP2 handshake: it has to
// decide which protocol it is looking at first, and then either serve it or hand
// it to the legacy transport.
const (
	// ntcp2MinMsg1Size is the smallest possible NTCP2 message 1: the 32-byte
	// obfuscated ephemeral key, the 16-byte encrypted options block and its
	// 16-byte Poly1305 tag, with zero padding. The spec names this number
	// directly: "Wait for at least 64 bytes (minimum NTCP2 message 1 size)".
	ntcp2MinMsg1Size = msg1Size

	// ntcp1SizeThreshold is the byte count that separates the two protocols:
	// "If the initial received data is 288 or more bytes, the incoming connection
	// is version 1." NTCP2 initiators dialing an "NTCP"-published peer keep
	// message 1 (padding included) at or below 287 bytes for exactly this reason
	// — §"1) SessionRequest": "Alice must limit the maximum size of this message,
	// including padding, to 287 bytes or less. This facilitates automatic protocol
	// identification by Bob."
	ntcp1SizeThreshold = 288

	// ntcp2MaxMsg1Size is the largest NTCP2 message 1 Bob will accept: the 64-byte
	// frame plus the 880-byte padding ceiling of §"1) SessionRequest" ("The
	// maximum padding is 880 bytes"). Reading no further bounds the buffered bytes
	// to what the handshake can consume.
	ntcp2MaxMsg1Size = ntcp2MinMsg1Size + 880

	// DefaultVersionDetectTimeout is the "short time" Bob waits for more data
	// before deciding on the bytes already in hand. It is additionally bounded by
	// the handshake deadline, so detection can never widen the slowloris window.
	DefaultVersionDetectTimeout = 100 * time.Millisecond
)

// detectedProtocol is the outcome of version detection.
type detectedProtocol int

const (
	// protocolNTCP2 marks a connection this package continues to serve.
	protocolNTCP2 detectedProtocol = iota
	// protocolNTCP1 marks a connection running the legacy NTCP protocol, which
	// this package does not implement.
	protocolNTCP1
)

func (p detectedProtocol) String() string {
	if p == protocolNTCP1 {
		return "NTCP1"
	}
	return "NTCP2"
}

// VersionDetector handles a connection that version detection identified as NTCP
// version 1.
//
// This package implements NTCP2 only, so the default behaviour is to close such a
// connection. A router published as "NTCP" that also runs an NTCP version 1
// transport registers a detector to hand the connection to it, so the legacy peer
// is served instead of rejected. The detector takes ownership of conn and must
// eventually close it.
type VersionDetector interface {
	// DetectNTCP1 is called with the accepted connection whose initial data was
	// detected as NTCP version 1, together with the bytes already read for
	// detection.
	DetectNTCP1(conn net.Conn, initial []byte)
}

// detectNTCPVersion reads the beginning of an accepted connection, classifies it,
// and returns the bytes it consumed so an NTCP2 handshake can continue from
// exactly the same stream position.
//
// The strategy is the spec's post-adoption one: as soon as a minimum-size message
// 1 is in hand, run the first stage of the NTCP2 decode (decrypt the 32-byte X key
// with AES-256 using RH_B and check it is a valid curve point). A stream that
// crosses 288 bytes, or that fails that check and never fills up, is version 1. A
// conforming NTCP2 initiator therefore costs one read and no extra waiting.
func detectNTCPVersion(cfg *Config, raw net.Conn, deadline time.Time) ([]byte, detectedProtocol, error) {
	window := DefaultVersionDetectTimeout
	if !deadline.IsZero() {
		if remaining := time.Until(deadline); remaining < window {
			window = remaining
		}
	}
	if window <= 0 {
		return nil, protocolNTCP2, oops.
			Code("HANDSHAKE_TIMEOUT").
			In("ntcp2").
			Errorf("version detection: handshake deadline already expired")
	}
	if err := raw.SetReadDeadline(time.Now().Add(window)); err != nil {
		return nil, protocolNTCP2, oops.
			Code("SET_DEADLINE_FAILED").
			In("ntcp2").
			Wrapf(err, "version detection: failed to set the read deadline")
	}

	buf := make([]byte, 0, ntcp2MaxMsg1Size)
	tmp := make([]byte, ntcp2MaxMsg1Size)

	for {
		if len(buf) >= ntcp1SizeThreshold {
			return buf, protocolNTCP1, nil
		}
		// A plausible NTCP2 message 1 is decided on immediately, without waiting
		// out the detection window.
		if len(buf) >= ntcp2MinMsg1Size && classifyNTCP2(cfg, buf) {
			return buf, protocolNTCP2, nil
		}

		n, err := raw.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			// EOF or the deadline. Silence after a full message 1 is the expected
			// NTCP2 case — the initiator waits for our reply — so decide on what
			// arrived rather than treating a stalled stream as an error.
			if len(buf) >= ntcp1SizeThreshold {
				return buf, protocolNTCP1, nil
			}
			if classifyNTCP2(cfg, buf) {
				return buf, protocolNTCP2, nil
			}
			return buf, protocolNTCP1, nil
		}
	}
}

// classifyNTCP2 reports whether initial can plausibly be the start of an NTCP2
// message 1, applying the spec's stage-one check: "Decrypt the first 32 bytes (the
// X key) of the SessionRequest packet using AES-256 with key RH_B. Verify a valid
// point on the curve."
//
// That check is only meaningful for an AES-obfuscated connection, which is what
// §"Version Detection" is about: a published "NTCP" address always carries the
// obfuscation IV. Without obfuscation there is no cheap key-dependent test for a
// length-ambiguous stream, so the bytes go to the normal handshake and its AEAD
// check decides.
func classifyNTCP2(cfg *Config, initial []byte) bool {
	if len(initial) < ntcp2MinMsg1Size {
		// Too short to be any NTCP2 message 1. Nothing better to do than let the
		// handshake read the rest and fail on the AEAD tag if it is not NTCP2.
		return true
	}
	if !cfg.EnableAESObfuscation || len(cfg.ObfuscationIV) != IVSize {
		return true
	}

	// RH_B is the AES-256 key and i= the published 16-byte IV, exactly as the
	// inbound modifier uses them.
	block, err := aes.NewCipher(cfg.BobRouterHash[:])
	if err != nil {
		// A 32-byte router hash cannot fail here; treat an unexpected failure as
		// "indistinguishable" and continue into the handshake instead of dropping
		// a connection on a crypto-library error.
		return true
	}

	x := make([]byte, StaticKeySize)
	cipher.NewCBCDecrypter(block, cfg.ObfuscationIV).CryptBlocks(x, initial[:StaticKeySize])

	// Valid Curve25519 public keys have the high bit of the last byte clear. Same
	// test as AESObfuscationModifier.ModifyInbound applies to message 1.
	if x[StaticKeySize-1]&0x80 != 0 {
		flog("classifyNTCP2", logger.Fields{
			"received_bytes": len(initial),
		}).Debug("first 32 bytes do not decrypt to a valid curve point; treating the connection as NTCP version 1")
		return false
	}
	return true
}

// prefetchConn is an accepted connection whose initial bytes were consumed by
// version detection. Those bytes are replayed to the NTCP2 handshake so the stream
// is seen exactly as it would be without detection, and the real connection stays
// reachable through Unwrap for the TCP-specific operations the handshake and
// teardown paths need.
type prefetchConn struct {
	net.Conn
	prefetched []byte
}

// newPrefetchConn wraps conn so that prefetched is read first.
func newPrefetchConn(conn net.Conn, prefetched []byte) *prefetchConn {
	return &prefetchConn{Conn: conn, prefetched: prefetched}
}

// Unwrap exposes the wrapped connection, following the convention net's own
// wrappers use, so [asTCPConn] can reach the *net.TCPConn.
func (p *prefetchConn) Unwrap() net.Conn { return p.Conn }

// Read drains the prefetched bytes before reading the socket.
func (p *prefetchConn) Read(b []byte) (int, error) {
	if len(p.prefetched) > 0 {
		n := copy(b, p.prefetched)
		if n == len(p.prefetched) {
			p.prefetched = nil
		} else {
			p.prefetched = p.prefetched[n:]
		}
		return n, nil
	}
	return p.Conn.Read(b)
}

// asTCPConn returns the *net.TCPConn behind conn, looking through the wrappers
// this package adds. It returns nil for a connection that is not TCP.
func asTCPConn(conn net.Conn) *net.TCPConn {
	for conn != nil {
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp
		}
		unwrapper, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			return nil
		}
		conn = unwrapper.Unwrap()
	}
	return nil
}
