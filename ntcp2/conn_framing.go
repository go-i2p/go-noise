package ntcp2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/iobuf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// FrameLengthFieldSize is the size of the SipHash-obfuscated length field.
const FrameLengthFieldSize = 2

// Read implements net.Conn.Read.
// When a length obfuscator is set, reads use NTCP2 framed I/O:
//  1. Return any buffered plaintext from a previous frame first
//  2. Read exactly 2 bytes from the underlying TCP connection
//  3. XOR with SipHash inbound mask to recover the frame length
//  4. Read exactly frameLength bytes of ciphertext from TCP
//  5. Decrypt the ciphertext via the Noise cipher state
//  6. Copy plaintext into the caller's buffer; buffer any remainder
//
// When no length obfuscator is set, delegates directly to NoiseConn.Read.
func (nc *Conn) Read(b []byte) (int, error) {
	if nc.broken.Load() {
		flog("NTCP2Conn.Read").Warn("Read attempted on broken NTCP2 connection")
		return 0, oops.
			Code("CONNECTION_BROKEN").
			In("ntcp2").
			Errorf("connection is broken due to previous framing error (SipHash state desynchronized)")
	}
	// STATE-1 / RACE-3: reject all data-phase reads until the handshake has
	// completed and the SipHash cipher state has been installed. Without this
	// guard a caller can drive readDirect() before cipher keys are set, which
	// either forwards plaintext bytes from the handshake stream or operates on
	// an uninitialised cipher state.
	if !nc.established.Load() {
		return 0, oops.
			Code("NOT_ESTABLISHED").
			In("ntcp2").
			Errorf("NTCP2 handshake not completed")
	}
	if nc.lengthObfuscator.Load() == nil {
		return nc.readDirect(b)
	}
	nc.readMu.Lock()
	defer nc.readMu.Unlock()
	// Drain buffered plaintext from a previous oversized frame first.
	if n, drained := iobuf.DrainPendingBuffer(&nc.readBuffer, b, true); drained || n > 0 {
		return n, nil
	}
	return nc.readFramed(b)
}

// readDirect delegates directly to the underlying NoiseConn for unframed reads.
// Per the io.Reader contract, returns both the bytes read and any error.
// Errors from NoiseConn are returned directly without re-wrapping, since
// NoiseConn already wraps errors with appropriate context.
func (nc *Conn) readDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Read(b)
	if n > 0 {
		nc.logger.Trace("NTCP2 data read (direct)",
			"bytes_read", n,
			"local_addr", nc.localAddr.String(),
			"remote_addr", nc.remoteAddr.String())
	}
	return n, err
}

// readFramed reads an NTCP2 data-phase frame with SipHash length deobfuscation.
func (nc *Conn) readFramed(b []byte) (int, error) {
	if err := nc.guardNonce(nc.readNonce, "read"); err != nil {
		return 0, err
	}

	slm := nc.lengthObfuscator.Load()
	underlying := nc.noiseConn.Underlying()

	frameLen, err := nc.readObfuscatedFrameLength(underlying, slm)
	if err != nil {
		return 0, err
	}

	plaintext, err := nc.readAndDecryptFrame(underlying, frameLen)
	if err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain after decryption (e.g., strip NTCP2 AEAD padding).
	plaintext, err = nc.applyInboundModifier(plaintext)
	if err != nil {
		return 0, err
	}

	n := nc.bufferPlaintext(b, plaintext)

	// Zero the original Decrypt output so sensitive plaintext does not linger
	// on the heap after the caller's buffer (and readBuffer) has been filled.
	// Per the NTCP2 spec: "routers should zero-out any in-memory ephemeral data".
	// Note: bufferPlaintext deep-copies the overflow into readBuffer, so zeroing
	// plaintext here is safe and does not affect the buffered remainder.
	clear(plaintext)

	nc.readNonce++

	nc.logger.Trace("NTCP2 data read (framed)",
		"frame_length", frameLen,
		"plaintext_length", len(plaintext),
		"bytes_copied", n,
		"bytes_buffered", len(plaintext)-n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// readObfuscatedFrameLength reads and deobfuscates the 2-byte SipHash frame length field.
// After this call the SipHash inbound state has advanced; any subsequent error means
// the connection is irrecoverably desynchronized.
func (nc *Conn) readObfuscatedFrameLength(underlying net.Conn, slm *SipHashLengthModifier) (uint16, error) {
	lengthBuf := make([]byte, FrameLengthFieldSize)
	if _, err := io.ReadFull(underlying, lengthBuf); err != nil {
		return 0, oops.
			Code("READ_LENGTH_FAILED").
			In("ntcp2").
			With("read_nonce", nc.readNonce).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame length (frame #%d)", nc.readNonce)
	}

	mask := slm.NextInboundMask()
	obfuscatedLen := binary.BigEndian.Uint16(lengthBuf)
	frameLen := obfuscatedLen ^ mask

	nc.logger.Trace("Frame length deobfuscated",
		"obfuscated_len", obfuscatedLen,
		"mask", mask,
		"frame_len", frameLen,
		"read_nonce", nc.readNonce,
		"remote_addr", nc.remoteAddr.String())

	nc.logger.Debug("SipHash length deobfuscation",
		"obfuscated_raw", fmt.Sprintf("0x%04x", obfuscatedLen),
		"mask", fmt.Sprintf("0x%04x", mask),
		"result", frameLen,
		"read_nonce", nc.readNonce)

	if err := nc.validateFrameLength(frameLen); err != nil {
		nc.broken.Store(true)
		return 0, err
	}
	return frameLen, nil
}

// readAndDecryptFrame reads exactly frameLen bytes of ciphertext from the underlying
// connection and decrypts them via the Noise cipher state. On AEAD failure, applies
// probing-resistance behaviour before returning the error.
func (nc *Conn) readAndDecryptFrame(underlying net.Conn, frameLen uint16) ([]byte, error) {
	ciphertext := make([]byte, frameLen)
	nRead, err := io.ReadFull(underlying, ciphertext)
	if err != nil {
		nc.broken.Store(true)
		flog("NTCP2Conn.readAndDecryptFrame", logger.Fields{"frame_length": frameLen, "bytes_read":   nRead, "read_nonce":   nc.readNonce, "remote_addr":  nc.remoteAddr.String()}).WithError(err).Error("Frame data read failed (SipHash deobfuscated length may be wrong)")
		return nil, oops.
			Code("READ_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("bytes_actually_read", nRead).
			With("read_nonce", nc.readNonce).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame data (frame #%d, expected %d bytes, got %d)", nc.readNonce, frameLen, nRead)
	}

	plaintext, err := nc.noiseConn.Decrypt(ciphertext)
	if err != nil {
		nc.broken.Store(true)
		nc.handleAEADError(underlying)
		return nil, oops.
			Code("DECRYPT_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to decrypt frame")
	}
	return plaintext, nil
}

// bufferPlaintext copies decrypted plaintext into the caller's buffer and stores
// any remainder in readBuffer for subsequent Read calls.
// LEAK-3: cap the readBuffer to prevent a stalling consumer from being used as
// a remote memory-exhaustion vector. The maximum data-phase frame is 65535 bytes;
// a Poly1305 tag adds 16 bytes of overhead, so the largest legitimate overflow is
// SpecMaxFrameSize bytes. Anything larger indicates a bug or an attack.
const maxReadBufferSize = 65535

func (nc *Conn) bufferPlaintext(b, plaintext []byte) int {
	n := copy(b, plaintext)
	overflow := plaintext[n:]
	if len(overflow) > 0 {
		if len(overflow) > maxReadBufferSize {
			// Truncate rather than abort; the frame was already decrypted
			// successfully, so silently discarding excess plaintext is safer
			// than crashing, but flag the connection as broken since the
			// SipHash counter has advanced and the truncated data is lost.
			nc.broken.Store(true)
			flog("NTCP2Conn.bufferPlaintext", logger.Fields{"overflow": len(overflow)}).Error("plaintext overflow exceeds max read buffer; connection is broken")
			overflow = overflow[:maxReadBufferSize]
		}
		nc.readBuffer = make([]byte, len(overflow))
		m := copy(nc.readBuffer, overflow)
		// Zero the tail of readBuffer to prevent leaking previously-decrypted I2NP messages
		// through heap dumps or side-channel disclosure
		for i := m; i < len(nc.readBuffer); i++ {
			nc.readBuffer[i] = 0
		}
	}
	return n
}

// validateFrameLength checks that the deobfuscated frame length is within the
// NTCP2 spec range of MinDataPhaseFrameSize–SpecMaxFrameSize (16–65535).
// Per the spec: "Take the same error action for an invalid length field value
// in the data phase" — i.e., the probing-resistance delay from handleAEADError
// is applied before returning the error.
func (nc *Conn) validateFrameLength(frameLen uint16) error {
	if frameLen < MinDataPhaseFrameSize {
		flog("NTCP2Conn.validateFrameLength", logger.Fields{"frame_length": frameLen}).Warn("Frame length below minimum")
		if underlying := nc.noiseConn.Underlying(); underlying != nil {
			nc.handleAEADError(underlying)
		}
		return oops.
			Code("FRAME_TOO_SMALL").
			In("ntcp2").
			With("frame_length", frameLen).
			With("min_frame_size", MinDataPhaseFrameSize).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("frame length %d below minimum %d", frameLen, MinDataPhaseFrameSize)
	}

	// Note: the FRAME_TOO_LARGE check (frameLen > SpecMaxFrameSize) is omitted here
	// because frameLen is a uint16 and SpecMaxFrameSize == math.MaxUint16 (65535).
	// A uint16 value can never exceed 65535, so the branch is unreachable dead code.
	// The wire-format type constraint enforces the upper bound; no runtime check is needed.

	return nil
}

// Write implements net.Conn.Write.
// When a length obfuscator is set, writes use NTCP2 framed I/O:
//  1. Encrypt the plaintext via the Noise cipher state
//  2. Compute the ciphertext length as a uint16
//  3. XOR with SipHash outbound mask to obfuscate the length
//  4. Write [2-byte obfuscated length][ciphertext] to the underlying TCP connection
//
// When no length obfuscator is set, delegates directly to NoiseConn.Write.
// Large writes are transparently split into multiple frames of at most
// MaxFrameSize minus Poly1305Overhead bytes of plaintext each.
func (nc *Conn) Write(b []byte) (int, error) {
	if nc.broken.Load() {
		flog("NTCP2Conn.Write").Warn("Write attempted on broken NTCP2 connection")
		return 0, oops.
			Code("CONNECTION_BROKEN").
			In("ntcp2").
			Errorf("connection is broken due to previous framing error (SipHash state desynchronized)")
	}
	// STATE-1 / RACE-3: mirror the Read guard — reject writes before the
	// handshake has finished and SipHash outbound keys are installed.
	if !nc.established.Load() {
		return 0, oops.
			Code("NOT_ESTABLISHED").
			In("ntcp2").
			Errorf("NTCP2 handshake not completed")
	}
	if nc.lengthObfuscator.Load() == nil {
		return nc.writeDirect(b)
	}
	return nc.writeFramed(b)
}

// writeDirect delegates directly to the underlying NoiseConn for unframed writes.
// Errors from NoiseConn are returned directly without re-wrapping, since
// NoiseConn already wraps errors with appropriate context.
func (nc *Conn) writeDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Write(b)
	if err != nil {
		return n, err
	}

	nc.logger.Trace("NTCP2 data written (direct)",
		"bytes_written", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// applyOutboundModifier passes plaintext through the NoiseConn's modifier chain
// for PhaseData. Used by the framed write path before Encrypt. Returns data
// unchanged when no modifier chain is configured.
// Note: This is a transport-specific override of conn.Conn.applyOutboundModifier (conn/io.go).
func (nc *Conn) applyOutboundModifier(data []byte) ([]byte, error) {
	chain := nc.noiseConn.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyOutbound(handshake.PhaseData, data)
}

// applyInboundModifier passes decrypted plaintext through the NoiseConn's
// modifier chain for PhaseData. Used by the framed read path after Decrypt.
// Returns data unchanged when no modifier chain is configured.
// Note: This is a transport-specific override of conn.Conn.applyInboundModifier (conn/io.go).
func (nc *Conn) applyInboundModifier(data []byte) ([]byte, error) {
	chain := nc.noiseConn.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyInbound(handshake.PhaseData, data)
}

// writeFramed writes NTCP2 data-phase frame(s) with SipHash length obfuscation.
// Large payloads are transparently split into multiple frames of at most
// getMaxFrameSize() - Poly1305Overhead bytes of plaintext each.
// The frame size is determined by the NTCP2Config if set, otherwise
// falls back to the constant MaxFrameSize. Per the spec, senders should
// "limit frames to a few KB rather than maximizing the frame size."
func (nc *Conn) writeFramed(b []byte) (int, error) {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()

	// Defensive check against config corruption or future atomic-set bugs.
	// Config validation normally ensures getMaxFrameSize() >= 32, but
	// if that invariant is broken, the subtraction below would underflow
	// to a huge uint, causing unbounded allocations.
	maxFrameSize := nc.getMaxFrameSize()
	if maxFrameSize < Poly1305Overhead {
		return 0, oops.
			Code("INVALID_FRAME_SIZE").
			In("ntcp2").
			With("maxFrameSize", maxFrameSize).
			With("poly1305Overhead", Poly1305Overhead).
			Errorf("maxFrameSize %d < Poly1305Overhead %d would underflow", maxFrameSize, Poly1305Overhead)
	}

	maxPlaintext := maxFrameSize - Poly1305Overhead
	totalWritten := 0

	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPlaintext {
			chunk = b[:maxPlaintext]
		}
		b = b[len(chunk):]

		n, err := nc.writeSingleFrame(chunk)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
	}

	return totalWritten, nil
}

// writeSingleFrame encrypts one chunk and writes it as an NTCP2 wire frame.
func (nc *Conn) writeSingleFrame(b []byte) (int, error) {
	if err := nc.guardNonce(nc.writeNonce, "write"); err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain before encryption (e.g., NTCP2 AEAD padding).
	// We encrypt the modified bytes but report the original len(b) to the caller.
	toEncrypt, err := nc.applyOutboundModifier(b)
	if err != nil {
		return 0, err
	}

	encrypted, err := nc.encryptFrame(toEncrypt)
	if err != nil {
		return 0, err
	}

	slm := nc.lengthObfuscator.Load()

	// Diagnostic snapshot of the SipHash outbound state BEFORE the mask is
	// consumed by buildWireFrame. Cheap (uint64 read under mutex); only
	// logged at Warn for the first 3 frames per session below.
	var ivBefore uint64
	if slm != nil {
		ivBefore = slm.PeekOutboundIV()
	}

	frame, mask, err := nc.buildWireFrameWithMask(encrypted, slm)
	if err != nil {
		return 0, err
	}

	bytesWritten, err := nc.writeWireFrame(frame)
	if err != nil {
		return 0, err
	}

	nc.logDiagnosticFrame(slm, b, toEncrypt, encrypted, frame, bytesWritten, mask, ivBefore)

	nc.writeNonce++

	nc.logger.Trace("NTCP2 data written (framed)",
		"plaintext_length", len(b),
		"encrypted_length", len(encrypted),
		"frame_length", len(frame),
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return len(b), nil
}

// logDiagnosticFrame emits bounded Trace-level diagnostics for early outbound
// frames when debug wire-dump mode is enabled.
func (nc *Conn) logDiagnosticFrame(
	slm *SipHashLengthModifier,
	rawPlaintext []byte,
	paddedPlaintext []byte,
	encrypted []byte,
	frame []byte,
	bytesWritten int,
	mask uint16,
	ivBefore uint64,
) {
	// Captures the full pipeline state needed to diagnose silent peer EOFs
	// after handshake. Bounded volume: only first 3 frames per session.
	if nc.writeNonce >= 3 || slm == nil || msg1WireDumpRemaining.Load() <= 0 {
		return
	}

	ivAfter := slm.PeekOutboundIV()
	nc.logger.Trace(
		"NTCP2 outbound frame diagnostic",
		"frame_index", nc.writeNonce,
		"plaintext_len", len(rawPlaintext),
		"padded_plaintext_len", len(paddedPlaintext),
		"ciphertext_len", len(encrypted),
		"wire_frame_len", len(frame),
		"wire_bytes_written", bytesWritten,
		"obfuscated_length_be_hex", fmt.Sprintf("%02x%02x", frame[0], frame[1]),
		"siphash_mask_hex", fmt.Sprintf("%04x", mask),
		"siphash_iv_before_hex", fmt.Sprintf("%016x", ivBefore),
		"siphash_iv_after_hex", fmt.Sprintf("%016x", ivAfter),
	)

	// One-shot plaintext block layout dump for frame 0 only. Plaintext
	// dumps stay Trace-level and should not be enabled in production.
	if nc.writeNonce != 0 {
		return
	}

	rawCap := len(rawPlaintext)
	if rawCap > 64 {
		rawCap = 64
	}
	padCap := len(paddedPlaintext)
	if padCap > 96 {
		padCap = 96
	}

	nc.logger.Trace(
		"NTCP2 outbound frame#0 plaintext dump",
		"raw_plaintext_len", len(rawPlaintext),
		"padded_plaintext_len", len(paddedPlaintext),
		"raw_plaintext_head_hex", hex.EncodeToString(rawPlaintext[:rawCap]),
		"padded_plaintext_head_hex", hex.EncodeToString(paddedPlaintext[:padCap]),
	)
}

// encryptFrame encrypts plaintext and validates the resulting ciphertext size
// against the NTCP2 maximum frame size.
func (nc *Conn) encryptFrame(b []byte) ([]byte, error) {
	encrypted, err := nc.noiseConn.Encrypt(b)
	if err != nil {
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("ntcp2").
			With("plaintext_len", len(b)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to encrypt frame")
	}

	if len(encrypted) > SpecMaxFrameSize {
		return nil, oops.
			Code("FRAME_TOO_LARGE").
			In("ntcp2").
			With("encrypted_len", len(encrypted)).
			With("max_frame_size", SpecMaxFrameSize).
			Errorf("encrypted frame (%d bytes) exceeds maximum frame size (%d)", len(encrypted), SpecMaxFrameSize)
	}
	return encrypted, nil
}

// buildWireFrame constructs the NTCP2 wire frame by prepending a 2-byte SipHash-obfuscated
// length to the ciphertext. After this call the SipHash outbound state has advanced.
func (nc *Conn) buildWireFrame(encrypted []byte, slm *SipHashLengthModifier) ([]byte, error) {
	frame, _, err := nc.buildWireFrameWithMask(encrypted, slm)
	return frame, err
}

// buildWireFrameWithMask is identical to buildWireFrame but also returns the
// SipHash mask used for the obfuscated length field, for diagnostic logging.
// Returns error (L-1) if encrypted frame length exceeds maximum (defense-in-depth check).
func (nc *Conn) buildWireFrameWithMask(encrypted []byte, slm *SipHashLengthModifier) ([]byte, uint16, error) {
	// Defensive check: upstream encryptFrame() guarantees len(encrypted) <= SpecMaxFrameSize (0xFFFF).
	// This guard is unreachable in production, but retained as defense-in-depth
	// to prevent integer overflow during uint16 cast.
	// L-1: Return error instead of panicking
	if len(encrypted) > 0xFFFF {
		return nil, 0, oops.
			Code("FRAME_TOO_LARGE_AT_CAST").
			In("ntcp2").
			With("encrypted_len", len(encrypted)).
			Errorf("encrypted frame length %d exceeds uint16 max; should have been caught by encryptFrame", len(encrypted))
	}
	frameLen := uint16(len(encrypted))
	mask := slm.NextOutboundMask()
	obfuscatedLen := frameLen ^ mask

	frame := make([]byte, FrameLengthFieldSize+len(encrypted))
	binary.BigEndian.PutUint16(frame[:FrameLengthFieldSize], obfuscatedLen)
	copy(frame[FrameLengthFieldSize:], encrypted)
	return frame, mask, nil
}

// writeWireFrame writes the complete wire frame atomically to the underlying TCP connection.
// Marks the connection as broken on any write error or partial write. Returns the
// number of bytes actually accepted by the underlying socket (for diagnostics).
func (nc *Conn) writeWireFrame(frame []byte) (int, error) {
	underlying := nc.noiseConn.Underlying()
	n, err := underlying.Write(frame)
	if err != nil {
		nc.broken.Store(true)
		return n, oops.
			Code("WRITE_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", len(frame)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to write frame")
	}

	if n != len(frame) {
		nc.broken.Store(true)
		return n, oops.
			Code("PARTIAL_WRITE").
			In("ntcp2").
			With("expected", len(frame)).
			With("written", n).
			Errorf("partial frame write: wrote %d of %d bytes", n, len(frame))
	}
	return n, nil
}

// getMaxFrameSize returns the configured maximum frame size for frame splitting.
// If an NTCP2Config is set and has a valid MaxFrameSize, that value is used.
// Otherwise falls back to DefaultMaxFrameSize (16384).
// Per the spec: "it is recommended that the sender limit frames to a few KB
// rather than maximizing the frame size."
func (nc *Conn) getMaxFrameSize() int {
	cfg := nc.ntcp2Config.Load()
	if cfg != nil && cfg.MaxFrameSize > 0 && cfg.MaxFrameSize <= SpecMaxFrameSize {
		return cfg.MaxFrameSize
	}
	return DefaultMaxFrameSize
}
