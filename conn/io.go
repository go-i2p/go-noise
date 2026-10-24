package conn

// io.go contains the low-level I/O helpers for NoiseConn:
// read/write framing, encryption, decryption, modifier chain application,
// state validation, and exported crypto/config accessors for the data transport path.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// applyModifierChain passes data through the modifier chain for a given phase.
// isOutbound determines whether ModifyOutbound or ModifyInbound is called.
// Logs at debug level if a chain is applied; returns data unchanged if no chain is configured.
func (nc *Conn) applyModifierChain(isOutbound bool, phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	chain := nc.config.GetModifierChain()
	if chain == nil {
		return data, nil
	}

	var direction, funcName string
	if isOutbound {
		direction = "outbound"
		funcName = "applyOutbound"
	} else {
		direction = "inbound"
		funcName = "applyInbound"
	}

	log.WithFields(i2plogger.Fields{
		"pkg":       "noise",
		"func":      "NoiseConn." + funcName,
		"phase":     phase.String(),
		"data_len":  len(data),
		"direction": direction,
	}).Debug("applying modifier chain")

	if isOutbound {
		return chain.ModifyOutbound(phase, data)
	}
	return chain.ModifyInbound(phase, data)
}

// applyOutboundModifier passes encrypted plaintext through the modifier chain
// for PhaseData (post-handshake data transport). Called by Write before encryption.
// Returns data unchanged if no modifier chain is configured.
// Note: NTCP2 provides a transport-specific override in ntcp2/conn_framing.go.
func (nc *Conn) applyOutboundModifier(data []byte) ([]byte, error) {
	return nc.applyModifierChain(true, handshake.PhaseData, data)
}

// applyInboundModifier passes decrypted plaintext through the modifier chain
// for PhaseData (post-handshake data transport). Called by Read after decryption.
// Returns data unchanged if no modifier chain is configured.
// Note: NTCP2 provides a transport-specific override in ntcp2/conn_framing.go.
func (nc *Conn) applyInboundModifier(data []byte) ([]byte, error) {
	return nc.applyModifierChain(false, handshake.PhaseData, data)
}

// applyHandshakeOutbound passes outgoing handshake data through the modifier
// chain for the given handshake phase. Called by sendNoiseHandshakeMsg after
// WriteMessage and before writeFramedMessage.
func (nc *Conn) applyHandshakeOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return nc.applyModifierChain(true, phase, data)
}

// applyHandshakeInbound passes incoming handshake data through the modifier
// chain for the given handshake phase. Called by receiveNoiseHandshakeMsg after
// readFramedMessage and before ReadMessage.
func (nc *Conn) applyHandshakeInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return nc.applyModifierChain(false, phase, data)
}

// validateConnState validates the connection state before I/O operations.
// isSend: true for write validation, false for read validation.
func (nc *Conn) validateConnState(isSend bool) error {
	if nc.isClosed() {
		return oops.
			Code("CONN_CLOSED").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("connection is closed")
	}

	if !nc.isHandshakeDone() {
		return oops.
			Code("HANDSHAKE_NOT_DONE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("handshake not completed")
	}

	var cipherState *noise.CipherState
	var direction string
	if isSend {
		cipherState = nc.sendCipherState
		direction = "send"
	} else {
		cipherState = nc.recvCipherState
		direction = "receive"
	}

	if cipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("%s cipher state not initialized", direction)
	}

	return nil
}

// validateReadState validates the connection state before reading.
//
// Deprecated: use validateConnState(false) instead.
func (nc *Conn) validateReadState() error {
	return nc.validateConnState(false)
}

// validateWriteState validates the connection state before writing.
//
// Deprecated: use validateConnState(true) instead.
func (nc *Conn) validateWriteState() error {
	return nc.validateConnState(true)
}

// configureWriteTimeout sets the write timeout if configured.
// configureDeadline is a helper for setting read or write deadlines on the underlying connection.
// It accepts a timeout duration and a deadline setter function to avoid code duplication
// between configureReadTimeout and configureWriteTimeout.
func (nc *Conn) configureDeadline(timeout time.Duration, setDeadline func(time.Time) error, timeoutType string) error {
	if timeout > 0 {
		if err := setDeadline(time.Now().Add(timeout)); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				With("timeout", timeout).
				With("type", timeoutType).
				Wrapf(err, "failed to set %s deadline", timeoutType)
		}
	}
	return nil
}

func (nc *Conn) configureWriteTimeout() error {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.configureWriteTimeout", "timeout": nc.config.WriteTimeout}).Debug("setting write deadline")
	return nc.configureDeadline(nc.config.WriteTimeout, nc.underlying.SetWriteDeadline, "write")
}

// encryptData encrypts the provided data using the send cipher state.
func (nc *Conn) encryptData(data []byte) ([]byte, error) {
	encrypted, err := nc.sendCipherState.Encrypt(nil, nil, data)
	if err != nil {
		// Noise spec §11 "Sending and receiving the transport message
		// stream": "If EncryptWithAd() or DecryptWithAd() signal an error due
		// to nonce exhaustion, then the application must delete the CipherState
		// and terminate the session."
		if errors.Is(err, noise.ErrMaxNonce) {
			nc.terminateNonceExhausted("send")
			return nil, oops.
				Code("NONCE_EXHAUSTED").
				In("noise").
				With("direction", "send").
				With("plaintext_len", len(data)).
				Wrapf(err, "send cipher state nonce exhausted; session terminated")
		}
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("noise").
			With("plaintext_len", len(data)).
			Wrapf(err, "failed to encrypt data")
	}
	return encrypted, nil
}

// writeEncryptedData writes a length-prefixed encrypted frame to the
// underlying connection and handles the response. Per Noise spec §13
// "Application responsibilities", each message is preceded by a 2-byte
// big-endian length prefix.
func (nc *Conn) writeEncryptedData(originalData, encryptedData []byte) (int, error) {
	if err := nc.writeFramedMessage(encryptedData); err != nil {
		return 0, oops.
			Code("UNDERLYING_WRITE_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			With("encrypted_len", len(encryptedData)).
			Wrapf(err, "underlying connection write failed")
	}

	// Track metrics for written data
	nc.metrics.AddBytesWritten(int64(len(originalData)))

	nc.logger.WithFields(i2plogger.Fields{
		"pkg":             "noise",
		"func":            "NoiseConn.writeEncryptedData",
		"plaintext_bytes": len(originalData),
		"encrypted_bytes": len(encryptedData),
	}).Trace("encrypted data written to wire")

	return len(originalData), nil
}

// configureReadTimeout sets the read timeout if configured.
func (nc *Conn) configureReadTimeout() error {
	return nc.configureDeadline(nc.config.ReadTimeout, nc.underlying.SetReadDeadline, "read")
}

// readEncryptedData reads a length-prefixed encrypted frame from the
// underlying connection. Per the Noise spec §13 "Application responsibilities",
// each message is preceded by a 2-byte big-endian length field. This method reads the length, then
// reads exactly that many bytes of ciphertext before returning.
func (nc *Conn) readEncryptedData(b []byte) (encryptedData []byte, encryptedLen int, err error) {
	encryptedData, err = nc.readFramedMessage()
	if err != nil {
		return nil, 0, err
	}
	encryptedLen = len(encryptedData)
	return encryptedData, encryptedLen, err
}

// writeFramedMessage writes a 2-byte big-endian length prefix followed by
// the message data to the underlying connection. Per Noise spec §13:
// "applications are recommended to add a 16-bit big-endian length field prior
// to each message."
func (nc *Conn) writeFramedMessage(data []byte) error {
	if len(data) > maxNoiseMessageSize {
		return oops.
			Code("MESSAGE_TOO_LARGE").
			In("noise").
			With("message_len", len(data)).
			With("max_len", maxNoiseMessageSize).
			Errorf("message exceeds maximum Noise message size")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(data)))
	if _, err := nc.underlying.Write(header[:]); err != nil {
		return oops.
			Code("WRITE_LENGTH_FAILED").
			In("noise").
			Wrapf(err, "failed to write message length prefix")
	}
	if _, err := nc.underlying.Write(data); err != nil {
		return oops.
			Code("WRITE_PAYLOAD_FAILED").
			In("noise").
			Wrapf(err, "failed to write message payload")
	}
	return nil
}

// readFramedMessage reads a 2-byte big-endian length prefix from the
// underlying connection, then reads exactly that many bytes. This ensures
// complete Noise messages are received before decryption, preventing
// AES-GCM authentication failures from partial TCP reads.
func (nc *Conn) readFramedMessage() ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(nc.underlying, header[:]); err != nil {
		return nil, oops.
			Code("READ_LENGTH_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			Wrapf(err, "failed to read message length prefix")
	}
	msgLen := binary.BigEndian.Uint16(header[:])
	if msgLen == 0 {
		return nil, oops.
			Code("EMPTY_MESSAGE").
			In("noise").
			Errorf("received zero-length message")
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(nc.underlying, buf); err != nil {
		return nil, oops.
			Code("UNDERLYING_READ_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			With("expected_len", msgLen).
			Wrapf(err, "failed to read complete message")
	}
	return buf, nil
}

// decryptData decrypts the provided encrypted data.
func (nc *Conn) decryptData(encrypted []byte, encryptedLen int) ([]byte, error) {
	decrypted, err := nc.recvCipherState.Decrypt(nil, nil, encrypted)
	if err != nil {
		// Nonce exhaustion is not a recoverable decrypt failure: the session
		// must be terminated (Noise spec §11). A plain authentication failure
		// is left to the caller, which the same section permits.
		if errors.Is(err, noise.ErrMaxNonce) {
			nc.terminateNonceExhausted("receive")
			return nil, oops.
				Code("NONCE_EXHAUSTED").
				In("noise").
				With("direction", "receive").
				With("encrypted_len", encryptedLen).
				Wrapf(err, "receive cipher state nonce exhausted; session terminated")
		}
		return nil, oops.
			Code("DECRYPT_FAILED").
			In("noise").
			With("encrypted_len", encryptedLen).
			Wrapf(err, "failed to decrypt received data")
	}
	return decrypted, nil
}

// copyDecryptedData copies decrypted data to the user buffer and logs the operation.
// If the decrypted data exceeds the user buffer, the excess is stored in pendingPlaintext
// for subsequent Read calls, conforming to the io.Reader contract.
func (nc *Conn) copyDecryptedData(b, decrypted []byte, encryptedLen, decryptedLen int) (int, error) {
	copied := copy(b, decrypted)

	// Store overflow for next Read call
	if copied < len(decrypted) {
		nc.pendingPlaintext = make([]byte, len(decrypted)-copied)
		copy(nc.pendingPlaintext, decrypted[copied:])
	}

	// Track metrics for read data
	nc.metrics.AddBytesRead(int64(copied))

	nc.logger.Trace("Data read", i2plogger.Fields{
		"encrypted_len": encryptedLen,
		"decrypted_len": decryptedLen,
		"copied_len":    copied,
		"pending_len":   len(nc.pendingPlaintext),
	})

	return copied, nil
}

// Encrypt encrypts plaintext data using the connection's cipher state
// without writing to the underlying connection. This lets callers separate
// encryption from wire-level framing, for example NTCP2's SipHash-obfuscated
// length prefix.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
//
// The connection must have completed the Noise handshake.
// Thread Safety: Same guarantees as Write().
func (nc *Conn) Encrypt(data []byte) ([]byte, error) {
	if err := nc.validateWriteState(); err != nil {
		return nil, err
	}
	return nc.encryptData(data)
}

// Decrypt decrypts ciphertext data using the connection's cipher state
// without reading from the underlying connection. This lets callers separate
// decryption from wire-level framing, for example NTCP2's SipHash-obfuscated
// length prefix.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
//
// The connection must have completed the Noise handshake.
// Thread Safety: Same guarantees as Read().
func (nc *Conn) Decrypt(encrypted []byte) ([]byte, error) {
	if err := nc.validateReadState(); err != nil {
		return nil, err
	}
	return nc.decryptData(encrypted, len(encrypted))
}

// Underlying returns the underlying net.Conn for direct wire access.
// This is needed for protocols like NTCP2 that add framing (for example,
// SipHash-obfuscated length prefixes) between the TCP connection and the
// encrypted Noise frames.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
//
// Callers should use Encrypt and Decrypt for the crypto and write or read
// the resulting bytes to and from this connection with their own framing.
func (nc *Conn) Underlying() net.Conn {
	return nc.underlying
}

// Config returns the connection configuration.
func (nc *Conn) Config() *ConnConfig {
	return nc.config
}

// GetModifierChain returns the HandshakeModifier chain from the config.
// It returns nil if no modifiers are configured. NTCP2 framed I/O uses this
// to apply PhaseData transforms (padding, obfuscation) around Encrypt and
// Decrypt.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Conn) GetModifierChain() *handshake.ModifierChain {
	return nc.config.GetModifierChain()
}

// terminateNonceExhausted deletes the cipher state key material and terminates
// the session, as the Noise Protocol Framework requires once a CipherState's
// nonce counter is exhausted.
//
// Noise spec §11: "If EncryptWithAd() or DecryptWithAd() signal an error due to
// nonce exhaustion, then the application must delete the CipherState and
// terminate the session." §5 explains why this is not optional: nonces "are not
// allowed to wrap back to zero due to integer overflow, and the maximum nonce
// value is reserved", so continuing past the ceiling would reuse a nonce under
// the same key.
//
// direction is "send" or "receive", for the log line. Safe to call while the
// caller holds readMutex or writeMutex: ZeroKeys() takes no lock, and Close()
// closes the socket before acquiring those mutexes, so it cannot deadlock here.
func (nc *Conn) terminateNonceExhausted(direction string) {
	nc.logger.Error("nonce exhausted, terminating session per Noise spec section 11",
		"direction", direction,
		"local_addr", nc.LocalAddr().String(),
		"remote_addr", nc.RemoteAddr().String())
	nc.ZeroKeys()
	go func() {
		if err := nc.Close(); err != nil {
			nc.logger.Debug("close after nonce exhaustion returned an error", "error", err.Error())
		}
	}()
}
