package noise

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/noise"
	"github.com/go-i2p/go-noise/internal"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// NoiseConn implements net.Conn with Noise Protocol encryption.
// It wraps an underlying net.Conn and provides encrypted communication
// following the Noise Protocol Framework specification.
type NoiseConn struct {
	// underlying is the wrapped network connection
	underlying net.Conn

	// config contains the Noise protocol configuration
	config *ConnConfig

	// cipherState handles encryption/decryption after handshake
	cipherState *noise.CipherState

	// handshakeState handles the handshake process
	handshakeState *noise.HandshakeState

	// localAddr is the local Noise address
	localAddr *NoiseAddr

	// remoteAddr is the remote Noise address
	remoteAddr *NoiseAddr

	// state tracks the connection lifecycle and metrics
	state internal.ConnState

	// metrics tracks connection performance data
	metrics *internal.ConnectionMetrics

	// stateMutex protects state transitions
	stateMutex sync.RWMutex

	// handshakeMutex protects handshake operations
	handshakeMutex sync.Mutex

	// logger for connection events
	logger *logger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager *ShutdownManager

	// closeMutex protects close operations
	closeMutex sync.Mutex
}

// NewNoiseConn creates a new NoiseConn wrapping the underlying connection.
// The handshake must be completed before using Read/Write operations.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*NoiseConn, error) {
	if err := validateNewConnParams(underlying, config); err != nil {
		return nil, err
	}

	hs, err := createHandshakeState(config)
	if err != nil {
		return nil, err
	}

	localAddr, remoteAddr := createNoiseAddresses(underlying, config)

	nc := &NoiseConn{
		underlying:     underlying,
		config:         config,
		handshakeState: hs,
		localAddr:      localAddr,
		remoteAddr:     remoteAddr,
		logger:         log,
		metrics:        internal.NewConnectionMetrics(),
		state:          internal.StateInit,
	}

	nc.logger.Debug("NoiseConn created")
	return nc, nil
}

// Read reads data from the connection.
// If the handshake is not complete, it will return an error.
func (nc *NoiseConn) Read(b []byte) (int, error) {
	if err := nc.validateReadState(); err != nil {
		return 0, err
	}

	if err := nc.configureReadTimeout(); err != nil {
		return 0, err
	}

	encrypted, n, err := nc.readEncryptedData(b)
	if err != nil {
		return 0, err
	}

	decrypted, err := nc.decryptData(encrypted[:n], n)
	if err != nil {
		return 0, err
	}

	return nc.copyDecryptedData(b, decrypted, n, len(decrypted))
}

// Write writes data to the connection.
// If the handshake is not complete, it will return an error.
func (nc *NoiseConn) Write(b []byte) (int, error) {
	if err := nc.validateWriteState(); err != nil {
		return 0, err
	}

	if err := nc.configureWriteTimeout(); err != nil {
		return 0, err
	}

	encrypted, err := nc.encryptData(b)
	if err != nil {
		return 0, err
	}

	return nc.writeEncryptedData(b, encrypted)
}

// validateWriteState validates the connection state before writing.
func (nc *NoiseConn) validateWriteState() error {
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

	if nc.cipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			Errorf("cipher state not initialized")
	}

	return nil
}

// configureWriteTimeout sets the write timeout if configured.
func (nc *NoiseConn) configureWriteTimeout() error {
	if nc.config.WriteTimeout > 0 {
		if err := nc.underlying.SetWriteDeadline(time.Now().Add(nc.config.WriteTimeout)); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				With("timeout", nc.config.WriteTimeout).
				Wrapf(err, "failed to set write deadline")
		}
	}
	return nil
}

// encryptData encrypts the provided data using the cipher state.
func (nc *NoiseConn) encryptData(data []byte) ([]byte, error) {
	encrypted, err := nc.cipherState.Encrypt(nil, nil, data)
	// encrypted, err := nc.cipherState.Encrypt(nil, nil, data)
	if err != nil {
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("noise").
			With("plaintext_len", len(data)).
			Wrapf(err, "failed to encrypt data")
	}
	return encrypted, nil
}

// writeEncryptedData writes encrypted data to the underlying connection and handles the response.
func (nc *NoiseConn) writeEncryptedData(originalData, encryptedData []byte) (int, error) {
	n, err := nc.underlying.Write(encryptedData)
	if err != nil {
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

	nc.logger.WithFields(logrus.Fields{
		"plaintext_len": len(originalData),
		"encrypted_len": len(encryptedData),
		"written_len":   n,
	}).Trace("Data written")

	if n == len(encryptedData) {
		return len(originalData), nil
	}

	return 0, oops.
		Code("PARTIAL_WRITE").
		In("noise").
		With("expected", len(encryptedData)).
		With("written", n).
		Errorf("partial write not supported with encryption")
}

// Close closes the connection.
func (nc *NoiseConn) Close() error {
	nc.closeMutex.Lock()
	defer nc.closeMutex.Unlock()

	if nc.isClosed() {
		return nil // Already closed
	}

	nc.setState(internal.StateClosed)
	nc.logger.Debug("Closing NoiseConn")

	// Unregister from shutdown manager if set
	if nc.shutdownManager != nil {
		nc.shutdownManager.UnregisterConnection(nc)
	}

	err := nc.underlying.Close()
	if err != nil {
		return oops.
			Code("UNDERLYING_CLOSE_FAILED").
			In("noise").
			With("state", nc.getState().String()).
			Wrapf(err, "failed to close underlying connection")
	}

	return nil
}

// GetConnectionMetrics returns the current connection statistics
func (nc *NoiseConn) GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration) {
	return nc.metrics.GetStats()
}

// GetConnectionState returns the current connection state
func (nc *NoiseConn) GetConnectionState() internal.ConnState {
	return nc.getState()
}

// SetShutdownManager sets the shutdown manager for this connection.
// If a shutdown manager is set, the connection will be automatically
// registered for graceful shutdown coordination.
func (nc *NoiseConn) SetShutdownManager(sm *ShutdownManager) {
	nc.shutdownManager = sm
	if sm != nil {
		sm.RegisterConnection(nc)
	}
}

// LocalAddr returns the local network address.
func (nc *NoiseConn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr returns the remote network address.
func (nc *NoiseConn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (nc *NoiseConn) SetDeadline(t time.Time) error {
	if err := nc.underlying.SetDeadline(t); err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set deadline on underlying connection")
	}
	return nil
}

// SetReadDeadline sets the read deadline.
func (nc *NoiseConn) SetReadDeadline(t time.Time) error {
	if err := nc.underlying.SetReadDeadline(t); err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set read deadline on underlying connection")
	}
	return nil
}

// SetWriteDeadline sets the write deadline.
func (nc *NoiseConn) SetWriteDeadline(t time.Time) error {
	if err := nc.underlying.SetWriteDeadline(t); err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set write deadline on underlying connection")
	}
	return nil
}

// Handshake performs the Noise Protocol handshake.
// This must be called before using Read/Write operations.
func (nc *NoiseConn) Handshake(ctx context.Context) error {
	nc.handshakeMutex.Lock()
	defer nc.handshakeMutex.Unlock()

	if nc.isHandshakeDone() {
		return nil // Already completed
	}

	nc.setState(internal.StateHandshaking)
	nc.metrics.SetHandshakeStart()
	nc.logger.Info("Starting Noise handshake")

	handshakeCtx := nc.createHandshakeContext(ctx)
	defer handshakeCtx.cancel()

	if err := nc.executeRoleBasedHandshake(handshakeCtx.ctx); err != nil {
		// On failure, return to init state for potential retry
		nc.setState(internal.StateInit)
		return err
	}

	nc.markHandshakeComplete()
	return nil
}

// performInitiatorHandshake handles the initiator side of the handshake.
func (nc *NoiseConn) performInitiatorHandshake(ctx context.Context) error {
	// This is a simplified implementation - real implementation would
	// follow the specific Noise pattern message flow

	// Write initial message
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to write handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send handshake message")
	}

	// Store cipher states (simplified)
	if cs1 != nil && cs2 != nil {
		// For initiator, typically use cs1 for sending
		nc.cipherState = cs1
	}

	return nil
}

// performResponderHandshake handles the responder side of the handshake.
func (nc *NoiseConn) performResponderHandshake(ctx context.Context) error {
	// This is a simplified implementation - real implementation would
	// follow the specific Noise pattern message flow

	// Read initial message
	buffer := make([]byte, 1024)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read handshake message")
	}

	// Process message
	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process handshake message")
	}

	// Store cipher states (simplified)
	if cs1 != nil && cs2 != nil {
		// For responder, typically use cs2 for sending
		nc.cipherState = cs2
	}

	return nil
}

// parseHandshakePattern maps pattern name strings to go-i2p/noise HandshakePattern types.
// This enables configurable pattern selection from string-based configuration.
func parseHandshakePattern(patternName string) (noise.HandshakePattern, error) {
	switch patternName {
	case "Noise_NN_25519_AESGCM_SHA256", "NN":
		return noise.HandshakeNN, nil
	case "Noise_NK_25519_AESGCM_SHA256", "NK":
		return noise.HandshakeNK, nil
	case "Noise_NX_25519_AESGCM_SHA256", "NX":
		return noise.HandshakeNX, nil
	case "Noise_XN_25519_AESGCM_SHA256", "XN":
		return noise.HandshakeXN, nil
	case "Noise_XK_25519_AESGCM_SHA256", "XK":
		return noise.HandshakeXK, nil
	case "Noise_XX_25519_AESGCM_SHA256", "XX":
		return noise.HandshakeXX, nil
	case "Noise_KN_25519_AESGCM_SHA256", "KN":
		return noise.HandshakeKN, nil
	case "Noise_KK_25519_AESGCM_SHA256", "KK":
		return noise.HandshakeKK, nil
	case "Noise_KX_25519_AESGCM_SHA256", "KX":
		return noise.HandshakeKX, nil
	case "Noise_IN_25519_AESGCM_SHA256", "IN":
		return noise.HandshakeIN, nil
	case "Noise_IK_25519_AESGCM_SHA256", "IK":
		return noise.HandshakeIK, nil
	case "Noise_IX_25519_AESGCM_SHA256", "IX":
		return noise.HandshakeIX, nil
	case "Noise_N_25519_AESGCM_SHA256", "N":
		return noise.HandshakeN, nil
	case "Noise_K_25519_AESGCM_SHA256", "K":
		return noise.HandshakeK, nil
	case "Noise_X_25519_AESGCM_SHA256", "X":
		return noise.HandshakeX, nil
	default:
		return noise.HandshakePattern{}, oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			With("pattern", patternName).
			Errorf("unsupported handshake pattern: %s", patternName)
	}
}

// validateReadState validates the connection state before reading.
func (nc *NoiseConn) validateReadState() error {
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

	if nc.cipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("cipher state not initialized")
	}

	return nil
}

// configureReadTimeout sets the read timeout if configured.
func (nc *NoiseConn) configureReadTimeout() error {
	if nc.config.ReadTimeout > 0 {
		if err := nc.underlying.SetReadDeadline(time.Now().Add(nc.config.ReadTimeout)); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				With("timeout", nc.config.ReadTimeout).
				Wrapf(err, "failed to set read deadline")
		}
	}
	return nil
}

// readEncryptedData reads encrypted data from the underlying connection.
func (nc *NoiseConn) readEncryptedData(b []byte) ([]byte, int, error) {
	encrypted := make([]byte, len(b)+16) // Additional space for auth tag
	n, err := nc.underlying.Read(encrypted)
	if err != nil {
		return nil, 0, oops.
			Code("UNDERLYING_READ_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			Wrapf(err, "underlying connection read failed")
	}
	return encrypted, n, nil
}

// decryptData decrypts the provided encrypted data.
func (nc *NoiseConn) decryptData(encrypted []byte, encryptedLen int) ([]byte, error) {
	decrypted, err := nc.cipherState.Decrypt(nil, nil, encrypted)
	if err != nil {
		return nil, oops.
			Code("DECRYPT_FAILED").
			In("noise").
			With("encrypted_len", encryptedLen).
			Wrapf(err, "failed to decrypt received data")
	}
	return decrypted, nil
}

// copyDecryptedData copies decrypted data to the user buffer and logs the operation.
func (nc *NoiseConn) copyDecryptedData(b, decrypted []byte, encryptedLen, decryptedLen int) (int, error) {
	copied := copy(b, decrypted)

	// Track metrics for read data
	nc.metrics.AddBytesRead(int64(copied))

	nc.logger.Trace("Data read", logrus.Fields{
		"encrypted_len": encryptedLen,
		"decrypted_len": decryptedLen,
		"copied_len":    copied,
	})

	return copied, nil
}

// validateNewConnParams validates the parameters for creating a new NoiseConn.
func validateNewConnParams(underlying net.Conn, config *ConnConfig) error {
	if underlying == nil {
		return oops.
			Code("INVALID_CONN").
			In("noise").
			Errorf("underlying connection cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("noise").
			Errorf("config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("noise").
			Wrapf(err, "config validation failed")
	}

	return nil
}

// createHandshakeState creates and initializes the Noise handshake state.
func createHandshakeState(config *ConnConfig) (*noise.HandshakeState, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

	pattern, err := parseHandshakePattern(config.Pattern)
	if err != nil {
		return nil, oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", config.Pattern).
			Wrapf(err, "invalid handshake pattern")
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      nil, // Use crypto/rand
		Pattern:     pattern,
		Initiator:   config.Initiator,
		StaticKeypair: noise.DHKey{
			Private: config.StaticKey,
			Public:  nil, // Will be computed
		},
	})
	if err != nil {
		return nil, oops.
			Code("HANDSHAKE_INIT_FAILED").
			In("noise").
			With("pattern", config.Pattern).
			With("initiator", config.Initiator).
			Wrapf(err, "failed to create handshake state")
	}

	return hs, nil
}

// createNoiseAddresses creates local and remote Noise addresses.
func createNoiseAddresses(underlying net.Conn, config *ConnConfig) (*NoiseAddr, *NoiseAddr) {
	role := "responder"
	if config.Initiator {
		role = "initiator"
	}

	localAddr := NewNoiseAddr(underlying.LocalAddr(), config.Pattern, role)

	remoteRole := "initiator"
	if config.Initiator {
		remoteRole = "responder"
	}
	remoteAddr := NewNoiseAddr(underlying.RemoteAddr(), config.Pattern, remoteRole)

	return localAddr, remoteAddr
}

// handshakeContext encapsulates context management for handshake operations.
type handshakeContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// createHandshakeContext creates a context with timeout for handshake operations.
func (nc *NoiseConn) createHandshakeContext(ctx context.Context) *handshakeContext {
	handshakeCtx, cancel := context.WithTimeout(ctx, nc.config.HandshakeTimeout)
	return &handshakeContext{
		ctx:    handshakeCtx,
		cancel: cancel,
	}
}

// executeRoleBasedHandshake performs handshake based on initiator/responder role.
func (nc *NoiseConn) executeRoleBasedHandshake(ctx context.Context) error {
	if nc.config.Initiator {
		if err := nc.performInitiatorHandshake(ctx); err != nil {
			return oops.
				Code("INITIATOR_HANDSHAKE_FAILED").
				In("noise").
				Wrapf(err, "initiator handshake failed")
		}
	} else {
		if err := nc.performResponderHandshake(ctx); err != nil {
			return oops.
				Code("RESPONDER_HANDSHAKE_FAILED").
				In("noise").
				Wrapf(err, "responder handshake failed")
		}
	}
	return nil
}

// markHandshakeComplete sets the handshake completion state and logs success.
func (nc *NoiseConn) markHandshakeComplete() {
	nc.setState(internal.StateEstablished)
	nc.metrics.SetHandshakeEnd()
	nc.logger.Info("Noise handshake completed successfully")
}

// isClosed returns true if the connection is closed
func (nc *NoiseConn) isClosed() bool {
	return nc.getState() == internal.StateClosed
}

// isHandshakeDone returns true if the handshake is complete
func (nc *NoiseConn) isHandshakeDone() bool {
	state := nc.getState()
	return state == internal.StateEstablished || state == internal.StateClosed
}

// getState returns the current connection state in a thread-safe manner
func (nc *NoiseConn) getState() internal.ConnState {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()
	return nc.state
}

// setState sets the connection state in a thread-safe manner
func (nc *NoiseConn) setState(newState internal.ConnState) {
	nc.stateMutex.Lock()
	defer nc.stateMutex.Unlock()

	oldState := nc.state
	nc.state = newState

	nc.logger.WithFields(logrus.Fields{
		"old_state": oldState.String(),
		"new_state": newState.String(),
	}).Debug("Connection state changed")
}
