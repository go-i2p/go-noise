package conn

import (
	"time"

	"github.com/go-i2p/go-noise/mod"
	shutdown "github.com/go-i2p/go-noise/shutdown"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// GetConnectionMetrics returns the current connection statistics
func (nc *Conn) GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration) {
	return nc.metrics.GetStats()
}

// metricsForTest returns the underlying ConnectionMetrics for test access.
// This decouples tests from the internal field name, so only this accessor
// needs updating if the field is renamed or restructured.
func (nc *Conn) metricsForTest() *mod.ConnectionMetrics {
	return nc.metrics
}

// GetConnectionState returns the current connection state
//
// Thread Safety: This method is safe for concurrent use. It uses a read lock
// on the state mutex, allowing multiple goroutines to read the state simultaneously
// while preventing inconsistent reads during state transitions.
func (nc *Conn) GetConnectionState() ConnState {
	return nc.getState()
}

// PeerStatic returns the static public key provided by the remote peer
// during the Noise handshake. Returns nil if the handshake has not completed
// or if the handshake pattern does not transmit a static key.
//
// Thread Safety: This method is safe for concurrent use. Takes stateMutex.RLock()
// to protect access to handshakeState (see LOW-3 audit finding).
func (nc *Conn) PeerStatic() []byte {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()

	if nc.handshakeState == nil {
		log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.PeerStatic"}).Debug("handshake state is nil")
		return nil
	}
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.PeerStatic"}).Debug("returning peer static key")
	return nc.handshakeState.PeerStatic()
}

// ChannelBinding returns the handshake hash (h) from the completed Noise session.
// This is the hash of all handshake transcript data and can be used for:
//   - Channel binding (tying an application-layer credential to the Noise session)
//   - Deriving additional key material via HKDF (e.g., NTCP2's SipHash keys)
//
// Returns nil if the handshake has not been initiated.
//
// Thread Safety: This method is safe for concurrent use. Takes stateMutex.RLock()
// to protect access to handshakeState (see LOW-3 audit finding).
func (nc *Conn) ChannelBinding() []byte {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()

	if nc.handshakeState == nil {
		log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.ChannelBinding"}).Debug("handshake state is nil")
		return nil
	}
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.ChannelBinding"}).Debug("returning handshake hash")
	return nc.handshakeState.ChannelBinding()
}

// SendCipherState returns the send-direction CipherState for direct access
// by protocol layers (e.g., NTCP2 SipHash key derivation).
// Returns nil before the handshake produces cipher states.
//
// Thread Safety: This method is safe for concurrent use. Takes stateMutex.RLock()
// to protect access to sendCipherState (see LOW-3 audit finding).
func (nc *Conn) SendCipherState() *noise.CipherState {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()
	return nc.sendCipherState
}

// RecvCipherState returns the receive-direction CipherState for direct access
// by protocol layers.
// Returns nil before the handshake produces cipher states.
//
// Thread Safety: This method is safe for concurrent use. Takes stateMutex.RLock()
// to protect access to recvCipherState (see LOW-3 audit finding).
func (nc *Conn) RecvCipherState() *noise.CipherState {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()
	return nc.recvCipherState
}

// ZeroKeys securely zeroes the send and receive cipher state key material.
// This delegates to the upstream CipherState.ZeroKey() which overwrites the
// key bytes with zeros and marks the cipher states as invalid.
//
// After calling ZeroKeys, the connection can no longer encrypt or decrypt data.
// Any subsequent Read/Write calls will fail.
func (nc *Conn) ZeroKeys() {
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.ZeroKeys"}).Debug("zeroing cipher state key material")
	if nc.sendCipherState != nil {
		nc.sendCipherState.ZeroKey()
	}
	if nc.recvCipherState != nil {
		nc.recvCipherState.ZeroKey()
	}
}

// AdditionalSymmetricKeys returns the Additional Symmetric Key (ASK) values
// derived during the handshake Split(), per Noise spec §10.3.
// Returns nil if no labels were configured or the handshake hasn't completed.
// The returned keys correspond 1:1 to the configured AdditionalSymmetricKeyLabels.
//
// Thread Safety: This method is safe for concurrent use. Takes stateMutex.RLock()
// to protect access to handshakeState (see M-2 audit finding).
func (nc *Conn) AdditionalSymmetricKeys() [][]byte {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()

	if nc.handshakeState == nil {
		log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.AdditionalSymmetricKeys"}).Debug("handshake state is nil")
		return nil
	}
	keys := nc.handshakeState.AdditionalSymmetricKeys()
	log.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.AdditionalSymmetricKeys", "key_count": len(keys)}).Debug("returning ASK values")
	return keys
}

// Rekey triggers a rekey operation on the underlying cipher state.
// This advances the encryption key material per the Noise Protocol specification
// (encrypts 32 zero bytes with nonce 2^64-1, takes first 32 bytes as new key).
//
// Rekey requires the handshake to be complete (connection in Established state).
// It is safe for concurrent use; the underlying CipherState.Rekey() is mutex-protected.
func (nc *Conn) Rekey() error {
	if nc.getState() != mod.StateEstablished {
		return oops.
			Code("REKEY_INVALID_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("cannot rekey: connection is not in established state")
	}
	if nc.sendCipherState == nil || nc.recvCipherState == nil {
		return oops.
			Code("REKEY_NO_CIPHER").
			In("noise").
			Errorf("cipher states not available for rekeying")
	}
	nc.sendCipherState.Rekey()
	nc.recvCipherState.Rekey()
	nc.logger.WithFields(i2plogger.Fields{
		"pkg":         "noise",
		"func":        "NoiseConn.Rekey",
		"pattern":     nc.config.Pattern,
		"local_addr":  nc.localAddr.String(),
		"remote_addr": nc.remoteAddr.String(),
	}).Info("Rekey completed")
	return nil
}

// SetShutdownManager sets the shutdown manager for this connection.
// If a shutdown manager is set, the connection will be automatically
// registered for graceful shutdown coordination.
func (nc *Conn) SetShutdownManager(sm shutdown.Shutdowner) {
	nc.shutdownManager = sm
	if sm != nil {
		sm.RegisterConnection(nc)
	}
}

// getState returns the current connection state in a thread-safe manner
func (nc *Conn) getState() mod.ConnState {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()
	return nc.state
}

// setState sets the connection state in a thread-safe manner
func (nc *Conn) setState(newState mod.ConnState) {
	nc.stateMutex.Lock()
	defer nc.stateMutex.Unlock()

	oldState := nc.state
	nc.state = newState

	nc.logger.WithFields(i2plogger.Fields{
		"old_state": oldState.String(),
		"new_state": newState.String(),
	}).Debug("Connection state changed")
}

// isClosed returns true if the connection is closed.
// Provided for test code; production code should use getState() == mod.StateClosed directly.
func (nc *Conn) isClosed() bool {
	return nc.getState() == mod.StateClosed
}

// isHandshakeDone returns true if the handshake is complete.
// Provided for test code; production code should use getState() == mod.StateEstablished directly.
func (nc *Conn) isHandshakeDone() bool {
	state := nc.getState()
	return state == mod.StateEstablished
}
