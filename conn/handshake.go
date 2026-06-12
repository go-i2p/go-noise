package conn

import (
	"context"
	"crypto/ecdh"
	"net"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/mod"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// Handshake performs a single Noise Protocol handshake attempt.
// This must be called before using Read/Write operations.
//
// Handshake always performs exactly one attempt and does not use the
// HandshakeRetries or RetryBackoff configuration fields. To perform a
// handshake with automatic retries and exponential backoff, use
// HandshakeWithRetry instead.
//
// Thread Safety: This method is safe for concurrent use but handshake operations
// are serialized. Only one handshake can be in progress at a time per connection.
// If multiple goroutines call Handshake concurrently, they will be queued and
// execute sequentially. If the handshake is already complete, subsequent calls
// will return immediately without error.
func (nc *Conn) Handshake(ctx context.Context) error {
	nc.handshakeMutex.Lock()
	defer nc.handshakeMutex.Unlock()

	if nc.getState() == mod.StateEstablished {
		return nil // Already completed
	}

	nc.setState(mod.StateHandshaking)
	nc.metrics.SetHandshakeStart()
	nc.logger.WithFields(i2plogger.Fields{
		"pkg":               "noise",
		"func":              "NoiseConn.Handshake",
		"pattern":           nc.config.Pattern,
		"role":              baseconfig.RoleString(nc.config.Initiator),
		"local_addr":        nc.LocalAddr().String(),
		"remote_addr":       nc.RemoteAddr().String(),
		"handshake_timeout": nc.config.HandshakeTimeout,
		"retry_enabled":     nc.config.HandshakeRetries > 0,
		"max_retries":       nc.config.HandshakeRetries,
	}).Info("starting noise protocol handshake")

	timeout := nc.config.HandshakeTimeout
	if timeout <= 0 {
		timeout = baseconfig.DefaultHandshakeTimeout
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, timeout)
	defer cancelHandshake()

	if err := nc.executeRoleBasedHandshake(handshakeCtx); err != nil {
		// On failure, recreate the handshake state so that retry attempts
		// start with fresh nonce counters and chaining key, as required by
		// the Noise protocol specification.
		nc.resetHandshakeState()
		nc.setState(mod.StateInit)
		return err
	}

	// Call post-handshake hook before marking established.
	// This allows protocol layers to derive additional key material
	// (e.g., SipHash keys from the handshake hash for NTCP2).
	if nc.config.PostHandshakeHook != nil {
		if err := nc.config.PostHandshakeHook(nc); err != nil {
			nc.setState(mod.StateInit)
			return oops.
				Code("POST_HANDSHAKE_HOOK_FAILED").
				In("noise").
				Wrapf(err, "post-handshake hook failed")
		}
	}

	nc.markHandshakeComplete()
	return nil
}

// sendNoiseHandshakeMsg writes a Noise handshake message to the underlying connection
// and updates cipher states. The phase parameter specifies the handshake phase for
// modifier chain application. The label parameter identifies the message for error context.
func (nc *Conn) sendNoiseHandshakeMsg(phase handshake.HandshakePhase, label string) error {
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create %s handshake message", label)
	}

	msg, err = nc.applyHandshakeOutbound(phase, msg)
	if err != nil {
		return err
	}

	if err := nc.writeFramedMessage(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send %s handshake message", label)
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// receiveNoiseHandshakeMsg reads a length-prefixed Noise handshake message from
// the underlying connection, processes it via the handshake state, and updates
// cipher states. The phase parameter specifies the handshake phase for modifier
// chain application. The label parameter identifies the message for error context.
func (nc *Conn) receiveNoiseHandshakeMsg(phase handshake.HandshakePhase, label string) error {
	buffer, err := nc.readFramedMessage()
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read %s handshake message", label)
	}

	buffer, err = nc.applyHandshakeInbound(phase, buffer)
	if err != nil {
		return err
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer)
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process %s handshake message", label)
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// updateCipherStates updates the cipher states when they become available.
// Per the Noise spec, Split() returns (cs1, cs2) where:
//   - Initiator uses cs1 for sending and cs2 for receiving
//   - Responder uses cs1 for receiving and cs2 for sending
//
// Both cipher states must be non-nil for the handshake to be considered complete.
// During intermediate handshake messages, one or both may still be nil.
//
// Thread Safety: the cipher-state pointer writes are guarded by stateMutex so
// that they are mutually exclusive with the public accessor methods
// (SendCipherState/RecvCipherState/etc.), which read the same fields under
// stateMutex.RLock(). This is invoked while holding handshakeMutex, so the
// lock-acquisition order is always handshakeMutex -> stateMutex.
func (nc *Conn) updateCipherStates(cs1, cs2 *noise.CipherState) {
	if cs1 == nil && cs2 == nil {
		return
	}

	nc.stateMutex.Lock()
	if nc.config.Initiator {
		// Initiator: cs1 = send, cs2 = receive
		if cs1 != nil {
			nc.sendCipherState = cs1
		}
		if cs2 != nil {
			nc.recvCipherState = cs2
		}
	} else {
		// Responder: cs1 = receive, cs2 = send
		if cs1 != nil {
			nc.recvCipherState = cs1
		}
		if cs2 != nil {
			nc.sendCipherState = cs2
		}
	}
	hasSend := nc.sendCipherState != nil
	hasRecv := nc.recvCipherState != nil
	nc.stateMutex.Unlock()

	nc.logger.WithFields(i2plogger.Fields{
		"pkg":             "noise",
		"func":            "NoiseConn.updateCipherStates",
		"pattern":         nc.config.Pattern,
		"role":            baseconfig.RoleString(nc.config.Initiator),
		"has_send_cs":     hasSend,
		"has_recv_cs":     hasRecv,
		"handshake_ready": hasSend && hasRecv,
	}).Debug("cipher states updated during handshake")
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
func createHandshakeState(config *ConnConfig, privateStaticKey []byte) (*noise.HandshakeState, error) {
	cs := config.CipherSuite
	if cs == nil {
		cs = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	}

	pattern, err := parseHandshakePattern(config.Pattern)
	if err != nil {
		return nil, oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", config.Pattern).
			Wrapf(err, "invalid handshake pattern")
	}

	// Derive the public key from the private key so the upstream library
	// can use it in pre-messages and static key transmission patterns.
	// The StaticKeypair requires both Private and Public to be set;
	// the upstream library does NOT compute the public key automatically.
	// Use the per-connection private key copy to avoid corrupting the caller's config.
	var staticKeypair noise.DHKey
	if len(privateStaticKey) > 0 {
		privKey, err := ecdh.X25519().NewPrivateKey(privateStaticKey)
		if err != nil {
			return nil, oops.
				Code("INVALID_STATIC_KEY").
				In("noise").
				Wrapf(err, "failed to derive public key from static private key")
		}
		staticKeypair = noise.DHKey{
			Private: privateStaticKey,
			Public:  privKey.PublicKey().Bytes(),
		}
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:                  cs,
		Random:                       nil, // Use crypto/rand
		Pattern:                      pattern,
		Initiator:                    config.Initiator,
		ProtocolName:                 config.ProtocolName,
		AdditionalSymmetricKeyLabels: config.AdditionalSymmetricKeyLabels,
		StaticKeypair:                staticKeypair,
		PeerStatic:                   config.RemoteKey,
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
func createNoiseAddresses(underlying net.Conn, config *ConnConfig) (*Addr, *Addr) {
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

// executeRoleBasedHandshake performs handshake based on initiator/responder role.
// It translates the context deadline into a socket-level deadline so that
// underlying Read/Write calls (which do not observe context) are bounded.
func (nc *Conn) executeRoleBasedHandshake(ctx context.Context) error {
	// Enforce context deadline on the underlying socket so that blocking
	// Read/Write calls respect the handshake timeout.
	if deadline, ok := ctx.Deadline(); ok {
		if err := nc.underlying.SetDeadline(deadline); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				Wrapf(err, "failed to set handshake deadline on underlying connection")
		}
		// Clear the deadline once the handshake finishes (or fails) so
		// subsequent data-phase I/O is not accidentally time-limited.
		defer func() {
			if err := nc.underlying.SetDeadline(time.Time{}); err != nil {
				nc.logger.WithFields(i2plogger.Fields{
					"pkg":  "noise",
					"func": "executeRoleBasedHandshake",
				}).Debug("failed to clear handshake deadline")
			}
		}()
	}

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
func (nc *Conn) markHandshakeComplete() {
	nc.setState(mod.StateEstablished)
	nc.metrics.SetHandshakeEnd()
	nc.logger.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.markHandshakeComplete"}).Info("Noise handshake completed successfully")
}

// resetHandshakeState recreates the HandshakeState from the original config
// so that retry attempts begin with fresh nonce counters and chaining key.
// Any partial cipher states from a failed handshake are also cleared.
//
// Thread Safety: the handshakeState and cipher-state pointer writes are guarded
// by stateMutex so they are mutually exclusive with the public accessors that
// read those fields under stateMutex.RLock(). Invoked while holding
// handshakeMutex (order: handshakeMutex -> stateMutex).
func (nc *Conn) resetHandshakeState() {
	hs, err := createHandshakeState(nc.config, nc.privateStaticKey)
	if err != nil {
		nc.logger.WithFields(i2plogger.Fields{
			"pkg":  "noise",
			"func": "NoiseConn.resetHandshakeState", "error": err.Error(),
		}).Error("failed to recreate handshake state for retry")
		return
	}
	nc.stateMutex.Lock()
	nc.handshakeState = hs
	nc.sendCipherState = nil
	nc.recvCipherState = nil
	nc.stateMutex.Unlock()
}

// WriteHandshakeMsgToBytes executes one Noise handshake outbound step with the
// given payload, runs it through the modifier chain, and returns the raw wire
// bytes WITHOUT any length-prefix framing. This is used by protocol-specific
// handshake implementations (e.g. NTCP2) that require exact control over wire
// framing.
//
// The caller is responsible for calling StartHandshake before the first call
// and CompleteHandshake after the final message.
func (nc *Conn) WriteHandshakeMsgToBytes(phase handshake.HandshakePhase, payload []byte) ([]byte, error) {
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create handshake message for phase %v", phase)
	}
	msg, err = nc.applyHandshakeOutbound(phase, msg)
	if err != nil {
		return nil, err
	}
	nc.updateCipherStates(cs1, cs2)
	return msg, nil
}

// ReadHandshakeMsgFromBytes processes raw inbound Noise handshake bytes,
// applies the modifier chain, runs the Noise ReadMessage, and returns the
// decrypted payload. The caller must supply exactly the bytes that form the
// wire message (no length prefix).
//
// The caller is responsible for calling StartHandshake before the first call
// and CompleteHandshake after the final message.
func (nc *Conn) ReadHandshakeMsgFromBytes(phase handshake.HandshakePhase, wireData []byte) ([]byte, error) {
	data, err := nc.applyHandshakeInbound(phase, wireData)
	if err != nil {
		return nil, err
	}
	payload, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, data)
	if err != nil {
		return nil, oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process handshake message for phase %v", phase)
	}
	nc.updateCipherStates(cs1, cs2)
	return payload, nil
}

// StartHandshake transitions the connection to the handshaking state and
// records the handshake start time. Call this once before the first
// WriteHandshakeMsgToBytes or ReadHandshakeMsgFromBytes call.
func (nc *Conn) StartHandshake() {
	nc.setState(mod.StateHandshaking)
	nc.metrics.SetHandshakeStart()
}

// CompleteHandshake marks the connection as fully established after the
// final handshake message has been processed. Call this once after the
// last WriteHandshakeMsgToBytes / ReadHandshakeMsgFromBytes call.
func (nc *Conn) CompleteHandshake() {
	nc.markHandshakeComplete()
}

// RunPostHandshakeHook executes the PostHandshakeHook configured on this
// connection, if one is set. Protocol-specific handshake implementations
// (e.g. NTCP2Conn.Handshake) must call this before CompleteHandshake so
// that post-handshake key derivation (e.g. SipHash keys) runs correctly.
//
// Returns nil if no hook is configured.
func (nc *Conn) RunPostHandshakeHook() error {
	if nc.config.PostHandshakeHook == nil {
		return nil
	}
	return nc.config.PostHandshakeHook(nc)
}

// FailHandshake resets the handshake state machine so that a fresh attempt
// can be made (or so that close/cleanup code sees a consistent state).
func (nc *Conn) FailHandshake() {
	nc.resetHandshakeState()
	nc.setState(mod.StateInit)
}

// GetHandshakeHash returns the hash of the handshake transcript from the
// underlying noise.HandshakeState. This can be used by protocol layers to
// derive post-handshake key material (e.g. SipHash keys for NTCP2 data phase).
func (nc *Conn) GetHandshakeHash() []byte {
	if nc.handshakeState == nil {
		return nil
	}
	h := nc.handshakeState.ChannelBinding()
	if h == nil {
		return nil
	}
	result := make([]byte, len(h))
	copy(result, h)
	return result
}

// MixHashData mixes additional data into the Noise symmetric hash state.
// This is required by the NTCP2 spec to authenticate cleartext padding bytes
// that appear after AEAD frames in messages 1 and 2 (§4.4.1, §4.4.2).
// Call this after reading and discarding cleartext padding, passing the raw
// padding bytes so that the hash state stays in sync with the peer.
func (nc *Conn) MixHashData(data []byte) {
	if nc.handshakeState != nil && len(data) > 0 {
		nc.handshakeState.MixHash(data)
	}
}
