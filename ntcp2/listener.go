package ntcp2

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Listener implements net.Listener for accepting NTCP2 transport connections.
// It accepts raw TCP connections from the underlying listener, wraps each in a
// NoiseConn created via NTCP2Config.ToConnConfig() (which sets the correct
// CipherSuite, ProtocolName, and Modifiers), and then wraps that in an NTCP2Conn.
type Listener struct {
	// underlying is the raw TCP listener
	underlying net.Listener

	// config contains the NTCP2-specific configuration
	config *Config

	// addr is the NTCP2 address for this listener
	addr *Addr

	// logger for listener events (pointer so runtime log-level changes are visible)
	logger *logger.Logger

	// closed indicates if the listener has been closed (atomic for lock-free reads)
	closed atomic.Bool
}

// NewNTCP2Listener creates a new NTCP2Listener that wraps the underlying TCP listener.
// The listener will accept connections and wrap them in NTCP2Conn instances
// configured as responders with NTCP2-specific addressing and protocol handling.
func NewNTCP2Listener(underlying net.Listener, config *Config) (*Listener, error) {
	if err := validateListenerInput(underlying, config); err != nil {
		return nil, err
	}

	ntcp2Addr, err := createNTCP2Address(underlying, config)
	if err != nil {
		return nil, err
	}

	return initializeListener(underlying, config, ntcp2Addr), nil
}

// validateListenerInput checks if the underlying listener and config parameters are valid
func validateListenerInput(underlying net.Listener, config *Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_UNDERLYING_LISTENER").
			In("ntcp2").
			Errorf("underlying listener cannot be nil")
	}

	if err := validateConfigPresence(config); err != nil {
		return err
	}

	if err := validateConfigValue(config); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "invalid ntcp2 listener configuration")
	}

	return nil
}

// createNTCP2Address creates the NTCP2 address for the listener from the underlying address and config
func createNTCP2Address(underlying net.Listener, config *Config) (*Addr, error) {
	ntcp2Addr, err := NewNTCP2Addr(underlying.Addr(), config.BobRouterHash, "responder")
	if err != nil {
		return nil, oops.
			Code("ADDR_CREATION_FAILED").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "failed to create ntcp2 address")
	}

	return ntcp2Addr, nil
}

// initializeListener creates and configures the final NTCP2Listener with logging
func initializeListener(underlying net.Listener, config *Config, ntcp2Addr *Addr) *Listener {
	nl := &Listener{
		underlying: underlying,
		config:     config,
		addr:       ntcp2Addr,
		logger:     log,
	}

	nl.logger.Info("NTCP2 listener created",
		"pattern", config.Pattern,
		"listener_address", underlying.Addr().String(),
		"router_hash", formatRouterHash(config.BobRouterHash))

	return nl
}

// createResponderConnConfig creates a ConnConfig for an accepted (responder)
// connection via the full NTCP2Config.ToConnConfig() path, ensuring the
// CipherSuite, ProtocolName, and Modifiers are all correctly set.
// It also returns the per-connection NTCP2Config so the PostHandshakeHook's
// SipHash keys can be propagated to the NTCP2Conn after handshake.
func (nl *Listener) createResponderConnConfig() (*noise.ConnConfig, *Config, error) {
	// Clone the listener's config to get an independent per-connection config.
	// Clone() avoids copying the atomic.Pointer and is resilient to new fields.
	responderCfg := nl.config.Clone()
	responderCfg.Initiator = false
	connConfig, err := responderCfg.ToConnConfig()
	if err != nil {
		return nil, nil, oops.
			Code("CONN_CONFIG_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to create responder ConnConfig")
	}
	return connConfig, responderCfg, nil
}

// createRemoteNTCP2Addr creates the remote NTCP2 address for the accepted connection.
// Note: PeerStatic() returns the remote peer's Noise static public key (32 bytes).
// The NTCP2 spec defines the router hash as SHA-256(RouterIdentity), where the
// static key is only part of the full RouterIdentity.  As a placeholder we use
// SHA-256(static_key), which is a deterministic 32-byte value derived from the
// peer's long-term identity material rather than the raw key bytes (AUDIT 5.3).
// The router transport layer should call PropagatePeerStaticKey() after handshake
// completion and ultimately replace this placeholder with the proper
// SHA-256(RouterIdentity) once the full RouterIdentity is available from msg3.
func (nl *Listener) createRemoteNTCP2Addr(noiseConn *noise.NoiseConn) (*Addr, error) {
	var remoteHash data.Hash
	remoteRouterHash := noiseConn.PeerStatic()
	if len(remoteRouterHash) >= 32 {
		// AUDIT 5.3: Hash the static key with SHA-256 rather than copying the
		// raw bytes directly into the Hash field.  data.NewHashFromSlice stores
		// the 32-byte key verbatim which is not SHA-256(RouterIdentity).
		remoteHash = data.HashData(remoteRouterHash[:32])
	} else if nl.config.RemoteRouterHash != nil {
		remoteHash = *nl.config.RemoteRouterHash
	}
	// else remoteHash stays zero value

	remoteAddr, err := NewNTCP2Addr(noiseConn.RemoteAddr(), remoteHash, "initiator")
	if err != nil {
		return nil, oops.
			Code("REMOTE_ADDR_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create remote ntcp2 address")
	}
	return remoteAddr, nil
}

// wrapInNTCP2Conn wraps the noise connection in an NTCP2Conn.
// perConnConfig is the per-connection NTCP2Config whose PostHandshakeHook
// will store derived SipHash keys; it is saved on the conn so that
// PropagateSipHash() can copy them after the handshake completes.
func (nl *Listener) wrapInNTCP2Conn(noiseConn *noise.NoiseConn, remoteAddr *Addr, perConnConfig *Config) (*Conn, error) {
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, nl.addr, remoteAddr)
	if err != nil {
		return nil, oops.
			Code("NTCP2_WRAP_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create ntcp2 connection")
	}

	// Store the per-connection config so PropagateSipHash can read derived keys.
	ntcp2Conn.SetNTCP2Config(perConnConfig)

	return ntcp2Conn, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection is wrapped in an NTCP2Conn configured as a responder
// with the full NTCP2 cipher suite, protocol name, and modifiers.
//
// The returned connection has NOT yet performed the Noise handshake.
// RemoteAddr().(*Addr).RouterHash is a zero value until Handshake(ctx) and
// PropagatePeerStaticKey() complete. Most callers should use
// AcceptWithHandshake (if available) or call Handshake explicitly after Accept.
func (nl *Listener) Accept() (net.Conn, error) {
	if err := nl.validateAcceptState(); err != nil {
		return nil, err
	}

	// Accept raw TCP connection from the underlying listener.
	// No mutex needed: isClosed() uses atomic.Bool, and
	// net.TCPListener.Accept() is concurrency-safe.
	underlying, err := nl.underlying.Accept()
	if err != nil {
		return nil, oops.
			Code("ACCEPT_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to accept connection")
	}

	// Create ConnConfig with full NTCP2 settings (CipherSuite, ProtocolName, Modifiers).
	connConfig, perConnConfig, err := nl.createResponderConnConfig()
	if err != nil {
		underlying.Close()
		return nil, err
	}

	// Wrap in NoiseConn using the properly configured ConnConfig.
	noiseConn, err := noise.NewNoiseConn(underlying, connConfig)
	if err != nil {
		underlying.Close()
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", underlying.RemoteAddr().String()).
			Wrapf(err, "failed to create noise connection")
	}

	// BUG-RC-2 / BUG-SM-2: Compute the single authoritative handshake deadline
	// from the moment Accept() returns. Store it on the conn so Handshake() can
	// use min(derived, acceptDeadline) rather than resetting to time.Now()+timeout
	// (which would grant the peer an extra window if the caller delays).
	//
	// IMPORTANT — caller configuration note:
	// The effective handshake timeout is driven by connConfig.HandshakeTimeout,
	// which comes from the NTCP2Config passed to NewNTCP2Listener. To obtain a
	// longer timeout (e.g. 60 s) the caller MUST use
	//
	//   cfg = cfg.WithHandshakeTimeout(60 * time.Second)
	//
	// before constructing the listener. Passing a longer-deadline context to
	// Handshake() alone is NOT sufficient: this Accept() path sets the TCP
	// deadline immediately from the config value, and Handshake() uses
	// min(ctx_deadline, acceptDeadline) so the config value is the hard cap.
	handshakeTimeout := connConfig.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeoutSeconds * time.Second
	}
	acceptDeadline := time.Now().Add(handshakeTimeout)
	// Set the deadline immediately so the TCP stack enforces it even before
	// Handshake() is called (BUG-EH-2 fix: check and log the error).
	if tcpConn, ok := underlying.(*net.TCPConn); ok {
		if err := tcpConn.SetDeadline(acceptDeadline); err != nil {
			flog("Accept", logger.Fields{"error": err}).Warn("failed to set initial handshake deadline on accepted TCP conn")
		}
	}

	remoteAddr, err := nl.createRemoteNTCP2Addr(noiseConn)
	if err != nil {
		noiseConn.Close()
		return nil, err
	}

	ntcp2Conn, err := nl.wrapInNTCP2Conn(noiseConn, remoteAddr, perConnConfig)
	if err != nil {
		noiseConn.Close()
		return nil, err
	}
	// Record the accept-time deadline so Handshake() cannot extend it.
	ntcp2Conn.handshakeDeadline = acceptDeadline

	nl.logAcceptedConnection(ntcp2Conn)
	return ntcp2Conn, nil
}

// validateAcceptState checks if the listener is in a valid state for accepting connections.
func (nl *Listener) validateAcceptState() error {
	if nl.isClosed() {
		return oops.
			Code("LISTENER_CLOSED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Errorf("ntcp2 listener is closed")
	}
	return nil
}

// logAcceptedConnection logs details about the newly accepted connection.
func (nl *Listener) logAcceptedConnection(ntcp2Conn *Conn) {
	nl.logger.Debug("accepted new NTCP2 connection",
		"listener_addr", nl.addr.String(),
		"remote_addr", ntcp2Conn.RemoteAddr().String())
}

// Close closes the listener and prevents new connections from being accepted.
// Any blocked Accept operations will be unblocked and return errors.
func (nl *Listener) Close() error {
	if !nl.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	// AUDIT 2.4: Close the replay detector to stop any background cleanup goroutines
	if nl.config != nil && nl.config.ReplayDetector != nil {
		nl.config.ReplayDetector.Close()
	}

	err := nl.underlying.Close()
	if err != nil {
		nl.logger.Error("error closing underlying listener",
			"listener_addr", nl.addr.String(),
			"error", err.Error())

		return oops.
			Code("CLOSE_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to close underlying listener")
	}

	nl.logger.Info("NTCP2 listener closed",
		"listener_addr", nl.addr.String())

	return nil
}

// Addr returns the listener's network address.
// This is an NTCP2Addr that wraps the underlying listener's address.
func (nl *Listener) Addr() net.Addr {
	return nl.addr
}

// isClosed returns true if the listener has been closed.
// Thread-safe: uses atomic.Bool.Load().
func (nl *Listener) isClosed() bool {
	return nl.closed.Load()
}

// formatRouterHash formats a router hash for logging (first 8 bytes as hex).
func formatRouterHash(hash data.Hash) string {
	return fmt.Sprintf("%x...", hash[:8])
}

// AcceptWithHandshake waits for the next connection and automatically
// performs the NTCP2 handshake. This mirrors DialNTCP2WithHandshakeContext
// for the responder side.
func (nl *Listener) AcceptWithHandshake(ctx context.Context) (ConnIface, error) {
	conn, err := nl.Accept()
	if err != nil {
		return nil, err
	}
	ntcp2Conn := conn.(*Conn)
	// Use the NTCP2-specific handshake which writes raw Noise messages without
	// 2-byte length prefixes. The standard NoiseConn.Handshake() adds length
	// framing that the NTCP2 spec explicitly forbids on messages 1, 2, and 3.
	if err := ntcp2Conn.Handshake(ctx); err != nil {
		ntcp2Conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "NTCP2 handshake failed during accept")
	}
	// Propagate the peer's static key to the remote address so the router
	// hash is available for session deduplication on inbound connections.
	// REACH-3: Previously this failure was only logged as a warning and the
	// connection was returned to the caller with an incomplete remote address.
	// Without the peer's static key the router transport layer cannot perform
	// session deduplication, which is a correctness (and potentially security)
	// requirement. Fail the accept so the caller is not handed a half-initialised
	// connection.
	if err := ntcp2Conn.PropagatePeerStaticKey(); err != nil {
		ntcp2Conn.Close()
		return nil, oops.
			Code("PEER_STATIC_KEY_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to propagate peer static key after accept handshake")
	}
	return ntcp2Conn, nil
}
