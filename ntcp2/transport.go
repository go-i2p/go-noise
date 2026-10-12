package ntcp2

import (
	"context"
	"net"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise"
	modvalidation "github.com/go-i2p/go-noise/mod/validation"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DialNTCP2 opens a TCP connection to addr and wraps it as an NTCP2
// connection. It combines dialing, Noise setup, and NTCP2 wrapping in one
// call. The returned connection has not performed the handshake yet; call
// Handshake (or use DialNTCP2WithHandshake) before sending data.
//
// For more control over the underlying connection, dial with net.Dial and
// wrap it with WrapNTCP2Conn instead.
func DialNTCP2(network, addr string, config *Config) (*Conn, error) {
	return DialNTCP2Context(context.Background(), network, addr, config)
}

// DialNTCP2Context is like DialNTCP2 but takes a context that can cancel
// or time-bound the dial.
func DialNTCP2Context(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	flog("DialNTCP2Context", logger.Fields{"address": addr}).Debug("Dialing NTCP2 connection with context")
	if err := validateNTCP2DialParams(network, addr, config); err != nil {
		return nil, err
	}

	conn, err := establishTCPConnectionContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	noiseConn, err := createNoiseConnection(conn, config, network, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return buildNTCP2Connection(noiseConn, conn, config, network, addr)
}

// DialNTCP2WithHandshake opens a connection to addr and performs the NTCP2
// handshake automatically. The returned connection is ready for data-phase
// I/O.
func DialNTCP2WithHandshake(network, addr string, config *Config) (*Conn, error) {
	return DialNTCP2WithHandshakeContext(context.Background(), network, addr, config)
}

// DialNTCP2WithHandshakeContext is like DialNTCP2WithHandshake but takes a
// context that can cancel or time-bound the dial and handshake.
func DialNTCP2WithHandshakeContext(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	flog("DialNTCP2WithHandshakeContext", logger.Fields{"address": addr}).Debug("Dialing NTCP2 with handshake")
	ntcp2Conn, err := DialNTCP2Context(ctx, network, addr, config)
	if err != nil {
		return nil, err
	}

	// Note: SetNTCP2Config was already called inside DialNTCP2 → buildNTCP2Connection.
	// No second call needed here.

	// Use the NTCP2-specific handshake which writes raw Noise messages without
	// 2-byte length prefixes. The standard NoiseConn.Handshake() adds length
	// framing that the NTCP2 spec explicitly forbids on messages 1, 2, and 3.
	if err := ntcp2Conn.Handshake(ctx); err != nil {
		ntcp2Conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "NTCP2 handshake failed")
	}

	// Propagate the peer's static key to the remote address so the router
	// hash is available for session deduplication.
	if err := ntcp2Conn.PropagatePeerStaticKey(); err != nil {
		flog("DialNTCP2").WithError(err).Warn("peer static key not propagated after dial handshake")
	}

	return ntcp2Conn, nil
}

// ListenNTCP2 starts listening on addr and returns a Listener that accepts
// NTCP2 connections. It combines net.Listen and NewNTCP2Listener in one
// call. For more control over the underlying listener, use net.Listen
// followed by NewNTCP2Listener.
//
// Restart behavior: by default, after shutdown the port stays in
// TIME_WAIT state for about 30-60 seconds (system-dependent), during which
// rebinding fails with "address already in use". Enable
// config.AllowReuseAddress via WithReuseAddress(true) to reduce this delay
// by setting SO_REUSEADDR, allowing quick rebinding after shutdown. Use
// with caution in production: stale packets from the previous listener
// instance may be delivered to the new listener during the overlap window.
func ListenNTCP2(network, addr string, config *Config) (*Listener, error) {
	return ListenNTCP2WithContext(context.Background(), network, addr, config)
}

// ListenNTCP2WithContext is like ListenNTCP2 but accepts a context that can
// cancel or time-bound the socket creation step.
func ListenNTCP2WithContext(ctx context.Context, network, addr string, config *Config) (*Listener, error) {
	flog("ListenNTCP2", logger.Fields{"address": addr}).Debug("Creating NTCP2 listener")
	if err := validateNTCP2ListenParams(network, addr, config); err != nil {
		return nil, err
	}

	// Create the underlying TCP listener
	var listener net.Listener
	var err error

	// Capture SO_REUSEADDR errors instead of silently discarding them.
	// If the caller set AllowReuseAddress: true, they expect fast restart
	// semantics. If SO_REUSEADDR fails (e.g., permission error, unsupported
	// platform), fail fast.
	if config.AllowReuseAddress && (network == "tcp" || network == "tcp4" || network == "tcp6") {
		// SO_REUSEADDR is applied only on supported platforms.
		// The semantics and availability of SO_REUSEADDR varies between
		// operating systems.
		// On Linux, it allows immediate reuse after Close() (TIME_WAIT bypass).
		// On macOS and Windows, it has different semantics and may not be
		// advisable for all use cases.
		// This code path is guarded to ensure correct behavior on all platforms.
		lc := &net.ListenConfig{
			Control: reuseAddrControl,
		}
		listener, err = lc.Listen(ctx, network, addr)
	} else {
		listener, err = net.Listen(network, addr)
	}

	if err != nil {
		return nil, oops.
			Code("LISTEN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to listen on %s://%s", network, addr)
	}

	// Create the NTCP2 listener wrapper
	ntcp2Listener, err := NewNTCP2Listener(listener, config)
	if err != nil {
		listener.Close()
		return nil, oops.
			Code("NTCP2_LISTENER_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 listener")
	}

	return ntcp2Listener, nil
}

// WrapNTCP2Conn wraps an existing connection as an NTCP2 connection. It
// creates the Noise wrapper and NTCP2 addresses. The returned connection
// has not performed the handshake yet.
func WrapNTCP2Conn(conn net.Conn, config *Config) (*Conn, error) {
	flog("WrapNTCP2Conn").Debug("Wrapping connection with NTCP2")
	if err := validateWrapConnParams(conn, config); err != nil {
		return nil, err
	}

	noiseConn, err := createWrappedNoiseConnection(conn, config)
	if err != nil {
		return nil, err
	}

	localAddr, remoteAddr, err := createDialAddresses(conn, config)
	if err != nil {
		return nil, oops.
			Code("ADDRESS_CREATION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create NTCP2 addresses")
	}

	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	// Store the config so PropagateSipHash() can be called after handshake.
	ntcp2Conn.SetNTCP2Config(config)

	// Set the SipHash length obfuscator for data-phase framing if already available.
	if slm := config.SipHashModifier(); slm != nil {
		ntcp2Conn.SetLengthObfuscator(slm)
	}

	return ntcp2Conn, nil
}

// validateWrapConnParams validates the input parameters for WrapNTCP2Conn.
func validateWrapConnParams(conn net.Conn, config *Config) error {
	if conn == nil {
		return oops.
			Code("INVALID_CONNECTION").
			In("ntcp2").
			Errorf("connection cannot be nil")
	}

	if err := validateConfigPresence(config); err != nil {
		return err
	}

	return nil
}

// createWrappedNoiseConnection converts the NTCP2 config and creates a Noise connection.
func createWrappedNoiseConnection(conn net.Conn, config *Config) (*noise.NoiseConn, error) {
	noiseConfig, err := config.ToConnConfig()
	if err != nil {
		return nil, oops.
			Code("CONFIG_CONVERSION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to convert NTCP2 config to Noise config")
	}

	noiseConn, err := noise.NewNoiseConn(conn, noiseConfig)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create noise connection")
	}

	return noiseConn, nil
}

// WrapNTCP2Listener wraps an existing listener so that accepted
// connections are NTCP2 connections. It is an alias for NewNTCP2Listener.
func WrapNTCP2Listener(listener net.Listener, config *Config) (*Listener, error) {
	return NewNTCP2Listener(listener, config)
}

// validateBasicParams validates common parameters for dial and listen operations.
func validateBasicParams(network, addr string, config *Config) error {
	if err := modvalidation.ValidateNetworkAddr(network, addr, "ntcp2"); err != nil {
		return err
	}

	if err := validateConfigPresence(config); err != nil {
		return err
	}

	return nil
}

func validateConfigPresence(config *Config) error {
	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("ntcp2 config cannot be nil")
	}

	return nil
}

func validateConfigValue(config *Config) error {
	if err := validateConfigPresence(config); err != nil {
		return err
	}

	if err := config.Validate(); err != nil {
		return err
	}

	return nil
}

// validateNTCP2Params validates the parameters for NTCP2 operations.
// requireInitiator controls whether Initiator must be true (for dial) or false (for listen).
func validateNTCP2Params(network, addr string, config *Config, requireInitiator bool) error {
	if err := validateBasicParams(network, addr, config); err != nil {
		return err
	}

	// Validate Initiator flag based on operation type
	if config.Initiator != requireInitiator {
		op := "dial"
		if !requireInitiator {
			op = "listen"
		}
		expected := true
		if !requireInitiator {
			expected = false
		}
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ntcp2").
			With("initiator", config.Initiator).
			With("expected", expected).
			Errorf("%s operations require initiator=%v in config", op, expected)
	}

	// Validate the configuration
	if err := validateConfigValue(config); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ntcp2").
			Wrapf(err, "NTCP2 config validation failed")
	}

	return nil
}

// validateNTCP2DialParams validates the parameters for dial operations
func validateNTCP2DialParams(network, addr string, config *Config) error {
	return validateNTCP2Params(network, addr, config, true) // requireInitiator=true
}

// validateNTCP2ListenParams validates the parameters for listen operations
func validateNTCP2ListenParams(network, addr string, config *Config) error {
	return validateNTCP2Params(network, addr, config, false) // requireInitiator=false
}

// createDialAddresses creates the local and remote NTCP2 addresses for dial operations
func createDialAddresses(conn net.Conn, config *Config) (*Addr, *Addr, error) {
	// Determine roles from the config's Initiator flag so WrapNTCP2Conn
	// labels them correctly for both initiator and responder connections.
	localRole := "initiator"
	remoteRole := "responder"
	if !config.Initiator {
		localRole = "responder"
		remoteRole = "initiator"
	}

	// Create local address from connection's local address
	localAddr, err := NewNTCP2Addr(
		conn.LocalAddr(),
		config.BobRouterHash,
		localRole,
	)
	if err != nil {
		return nil, nil, oops.
			Code("LOCAL_ADDR_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create local NTCP2 address")
	}

	// Validate RemoteRouterHash length early so the error clearly
	// indicates the config source rather than a generic NewNTCP2Addr failure.
	// (data.Hash type guarantees correct size; this check is a no-op placeholder)

	// Create remote address from connection's remote address and config.
	// For responder connections (e.g., WrapNTCP2Conn on accepted conns),
	// the remote router hash may not be known until after the handshake
	// completes and PeerStaticKey() is available. Use a placeholder zero
	// hash in that case.
	var remoteHash data.Hash
	if config.RemoteRouterHash != nil {
		remoteHash = *config.RemoteRouterHash
	}

	remoteAddr, err := NewNTCP2Addr(
		conn.RemoteAddr(),
		remoteHash,
		remoteRole,
	)
	if err != nil {
		return nil, nil, oops.
			Code("REMOTE_ADDR_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create remote NTCP2 address")
	}

	return localAddr, remoteAddr, nil
}

// establishTCPConnection dials the underlying TCP connection with proper error handling.
func establishTCPConnection(network, addr string) (net.Conn, error) {
	return establishTCPConnectionContext(context.Background(), network, addr)
}

// establishTCPConnectionContext dials the underlying TCP connection with context support.
func establishTCPConnectionContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, oops.
			Code("DIAL_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to dial %s://%s", network, addr)
	}
	return conn, nil
}

// createNoiseConnection converts NTCP2Config to ConnConfig and creates the underlying Noise connection.
func createNoiseConnection(conn net.Conn, config *Config, network, addr string) (*noise.NoiseConn, error) {
	noiseConfig, err := config.ToConnConfig()
	if err != nil {
		return nil, oops.
			Code("CONFIG_CONVERSION_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to convert NTCP2 config to Noise config")
	}

	noiseConn, err := noise.NewNoiseConn(conn, noiseConfig)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	return noiseConn, nil
}

// buildNTCP2Connection creates NTCP2 addresses and wraps the noise connection with NTCP2Conn.
func buildNTCP2Connection(noiseConn *noise.NoiseConn, conn net.Conn, config *Config, network, addr string) (*Conn, error) {
	localAddr, remoteAddr, err := createDialAddresses(conn, config)
	if err != nil {
		noiseConn.Close()
		return nil, oops.
			Code("ADDRESS_CREATION_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 addresses")
	}

	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	if err != nil {
		noiseConn.Close()
		return nil, oops.
			Code("NTCP2_CONN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 connection")
	}

	// Store the config so PropagateSipHash() can be called after handshake.
	ntcp2Conn.SetNTCP2Config(config)

	// Set the SipHash length obfuscator for data-phase framing if already available.
	// This covers the case where SipHash keys were pre-configured rather than
	// derived via PostHandshakeHook.
	if slm := config.SipHashModifier(); slm != nil {
		ntcp2Conn.SetLengthObfuscator(slm)
	}

	return ntcp2Conn, nil
}
