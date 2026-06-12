package server

import (
	"context"
	"net"

	"github.com/go-i2p/logger"
	path "github.com/go-i2p/path"
	"github.com/samber/oops"
)

// DialSSU2 creates an SSU2 connection to the remote address without performing handshake.
// Use DialSSU2WithHandshake for automatic handshake completion.
//
// Design rationale:
// - Follows standard library pattern (net.Dial)
// - Uses UDP for connectionless transport
// - Creates minimal viable connection wrapper
// - Handshake is separate for flexibility (manual control)
//
// BINDING TRADE-OFFS vs. DialSSU2WithConn:
// This function creates a NEW UDP socket with an ephemeral source port. Trade-offs:
//   - PROS:
//   - Each dial gets a unique source port (connection multiplexing on initiator side)
//   - No risk of packet cross-talk or demux errors
//   - CONS:
//   - Firewall/netfilter may reject ephemeral source ports (EPERM errors)
//   - NAT bindings will differ from advertised listening port (routing failures)
//   - File descriptor exhaustion under sustained dial load
//   - No shared state with listener socket (cannot coordinate keep-alives)
//
// IMPORTANT: Do NOT co-locate DialSSU2 on the same port as a ListenSSU2 in the
// same process. Both trying to bind the same port will fail (kernel won't allow).
// Use DialSSU2WithConn to multiplex outbound connections over the listener socket.
// AUDIT 7.1 — Ephemeral source-port dial vs. multiplexed socket.
//
// Parameters:
//   - localAddr: Local UDP address to bind to (use nil for automatic, or specify port 0 for OS-selected ephemeral)
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an SSU2Conn ready for handshake, or an error if creation fails.
func DialSSU2(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "DialSSU2", "remote_addr": remoteAddr}).Debug("Dialing SSU2 connection")
	if err := validateDialParams(localAddr, remoteAddr, config); err != nil {
		return nil, err
	}

	// Create UDP connection
	packetConn, err := createUDPConnection(localAddr)
	if err != nil {
		return nil, err
	}

	// PORT-2: When localAddr is nil the OS assigns an ephemeral port. Validate
	// the actual bound address so that surprising binds (loopback-only, reserved
	// port, etc.) are caught before a handshake is attempted against a remote peer.
	if localAddr == nil {
		if actualLocal, ok := packetConn.LocalAddr().(*net.UDPAddr); ok {
			if err := validateDialLocalAddress(actualLocal, config); err != nil {
				packetConn.Close()
				return nil, oops.
					Code("INVALID_BOUND_LOCAL_ADDRESS").
					In("ssu2_transport").
					With("local_address", actualLocal.String()).
					Wrapf(err, "OS-assigned local address failed validation")
			}
		}
	}

	// Create SSU2 connection wrapper
	conn, err := createSSU2Connection(packetConn, remoteAddr, config)
	if err != nil {
		packetConn.Close()
		return nil, err
	}

	// Mark that this connection owns the PacketConn (created here),
	// so CloseWithReason will close it.
	conn.SetOwnsUnderlying(true)

	// Runtime guard: log ephemeral binding behavior. If a listener is also running
	// on this interface, recommend using DialSSU2WithConn for multiplexing.
	// AUDIT 7.1 — Ephemeral source-port dial vs. multiplexed socket.
	if conn.LocalAddr() != nil {
		log.WithFields(logger.Fields{
			"pkg":              "server",
			"func":             "DialSSU2",
			"ephemeral_bind":   true,
			"local_addr":       conn.LocalAddr().String(),
			"ephemeral_source": "new UDP socket",
		}).Warn("DialSSU2 created ephemeral socket; if a listener also runs on this interface, consider DialSSU2WithConn for multiplexing")
	}

	return conn, nil
}

// DialSSU2WithConn creates an SSU2 connection using an existing net.PacketConn
// (typically the listener socket) instead of creating a new UDP socket.
//
// This is the RECOMMENDED approach when outbound connections are co-located
// with a listener: all outbound connections share the listener's UDP socket so
// that handshake and data packets originate from the published listening port.
// This avoids:
//   - Firewall/netfilter EPERM errors from ephemeral source ports
//   - NAT binding mismatches (source port != advertised port)
//   - File descriptor exhaustion under sustained load
//   - Accidental binding conflicts with the listener socket (co-location errors)
//
// The caller is responsible for demultiplexing responses by ConnectionID.
// The provided PacketConn is NOT closed when the returned SSU2Conn is closed.
//
// AUDIT 7.1 — Ephemeral source-port dial vs. multiplexed socket.
//
// Parameters:
//   - packetConn: Existing UDP PacketConn to send/receive through (e.g., from ListenSSU2)
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an SSU2Conn ready for handshake, or an error if creation fails.
func DialSSU2WithConn(packetConn net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "DialSSU2WithConn", "remote_addr": remoteAddr}).Debug("Dialing SSU2 connection with existing PacketConn")
	if packetConn == nil {
		return nil, oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_transport").
			Errorf("packet connection cannot be nil")
	}
	if err := validateDialParams(nil, remoteAddr, config); err != nil {
		return nil, err
	}

	// BUG-PB-1: validate the provided socket's local address against the same
	// config constraints (reserved ports, loopback policy) that DialSSU2 applies
	// to its explicitly-passed localAddr argument. Without this check a caller
	// can pass an already-bound socket that would have been rejected by DialSSU2.
	if localAddr, ok := packetConn.LocalAddr().(*net.UDPAddr); ok {
		if err := validateDialLocalAddress(localAddr, config); err != nil {
			return nil, oops.
				Code("INVALID_LOCAL_ADDR").
				In("ssu2_transport").
				With("local_address", localAddr.String()).
				Wrapf(err, "provided PacketConn local address failed validation")
		}
	}

	// Create SSU2 connection wrapper using the shared socket
	conn, err := createSSU2Connection(packetConn, remoteAddr, config)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// DialSSU2WithHandshake creates an SSU2 connection and performs the handshake automatically.
// This is the recommended function for most use cases.
func DialSSU2WithHandshake(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	return DialSSU2WithHandshakeContext(context.Background(), localAddr, remoteAddr, config)
}

// DialSSU2WithConnAndHandshake creates an SSU2 connection over an existing
// PacketConn and performs the handshake automatically.
// This is the recommended function for multiplexed SSU2 transports.
func DialSSU2WithConnAndHandshake(packetConn net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	return DialSSU2WithConnAndHandshakeContext(context.Background(), packetConn, remoteAddr, config)
}

// performSSU2Handshake performs the Noise handshake on an already-created
// SSU2Conn, closing the conn and returning a wrapped error on failure.
// Both DialSSU2WithHandshakeContext and DialSSU2WithConnAndHandshakeContext
// delegate their identical handshake+cleanup tail to this helper.
func performSSU2Handshake(ctx context.Context, conn *SSU2Conn) (*SSU2Conn, error) {
	if err := conn.Handshake(ctx); err != nil {
		conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 handshake failed")
	}
	return conn, nil
}

// DialSSU2WithConnAndHandshakeContext creates an SSU2 connection over an existing
// PacketConn and performs the handshake with context support.
func DialSSU2WithConnAndHandshakeContext(ctx context.Context, packetConn net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "DialSSU2WithConnAndHandshakeContext", "remote_addr": remoteAddr}).Debug("Dialing with handshake on existing PacketConn")
	conn, err := DialSSU2WithConn(packetConn, remoteAddr, config)
	if err != nil {
		return nil, err
	}
	return performSSU2Handshake(ctx, conn)
}

// DialSSU2WithHandshakeContext creates an SSU2 connection and performs the handshake with context.
// The context can be used to cancel the dial or handshake operations.
//
// Design rationale:
// - Context enables timeout and cancellation
// - Follows Go standard patterns (context.Context for cancellable operations)
// - Automatic cleanup on handshake failure
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - localAddr: Local UDP address to bind to (use nil for automatic)
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an established SSU2Conn, or an error if dial or handshake fails.
func DialSSU2WithHandshakeContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "DialSSU2WithHandshakeContext", "remote_addr": remoteAddr}).Debug("Dialing with handshake and context")
	conn, err := DialSSU2(localAddr, remoteAddr, config)
	if err != nil {
		return nil, err
	}
	return performSSU2Handshake(ctx, conn)
}

// ListenSSU2 creates an SSU2 listener on the specified address.
// The listener is ready to accept incoming connections immediately after creation.
//
// Design rationale:
// - Follows standard library pattern (net.Listen)
// - Creates UDP socket for connectionless transport
// - Starts packet routing automatically
// - Single socket multiplexed across all connections
//
// Parameters:
//   - addr: Local UDP address to listen on
//   - config: SSU2 configuration for accepted connections
//
// Returns an SSU2Listener ready to accept, or an error if creation fails.
func ListenSSU2(addr *net.UDPAddr, config *SSU2Config) (*SSU2Listener, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "ListenSSU2", "address": addr}).Debug("Creating SSU2 listener")
	if err := validateListenParams(addr, config); err != nil {
		return nil, err
	}

	// Create UDP listener
	packetConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, oops.
			Code("LISTEN_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to listen on UDP address")
	}

	// Create SSU2 listener wrapper
	listener, err := NewSSU2Listener(packetConn, config)
	if err != nil {
		packetConn.Close()
		return nil, oops.
			Code("SSU2_LISTENER_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to create SSU2 listener")
	}

	// AUDIT 7.2: Set UDP receive buffer to accommodate high-rate traffic.
	// The default OS kernel UDP buffer (typically 212 KB on Linux) may be too
	// small for router workloads. Without explicit buffer configuration, the
	// kernel silently drops inbound datagrams before they reach ReadFrom,
	// contributing to the droppedPackets counter and reducing throughput.
	// Set buffer to a larger value (e.g., 8 MB) to improve packet handling
	// under burst traffic and flood conditions.
	if err := packetConn.SetReadBuffer(8 * 1024 * 1024); err != nil {
		log.WithFields(logger.Fields{
			"pkg":     "server",
			"func":    "ListenSSU2",
			"address": addr,
			"error":   err,
		}).Warn("AUDIT 7.2: SetReadBuffer failed; using OS default")
		// BUG-PB-2: record the failure in the listener so Stats() can expose it
		// to monitoring without relying on log scraping.
		listener.readBufferFailed.Store(true)
	}

	// Start packet routing
	if err := listener.Start(); err != nil {
		listener.Close()
		return nil, oops.
			Code("LISTENER_START_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to start SSU2 listener")
	}

	return listener, nil
}

// WrapSSU2Conn wraps an existing net.PacketConn with SSU2Conn.
// This function provides manual control over the underlying connection.
//
// Design rationale:
// - Allows reuse of existing PacketConn (e.g., with custom options)
// - Does NOT perform handshake (caller controls timing)
// - Validates connection type for safety
//
// Parameters:
//   - underlying: Existing PacketConn to wrap
//   - remoteAddr: Remote UDP address for the connection
//   - config: SSU2 configuration for the connection
//
// Returns an SSU2Conn wrapper, or an error if wrapping fails.
func WrapSSU2Conn(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	if err := validateWrapConnParams(underlying, remoteAddr, config); err != nil {
		return nil, err
	}

	return createSSU2Connection(underlying, remoteAddr, config)
}

// WrapSSU2Listener wraps an existing net.PacketConn with SSU2Listener.
// This function provides manual control over the underlying connection.
//
// Design rationale:
// - Allows reuse of existing PacketConn (e.g., with custom socket options)
// - Does NOT start packet routing (caller controls timing)
// - Validates connection type for safety
//
// Parameters:
//   - underlying: Existing PacketConn to wrap
//   - config: SSU2 configuration for accepted connections
//
// Returns an SSU2Listener wrapper ready to start, or an error if wrapping fails.
func WrapSSU2Listener(underlying net.PacketConn, config *SSU2Config) (*SSU2Listener, error) {
	if err := validateWrapListenerParams(underlying, config); err != nil {
		return nil, err
	}

	return NewSSU2Listener(underlying, config)
}

// validateDialParams validates parameters for DialSSU2.
func validateDialParams(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	if remoteAddr == nil {
		return oops.
			Code("INVALID_REMOTE_ADDRESS").
			In("ssu2_transport").
			Errorf("remote address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	// Dial operations should use initiator role
	if !config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ssu2_transport").
			Errorf("dial operations require initiator=true in config")
	}

	// AUDIT 7.2 — Validate remote address (target peer)
	if err := validateSourceAddress(remoteAddr, config); err != nil {
		return oops.
			Code("INVALID_REMOTE_ADDRESS").
			In("ssu2_transport").
			With("remote_address", remoteAddr.String()).
			Wrapf(err, "remote address validation failed")
	}

	// AUDIT 7.2 — Validate local address if specified
	// NOTE: Port 0 is allowed for local addresses (means "bind to any available port")
	if localAddr != nil {
		if err := validateDialLocalAddress(localAddr, config); err != nil {
			return oops.
				Code("INVALID_LOCAL_ADDRESS").
				In("ssu2_transport").
				With("local_address", localAddr.String()).
				Wrapf(err, "local address validation failed")
		}
	}

	return nil
}

// validateListenParams validates parameters for ListenSSU2.
func validateListenParams(addr *net.UDPAddr, config *SSU2Config) error {
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("ssu2_transport").
			Errorf("listen address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	// Listen operations should use responder role
	if config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ssu2_transport").
			Errorf("listen operations require initiator=false in config")
	}

	// AUDIT 7.2 — Validate listen address (allows port 0)
	if err := validateListenAddress(addr, config); err != nil {
		return oops.
			Code("INVALID_LISTEN_ADDRESS").
			In("ssu2_transport").
			With("listen_address", addr.String()).
			Wrapf(err, "listen address validation failed")
	}

	return nil
}

// validateWrapConnParams validates parameters for WrapSSU2Conn.
func validateWrapConnParams(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_transport").
			Errorf("underlying packet connection cannot be nil")
	}

	if remoteAddr == nil {
		return oops.
			Code("INVALID_REMOTE_ADDRESS").
			In("ssu2_transport").
			Errorf("remote address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	return nil
}

// validateWrapListenerParams validates parameters for WrapSSU2Listener.
func validateWrapListenerParams(underlying net.PacketConn, config *SSU2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_transport").
			Errorf("underlying packet connection cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	return nil
}

// validateSourceAddress validates a UDP address for dial operations.
// AUDIT 7.2 — Address validation.
// Rejects:
//   - nil address
//   - port 0 (requires explicit source port for dial)
//   - reserved ports (1-1023)
//   - loopback addresses (127.0.0.0/8, ::1) unless config.AllowLoopback is true
func validateSourceAddress(addr *net.UDPAddr, config *SSU2Config) error {
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("ssu2_transport").
			Errorf("address cannot be nil")
	}

	// Check port using IsValidSourcePort (rejects nil and port 0)
	if !path.IsValidSourcePort(addr) {
		return oops.
			Code("INVALID_PORT").
			In("ssu2_transport").
			With("port", addr.Port).
			Errorf("port cannot be zero or invalid")
	}

	// Reject reserved ports (1-1023) except when explicitly allowed for tests
	if addr.Port > 0 && addr.Port < 1024 {
		return oops.
			Code("RESERVED_PORT").
			In("ssu2_transport").
			With("port", addr.Port).
			Errorf("reserved port %d is not permitted", addr.Port)
	}

	// Check for loopback address unless explicitly allowed
	if !config.AllowLoopback {
		if addr.IP.IsLoopback() {
			return oops.
				Code("LOOPBACK_ADDRESS").
				In("ssu2_transport").
				With("address", addr.IP.String()).
				Errorf("loopback address %s is not permitted (set config.AllowLoopback=true for tests)", addr.IP.String())
		}
	}

	return nil
}

// validateDialLocalAddress validates a UDP address for dial's local address.
// AUDIT 7.2 — Address validation for dial local binding.
// Rejects:
//   - reserved ports (1-1023) when explicitly bound (port > 0 and < 1024)
//   - loopback addresses (127.0.0.0/8, ::1) unless config.AllowLoopback is true
//
// NOTE: Port 0 is allowed for local addresses (means "bind to any available port").
// This is standard Go networking practice and is used when the caller doesn't
// care which ephemeral port is used.
func validateDialLocalAddress(addr *net.UDPAddr, config *SSU2Config) error {
	if addr == nil {
		return nil // nil local address is OK (means use default)
	}

	// For dial local address, port 0 is allowed (means "any available ephemeral port")
	// Just reject reserved ports if explicitly specified (port > 0 and < 1024)
	if addr.Port > 0 && addr.Port < 1024 {
		return oops.
			Code("RESERVED_PORT").
			In("ssu2_transport").
			With("port", addr.Port).
			Errorf("reserved port %d is not permitted", addr.Port)
	}

	// Check for loopback address unless explicitly allowed
	if !config.AllowLoopback {
		if addr.IP.IsLoopback() {
			return oops.
				Code("LOOPBACK_ADDRESS").
				In("ssu2_transport").
				With("address", addr.IP.String()).
				Errorf("loopback address %s is not permitted (set config.AllowLoopback=true for tests)", addr.IP.String())
		}
	}

	return nil
}

// AUDIT 7.2 — Address validation for listen.
// Rejects:
//   - nil address
//   - reserved ports (1-1023) when explicitly bound (port > 0)
//   - loopback addresses (127.0.0.0/8, ::1) unless config.AllowLoopback is true
//
// NOTE: Port 0 is allowed for listen operations (means "bind to any available port").
// This is standard Go networking practice and is used in tests.
func validateListenAddress(addr *net.UDPAddr, config *SSU2Config) error {
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("ssu2_transport").
			Errorf("address cannot be nil")
	}

	// For listen, port 0 is allowed (means "any available port")
	// Just reject reserved ports if explicitly specified (port > 0 and < 1024)
	if addr.Port > 0 && addr.Port < 1024 {
		return oops.
			Code("RESERVED_PORT").
			In("ssu2_transport").
			With("port", addr.Port).
			Errorf("reserved port %d is not permitted", addr.Port)
	}

	// Check for loopback address unless explicitly allowed
	if !config.AllowLoopback {
		if addr.IP.IsLoopback() {
			return oops.
				Code("LOOPBACK_ADDRESS").
				In("ssu2_transport").
				With("address", addr.IP.String()).
				Errorf("loopback address %s is not permitted (set config.AllowLoopback=true for tests)", addr.IP.String())
		}
	}

	return nil
}

// createUDPConnection creates a UDP PacketConn bound to the specified local address.
func createUDPConnection(localAddr *net.UDPAddr) (net.PacketConn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "createUDPConnection", "local_addr": localAddr}).Debug("Creating UDP connection")
	packetConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, oops.
			Code("UDP_DIAL_FAILED").
			In("ssu2_transport").
			With("local_address", localAddr).
			Wrapf(err, "failed to create UDP connection")
	}
	return packetConn, nil
}

// createSSU2Connection creates an SSU2Conn from a PacketConn and configuration.
func createSSU2Connection(packetConn net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "createSSU2Connection", "remote_addr": remoteAddr}).Debug("Creating SSU2 connection wrapper")
	// Generate connection ID if not set
	if config.ConnectionID == 0 {
		connID, err := GenerateConnectionID()
		if err != nil {
			return nil, oops.
				Code("CONNECTION_ID_GENERATION_FAILED").
				In("ssu2_transport").
				Wrapf(err, "failed to generate connection ID")
		}
		config.ConnectionID = connID
	}

	// For initiator connections, we need static keys
	staticKey := config.StaticKey
	// Use the remote X25519 static key for the Noise XK handshake (C-1).
	// This is NOT the router hash — it is the peer's actual static public key.
	remoteStaticKey := config.RemoteStaticKey

	conn, err := NewSSU2Conn(
		packetConn,
		remoteAddr,
		config,
		config.Initiator,
		staticKey,
		remoteStaticKey,
	)
	if err != nil {
		return nil, oops.
			Code("SSU2_CONN_FAILED").
			In("ssu2_transport").
			With("remote_address", remoteAddr).
			Wrapf(err, "failed to create SSU2 connection")
	}

	return conn, nil
}
