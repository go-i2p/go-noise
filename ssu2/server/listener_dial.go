package server

import (
	"context"
	"net"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DialSSU2ViaListener initiates an outbound SSU2 session that shares this
// listener's bound socket. The listener demultiplexes handshake replies
// (SessionCreated / Retry) and all subsequent data packets back to the
// returned connection. The caller does NOT run a read loop; the listener
// remains the sole socket reader (single-reader invariant preserved).
//
// Design rationale:
//   - Outbound sessions use the listener's socket to reach same advertised port
//   - Replies are demuxed by the listener using the handshake's header protector
//   - Connection remains in pending registry during handshake, then migrates to
//     normal router on success
//   - Preserves single-reader invariant: no second goroutine reads the fd
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an established SSU2Conn, or an error if creation or handshake fails.
func (l *SSU2Listener) DialSSU2ViaListener(ctx context.Context, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	flog("DialSSU2ViaListener", logger.Fields{"remote_addr": remoteAddr.String()}).Debug("Initiating outbound SSU2 dial via listener")

	if err := validateParam(remoteAddr, "remote address", "INVALID_REMOTE_ADDR", "ssu2_listener"); err != nil {
		return nil, err
	}
	if err := validateParam(config, "configuration", "INVALID_CONFIG", "ssu2_listener"); err != nil {
		return nil, err
	}

	// Check if listener is still running
	l.closeMutex.Lock()
	if l.closed {
		l.closeMutex.Unlock()
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener is closed")
	}
	l.closeMutex.Unlock()

	// Create outbound connection using the listener's underlying socket
	// Set readsOwnSocket=false since listener owns the read loop
	conn, err := NewSSU2Conn(
		l.underlying,
		remoteAddr,
		config,
		true, // initiator
		config.StaticKey,
		config.RemoteStaticKey,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create outbound SSU2 connection")
	}

	// Tell the connection it doesn't own the underlying socket
	conn.SetReadsOwnSocket(false)

	// Get the source connection ID for routing
	sourceConnID := conn.GetSSU2Addr().ConnectionID()

	// Extract header protection key for the outbound session handshake.
	// NOTE: During handshake, the listener will attempt to deobfuscate incoming
	// replies using the pending outbound registry. We register with a nil protector
	// initially since the header protection keys are derived during the handshake
	// (after message 1 is sent). The listener's parseInboundPacket will handle
	// initial deobfuscation attempts. On handshake completion, the connection
	// moves to the normal router for data-phase routing.
	//
	// AUDIT 1.2 (ref): The listener handles deobfuscation for both inbound
	// (intro-key) and outbound (handshake-derived keys) sessions in parseInboundPacket.
	// This preserves the single-reader invariant by centralizing all socket reads
	// in the listener's receiveLoop.

	// Register in pending outbound registry
	// The listener will check this registry when parseInboundPacket fails
	if err := l.pendingOutbound.Register(sourceConnID, conn, nil); err != nil {
		conn.Close()
		return nil, oops.Wrapf(err, "failed to register pending outbound session")
	}

	// Run the handshake
	if err := conn.Handshake(ctx); err != nil {
		// Clean up on handshake failure
		l.pendingOutbound.Remove(sourceConnID)
		conn.Close()
		return nil, oops.Wrapf(err, "outbound SSU2 handshake via listener failed")
	}

	// Handshake succeeded. Move from pending to normal router registry.
	l.pendingOutbound.Remove(sourceConnID)
	if err := l.router.AddSession(conn); err != nil {
		// If we can't add to router, the conn was already established but we can't
		// route future packets. This is a critical failure.
		conn.Close()
		return nil, oops.Wrapf(err, "failed to register established session in router")
	}

	return conn, nil
}

// AUDIT 1.2: Single-reader invariant enforcement
// DialSSU2ViaListener ensures the single-reader invariant is maintained:
// - The listener's receiveLoop is the only goroutine reading from l.underlying
// - Outbound connections created via this method do NOT spawn a read loop
// - SetReadsOwnSocket(false) prevents outbound conns from attempting reads
// - The pending outbound registry is consulted during parseInboundPacket
// - Once handshake completes, outbound sessions use the normal router for
//   data-phase packets (still read by listener, routed to the appropriate conn)
//
// This design preserves the strict single-reader guarantee while enabling
// multiplexed outbound dials over the listener socket.
