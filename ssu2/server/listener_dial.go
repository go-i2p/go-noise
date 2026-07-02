package server

import (
	"context"
	"net"

	"github.com/go-i2p/go-noise/ssu2/wire"
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
// Key derivation and registry update flow:
//  1. A Retry protector (keyed on config.RemoteIntroKey) is installed at
//     registration time — before the handshake starts and before a Retry
//     packet can arrive — so the listener can route Retry packets immediately.
//  2. SessCreateHeaderKey is derived inside sendSessionRequest.  The conn
//     signals it via sessCreateKeyNotifyCh (capacity 1).  DialSSU2ViaListener
//     waits for that signal and calls SetProtector before the responder can
//     send SessionCreated (the responder can only reply after receiving the
//     SessionRequest, which we send after signalling the key).
//  3. Handshake runs in a background goroutine; DialSSU2ViaListener blocks
//     on the key channel first, then on the goroutine result channel.
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

	// Create outbound connection using the listener's underlying socket.
	// readsOwnSocket=false: the listener owns the read loop; the conn must
	// not spawn a second goroutine reading the same fd.
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
	conn.SetReadsOwnSocket(false)

	sourceConnID := conn.GetSSU2Addr().ConnectionID()

	// Build a Retry protector immediately: Retry uses the responder's intro key
	// for both k_header_1 and k_header_2, which is known before the handshake.
	// This lets the listener deobfuscate a Retry reply before SessCreateHeaderKey
	// is derived.
	var retryProtector *HeaderProtector
	if len(config.RemoteIntroKey) == wire.HeaderKeySize {
		retryProtector, err = wire.NewHeaderProtector(
			config.RemoteIntroKey, config.RemoteIntroKey,
			wire.HeaderTypeRetry,
		)
		if err != nil {
			conn.Close()
			return nil, oops.Wrapf(err, "failed to build Retry header protector")
		}
	}

	// Register with the Retry protector (SessionCreated protector will follow
	// via SetProtector once SessCreateHeaderKey is derived in sendSessionRequest).
	if err := l.pendingOutbound.Register(sourceConnID, conn, retryProtector); err != nil {
		conn.Close()
		return nil, oops.Wrapf(err, "failed to register pending outbound session")
	}

	// Arm the key notification channel so the handshake goroutine can signal
	// when SessCreateHeaderKey is ready.
	keyCh := make(chan *wire.HeaderProtector, 1)
	conn.SetListenerKeyNotify(keyCh)

	// Run the handshake concurrently.  We must not block here: we need to
	// receive the SessCreate key from keyCh and install it in the registry
	// before Handshake returns (and before the responder's SessionCreated
	// arrives, though in practice the responder cannot send it until it has
	// received our SessionRequest, which is sent only after notifySessCreateKey
	// fires, so the ordering is guaranteed on a non-adversarial link).
	hsErrCh := make(chan error, 1)
	go func() {
		hsErrCh <- conn.Handshake(ctx)
	}()

	// Wait for the SessCreate protector to become available, then install it.
	select {
	case p := <-keyCh:
		if err := l.pendingOutbound.SetProtector(sourceConnID, p); err != nil {
			// SetProtector failing means the session was cleaned up concurrently
			// (e.g. listener closed).  Abort and drain the handshake goroutine.
			l.pendingOutbound.Remove(sourceConnID)
			conn.Close()
			<-hsErrCh
			return nil, oops.Wrapf(err, "failed to install SessionCreated header protector")
		}
	case <-ctx.Done():
		// Context cancelled before SessCreateHeaderKey was derived.
		l.pendingOutbound.Remove(sourceConnID)
		conn.Close()
		<-hsErrCh
		return nil, oops.Wrapf(ctx.Err(), "context cancelled before SessCreateHeaderKey was available")
	case hsErr := <-hsErrCh:
		// Handshake finished (failed) before we got the key signal.
		l.pendingOutbound.Remove(sourceConnID)
		conn.Close()
		if hsErr != nil {
			return nil, oops.Wrapf(hsErr, "outbound SSU2 handshake via listener failed (early)")
		}
		// Handshake succeeded without signalling the key — should not happen
		// for a spec-compliant flow, but handle gracefully.
		if err := l.router.AddSession(conn); err != nil {
			conn.Close()
			return nil, oops.Wrapf(err, "failed to register established session in router")
		}
		return conn, nil
	}

	// Key installed.  Now wait for the full handshake to complete.
	if err := <-hsErrCh; err != nil {
		l.pendingOutbound.Remove(sourceConnID)
		conn.Close()
		return nil, oops.Wrapf(err, "outbound SSU2 handshake via listener failed")
	}

	// Handshake succeeded. Move from pending to normal router registry.
	l.pendingOutbound.Remove(sourceConnID)
	if err := l.router.AddSession(conn); err != nil {
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
