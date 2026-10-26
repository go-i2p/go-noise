package server

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/mod/replaycache"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Listener is the server side of SSU2: it accepts incoming SSU2
// connections over UDP. It implements the standard net.Listener interface,
// so it can be used anywhere a net.Listener is expected.
//
// # How it works
//
// All sessions share a single UDP socket (multiplexing). Incoming packets
// are read by one goroutine, queued, and processed by a small pool of worker
// goroutines. Each packet is routed to the session it belongs to, or — if it
// is a valid new handshake — a new session is created and queued for
// Accept().
//
// # What it does
//
//   - Routes packets to existing sessions via a PacketRouter.
//   - Creates new sessions for valid SessionRequest packets.
//   - Validates retry tokens (via a TokenCache) to prevent spoofing.
//   - Rate-limits SessionRequests per source IP to blunt floods.
//   - Deduplicates retransmitted SessionRequests so a lost reply does not
//     create a duplicate session.
//
// Thread safety: all public methods are thread-safe.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
type SSU2Listener struct {
	// underlying is the UDP socket for receiving packets
	underlying net.PacketConn

	// config holds listener configuration. Stored atomically because the
	// receiveLoop and session workers read it concurrently with identity
	// updates (UpdateIdentity); a plain pointer would be a data race.
	// Sessions receive their own Clone(), so an in-flight handshake is never
	// affected by a later update.
	config atomic.Pointer[SSU2Config]

	// addr is the SSU2 address for this listener
	addr *SSU2Addr

	// The router is the single owner of all sessions; all session queries go
	// through it via GetSession/SessionCount/RemoveSession.
	// pendingByInitiator is the only listener-local session tracking
	// (pre-establishment dedup only).

	// pendingByInitiator maps (initiatorConnID, remoteAddr) to SSU2Conn to
	// dedup retransmitted SessionRequests. This prevents creating duplicate
	// sessions for handshake retransmits. Key format: hex(initiatorConnID)|IP:port
	// Protected by sessionMutex. Bound by MaxSessions.
	pendingByInitiator map[string]*SSU2Conn
	sessionMutex       sync.RWMutex

	// tokenCache validates retry tokens
	tokenCache *TokenCache

	// tokenAdmission gates retry-token issuance against off-path
	// spoofed-source flooding. Two layers are applied before a token
	// cache entry is allocated:
	//  - firstSight demands that the source address be observed in a
	//    prior packet within FirstSightWindow before a token is issued
	//    (forcing an attacker to spend ≥2 packets per spoofed IP, on
	//    separate, cheaper tracker state).
	//  - issuanceLimiter caps the total tokens/sec issued across all
	//    peers so that even a bypassed first-sight cannot amplify
	//    issuance rate.
	firstSight      *firstSightTracker
	issuanceLimiter *tokenIssuanceLimiter

	// acceptQueue buffers established connections ready to be accepted
	acceptQueue chan *SSU2Conn

	// packetQueue buffers incoming packets for worker pool processing
	packetQueue chan incomingPacket

	// router routes packets to sessions
	router *PacketRouter

	// introHeaderProtector decrypts header protection on incoming new-session
	// packets (SessionRequest, TokenRequest). Per the SSU2 spec, both header
	// protection keys for these packet types are the receiver's intro key.
	// Nil when config.IntroKey is unset, in which case the listener assumes
	// inbound packets are sent with plaintext headers (test mode).
	// The listener attempts header-protection decryption for incoming packets
	// that fail plaintext deserialization, enabling interop with
	// spec-compliant SSU2 peers (i2pd / Java I2P).
	// Stored atomically because it is derived from config.IntroKey and is
	// rebuilt by UpdateIdentity while the packet workers read it.
	introHeaderProtector atomic.Pointer[HeaderProtector]

	// pendingOutbound tracks outbound sessions awaiting their
	// SessionCreated/Retry replies over the listener's socket. During
	// handshake, the listener uses these sessions' header protectors to
	// deobfuscate and route incoming replies. This preserves the
	// single-reader invariant — no second read loop, only temporary header
	// protectors for demultiplexing (see outbound_demux.go). On handshake
	// completion, sessions move to the normal router and pendingOutbound is
	// cleaned up.
	pendingOutbound *PendingOutboundRegistry

	// acceptedSessions tracks all sessions (both accepted responder sessions and
	// outbound initiator sessions) that share the listener socket and require
	// per-session header-protector trial-deobfuscation for:
	//   - Inbound SessionConfirmed (responder-role sessions awaiting message 3)
	//   - Inbound Data packets (all roles once established)
	// These packet types use KDF-derived keys (not the listener's intro key) so
	// the intro-key protector cannot decode them; trial-deobfuscation against the
	// per-session AcceptedSessionRegistry is the only viable decode path.
	// Sessions are added in registerAndQueueConn and removed on Close().
	acceptedSessions *AcceptedSessionRegistry

	// sessionRateLimiter limits SessionRequest processing per source IP.
	sessionRateLimiter *ipRateLimiter

	// handshakeReplay caches previously-seen SessionRequest handshake values so
	// replays are rejected before the expensive Noise DH.
	//
	// Spec ref: ssu2.md §"Session Request" -> §"Notes": "Bob must maintain a local
	// cache of previously-used handshake values and reject duplicates, to prevent
	// replay attacks. Values in the cache must have a lifetime of at least 2*D. The
	// cache values are implementation-dependent, however the 32-byte X value (or its
	// encrypted equivalent) may be used. Reject by sending a Retry message containing
	// a zero token and a termination block."
	//
	// D is the maximum DateTime delta (config.MaxClockSkew), so the TTL is 2*D.
	// The cache key is SHA-256 over the raw (header-protected) 32-byte X value plus
	// the ciphertext, matching the existing per-session derivation
	// (handshake.computeSessionRequestReplayToken) so both layers agree.
	handshakeReplay *replaycache.TTLCache

	// droppedPackets counts packets silently discarded when packetQueue is
	// full. Accessed atomically to avoid races between receiveLoop and stats
	// readers.
	droppedPackets uint64

	// routingErrors counts packets that failed to route to a session and were
	// not handled as a TokenRequest. Accessed atomically.
	routingErrors uint64

	// outOfSessionHandler receives intro-key protected out-of-session messages
	// (Peer Test type 7, Hole Punch type 11) that arrive on this socket but do
	// not belong to any session. Per ssu2.rst §"Peer Test Process", messages 5-7
	// are "out-of-session using Peer Test blocks in a Peer Test message" and
	// §"Relay Process" step 5 is a Hole Punch sent directly to Alice, so neither
	// can be delivered through the session router: their connection IDs are
	// derived from the test/relay nonce, not from a session. Without a handler
	// these messages are dropped.
	//
	// Stored atomically because it is registered by the transport layer while
	// packet workers read it.
	outOfSessionHandler atomic.Pointer[outOfSessionHandler]

	// readBufferFailed is set when the OS rejected the SetReadBuffer call in
	// ListenSSU2. It is observable via Stats() so monitoring can detect
	// degraded-buffer conditions without polling debug logs.
	readBufferFailed atomic.Bool

	// Lifecycle management
	closed       bool
	started      bool // guards against double-Start()
	closeMutex   sync.Mutex
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// NewSSU2Listener creates a new SSU2 listener wrapping the specified packet
// connection. The listener starts in an idle state; call Start() to begin
// accepting connections.
//
// The listener accepts inbound SSU2 sessions over a single shared UDP socket.
// All accepted sessions multiplex over that one socket, and the listener
// validates retry tokens, rate-limits per source IP, and deduplicates
// retransmitted SessionRequests.
//
// Parameters:
//   - underlying: UDP PacketConn to receive packets from
//   - config: SSU2 configuration for accepted connections
//
// Returns a new SSU2Listener ready to start, or an error if configuration is
// invalid.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
func NewSSU2Listener(underlying net.PacketConn, config *SSU2Config) (*SSU2Listener, error) {
	flog("NewSSU2Listener").Debug("Creating new SSU2 listener")
	if err := validateParam(underlying, "underlying packet connection", "INVALID_PACKET_CONN", "ssu2_listener"); err != nil {
		return nil, err
	}

	if err := validateParam(config, "configuration", "INVALID_CONFIG", "ssu2_listener"); err != nil {
		return nil, err
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid configuration")
	}

	// Generate connection ID for listener address
	connID, err := GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	// Create listener SSU2 address using config's router hash
	addr, err := NewSSU2Addr(underlying.LocalAddr(), config.RouterHash, connID, "responder")
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 address")
	}

	l := &SSU2Listener{
		underlying:         underlying,
		addr:               addr,
		pendingByInitiator: make(map[string]*SSU2Conn),
		tokenCache:         newTokenCacheFromConfig(config),
		sessionRateLimiter: newIPRateLimiter(sessionRequestsPerSecond, sessionRateLimiterMaxIPs),
		handshakeReplay:    newHandshakeReplayCache(config),
		firstSight:         newFirstSightTracker(config.FirstSightWindow, config.FirstSightMaxEntries),
		issuanceLimiter:    newTokenIssuanceLimiter(config.GlobalTokenIssuanceRate, config.GlobalTokenIssuanceBurst),
		acceptQueue:        make(chan *SSU2Conn, 100), // Buffer 100 pending connections
		packetQueue:        make(chan incomingPacket, packetQueueSize),
		pendingOutbound:    NewPendingOutboundRegistry(config.MaxSessions, 30*time.Second),
		acceptedSessions:   NewAcceptedSessionRegistry(config.MaxSessions * 2),
		shutdownChan:       make(chan struct{}),
	}

	// Publish the config before any reader can start (Start() has not run yet).
	//
	// Deliberately stores the caller's pointer rather than a Clone(). go-i2p's
	// SSU2 transport populates ObfuscationIV and IntroKey on this config AFTER
	// the listener is constructed and started (persistent_config.go), and the
	// per-session config copy in buildConnConfig relies on seeing them through
	// the shared pointer. Cloning here would freeze those fields at their
	// construction values and silently disable ChaCha obfuscation for inbound
	// sessions. Callers that need to change identity material after start must
	// use UpdateIdentity, which republishes atomically.
	l.config.Store(config)

	// Create packet router with session creation callback
	l.router = NewPacketRouter(l.handleNewSession)

	if err := l.initHeaderProtection(config); err != nil {
		return nil, err
	}

	return l, nil
}

// Start begins accepting connections on the listener.
// This starts a goroutine to read packets from the underlying connection
// and route them to appropriate sessions.
//
// Returns error if the listener is already closed.
func (l *SSU2Listener) Start() error {
	flog("Start").Debug("Starting SSU2 listener")
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener is closed")
	}

	// Prevent double-Start(). A second Start() would spawn a duplicate set of
	// goroutines (packetWorkers + receiveLoop + tokenCleanupLoop) on the same
	// PacketConn, violating the single-reader invariant and doubling wg counts.
	if l.started {
		return oops.
			Code("LISTENER_ALREADY_STARTED").
			In("ssu2_listener").
			Errorf("listener is already started")
	}
	l.started = true

	// Start packet processing worker pool
	for i := 0; i < packetWorkers; i++ {
		l.wg.Add(1)
		go l.packetWorker()
	}

	// Start packet receive loop
	l.wg.Add(1)
	go l.receiveLoop()

	// Start periodic token cache cleanup to prevent expired token
	// accumulation under sustained connection churn.
	l.wg.Add(1)
	go l.tokenCleanupLoop()

	return nil
}

// Accept waits for and returns the next connection to the listener.
// Implements net.Listener interface.
//
// Returns:
//   - net.Conn: The accepted connection
//   - error: If the listener is closed or an error occurs
func (l *SSU2Listener) Accept() (net.Conn, error) {
	flog("Accept").Debug("Waiting to accept SSU2 connection")
	select {
	case conn := <-l.acceptQueue:
		if conn == nil {
			return nil, oops.
				Code("LISTENER_CLOSED").
				In("ssu2_listener").
				Errorf("listener closed")
		}
		return conn, nil
	case <-l.shutdownChan:
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener closed")
	}
}

// Close closes the listener, preventing new connections from being accepted.
// Existing sessions are not closed; they must be closed separately.
// Implements net.Listener interface.
//
// Returns error if close fails.
func (l *SSU2Listener) Close() error {
	flog("Close").Debug("Closing SSU2 listener")
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return nil // Already closed
	}

	l.closed = true
	close(l.shutdownChan)

	// Cancel all pending DestroyTimeout waits in parallel by closing their
	// forceDestroy channels. This prevents serial blocking when the listener
	// has multiple in-flight CloseWithReason calls waiting for the full timeout.
	sessions := l.router.GetAllSessions()
	for _, conn := range sessions {
		// Trigger forceDestroy channel closure to signal cancellation of the
		// DestroyTimeout wait. Use a goroutine per session to avoid blocking
		// on individual channel operations.
		go func(c *SSU2Conn) {
			c.TriggerForceDestroy()
		}(conn)
	}

	// Close the underlying connection first to unblock ReadFrom in
	// receiveLoop, rather than relying on deadline-based polling.
	closeErr := l.underlying.Close()

	// Wait for goroutines to finish before closing channels.
	// This prevents send-on-closed-channel panics in handleNewSession.
	l.wg.Wait()

	// Drain any sessions already queued in acceptQueue that the caller will
	// never dequeue now that the listener is closed. Without this, those
	// sessions remain fully established and their goroutines never stop — a
	// resource leak proportional to how full the acceptQueue was at shutdown.
	for {
		select {
		case conn, ok := <-l.acceptQueue:
			if !ok {
				// Channel was already closed (shouldn't happen here, but be safe).
				goto drained
			}
			_ = conn.CloseImmediate()
		default:
			goto drained
		}
	}
drained:
	// Safe to close accept queue now — all senders have exited
	close(l.acceptQueue)

	if closeErr != nil {
		return oops.Wrapf(closeErr, "failed to close underlying connection")
	}

	return nil
}

// Addr returns the listener's network address.
// Implements net.Listener interface.
//
// Returns the SSU2 address for this listener.
func (l *SSU2Listener) Addr() net.Addr {
	return l.addr
}

// GetAddr returns the string representation of the listener's address.
// Implements the ssu2path.ListenerRef interface.
func (l *SSU2Listener) GetAddr() string {
	if l.addr == nil {
		return ""
	}
	return l.addr.String()
}

// makeDedupKey creates a dedup index key from initiatorConnID and remoteAddr.
// Format: hex(initiatorConnID)|IP:port. Used to detect and deduplicate
// retransmitted SessionRequests.
func makeDedupKey(initiatorConnID uint64, remoteAddr *net.UDPAddr) string {
	if remoteAddr == nil {
		return ""
	}
	return fmt.Sprintf("%016x|%s", initiatorConnID, remoteAddr.String())
}

// handleNewSession is called by the router when a handshake packet arrives
// for a new session. It creates a new SSU2Conn and adds it to the accept queue.
//
// When config.RequireRetry is true and the SessionRequest does not carry a
// valid token, the listener sends a Retry message (with a generated token)
// instead of accepting the session. The initiator is expected to resend
// SessionRequest including the token from the Retry.
func (l *SSU2Listener) handleNewSession(remoteAddr *net.UDPAddr, packet *SSU2Packet) (*SSU2Conn, error) {
	flog("handleNewSession", logger.Fields{"remote_addr": remoteAddr.String()}).Debug("handleNewSession: creating new session for incoming handshake")

	// Validate source address (reject reserved ports, loopback unless allowed, etc.)
	if err := validateListenAddress(remoteAddr, l.config.Load()); err != nil {
		return nil, oops.
			Code("INVALID_SOURCE_ADDRESS").
			In("ssu2_listener").
			With("remote_address", remoteAddr.String()).
			Wrapf(err, "rejecting SessionRequest from invalid source address")
	}

	if err := l.enforceRateLimit(remoteAddr); err != nil {
		return nil, err
	}

	// Extract and validate initiator connection ID from packet header.
	initiatorConnID, err := l.extractSessionInitiatorID(packet)
	if err != nil {
		return nil, err
	}

	// Dedup BEFORE the replay gate. ssu2.md §"Session Request" tells Alice that a
	// retransmission must "Maintain same source and connection IDs, ephemeral key,
	// and packet number 0. Or, just retain and retransmit the same encrypted
	// packet", so a legitimate retransmit repeats the very handshake value the
	// §Notes replay cache keys on. Resolving the conflict in the direction that
	// keeps handshakes working: a repeat that matches an existing pending session is
	// a retransmit, and only an unmatched duplicate is a replay.
	existingConn := l.findExistingSessionByInitiator(initiatorConnID, remoteAddr)
	if existingConn != nil {
		return existingConn, nil
	}

	if err := l.handleSessionRequestToken(packet, remoteAddr); err != nil {
		// RETRY_SENT means we sent a Retry successfully — this is the normal
		// token-gate flow, not a failure. Return (nil, nil) so PacketRouter
		// drops the packet without incrementing routingErrors or emitting a WARN.
		var oopsErr oops.OopsError
		if errors.As(err, &oopsErr) && oopsErr.Code() == "RETRY_SENT" {
			return nil, nil
		}
		return nil, err
	}

	// Replay gate: a duplicate handshake value for a session we have no record of
	// is rejected before any DH work.
	if err := l.rejectSessionRequestReplay(packet, remoteAddr); err != nil {
		return nil, nil
	}

	// Create and configure new SSU2 connection.
	conn, connID, err := l.createSessionConnection(packet, remoteAddr, initiatorConnID)
	if err != nil {
		return nil, err
	}

	// Register connection and add to accept queue.
	return l.registerAndQueueConn(conn, connID, remoteAddr, initiatorConnID)
}

// extractSessionInitiatorID extracts and validates the initiator connection ID
// from the SessionRequest packet header.
//
// It validates that the header contains at least 24 bytes needed to read the
// initiator's source connection ID. Without this check, a truncated header
// would cause the dedup key to collapse to (0, remoteAddr), allowing a
// malicious peer to falsely "retransmit" to any existing zero-connID entry or
// create multiple sessions under the same dedup key.
func (l *SSU2Listener) extractSessionInitiatorID(packet *SSU2Packet) (uint64, error) {
	// Per the SSU2 spec, the SessionRequest header is exactly 32 bytes:
	//   [0:8]   destination connection ID
	//   [8:12]  packet number
	//   [12:16] protocol/type byte
	//   [16:24] source connection ID (initiator's connection ID)
	//   [24:32] token
	const minSessionRequestHeaderLen = 24
	if len(packet.Header) < minSessionRequestHeaderLen {
		return 0, oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2_listener").
			With("header_len", len(packet.Header)).
			With("min_len", minSessionRequestHeaderLen).
			Errorf("SessionRequest header too short to extract initiator connection ID")
	}
	return binary.BigEndian.Uint64(packet.Header[16:24]), nil
}

// findExistingSessionByInitiator checks the dedup index for an existing session
// keyed on (initiatorConnID, remoteAddr).
//
// If a session already exists for this (initiator key, source address) pair,
// route the retransmit to it instead of creating a duplicate.
func (l *SSU2Listener) findExistingSessionByInitiator(initiatorConnID uint64, remoteAddr *net.UDPAddr) *SSU2Conn {
	dedupKey := makeDedupKey(initiatorConnID, remoteAddr)
	l.sessionMutex.RLock()
	existingConn := l.pendingByInitiator[dedupKey]
	l.sessionMutex.RUnlock()

	if existingConn != nil {
		flog("findExistingSessionByInitiator", logger.Fields{"dedup_key": dedupKey, "remote_addr": remoteAddr.String()}).Debug("routing retransmit to existing pending session")
	}
	return existingConn
}

// createSessionConnection creates and configures a new SSU2Conn for an incoming
// SessionRequest.
//
// The advisory pre-check on SessionCount() is not performed here; the
// authoritative capacity check inside AddSessionIfBelowCap (called from
// registerAndQueueConn, under the correct lock) is the sole capacity gate.
//
// It marks the connection as not responsible for reading the socket, since the
// listener's receiveLoop is the sole socket reader and will feed packets to this
// session via RoutePacket → processInboundPacket → recvQueue. This prevents two
// goroutines (listener and recvLoop) from concurrently reading the same shared
// socket, which violates the SSU2 multiplexing invariant.
func (l *SSU2Listener) createSessionConnection(packet *SSU2Packet, remoteAddr *net.UDPAddr, initiatorConnID uint64) (*SSU2Conn, uint64, error) {
	// ssu2.md §"Session Request": Alice's Destination Connection ID (bytes 0-7)
	// is the value Bob echoes back as the Source Connection ID in SessionCreated
	// and Retry (§"Session Created" / §"Retry": "Source Connection ID :: The
	// Destination Connection ID received from Alice"), and the value Alice uses as
	// her data-phase Destination ("As sent in Session Request"). Java
	// (InboundEstablishState2 rcvConnID = SR dest) and i2pd
	// (ProcessFirstIncomingMessage m_SourceConnID = connID = SR dest, the key
	// AddSession/GetConnID register on) both make that SR destination the
	// responder's inbound routing key. We adopt it directly, so the existing
	// CreateSessionCreated(connID, initiatorConnID) source half echoes correctly
	// with no extra plumbing.
	connID, err := l.responderConnID(packet)
	if err != nil {
		return nil, 0, err
	}

	connConfig := l.buildConnConfig(packet, connID)

	if connConfig.InitiatorConnectionID != 0 && connConfig.InitiatorConnectionID == connID {
		return nil, 0, oops.Errorf("connection ID collision: source and destination IDs are identical (%d)", connID)
	}

	conn, err := NewSSU2Conn(l.underlying, remoteAddr, connConfig, false, l.config.Load().StaticKey, nil)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to create SSU2 connection")
	}

	conn.SetReadsOwnSocket(false)
	return conn, connID, nil
}

// responderConnID chooses the routing/echo connection ID for a new responder
// session. Per ssu2.md §"Session Request" -> §"Session Created"/§"Retry", this
// must be the Destination Connection ID Alice sent (header bytes 0-7): Bob echoes
// it as the Source Connection ID and both peers use it to route data-phase
// traffic. It is used only when nonzero and not already claimed by another
// session (a spoofed/zero/colliding value falls back to a fresh unique ID so the
// session is still demultiplexable).
func (l *SSU2Listener) responderConnID(packet *SSU2Packet) (uint64, error) {
	if len(packet.Header) >= 8 {
		if aliceDest := binary.BigEndian.Uint64(packet.Header[0:8]); aliceDest != 0 {
			if l.router.GetSession(aliceDest) == nil {
				return aliceDest, nil
			}
		}
	}
	return l.generateUniqueConnectionID()
}

// enforceRateLimit checks if the source IP has exceeded the SessionRequest rate.
//
// Design note: Rate limiting is per-IP only, not per-(IP, ConnectionID).
// This means:
//   - Legitimate retries (packet loss) consume the same rate-limit budget as floods
//   - A client experiencing packet loss may be temporarily rate-limited
//   - This trades some legitimate-retry accommodation for simpler flood defense
//
// Alternative designs considered:
//   - (IP, ConnectionID) bucketing: More complex state, vulnerable to connID cycling attacks
//   - Exempt-once allowance: Adds stateful tracking, unclear benefit for typical loss rates
//
// Current design intentionally treats all SessionRequests equally under the assumption
// that the configured rate limit (sessionRequestsPerSecond) is generous enough to
// accommodate reasonable retry behavior under normal packet loss conditions.
func (l *SSU2Listener) enforceRateLimit(remoteAddr *net.UDPAddr) error {
	flog("enforceRateLimit", logger.Fields{"remote_ip": remoteAddr.IP.String()}).Debug("enforceRateLimit: checking session request rate")
	if !l.sessionRateLimiter.Allow(remoteAddr.IP.String()) {
		return oops.
			Code("RATE_LIMITED").
			In("ssu2_listener").
			Errorf("SessionRequest rate limit exceeded for %s", remoteAddr.IP)
	}
	return nil
}

// handleSessionRequestToken validates the token in a SessionRequest, sending
// a Retry if required by config and no token is present.
func (l *SSU2Listener) handleSessionRequestToken(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	flog("handleSessionRequestToken", logger.Fields{"remote_addr": remoteAddr.String(), "message_type": packet.MessageType}).Debug("handleSessionRequestToken: validating session request token")
	if packet.MessageType != MessageTypeSessionRequest {
		return nil
	}

	err := l.validateSessionRequestToken(packet, remoteAddr)
	if err == nil {
		return nil
	}

	return l.handleSessionRequestTokenError(err, packet, remoteAddr)
}

// When RequireRetry is false, tokens are completely optional. A token that is
// present-but-invalid is treated the same as an absent token (i.e., allow the
// session) because the operator has explicitly opted out of token enforcement.
// An invalid/expired token is only fatal when RequireRetry=true.

func (l *SSU2Listener) handleSessionRequestTokenError(err error, packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	cfg := l.config.Load()
	if errors.Is(err, errNoTokenPresent) && cfg.RequireRetry {
		if retryErr := l.processTokenRequest(packet, remoteAddr); retryErr != nil {
			return oops.Wrapf(retryErr, "failed to send Retry")
		}
		return oops.
			Code("RETRY_SENT").
			In("ssu2_listener").
			Errorf("sent Retry to %s, awaiting re-request with token", remoteAddr)
	}

	if !errors.Is(err, errNoTokenPresent) && cfg.RequireRetry {
		return oops.
			Code("TOKEN_VALIDATION_FAILED").
			In("ssu2_listener").
			Wrap(err)
	}
	return nil
}

// verifyIntroKeyMessage opens an intro-key-sealed out-of-session payload with
// this listener's own intro key, so the caller can be certain the message was
// addressed to us and is unmodified.
//
// Returns the decrypted payload blocks when the payload opens successfully. In
// test mode (no intro key configured) peers send plaintext headers and
// payloads, so the packet payload is returned as-is with a nil error.
func (l *SSU2Listener) verifyIntroKeyMessage(packet *SSU2Packet) ([]byte, error) {
	cfg := l.config.Load()
	if cfg == nil || len(cfg.IntroKey) != HeaderKeySize {
		return packet.Payload, nil // header-protection/test mode: nothing to verify against
	}
	if len(packet.Header) < LongHeaderSize {
		return nil, oops.Errorf("intro-key message requires a %d-byte long header, got %d", LongHeaderSize, len(packet.Header))
	}
	plaintext, err := DecryptIntroKeyAEAD(
		cfg.IntroKey,
		packet.Header[:LongHeaderSize],
		packet.Payload,
		packet.MAC,
		packet.PacketNumber,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "Token Request AEAD validation failed")
	}
	return plaintext, nil
}

// tokenRequestMaxClockSkewDefault is the fallback DateTime skew window when
// SSU2Config.MaxClockSkew is unset. ssu2.md §"Recommended Constants" gives
// "±2 minutes"; config/defaults.go sets MaxClockSkew to 120s, so this only
// guards against a hand-built config that left it zero (which would otherwise
// silently disable the check, the audit F-07 defect class).
const tokenRequestMaxClockSkewDefault = 2 * time.Minute

// validateTokenRequestTimestamp enforces the DateTime skew check on an inbound
// Token Request.
//
// ssu2.md §"Token Request" -> §"Notes": "Bob must reject connections where the
// timestamp value is too far off from the current time. Call the maximum delta
// time D." and "Bob MAY send a Retry message containing a zero token and a
// Termination block with a clock skew reason code if the timestamp in the
// DateTime block is too far skewed." §"Token Request" -> §"Payload" lists the
// DateTime block as required (Java I2P InboundEstablishState2 throws "No
// DateTime block in Session/Token Request").
//
// Returns:
//   - skewExceeded=true, err=nil: a valid DateTime is present but too far off
//     the local clock. The caller MAY answer with a zero-token Retry carrying a
//     clock-skew Termination block, which the spec permits.
//   - err!=nil: the payload is malformed or the required DateTime block is
//     missing. §"Token Request" -> §"Notes" says "On most errors ... Bob should
//     halt further message processing and drop the message without responding",
//     so the caller drops silently.
//   - skewExceeded=false, err=nil: the skew is within the window; proceed.
func (l *SSU2Listener) validateTokenRequestTimestamp(plaintext []byte) (bool, error) {
	blocks, err := DeserializeBlocks(plaintext)
	if err != nil {
		return false, oops.Wrapf(err, "Token Request payload failed to deserialize")
	}
	dateTime := FindBlockByType(blocks, BlockTypeDateTime)
	if dateTime == nil {
		return false, oops.Code("MISSING_DATETIME").In("ssu2_listener").
			Errorf("Token Request missing required DateTime block")
	}
	if len(dateTime.Data) < 4 {
		return false, oops.Errorf("Token Request DateTime block too short: %d bytes", len(dateTime.Data))
	}
	cfg := l.config.Load()
	window := tokenRequestMaxClockSkewDefault
	if cfg != nil && cfg.MaxClockSkew > 0 {
		window = cfg.MaxClockSkew
	}
	remote := time.Unix(int64(binary.BigEndian.Uint32(dateTime.Data[:4])), 0)
	skew := time.Since(remote)
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		flog("validateTokenRequestTimestamp", logger.Fields{
			"skew": skew.String(), "max_skew": window.String(),
		}).Debug("Token Request timestamp skew exceeds the maximum")
		return true, nil
	}
	return false, nil
}

// generateUniqueConnectionID generates a connection ID and verifies uniqueness
// among active sessions. It checks the router (the single source of truth) and
// retries a few times to increase the probability of finding a unique ID
// despite concurrent workers also generating and checking IDs.
func (l *SSU2Listener) generateUniqueConnectionID() (uint64, error) {
	flog("generateUniqueConnectionID").Debug("generateUniqueConnectionID: generating unique connection ID")

	// Retry up to 5 times to find a unique connection ID. With a 64-bit random
	// space, collisions are extremely rare. Even if two workers race to
	// generate IDs, multiple retries increase the probability that at least one
	// attempt succeeds before another worker can claim it.
	const maxRetries = 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		connID, err := GenerateConnectionID()
		if err != nil {
			return 0, oops.Wrapf(err, "failed to generate connection ID")
		}

		if l.router.GetSession(connID) == nil {
			return connID, nil
		}

		if attempt < maxRetries-1 {
			flog("generateUniqueConnectionID", logger.Fields{"attempt": attempt + 1, "max_retries": maxRetries}).Debug("connection ID collision, retrying")
		}
	}

	return 0, oops.Errorf("failed to generate unique connection ID after %d attempts", maxRetries)
}

// buildConnConfig creates a connection-specific config from the listener config
// and the incoming SessionRequest packet.
//
// Placeholder RouterHash: for responder connections (listener-accepted), the
// RouterHash is initially set to SHA256(ephemeralKey) as a placeholder because
// the responder cannot yet authenticate the peer's static identity from the
// SessionRequest alone. This placeholder is sufficient for pre-establishment
// dedup (which keys on initiatorConnID + remoteAddr, not RouterHash) and does
// not break pre-handshake routing. However, the router layer MUST call
// SSU2Addr.UpdateRouterHash(realHash) after handshake completion to replace the
// placeholder with the true peer identity hash. Failure to update the hash may
// cause duplicate inbound sessions if other dedup mechanisms (outside go-noise)
// key on RouterHash. The hook is accessed via SSU2Conn.GetSSU2Addr() after the
// connection is established. See SSU2Addr.UpdateRouterHash godoc for details.
func (l *SSU2Listener) buildConnConfig(packet *SSU2Packet, connID uint64) *SSU2Config {
	flog("buildConnConfig", logger.Fields{"conn_id": connID}).Debug("buildConnConfig: building connection config from session request")
	var routerHash data.Hash
	if len(packet.EphemeralKey) == 32 {
		routerHash = data.NewHash(sha256.Sum256(packet.EphemeralKey))
	}

	connConfig := *l.config.Load()
	connConfig.ConnectionID = connID
	connConfig.RouterHash = routerHash
	connConfig.Initiator = false

	if len(packet.Header) >= 24 {
		connConfig.InitiatorConnectionID = binary.BigEndian.Uint64(packet.Header[16:24])
	}
	return &connConfig
}

// checkPendingCapacity validates the pending session count against the configured cap.
// Returns the effective max pending count and an error if capacity is exceeded.
// It applies a hard cap even when MaxSessions==0 to prevent remote memory DoS.
func (l *SSU2Listener) checkPendingCapacity() (int, error) {
	l.sessionMutex.RLock()
	pendingCount := len(l.pendingByInitiator)
	l.sessionMutex.RUnlock()

	const defaultMaxPendingByInitiator = 2000
	maxPendingByInitiator := l.config.Load().MaxSessions * 2
	if maxPendingByInitiator <= 0 {
		maxPendingByInitiator = defaultMaxPendingByInitiator
	}

	if pendingCount >= maxPendingByInitiator {
		return 0, oops.
			Code("PENDING_CAPACITY_EXCEEDED").
			In("ssu2_listener").
			With("pending_count", pendingCount).
			With("max_pending", maxPendingByInitiator).
			Errorf("pending session capacity exceeded, connection refused")
	}

	return maxPendingByInitiator, nil
}

// installCloseHook sets up the connection close hook to perform cleanup:
// removes the session from the router (if registered) and deletes from pending map.
// Returns an atomic.Bool that tracks registration state for the close hook to query.
// The registered flag prevents RemoveSession from being called if the session was
// never inserted due to a race or capacity error.
func (l *SSU2Listener) installCloseHook(conn *SSU2Conn, connID uint64, dedupKey string) *atomic.Bool {
	var registered atomic.Bool
	conn.SetCloseHook(func() {
		if registered.Load() {
			l.router.RemoveSession(connID)
		}
		// Remove from pending dedup index (safe even if never inserted).
		l.sessionMutex.Lock()
		delete(l.pendingByInitiator, dedupKey)
		l.sessionMutex.Unlock()
		// Remove from AcceptedSessionRegistry so the trial-deobfuscate scan does
		// not keep probing a closed session's (now-stale) header protectors.
		l.acceptedSessions.Remove(connID)
	})
	return &registered
}

// registerInRouter atomically performs the dedup check and router registration:
// checks if another concurrent worker beat us to the same dedup key, and if not,
// registers the session in the router. Must be called under sessionMutex.
// Returns the existing connection if a dedup race was lost, or an error if
// router registration failed.
func (l *SSU2Listener) registerInRouter(conn *SSU2Conn, connID uint64, dedupKey string, registered *atomic.Bool) (*SSU2Conn, error) {
	if existing, ok := l.pendingByInitiator[dedupKey]; ok {
		// Race lost: another worker registered for this initiator first.
		return existing, nil
	}
	if err := l.router.AddSessionIfBelowCap(conn, l.config.Load().MaxSessions); err != nil {
		return nil, oops.Wrapf(err, "failed to register session in router")
	}
	registered.Store(true)
	l.pendingByInitiator[dedupKey] = conn
	return conn, nil
}

// enqueueConnection sends the connection to the accept queue.
// Handles failure modes: listener shutdown and queue full. On any failure,
// removes the session from the router and tears down the connection,
// preventing leaks.
func (l *SSU2Listener) enqueueConnection(conn *SSU2Conn, connID uint64, dedupKey string) (*SSU2Conn, error) {
	select {
	case l.acceptQueue <- conn:
		return conn, nil
	case <-l.shutdownChan:
		l.router.RemoveSession(connID)
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener closed during session creation")
	default:
		l.router.RemoveSession(connID)
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("ACCEPT_QUEUE_FULL").
			In("ssu2_listener").
			Errorf("accept queue full, connection dropped")
	}
}

// registerAndQueueConn registers the connection in the sessions map and
// queues it for acceptance.
//
// Safety properties:
//   - The connection ID uniqueness check in generateUniqueConnectionID
//     releases its lock before this insert, so a concurrent worker could have
//     claimed the same ID. The insert is guarded by a re-check under the
//     write lock, rejecting (and tearing down) a colliding session instead of
//     silently overwriting and orphaning the previous one.
//   - The session map is capped at config.MaxSessions so a handshake
//     flood cannot grow the map and per-session goroutines without bound.
//   - On every early-return path the session is removed from the map
//     and torn down (no leaked goroutines), and a close hook is installed so a
//     normal close later deregisters the session from both routing maps.
//   - The pendingByInitiator dedup index is used for retransmit dedup.
func (l *SSU2Listener) registerAndQueueConn(conn *SSU2Conn, connID uint64, remoteAddr *net.UDPAddr, initiatorConnID uint64) (*SSU2Conn, error) {
	flog("registerAndQueueConn", logger.Fields{"conn_id": connID}).Debug("registerAndQueueConn: registering session and queuing for accept")

	// Create dedup key for retransmit detection.
	dedupKey := makeDedupKey(initiatorConnID, remoteAddr)

	// Check pending capacity before proceeding with registration.
	if _, err := l.checkPendingCapacity(); err != nil {
		_ = conn.CloseImmediate()
		return nil, err
	}

	// Install close hook early so cleanup runs regardless of
	// whether registration succeeds.
	registered := l.installCloseHook(conn, connID, dedupKey)

	// Perform dedup check, router registration, and
	// pendingByInitiator insert as a single atomic operation under sessionMutex.
	l.sessionMutex.Lock()
	existing, err := l.registerInRouter(conn, connID, dedupKey, registered)
	l.sessionMutex.Unlock()

	if err != nil {
		_ = conn.CloseImmediate()
		return nil, err
	}

	// If we lost the dedup race, return the existing connection (winner).
	if existing != conn {
		_ = conn.CloseImmediate()
		return existing, nil
	}

	// Register in AcceptedSessionRegistry so inbound SessionConfirmed and Data
	// packets (which use per-session KDF-derived header keys not decodable via
	// the listener's intro-key protector) can be trial-deobfuscated and routed.
	// Ignore errors: capacity exceeded means we still queue the session but just
	// won't be able to decode its header-protected inbound packets — the caller
	// will see a handshake timeout rather than a listener-level hard failure.
	if regErr := l.acceptedSessions.Register(connID, conn); regErr != nil {
		flog("registerAndQueueConn", logger.Fields{"conn_id": connID}).WithError(regErr).Warn("failed to register session in AcceptedSessionRegistry; inbound SessionConfirmed/Data will not be decodable")
	} else {
		// Wire up SessionConfirmed key notification (responder path only, but
		// harmless for initiators since notifySessConfirmedKey is a no-op when
		// sessConfirmedKeyNotifyCh is nil — we set it here for all accepted
		// sessions since they are all responders).
		sessConfirmedKeyCh := make(chan *HeaderProtector, 1)
		conn.SetAcceptedSessionConfirmedKeyNotify(sessConfirmedKeyCh)

		// Wire up data-phase inbound key notification (both roles).
		recvDataKeyCh := make(chan *HeaderProtector, 1)
		conn.SetAcceptedDataKeyNotify(recvDataKeyCh)

		// Background goroutines drain the key channels and install protectors.
		// Each goroutine exits on: key received, session closed, or listener
		// shutdown — whichever comes first.  l.wg is used so listener.Close()
		// waits for these goroutines before closing the accept queue.
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			select {
			case p := <-sessConfirmedKeyCh:
				if err := l.acceptedSessions.SetSessionConfirmedProtector(connID, p); err != nil {
					flog("sessConfirmedKeyNotify", logger.Fields{"conn_id": connID}).WithError(err).Warn("failed to install SessionConfirmed protector in AcceptedSessionRegistry")
				}
			case <-conn.CloseChan():
			case <-l.shutdownChan:
			}
		}()

		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			select {
			case p := <-recvDataKeyCh:
				if err := l.acceptedSessions.SetDataPhaseProtector(connID, p); err != nil {
					flog("recvDataKeyNotify", logger.Fields{"conn_id": connID}).WithError(err).Warn("failed to install data-phase protector in AcceptedSessionRegistry")
				}
			case <-conn.CloseChan():
			case <-l.shutdownChan:
			}
		}()
	}

	// Connection successfully registered; now queue it for accept.
	return l.enqueueConnection(conn, connID, dedupKey)
}

// validateSessionRequestToken reads and validates the token from a SessionRequest.
//
// The token is the 8-byte Token field at header bytes 24-31, NOT a payload block.
// ssu2.md §"Session Request" raw-contents table lists "Token" as a header field, and
// §"Inbound Packet Handling" step 2a is explicit about both the ordering and the
// location:
//
//	"If the token at header bytes 24-31 is accepted, then MixHash() the decrypted 32
//	 byte header and decrypt the message with Noise. Send a Session Created in response.
//	 If the token is not accepted, send a Retry message to the source IP/port with a
//	 token. Do not attempt to decrypt the message with Noise to avoid DDoS attacks."
//
// and §"Tokens": "If Bob does not accept the token in the Session Request message, Bob
// does NOT decrypt the message, as it requires an expensive DH operation."
//
// A Session Request may not even carry a New Token block: §"Session Request" -> §"Payload"
// allows only "DateTime block / Options block (optional) / Relay Tag Request block
// (optional) / Padding block (optional)". Reading the token from a New Token block inside
// the Noise-encrypted payload therefore required decrypting the message before the gate,
// which is exactly the DoS exposure the spec forbids (audit finding SS-01).
//
// Returns nil if the token is valid, errNoTokenPresent if it is absent/zero, or an error
// describing the validation failure.
func (l *SSU2Listener) validateSessionRequestToken(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	// The Token field occupies header bytes 24-31 of the 32-byte long header.
	const tokenHeaderOffset = 24
	if len(packet.Header) < tokenHeaderOffset+TokenSize {
		return errNoTokenPresent
	}

	token := make([]byte, TokenSize)
	copy(token, packet.Header[tokenHeaderOffset:tokenHeaderOffset+TokenSize])

	// A zero token means Alice has not received one yet; §"Session Request" defines
	// "Token :: 0 if not previously received from Bob".
	if isAllZero(token) {
		return errNoTokenPresent
	}

	// Validate and consume against the cache. Retry tokens are single-use and
	// short-lived, so expiry is enforced inside the cache and needs no separate
	// timestamp check here (§"Tokens": "Tokens may only be used once").
	local := l.localUDPAddress()
	if !l.tokenCache.ConsumeToken(token, remoteAddr, local) {
		// A presented-but-invalid token is not the token we issued for this
		// address. ssu2.md §"Handshake Retransmission" -> "### Retry":
		//
		//   "If a second Session Request message is received with a different but
		//    still-invalid token, drop the pending session and do not respond."
		//
		// So the outstanding token (the pending session's state) is discarded here,
		// and the caller responds with nothing. A later Session Request repeating the
		// previously issued token must NOT be accepted once the pending session has
		// been dropped.
		l.tokenCache.DeleteToken(remoteAddr, local)
		return oops.
			Code("INVALID_TOKEN").
			In("ssu2_listener").
			With("address", remoteAddr.String()).
			Errorf("token validation failed; pending session dropped")
	}

	return nil
}

// replayCacheTTLFloor bounds the replay cache when MaxClockSkew is unset.
// Spec ref: ssu2.md §"Session Request" -> §"Notes" - cache lifetime "at least 2*D".
const replayCacheTTLFloor = 4 * time.Minute

// newHandshakeReplayCache builds the SessionRequest replay cache with the
// spec-mandated minimum lifetime of 2*D, where D is the configured maximum clock
// skew (the "maximum delta time" of ssu2.md §"Session Request" -> §"Notes").
func newHandshakeReplayCache(config *SSU2Config) *replaycache.TTLCache {
	ttl := 2 * config.MaxClockSkew
	if ttl < replayCacheTTLFloor {
		ttl = replayCacheTTLFloor
	}
	return replaycache.New(replaycache.Config{
		TTL:             ttl,
		MaxSize:         handshakeReplayMaxSize,
		CleanupInterval: 30 * time.Second,
	})
}

// handshakeReplayMaxSize bounds replay-cache memory. Sized above the spec's 2*D
// lifetime window for the default skew so legitimate peers are not evicted early.
const handshakeReplayMaxSize = 8192

// sessionRequestReplayKey derives the replay cache value for a SessionRequest.
//
// Spec ref: ssu2.md §"Session Request" -> §"Notes": "the 32-byte X value (or its
// encrypted equivalent) may be used". The X value arrives header-encrypted (bytes
// 32-63 of the datagram), so the encrypted equivalent is used, together with the
// ciphertext, to identify the message uniquely.
func sessionRequestReplayKey(packet *SSU2Packet) [32]byte {
	h := sha256.New()
	h.Write(packet.EphemeralKey)
	h.Write(packet.Payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// rejectSessionRequestReplay implements the spec's SessionRequest replay
// rejection: a duplicate handshake value is answered with a Retry carrying a
// zero token and a Termination block, and the message is never decrypted.
//
// Returns nil when the packet is not a replay (or not a SessionRequest), a
// RETRY_SENT-coded error wrapped as REPLAY_REJECTED once the rejection Retry has
// gone out, or a send failure.
func (l *SSU2Listener) rejectSessionRequestReplay(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	if packet.MessageType != MessageTypeSessionRequest || l.handshakeReplay == nil {
		return nil
	}

	key := sessionRequestReplayKey(packet)
	if !l.handshakeReplay.CheckAndAdd(key) {
		return nil
	}

	flog("rejectSessionRequestReplay", logger.Fields{"remote_addr": remoteAddr.String()}).
		Debug("Duplicate SessionRequest handshake value: rejecting with zero-token Retry + Termination")

	// "Reject by sending a Retry message containing a zero token and a
	// termination block." A zero token tells the peer not to retry.
	//
	// The Retry cannot be sent without an intro key (it must be AEAD-sealed and
	// header-obfuscated), and ssu2.md §"Session Request" -> §"Notes" also says "On
	// most errors, including AEAD, DH, apparent replay, or key validation failure,
	// Bob should halt further message processing and drop the message without
	// responding", so a send failure degrades to a silent drop rather than an error.
	reason := TerminationSessionRequestError
	incomingSize := len(packet.Header) + len(packet.Payload) + len(packet.MAC)
	zeroToken := make([]byte, TokenSize)
	if err := l.sendRetry(remoteAddr, zeroToken, packet.Header, incomingSize, &reason); err != nil {
		flog("rejectSessionRequestReplay", logger.Fields{"error": err.Error()}).
			Debug("Replayed SessionRequest dropped without a rejection Retry")
	}
	return oops.
		Code("REPLAY_REJECTED").
		In("ssu2_listener").
		Errorf("replayed SessionRequest rejected")
}

// localUDPAddress returns the listener's bound local (destination) address, used to
// bind tokens to the source + destination pair required by ssu2.md §"Tokens".
//
// Go's net.PacketConn exposes only the socket's bound address, not the per-datagram
// destination IP, so a wildcard bind (0.0.0.0) maps every destination to one key. That
// is no weaker than the previous behaviour and is exact for the normal case of a listener
// bound to a specific interface address.
func (l *SSU2Listener) localUDPAddress() *net.UDPAddr {
	if l.underlying == nil {
		return nil
	}
	udpAddr, ok := l.underlying.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return udpAddr
}

// isAllZero reports whether every byte of b is zero.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// processTokenRequest handles a TokenRequest message by generating and sending
// a Retry message with a new token.
//
// Two admission gates run before a token cache entry is allocated, to blunt
// off-path spoofed-source flooding attacks:
//
//  1. First-sight: unless FirstSightRequired is disabled, a brand-new
//     source address is recorded but declined. The peer must re-request to
//     obtain a token. SSU2 clients retry TokenRequests per spec, so
//     legitimate peers recover transparently.
//  2. Global issuance rate: a single bucket caps total tokens/sec issued
//     across all peers, backstopping the first-sight gate against any
//     bypass and preventing issuance-rate amplification.
//
// When either gate rejects a request, no packet is sent in reply and no
// token cache state is allocated for the caller. The returned error is
// informational (callers of this method currently ignore it) and uses the
// NO_TOKEN_ISSUED code so operators can surface the counter.
func (l *SSU2Listener) processTokenRequest(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	if err := validateParam(remoteAddr, "remote address", "NIL_ADDRESS", "ssu2_listener"); err != nil {
		return err
	}

	// Validate the message's AEAD before responding.
	//
	// ssu2.md §"Packet Integrity": "Inbound packet handlers must always decrypt
	// the ChaCha20 payload and validate the MAC before processing the message",
	// and §"Token Request" -> §"Notes": "On most errors, including AEAD, or
	// apparent replay Bob should halt further message processing and drop the
	// message without responding." The §"Packet Integrity" exception that permits
	// answering from header values alone is scoped to the Session Request, not
	// the Token Request, so an unverified Token Request must not be answered.
	//
	// The Token Request payload is sealed with Bob's intro key (the receiver's
	// own) as k, the 4-byte header packet number as n, and the 32-byte header
	// before header encryption as ad (ssu2.md §"KDF for Token Request").
	plaintext, err := l.verifyIntroKeyMessage(packet)
	if err != nil {
		flog("processTokenRequest", logger.Fields{"remote_addr": remoteAddr.String()}).
			WithError(err).Debug("dropping Token Request that failed AEAD validation")
		return errNoTokenPresent
	}

	// Reject a Token Request whose DateTime is too far off the local clock,
	// before spending any token-issuance resources on it.
	//
	// ssu2.md §"Token Request" -> §"Notes" makes the skew check mandatory for
	// Bob. §"Handshake Retransmission" -> §"Token Request" notes the message is
	// not part of the Noise handshake, so the response is a zero-token Retry
	// with a clock-skew Termination block (a "don't retry" signal), which the
	// spec explicitly permits.
	skewExceeded, skewErr := l.validateTokenRequestTimestamp(plaintext)
	if skewErr != nil {
		// Malformed payload or missing DateTime: drop without responding, per
		// ssu2.md §"Token Request" -> §"Notes" ("On most errors ... Bob should
		// halt further message processing and drop the message without
		// responding").
		flog("processTokenRequest", logger.Fields{"remote_addr": remoteAddr.String()}).
			WithError(skewErr).Debug("dropping malformed Token Request")
		return errNoTokenPresent
	}
	if skewExceeded {
		// ssu2.md §"Token Request" -> §"Notes": Bob MAY answer excessive clock
		// skew with a zero-token Retry carrying a clock-skew Termination block
		// (a "don't retry" signal). No token state is allocated.
		reason := TerminationClockSkew
		zeroToken := make([]byte, TokenSize)
		incomingSize := len(packet.Header) + len(packet.Payload) + len(packet.MAC)
		if sendErr := l.sendRetry(remoteAddr, zeroToken, packet.Header, incomingSize, &reason); sendErr != nil {
			flog("processTokenRequest", logger.Fields{"error": sendErr.Error()}).
				Debug("failed to send clock-skew rejection Retry")
		}
		return errNoTokenPresent
	}

	addrKey := remoteAddr.String()

	// Gate 1 (Strategy 3): first-sight tracker. A brand-new address is
	// recorded and declined; the peer must re-request. This forces a
	// spoofing attacker to spend ≥2 packets per spoofed IP, and the
	// per-sighting state is smaller than a Token struct and lives in an
	// independent bounded map so exhausting first-sight cannot evict
	// real tokens.
	if l.config.Load().FirstSightRequired && !l.firstSight.ObserveAndAllow(addrKey) {
		flog("processTokenRequest", logger.Fields{"remote_addr": addrKey}).Debug("declining token issuance: first-sight only, peer must retry")
		return oops.
			Code("NO_TOKEN_ISSUED").
			In("ssu2_listener").
			With("reason", "first_sight").
			With("address", addrKey).
			Errorf("first-sight gate: deferring token issuance until retry")
	}

	// Gate 2 (Strategy 1): global issuance bucket. Even if the first-sight
	// gate passes, never issue more than the configured rate in aggregate.
	if !l.issuanceLimiter.Allow() {
		flog("processTokenRequest", logger.Fields{"remote_addr": addrKey}).Debug("declining token issuance: global issuance rate exceeded")
		return oops.
			Code("NO_TOKEN_ISSUED").
			In("ssu2_listener").
			With("reason", "global_rate_limit").
			With("address", addrKey).
			Errorf("global token issuance rate limit exceeded")
	}

	// Generate token for this address
	token, err := l.tokenCache.GenerateToken(remoteAddr, l.localUDPAddress())
	if err != nil {
		return oops.Wrapf(err, "failed to generate token")
	}

	// Create and send Retry message with token.
	// Per spec: Retry must not be larger than 3x the incoming message.
	incomingSize := len(packet.Header) + len(packet.Payload) + len(packet.MAC)
	return l.sendRetry(remoteAddr, token, packet.Header, incomingSize, nil)
}

// SessionCount returns the current number of active sessions.
// It queries the router (the single source of truth).
func (l *SSU2Listener) SessionCount() int {
	return l.router.SessionCount()
}

// AddSession registers an SSU2Conn under the given connection ID.
// This is primarily useful for testing and for reconnection scenarios.
// It delegates to the router (the single source of truth).
//
// Returns an error if conn is nil, if conn's actual connection ID (from its
// SSU2Addr) does not match the supplied connID, or if the router rejects
// registration (e.g. duplicate connection ID already registered).
func (l *SSU2Listener) AddSession(connID uint64, conn *SSU2Conn) error {
	if conn == nil {
		return oops.
			Code("INVALID_SESSION").
			In("ssu2_listener").
			Errorf("connection cannot be nil")
	}
	remote, ok := conn.RemoteAddr().(*SSU2Addr)
	if !ok || remote == nil {
		return oops.
			Code("INVALID_SESSION_ADDR").
			In("ssu2_listener").
			Errorf("connection must have SSU2Addr")
	}
	if actual := remote.ConnectionID(); actual != connID {
		return oops.
			Code("CONNECTION_ID_MISMATCH").
			In("ssu2_listener").
			With("requested_connection_id", connID).
			With("actual_connection_id", actual).
			Errorf("connID argument does not match connection's actual connection ID")
	}
	return l.router.AddSession(conn)
}

// RemoveSession deregisters the session with the given connection ID.
// It delegates to the router (the single source of truth).
func (l *SSU2Listener) RemoveSession(connID uint64) {
	l.router.RemoveSession(connID)
}

// Underlying returns the PacketConn used by this listener.
func (l *SSU2Listener) Underlying() net.PacketConn {
	return l.underlying
}

// Config returns the SSU2Config used by this listener.
func (l *SSU2Listener) Config() *SSU2Config {
	return l.config.Load()
}

// UpdateIdentity replaces the configuration used for new inbound sessions,
// without touching the socket or the sessions already established.
//
// An SSU2 responder's identity is consumed per session, not per socket:
// handleNewSession reads StaticKey when creating each session and
// buildConnConfig copies the whole config per SessionRequest. Updating the
// config in place is therefore sufficient to make subsequent handshakes use a
// new RouterInfo, and it preserves the live session table that recreating the
// listener would destroy. Rebinding the socket instead cannot work at all,
// because the old socket must stay open for the swap to be atomic and a second
// bind to the same port fails with EADDRINUSE.
//
// Like NewSSU2Listener, this stores the caller's pointer rather than a copy, so
// the caller must finish mutating cfg before publishing it (or call
// UpdateIdentity again afterwards). go-i2p's transport populates IntroKey and
// ObfuscationIV on this config after the listener starts, and the per-session
// copy in buildConnConfig depends on observing that through the shared pointer;
// a defensive copy here would freeze those fields and silently disable ChaCha
// obfuscation for inbound sessions.
//
// Derived state is rebuilt before the new config is published, so a packet
// arriving mid-update is decrypted with the new intro key while sessions are
// still created under the old static key for at most one handshake — the peer
// retransmits and converges. The reverse order would drop new-key SessionRequests.
func (l *SSU2Listener) UpdateIdentity(cfg *SSU2Config) error {
	if cfg == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_listener").
			Errorf("identity config cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_listener").
			Wrapf(err, "refusing to apply invalid identity config")
	}

	l.closeMutex.Lock()
	if l.closed {
		l.closeMutex.Unlock()
		return oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener is closed")
	}
	l.closeMutex.Unlock()

	// Rebuild the intro-key protector first (see ordering note above). The
	// protector is derived solely from IntroKey, so an update that clears it
	// must clear the field too rather than leave a stale protector decrypting
	// with a retired key.
	if len(cfg.IntroKey) != 32 {
		l.introHeaderProtector.Store(nil)
	} else if err := l.initHeaderProtection(cfg); err != nil {
		return oops.Wrapf(err, "failed to rebuild inbound header protection")
	}

	// The listener address carries the router hash; it is already guarded by
	// SSU2Addr's own RWMutex.
	l.addr.UpdateRouterHash(cfg.RouterHash)

	l.config.Store(cfg)
	return nil
}

// TokenCache returns the token cache used by this listener.
func (l *SSU2Listener) TokenCache() *TokenCache {
	return l.tokenCache
}

// Router returns the packet router used by this listener.
func (l *SSU2Listener) Router() *PacketRouter {
	return l.router
}

// tokenCleanupInterval is how often the listener removes expired tokens.
const tokenCleanupInterval = 60 * time.Second

// tokenCleanupLoop periodically removes expired tokens from the cache.
func (l *SSU2Listener) tokenCleanupLoop() {
	flog("tokenCleanupLoop", logger.Fields{"interval": tokenCleanupInterval}).Debug("tokenCleanupLoop: starting periodic token cache cleanup")
	defer l.wg.Done()

	ticker := time.NewTicker(tokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.shutdownChan:
			return
		case <-ticker.C:
			l.tokenCache.Cleanup()
			// Clean up stale first-sight entries so the tracker does not grow
			// to maxEntries and never shrink, which would permanently bypass
			// the first-sight gate for any addresses in the full map.
			l.firstSight.Cleanup()
		}
	}
}

// Per-IP rate limiter for SessionRequest processing.

const (
	// sessionRequestsPerSecond is the maximum SessionRequests per IP per second.
	sessionRequestsPerSecond = 10

	// sessionRateLimiterMaxIPs is the maximum number of IPs tracked.
	sessionRateLimiterMaxIPs = 10000
)

// ipRateLimiter implements a simple per-IP rate limiter using a token bucket
// approximation. Each IP is allowed a fixed number of requests per second.
//
// Eviction uses an O(1) LRU (a doubly-linked list ordered from
// least- to most-recently-seen) rather than an O(n) scan of the whole map.
// Under a spoofed-source flood a full scan would run for every new IP while
// holding the mutex, creating a throughput cliff. The list mirrors
// firstSightTracker.
type ipRateLimiter struct {
	entries map[string]*list.Element // ip -> element holding *rateLimitEntry
	order   *list.List               // front = LRU, back = MRU
	rate    int                      // max requests per second
	maxIPs  int
	mutex   sync.Mutex
}

type rateLimitEntry struct {
	ip        string
	tokens    float64
	lastCheck time.Time
}

func newIPRateLimiter(rate, maxIPs int) *ipRateLimiter {
	return &ipRateLimiter{
		entries: make(map[string]*list.Element),
		order:   list.New(),
		rate:    rate,
		maxIPs:  maxIPs,
	}
}

// Allow returns true if the request from the given IP should be permitted.
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	if el, exists := rl.entries[ip]; exists {
		entry := el.Value.(*rateLimitEntry)
		// Refill tokens based on elapsed time
		elapsed := now.Sub(entry.lastCheck).Seconds()
		entry.tokens += elapsed * float64(rl.rate)
		if entry.tokens > float64(rl.rate) {
			entry.tokens = float64(rl.rate)
		}
		entry.lastCheck = now
		rl.order.MoveToBack(el) // mark most-recently-used

		if entry.tokens >= 1 {
			entry.tokens--
			return true
		}
		return false
	}

	// New IP: evict the least-recently-used entry in O(1) if at capacity.
	if rl.maxIPs > 0 && len(rl.entries) >= rl.maxIPs {
		if front := rl.order.Front(); front != nil {
			oldest := front.Value.(*rateLimitEntry)
			delete(rl.entries, oldest.ip)
			rl.order.Remove(front)
		}
	}
	entry := &rateLimitEntry{
		ip:        ip,
		tokens:    float64(rl.rate) - 1,
		lastCheck: now,
	}
	rl.entries[ip] = rl.order.PushBack(entry)
	return true
}

// GetDroppedPackets returns the number of packets dropped due to full packetQueue.
// This metric indicates sustained overload where the listener cannot process incoming
// packets fast enough. Consider increasing packetQueueSize or packetWorkers if this
// counter grows under normal load.
func (l *SSU2Listener) GetDroppedPackets() uint64 {
	return atomic.LoadUint64(&l.droppedPackets)
}
