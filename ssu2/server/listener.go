package server

import (
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Listener implements net.Listener for accepting SSU2 connections over UDP.
// It manages incoming packets, routes them to existing sessions, and creates
// new sessions for valid handshake packets.
//
// Design rationale:
// - Uses PacketRouter to dispatch packets to appropriate sessions
// - Uses TokenCache to validate retry tokens and prevent spoofing
// - Implements net.Listener interface for compatibility with standard library
// - Single UDP socket shared across all sessions (multiplexing)
// - Worker pool limits goroutine count under traffic floods
//
// Thread Safety: All public methods are thread-safe.
type SSU2Listener struct {
	// underlying is the UDP socket for receiving packets
	underlying net.PacketConn

	// config holds listener configuration
	config *SSU2Config

	// addr is the SSU2 address for this listener
	addr *SSU2Addr

	// AUDIT 5.4: Stable source connection ID for Retry messages.
	// Per SSU2 spec, the responder's source ConnID in a Retry should be
	// stable across multiple Retries for the same peer, so the initiator
	// can use it as the destination ConnID in subsequent SessionRequests.
	// This is generated once at listener creation and reused for all Retries.
	retrySourceConnID [8]byte

	// AUDIT 8.3: Removed listener.sessions — router is now single session owner.
	// All session queries go through router via GetSession/SessionCount/RemoveSession.
	// pendingByInitiator is the only listener-local session tracking (pre-establishment dedup only).

	// pendingByInitiator maps (initiatorConnID, remoteAddr) to SSU2Conn to dedup
	// retransmitted SessionRequests. This prevents creating duplicate sessions for
	// handshake retransmits. Key format: hex(initiatorConnID)|IP:port
	// Protected by sessionMutex. Bound by MaxSessions.
	// AUDIT 8.1: dedup index keyed on initiator's source connID + source address
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
	// packets (SessionRequest, TokenRequest). Per SSU2 spec, both header
	// protection keys for these packet types are the receiver's intro key.
	// Nil when config.IntroKey is unset, in which case the listener assumes
	// inbound packets are sent with plaintext headers (legacy / test mode).
	// Addresses AUDIT C-1: the listener now attempts header-protection
	// decryption for incoming packets that fail plaintext deserialization,
	// enabling interop with spec-compliant SSU2 peers (i2pd / Java I2P).
	introHeaderProtector *HeaderProtector

	// sessionRateLimiter limits SessionRequest processing per source IP (M-6)
	sessionRateLimiter *ipRateLimiter

	// droppedPackets counts packets silently discarded when packetQueue is full (M-7).
	// Accessed atomically to avoid races between receiveLoop and stats readers.
	droppedPackets uint64

	// routingErrors counts packets that failed to route to a session and were
	// not handled as a TokenRequest (AUDIT 5.1). Previously these failures
	// were swallowed with no signal. Accessed atomically.
	routingErrors uint64

	// Lifecycle management
	closed       bool
	closeMutex   sync.Mutex
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// NewSSU2Listener creates a new SSU2 listener wrapping the specified packet connection.
// The listener starts in an idle state; call Start() to begin accepting connections.
//
// Parameters:
//   - underlying: UDP PacketConn to receive packets from
//   - config: SSU2 configuration for accepted connections
//
// Returns a new SSU2Listener ready to start, or an error if configuration is invalid.
func NewSSU2Listener(underlying net.PacketConn, config *SSU2Config) (*SSU2Listener, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "NewSSU2Listener"}).Debug("Creating new SSU2 listener")
	if underlying == nil {
		return nil, oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_listener").
			Errorf("underlying packet connection cannot be nil")
	}

	if config == nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ssu2_listener").
			Errorf("configuration cannot be nil")
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
		config:             config,
		addr:               addr,
		pendingByInitiator: make(map[string]*SSU2Conn),
		tokenCache:         newTokenCacheFromConfig(config),
		sessionRateLimiter: newIPRateLimiter(sessionRequestsPerSecond, sessionRateLimiterMaxIPs),
		firstSight:         newFirstSightTracker(config.FirstSightWindow, config.FirstSightMaxEntries),
		issuanceLimiter:    newTokenIssuanceLimiter(config.GlobalTokenIssuanceRate, config.GlobalTokenIssuanceBurst),
		acceptQueue:        make(chan *SSU2Conn, 100), // Buffer 100 pending connections
		packetQueue:        make(chan incomingPacket, packetQueueSize),
		shutdownChan:       make(chan struct{}),
	}

	// AUDIT 5.4: Initialize stable retry source connection ID
	// This ensures that all Retry messages from this listener use the same source ConnID
	if _, err := rand.Read(l.retrySourceConnID[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate retry source connection ID")
	}

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
	log.WithFields(logger.Fields{"pkg": "server", "func": "Start"}).Debug("Starting SSU2 listener")
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener is closed")
	}

	// Start packet processing worker pool
	for i := 0; i < packetWorkers; i++ {
		l.wg.Add(1)
		go l.packetWorker()
	}

	// Start packet receive loop
	l.wg.Add(1)
	go l.receiveLoop()

	// G-5: Start periodic token cache cleanup to prevent expired token
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "Accept"}).Debug("Waiting to accept SSU2 connection")
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "Close"}).Debug("Closing SSU2 listener")
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return nil // Already closed
	}

	l.closed = true
	close(l.shutdownChan)

	// AUDIT 3.2: Cancel all pending DestroyTimeout waits in parallel by closing
	// their forceDestroy channels. This prevents serial blocking when the listener
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

	// M-2: Close the underlying connection first to unblock ReadFrom
	// in receiveLoop, rather than relying on deadline-based polling.
	closeErr := l.underlying.Close()

	// Wait for goroutines to finish before closing channels.
	// This prevents send-on-closed-channel panics in handleNewSession.
	l.wg.Wait()

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
// Format: hex(initiatorConnID)|IP:port
// AUDIT 8.1: used to detect and deduplicate retransmitted SessionRequests.
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "handleNewSession", "remote_addr": remoteAddr.String()}).Debug("handleNewSession: creating new session for incoming handshake")

	// AUDIT 7.2 — Validate source address (reject reserved ports, loopback unless allowed, etc.)
	if err := validateListenAddress(remoteAddr, l.config); err != nil {
		return nil, oops.
			Code("INVALID_SOURCE_ADDRESS").
			In("ssu2_listener").
			With("remote_address", remoteAddr.String()).
			Wrapf(err, "rejecting SessionRequest from invalid source address")
	}

	if err := l.enforceRateLimit(remoteAddr); err != nil {
		return nil, err
	}

	if err := l.handleSessionRequestToken(packet, remoteAddr); err != nil {
		return nil, err
	}

	// AUDIT 8.1: Extract initiator connection ID early for dedup check.
	// Per SSU2 spec, initiator's source connID is at header[16:24].
	var initiatorConnID uint64
	if len(packet.Header) >= 24 {
		initiatorConnID = binary.BigEndian.Uint64(packet.Header[16:24])
	}

	// AUDIT 8.1: Check dedup index for existing session keyed on (initiatorConnID, remoteAddr).
	// If a session already exists for this (initiator key, source address) pair,
	// route the retransmit to it instead of creating a duplicate.
	dedupKey := makeDedupKey(initiatorConnID, remoteAddr)
	l.sessionMutex.RLock()
	existingConn := l.pendingByInitiator[dedupKey]
	l.sessionMutex.RUnlock()
	if existingConn != nil {
		log.WithFields(logger.Fields{
			"pkg":         "server",
			"func":        "handleNewSession",
			"dedup_key":   dedupKey,
			"remote_addr": remoteAddr.String(),
		}).Debug("handleNewSession: routing retransmit to existing pending session")
		return existingConn, nil
	}

	connID, err := l.generateUniqueConnectionID()
	if err != nil {
		return nil, err
	}

	connConfig := l.buildConnConfig(packet, connID)

	if connConfig.InitiatorConnectionID != 0 && connConfig.InitiatorConnectionID == connID {
		return nil, oops.Errorf("connection ID collision: source and destination IDs are identical (%d)", connID)
	}

	conn, err := NewSSU2Conn(l.underlying, remoteAddr, connConfig, false, l.config.StaticKey, nil)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 connection")
	}

	// AUDIT 1.2: Mark this listener-accepted responder session as not responsible for
	// reading the socket. The listener's receiveLoop is the sole socket reader and will
	// feed packets to this session via RoutePacket → processInboundPacket → recvQueue.
	// This prevents two goroutines (listener and recvLoop) from concurrently reading
	// the same shared socket, which violates the SSU2 multiplexing invariant.
	conn.SetReadsOwnSocket(false)

	// AUDIT 8.1: Pass dedup key to registerAndQueueConn
	return l.registerAndQueueConn(conn, connID, remoteAddr, initiatorConnID)
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "enforceRateLimit", "remote_ip": remoteAddr.IP.String()}).Debug("enforceRateLimit: checking session request rate")
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
	log.WithFields(logger.Fields{"pkg": "server", "func": "handleSessionRequestToken", "remote_addr": remoteAddr.String(), "message_type": packet.MessageType}).Debug("handleSessionRequestToken: validating session request token")
	if packet.MessageType != MessageTypeSessionRequest {
		return nil
	}

	err := l.validateSessionRequestToken(packet, remoteAddr)
	if err == nil {
		return nil
	}

	if errors.Is(err, errNoTokenPresent) && l.config.RequireRetry {
		if retryErr := l.processTokenRequest(packet, remoteAddr); retryErr != nil {
			return oops.Wrapf(retryErr, "failed to send Retry")
		}
		return oops.
			Code("RETRY_SENT").
			In("ssu2_listener").
			Errorf("sent Retry to %s, awaiting re-request with token", remoteAddr)
	}

	if !errors.Is(err, errNoTokenPresent) {
		return oops.
			Code("TOKEN_VALIDATION_FAILED").
			In("ssu2_listener").
			Wrap(err)
	}
	return nil
}

// generateUniqueConnectionID generates a connection ID and verifies uniqueness
// among active sessions.
// AUDIT 8.3: Checks router (single source of truth) instead of listener.sessions.
// AUDIT 8.1: Retry loop to increase probability of finding a unique ID despite
// concurrent workers also generating and checking IDs.
func (l *SSU2Listener) generateUniqueConnectionID() (uint64, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "generateUniqueConnectionID"}).Debug("generateUniqueConnectionID: generating unique connection ID")

	// AUDIT 8.1: Retry up to 5 times to find a unique connection ID.
	// With a 64-bit random space, collisions are extremely rare. Even if two
	// workers race to generate IDs, multiple retries increase the probability
	// that at least one attempt succeeds before another worker can claim it.
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
			log.WithFields(logger.Fields{
				"pkg":         "server",
				"func":        "generateUniqueConnectionID",
				"attempt":     attempt + 1,
				"max_retries": maxRetries,
			}).Debug("connection ID collision, retrying")
		}
	}

	return 0, oops.Errorf("failed to generate unique connection ID after %d attempts", maxRetries)
}

// buildConnConfig creates a connection-specific config from the listener config
// and the incoming SessionRequest packet.
//
// AUDIT 3.4 — Placeholder RouterHash Hook:
// For responder connections (listener-accepted), the RouterHash is initially set to
// SHA256(ephemeralKey) as a placeholder because the responder cannot yet authenticate
// the peer's static identity from the SessionRequest alone. This placeholder is
// sufficient for pre-establishment dedup (which keys on initiatorConnID + remoteAddr,
// not RouterHash) and does not break pre-handshake routing. However, the router layer
// MUST call SSU2Addr.UpdateRouterHash(realHash) after handshake completion to replace
// the placeholder with the true peer identity hash. Failure to update the hash may
// cause duplicate inbound sessions if other dedup mechanisms (outside go-noise) key
// on RouterHash. The hook is accessed via SSU2Conn.GetSSU2Addr() after the connection
// is established. See SSU2Addr.UpdateRouterHash godoc for details.
func (l *SSU2Listener) buildConnConfig(packet *SSU2Packet, connID uint64) *SSU2Config {
	log.WithFields(logger.Fields{"pkg": "server", "func": "buildConnConfig", "conn_id": connID}).Debug("buildConnConfig: building connection config from session request")
	var routerHash data.Hash
	if len(packet.EphemeralKey) == 32 {
		routerHash = data.NewHash(sha256.Sum256(packet.EphemeralKey))
	}

	connConfig := *l.config
	connConfig.ConnectionID = connID
	connConfig.RouterHash = routerHash
	connConfig.Initiator = false

	if len(packet.Header) >= 24 {
		connConfig.InitiatorConnectionID = binary.BigEndian.Uint64(packet.Header[16:24])
	}
	return &connConfig
}

// registerAndQueueConn registers the connection in the sessions map and
// queues it for acceptance.
//
// AUDIT fixes:
//   - 1.1: the connection ID uniqueness check in generateUniqueConnectionID
//     releases its lock before this insert, so a concurrent worker could have
//     claimed the same ID. The insert is now guarded by a re-check under the
//     write lock, rejecting (and tearing down) a colliding session instead of
//     silently overwriting and orphaning the previous one.
//   - 8.2: the session map is capped at config.MaxSessions so a handshake
//     flood cannot grow the map and per-session goroutines without bound.
//   - 2.1/2.2: on every early-return path the session is removed from the map
//     and torn down (no leaked goroutines), and a close hook is installed so a
//     normal close later deregisters the session from both routing maps.
//   - 8.1: pendingByInitiator dedup index is added for retransmit dedup.
func (l *SSU2Listener) registerAndQueueConn(conn *SSU2Conn, connID uint64, remoteAddr *net.UDPAddr, initiatorConnID uint64) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "server", "func": "registerAndQueueConn", "conn_id": connID}).Debug("registerAndQueueConn: registering session and queuing for accept")

	// AUDIT 8.1: Create dedup key for retransmit detection
	dedupKey := makeDedupKey(initiatorConnID, remoteAddr)

	// AUDIT 8.3: Check router for duplicate connection ID instead of listener.sessions
	if l.router.GetSession(connID) != nil {
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("DUPLICATE_CONNECTION_ID").
			In("ssu2_listener").
			With("connection_id", connID).
			Errorf("connection ID already registered")
	}

	// AUDIT 8.3: Check router session count instead of listener.sessions length
	if l.config.MaxSessions > 0 && l.router.SessionCount() >= l.config.MaxSessions {
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("MAX_SESSIONS_REACHED").
			In("ssu2_listener").
			With("max_sessions", l.config.MaxSessions).
			Errorf("maximum session count reached, connection refused")
	}

	// AUDIT 1.3: Install close hook BEFORE registering with router to prevent
	// race window where concurrent Close() is called before the hook is set.
	// The hook must be in place so that any concurrent close will properly
	// deregister the session from all tracking maps.
	conn.SetCloseHook(func() {
		l.router.RemoveSession(connID)
		// AUDIT 8.1: Remove from pending dedup index
		l.sessionMutex.Lock()
		delete(l.pendingByInitiator, dedupKey)
		l.sessionMutex.Unlock()
	})

	// AUDIT 8.3: Add to router (single source of truth for all sessions)
	if err := l.router.AddSession(conn); err != nil {
		_ = conn.CloseImmediate()
		return nil, oops.Wrapf(err, "failed to register session in router")
	}

	// AUDIT 8.1: Add session to pending dedup index.
	// AUDIT 1.1: Re-check under write lock to close the TOCTOU window that
	// exists between the read-only dedup lookup in handleNewSession and this
	// write.  Two concurrent packetWorker goroutines can both observe a nil
	// entry, both create a new SSU2Conn, and both reach here.  The first
	// worker to acquire the lock inserts its conn; the second must detect the
	// collision, undo its router registration, and return the already-inserted
	// session so the triggering packet is routed to it instead.
	l.sessionMutex.Lock()
	if existing, ok := l.pendingByInitiator[dedupKey]; ok {
		// Race lost: another worker registered for this initiator first.
		// Tear down our newly created connection and return the winner.
		l.sessionMutex.Unlock()
		l.router.RemoveSession(connID)
		_ = conn.CloseImmediate()
		return existing, nil
	}
	l.pendingByInitiator[dedupKey] = conn
	l.sessionMutex.Unlock()

	select {
	case l.acceptQueue <- conn:
		return conn, nil
	case <-l.shutdownChan:
		// AUDIT 2.1: do not leak the session/goroutines on shutdown.
		// AUDIT 8.3: Remove from router (single source of truth)
		l.router.RemoveSession(connID)
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener closed during session creation")
	default:
		// AUDIT 2.1: accept queue full — remove from the map and tear the
		// connection down so its reaper/replay goroutines do not leak.
		// AUDIT 8.3: Remove from router (single source of truth)
		l.router.RemoveSession(connID)
		_ = conn.CloseImmediate()
		return nil, oops.
			Code("ACCEPT_QUEUE_FULL").
			In("ssu2_listener").
			Errorf("accept queue full, connection dropped")
	}
}

// validateSessionRequestToken extracts and validates the token from a SessionRequest.
// Returns nil if the token is valid, errNoTokenPresent if no token block exists,
// or an error describing the validation failure.
func (l *SSU2Listener) validateSessionRequestToken(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	// Parse blocks from payload
	if len(packet.Payload) == 0 {
		return errNoTokenPresent
	}

	blocks, err := DeserializeBlocks(packet.Payload)
	if err != nil {
		return errNoTokenPresent
	}

	// Find NewToken block
	tokenBlock := FindBlockByType(blocks, BlockTypeNewToken)
	if tokenBlock == nil {
		return errNoTokenPresent
	}

	// Parse token from block
	newToken, err := ParseNewTokenBlock(tokenBlock)
	if err != nil {
		return oops.Wrapf(err, "failed to parse NewToken block")
	}

	// Check token expiration with clock skew tolerance
	// AUDIT 6.1: Account for client-server clock skew in token expiration check.
	// If the client's clock is ahead of the server's, the server should allow
	// the token to be valid for up to MaxClockSkew seconds past the expiration
	// timestamp. This prevents legitimate tokens from being rejected due to clock drift.
	now := time.Now().Unix()
	expirationWithSkew := int64(newToken.Expiration) + int64(l.config.MaxClockSkew.Seconds())
	if now > expirationWithSkew {
		return oops.
			Code("TOKEN_EXPIRED").
			In("ssu2_listener").
			With("expiration", newToken.Expiration).
			With("max_clock_skew", l.config.MaxClockSkew.Seconds()).
			Errorf("token has expired")
	}

	// Validate and consume token against cache
	if !l.tokenCache.ConsumeToken(newToken.Token, remoteAddr) {
		return oops.
			Code("INVALID_TOKEN").
			In("ssu2_listener").
			With("address", remoteAddr.String()).
			Errorf("token validation failed")
	}

	return nil
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
	if remoteAddr == nil {
		return oops.
			Code("NIL_ADDRESS").
			In("ssu2_listener").
			Errorf("remote address cannot be nil")
	}
	addrKey := remoteAddr.String()

	// Gate 1 (Strategy 3): first-sight tracker. A brand-new address is
	// recorded and declined; the peer must re-request. This forces a
	// spoofing attacker to spend ≥2 packets per spoofed IP, and the
	// per-sighting state is smaller than a Token struct and lives in an
	// independent bounded map so exhausting first-sight cannot evict
	// real tokens.
	if l.config.FirstSightRequired && !l.firstSight.ObserveAndAllow(addrKey) {
		log.WithFields(logger.Fields{
			"pkg":         "ssu2_listener",
			"func":        "processTokenRequest",
			"remote_addr": addrKey,
		}).Debug("declining token issuance: first-sight only, peer must retry")
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
		log.WithFields(logger.Fields{
			"pkg":         "ssu2_listener",
			"func":        "processTokenRequest",
			"remote_addr": addrKey,
		}).Debug("declining token issuance: global issuance rate exceeded")
		return oops.
			Code("NO_TOKEN_ISSUED").
			In("ssu2_listener").
			With("reason", "global_rate_limit").
			With("address", addrKey).
			Errorf("global token issuance rate limit exceeded")
	}

	// Generate token for this address
	token, err := l.tokenCache.GenerateToken(remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to generate token")
	}

	// Create and send Retry message with token.
	// Per spec: Retry must not be larger than 3x the incoming message.
	incomingSize := len(packet.Header) + len(packet.Payload) + len(packet.MAC)
	return l.sendRetry(remoteAddr, token, packet.Header, incomingSize)
}

// SessionCount returns the current number of active sessions.
// AUDIT 8.3: Queries router (single source of truth) instead of local listener.sessions.
func (l *SSU2Listener) SessionCount() int {
	return l.router.SessionCount()
}

// AddSession registers an SSU2Conn under the given connection ID.
// This is primarily useful for testing and for reconnection scenarios.
// AUDIT 8.3: Delegates to router (single source of truth).
func (l *SSU2Listener) AddSession(connID uint64, conn *SSU2Conn) {
	// Note: AddSession can fail if connID already exists, but we ignore
	// the error here for backward compatibility with test code.
	_ = l.router.AddSession(conn)
}

// RemoveSession deregisters the session with the given connection ID.
// AUDIT 8.3: Delegates to router (single source of truth).
func (l *SSU2Listener) RemoveSession(connID uint64) {
	l.router.RemoveSession(connID)
}

// Underlying returns the PacketConn used by this listener.
func (l *SSU2Listener) Underlying() net.PacketConn {
	return l.underlying
}

// Config returns the SSU2Config used by this listener.
func (l *SSU2Listener) Config() *SSU2Config {
	return l.config
}

// TokenCache returns the token cache used by this listener.
func (l *SSU2Listener) TokenCache() *TokenCache {
	return l.tokenCache
}

// Router returns the packet router used by this listener.
func (l *SSU2Listener) Router() *PacketRouter {
	return l.router
}

// tokenCleanupInterval is how often the listener removes expired tokens (G-5).
const tokenCleanupInterval = 60 * time.Second

// tokenCleanupLoop periodically removes expired tokens from the cache (G-5).
func (l *SSU2Listener) tokenCleanupLoop() {
	log.WithFields(logger.Fields{"pkg": "server", "func": "tokenCleanupLoop", "interval": tokenCleanupInterval}).Debug("tokenCleanupLoop: starting periodic token cache cleanup")
	defer l.wg.Done()

	ticker := time.NewTicker(tokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.shutdownChan:
			return
		case <-ticker.C:
			l.tokenCache.Cleanup()
		}
	}
}

// M-6: Per-IP rate limiter for SessionRequest processing.

const (
	// sessionRequestsPerSecond is the maximum SessionRequests per IP per second.
	sessionRequestsPerSecond = 10

	// sessionRateLimiterMaxIPs is the maximum number of IPs tracked.
	sessionRateLimiterMaxIPs = 10000
)

// ipRateLimiter implements a simple per-IP rate limiter using a token bucket
// approximation. Each IP is allowed a fixed number of requests per second.
//
// AUDIT 8.4: eviction uses an O(1) LRU (a doubly-linked list ordered from
// least- to most-recently-seen) rather than an O(n) scan of the whole map.
// Under a spoofed-source flood the old scan ran for every new IP while holding
// the mutex, creating a throughput cliff. The list mirrors firstSightTracker.
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
