package session

import (
	"context"
	"encoding/binary"
	"net"
	"sort"
	"time"

	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Handshake performs the SSU2 XK pattern handshake.
// For initiators: sends SessionRequest, receives SessionCreated, sends SessionConfirmed
// For responders: receives SessionRequest, sends SessionCreated, receives SessionConfirmed
//
// After successful handshake, connection state transitions to StateEstablished.
//
// Context cancellation semantics:
// -------------------------------
// The supplied context is honored via socket deadlines set before each blocking receive.
// Cancellation does NOT directly interrupt an in-progress ReadFrom syscall; instead,
// cancellation is detected when:
//  1. The next read times out (deadline expires), OR
//  2. Control returns to Handshake code that checks ctx.Err()
//
// This means cancellation latency equals the handshake timeout (typically a few seconds).
// If you require immediate cancellation, you must Close() the connection from another
// goroutine when ctx.Done() fires.
//
// This design avoids the complexity of a watchdog goroutine racing with handshake
// completion, at the cost of bounded cancellation latency.
func (h *SSU2Conn) Handshake(ctx context.Context) error {
	flog("Handshake").Debug("Starting SSU2 handshake")
	h.stateMutex.Lock()
	if h.state != StateInit {
		h.stateMutex.Unlock()
		// Return a specific error code for concurrent Handshake calls
		// to distinguish from other state errors. StateHandshaking means another
		// goroutine is already in the handshake; this should not be retried.
		if h.state == StateHandshaking {
			return oops.
				Code("HANDSHAKE_ALREADY_IN_PROGRESS").
				Errorf("handshake already in progress")
		}
		return oops.
			Code("INVALID_HANDSHAKE_STATE").
			Errorf("invalid state for handshake: %s", h.state)
	}
	h.state = StateHandshaking
	h.stateMutex.Unlock()

	// Start recvLoop (needed during handshake for receivePacketWithTimeout),
	// but only if this connection is responsible for reading the socket.
	// For listener-accepted responder sessions (readsOwnSocket=false), the listener's
	// receiveLoop is the sole socket reader and feeds packets via RoutePacket →
	// ProcessInboundPacket → recvQueue. Starting recvLoop here would cause two
	// goroutines reading the same socket, violating the SSU2 concurrent-reader
	// multiplexing invariant.
	// Started here rather than in the constructor so that callers who create
	// a conn but never call Handshake or Close don't leak a goroutine.
	if h.readsOwnSocket {
		h.wg.Add(1)
		go h.recvLoop()
	}

	// Ensure recvLoop is cleaned up if handshake fails. The CloseWithReason
	// call is idempotent (via closeOnce), so it's safe to call again later.
	// This prevents goroutine leaks when the handshake fails before
	// finalizeHandshake calls startDataLoops.
	var handshakeErr error
	defer func() {
		if handshakeErr != nil {
			_ = h.CloseWithReason(TerminationTimeout, nil)
		}
	}()

	if h.initiator {
		handshakeErr = h.handshakeInitiator(ctx)
	} else {
		handshakeErr = h.handshakeResponder(ctx)
	}
	return handshakeErr
}

// handshakeInitiator performs the initiator side of XK handshake.
func (h *SSU2Conn) handshakeInitiator(ctx context.Context) error {
	flog("handshakeInitiator").Debug("Starting SSU2 handshake as initiator")
	// Establish a single deadline for the entire initiator handshake.
	// Without this, each call to receiveHandshakeWithRetransmit starts a fresh
	// HandshakeTimeout window, allowing a malicious responder to keep the
	// initiator pinned for N × HandshakeTimeout instead of 1 × HandshakeTimeout.
	//
	// LEAK-2 / TIMEOUT-1: If HandshakeTimeout is zero and the caller's context
	// Ensure a single deadline for the entire initiator handshake.
	var cancel context.CancelFunc
	ctx, cancel = h.ensureHandshakeDeadline(ctx)
	if cancel != nil {
		defer cancel()
	}
	sessionRequest, err := h.sendSessionRequest()
	if err != nil {
		return err
	}

	response, err := h.awaitSessionCreated(ctx, sessionRequest)
	if err != nil {
		return err
	}

	if err := h.processSessionCreated(response); err != nil {
		return err
	}

	if err := h.sendSessionConfirmed(ctx); err != nil {
		return err
	}

	// ssu2.md §"Packet Numbering": "For Alice, outbound packet numbering starts
	// at 0 with Session Confirmed", and the worked example immediately below it
	// pairs "SessionConfirmed (0)" with "Data (1)". §"Packet Number" also states
	// "Each packet number may only be used once." Session Confirmed is sent with
	// packet number 0 (see [SSU2Conn.sendSessionConfirmed]), so the first data
	// packet must be 1. Without this reservation Alice's first Data packet
	// reuses number 0 and a compliant peer discards it as a duplicate (Java
	// marks 0 received on the inbound side, PeerState2.java:146, and starts its
	// own counter at 1 for outbound sessions, PeerState2.java:150).
	h.reserveInitiatorDataSequence()

	return h.finalizeHandshake()
}

// reserveInitiatorDataSequence consumes Alice's packet number 0, which the
// Session Confirmed message just used, so data-phase numbering starts at 1.
// Must be called after the Session Confirmed has been handed to the wire.
func (h *SSU2Conn) reserveInitiatorDataSequence() {
	flog("reserveInitiatorDataSequence").Debug("Reserving SSU2 packet number 0 for Session Confirmed")
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()
	if h.sendSequence == 0 {
		h.sendSequence = 1
	}
}

// markPeerConfirmedPacketSeen records the peer's Session Confirmed packet
// number in the inbound packet-number filter, so that number is not later
// accepted as a fresh data packet. Session Confirmed is the only handshake
// message inside a direction's data-phase numbering space (ssu2.md §"Packet
// Numbering"), and its fragments all carry the same number.
func (h *SSU2Conn) markPeerConfirmedPacketSeen(fragments []*SSU2Packet) {
	if len(fragments) == 0 {
		return
	}
	h.recvWindow.MarkSeen(fragments[0].PacketNumber)
}

// sendSessionRequest creates a SessionRequest, installs the SessCreateHeader
// key, sends the packet, and returns the raw request for retransmission.
func (h *SSU2Conn) sendSessionRequest() (*SSU2Packet, error) {
	flog("sendSessionRequest", logger.Fields{"connectionID": h.config.ConnectionID}).Debug("Creating and sending SessionRequest")
	// ssu2.md §"Session Request" -> header table: "Destination Connection ID ::
	// Randomly generated by Alice" and "Source Connection ID :: Randomly generated
	// by Alice, must not be equal to Destination Connection ID". §"Connection ID
	// Numbering": "Connection IDs must be randomly generated" and are nonzero in
	// practice (Java/i2pd both fill them with a random 8 bytes). The value is
	// retained so a post-Retry retransmit reuses the identical destination ID
	// ("connection IDs ... remain constant ... even after a Retry message").
	destConnID, err := h.sessionRequestDestConnID()
	if err != nil {
		return nil, err
	}

	// Record the endpoint this Session Request is going to, so
	// ProcessSessionCreated can require the reply to come from exactly there.
	// ssu2.md §"Session Created" -> §"Notes": "Alice must drop the message if
	// the source IP and port do not match the destination IP and port of the
	// Session Request."
	h.remoteAddrLock.RLock()
	h.handshakeHandler.SetExpectedPeerAddr(h.remoteAddr)
	h.remoteAddrLock.RUnlock()

	// ssu2.md §"Session Establishment" makes the token the fast path: "The
	// standard establishment sequence, when Alice has a valid token previously
	// received from Bob" is Session Request straight away, while "If Alice does
	// not have a valid token, Alice should send a Token Request message instead
	// of a Session Request, to avoid the asymmetric encryption overhead".
	// §"Session Request" defines the field as "Token :: 0 if not previously
	// received from Bob", so a token saved from an earlier New Token block must
	// be presented here — otherwise the §"Tokens" recommendation that tokens be
	// "sent at least once, during or soon after session establishment" buys
	// nothing and every reconnection pays a Token Request / Retry round trip.
	//
	// Presenting a stale token is safe: §"Session Establishment" covers exactly
	// that case ("when Alice thinks she has a valid token, but Bob rejects it
	// (perhaps because Bob restarted)") — Bob replies with a Retry and Alice
	// resends with the fresh token, which handleRetryResponse already does.
	sessionRequest, err := h.handshakeHandler.CreateSessionRequest(
		h.config.ConnectionID, destConnID, h.savedTokenOption()...)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionRequest")
	}

	if err := h.installBothHeaderKeys(); err != nil {
		return nil, err
	}

	// Notify the listener's pending outbound registry once SessCreateHeaderKey
	// is available so it can deobfuscate the SessionCreated reply.
	// This must happen BEFORE sending (and therefore before the responder can
	// reply), but after installBothHeaderKeys so the key is in the manager.
	h.notifySessCreateKey()

	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return nil, oops.Wrapf(err, "failed to send SessionRequest")
	}
	return sessionRequest, nil
}

// sessionRequestDestConnID returns the Destination Connection ID for this
// initiator's Session Request, generating a fresh random nonzero value on first
// call and caching it in h.initiatorDestConnID so a Retry retransmit reuses the
// identical ID.
//
// ssu2.md §"Session Request": "Destination Connection ID :: Randomly generated by
// Alice"; §"Connection ID Numbering": "Source and Destination IDs must NOT be
// identical" and "remain constant ... even after a Retry message". The value must
// differ from our source ID (h.config.ConnectionID); a collision is retried.
func (h *SSU2Conn) sessionRequestDestConnID() (uint64, error) {
	if h.initiatorDestConnID != 0 {
		return h.initiatorDestConnID, nil
	}
	for {
		id, err := GenerateConnectionID() // nonzero by construction
		if err != nil {
			return 0, oops.Wrapf(err, "failed to generate SessionRequest destination connection ID")
		}
		if id != h.config.ConnectionID {
			h.initiatorDestConnID = id
			return id, nil
		}
	}
}

// notifySessCreateKey fires the sessCreateKeyNotifyCh (if set) with the
// SessionCreated HeaderProtector built from the current SessCreateHeaderKey.
// Called after installBothHeaderKeys so the key is guaranteed to be present
// in headerProtector. Non-blocking: if the channel is full the send is dropped
// (the listener reads it promptly; a full channel means it already got the key).
func (h *SSU2Conn) notifySessCreateKey() {
	if h.sessCreateKeyNotifyCh == nil || h.headerProtector == nil {
		return
	}
	p, err := h.headerProtector.GetProtectorForType(wire.HeaderTypeSessionCreated)
	if err != nil {
		flog("notifySessCreateKey").WithError(err).Warn("could not build SessionCreated protector for listener notify")
		return
	}
	select {
	case h.sessCreateKeyNotifyCh <- p:
	default:
	}
}

// notifySessConfirmedKey fires the sessConfirmedKeyNotifyCh (if set) with the
// inbound SessionConfirmed HeaderProtector.  For a responder (isInitiator=false),
// GetProtectorForType(SessionConfirmed) returns k_header_1=introKey and
// k_header_2=sessionConfirmedHeader2, which are exactly the keys the listener
// needs to deobfuscate the inbound SessionConfirmed from the initiator.
// Called from createAndSendSessionCreated after installBothHeaderKeys, while
// the responder still holds the socket-write goroutine — before the initiator
// can send SessionConfirmed — so the listener registry is updated in time.
// Non-blocking; only fires for responder-role connections.
func (h *SSU2Conn) notifySessConfirmedKey() {
	if h.sessConfirmedKeyNotifyCh == nil || h.headerProtector == nil {
		return
	}
	p, err := h.headerProtector.GetProtectorForType(wire.HeaderTypeSessionConfirmed)
	if err != nil {
		flog("notifySessConfirmedKey").WithError(err).Warn("could not build SessionConfirmed inbound protector for listener notify")
		return
	}
	select {
	case h.sessConfirmedKeyNotifyCh <- p:
	default:
	}
}

// notifyRecvDataKey fires the recvDataKeyNotifyCh (if set) with the inbound
// Data-phase HeaderProtector (k_header_1=introKey, k_header_2=recvDataHeader2).
// Called from deriveDataPhaseKeys after SetKDFKeys installs recvDataHeader2.
// Fires for both initiator and responder connections that share a listener socket.
// Non-blocking.
func (h *SSU2Conn) notifyRecvDataKey() {
	if h.recvDataKeyNotifyCh == nil || h.headerProtector == nil {
		return
	}
	p, err := h.headerProtector.GetDataInboundProtector()
	if err != nil {
		flog("notifyRecvDataKey").WithError(err).Warn("could not build inbound Data protector for listener notify")
		return
	}
	select {
	case h.recvDataKeyNotifyCh <- p:
	default:
	}
}

// awaitSessionCreated waits for a SessionCreated response, handling Retry
// flow if the responder requires a token.
// awaitSessionCreated waits for a SessionCreated response, handling Retry
// flow if the responder requires a token.
func (h *SSU2Conn) awaitSessionCreated(ctx context.Context, sessionRequest *SSU2Packet) (*SSU2Packet, error) {
	flog("awaitSessionCreated", logger.Fields{"timeout": h.config.HandshakeTimeout}).Debug("Waiting for SessionCreated response")
	response, err := h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.handshakeWaitBudget(MessageTypeSessionRequest),
		MessageTypeSessionCreated, MessageTypeRetry)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to receive SessionCreated")
	}

	if response.MessageType != MessageTypeRetry {
		return response, nil
	}

	return h.handleRetryResponse(ctx, response)
}

// handleRetryResponse processes a Retry response and resends the
// SessionRequest with the extracted token.
// handleRetryResponse processes a Retry response and resends the
// SessionRequest with the extracted token.
func (h *SSU2Conn) handleRetryResponse(ctx context.Context, response *SSU2Packet) (*SSU2Packet, error) {
	flog("handleRetryResponse").Debug("Processing Retry and resending SessionRequest with token")
	// ERROR-2: The injection guard on the Retry dest connection ID must be
	// unconditional. Skipping it when the header is short allows an attacker
	// to inject a forged Retry (with a controlled token) by crafting a
	// truncated header that bypasses the connection ID comparison.
	if len(response.Header) < 8 {
		return nil, oops.
			Code("RETRY_HEADER_TOO_SHORT").
			In("session").
			Errorf("Retry header too short: %d bytes, need at least 8 for connection ID check", len(response.Header))
	}
	retryDestID := binary.BigEndian.Uint64(response.Header[0:8])
	if retryDestID != h.config.ConnectionID {
		return nil, oops.Errorf("Retry dest connection ID %d does not match our source ID %d (possible injection)", retryDestID, h.config.ConnectionID)
	}

	token, err := h.extractRetryToken(response)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract Retry token")
	}

	sessionRequest, err := h.handshakeHandler.CreateSessionRequestWithToken(
		h.config.ConnectionID, h.initiatorDestConnID, token,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionRequest with Retry token")
	}

	if err := h.installBothHeaderKeys(); err != nil {
		return nil, err
	}

	// Re-notify the listener registry: the post-Retry SessionRequest re-derives
	// SessCreateHeaderKey (same value but we re-signal so SetProtector is
	// idempotent and the registry entry is refreshed).
	h.notifySessCreateKey()

	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return nil, oops.Wrapf(err, "failed to send SessionRequest with token")
	}

	created, err := h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.handshakeWaitBudget(MessageTypeSessionRequest),
		MessageTypeSessionCreated)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to receive SessionCreated after Retry")
	}
	return created, nil
}

// installSessCreateHeaderKey installs the SessCreateHeader key into the
// header protector, if available.
func (h *SSU2Conn) installSessCreateHeaderKey() error {
	return h.installHeaderKey(h.handshakeHandler.SessCreateHeaderKey, "SessCreateHeaderKey")
}

// SetListenerKeyNotify arms the session-created key notification channel.
// DialSSU2ViaListener calls this before Handshake so it can update the
// pending outbound registry as soon as the initiator derives SessCreateHeaderKey.
// The channel must have capacity ≥ 1; the send is non-blocking (best-effort).
func (h *SSU2Conn) SetListenerKeyNotify(ch chan *wire.HeaderProtector) {
	h.sessCreateKeyNotifyCh = ch
}

// SetAcceptedSessionConfirmedKeyNotify arms the SessionConfirmed inbound-key
// notification channel for responder-role connections sharing a listener socket.
// The listener calls this after creating an accepted session so it can install
// the inbound SessionConfirmed header protector in AcceptedSessionRegistry as
// soon as createAndSendSessionCreated derives the key.
// The channel must have capacity ≥ 1; the send is non-blocking.
func (h *SSU2Conn) SetAcceptedSessionConfirmedKeyNotify(ch chan *wire.HeaderProtector) {
	h.sessConfirmedKeyNotifyCh = ch
}

// SetAcceptedDataKeyNotify arms the data-phase inbound-key notification channel
// for connections sharing a listener socket (initiator or responder role).
// The listener calls this so it can install the inbound Data header protector
// in AcceptedSessionRegistry as soon as finalizeHandshake derives the data keys.
// The channel must have capacity ≥ 1; the send is non-blocking.
func (h *SSU2Conn) SetAcceptedDataKeyNotify(ch chan *wire.HeaderProtector) {
	h.recvDataKeyNotifyCh = ch
}

// CloseChan returns the connection's close channel, which is closed when the
// connection enters StateClosed. Listeners use this to unblock notification
// goroutines waiting for key-derivation events, preventing goroutine leaks when
// the handshake fails or times out before keys are ever derived.
func (h *SSU2Conn) CloseChan() <-chan struct{} {
	return h.closeChan
}

// processSessionCreated validates and processes the SessionCreated response,
// extracts the remote connection ID, and installs the SessionConfirmed header key.
// processSessionCreated validates and processes the SessionCreated response,
// extracts the remote connection ID, and installs the SessionConfirmed header key.
func (h *SSU2Conn) processSessionCreated(response *SSU2Packet) error {
	flog("processSessionCreated", logger.Fields{"messageType": response.MessageType}).Debug("Validating and processing SessionCreated")
	if response.MessageType != MessageTypeSessionCreated {
		return oops.Errorf("expected SessionCreated, got type %d", response.MessageType)
	}

	if err := h.handshakeHandler.ProcessSessionCreated(response); err != nil {
		return oops.Wrapf(err, "failed to process SessionCreated")
	}

	if len(response.Header) >= 24 {
		h.remoteConnectionID.Store(binary.BigEndian.Uint64(response.Header[16:24]))
	}

	return h.installSessionConfirmedHeaderKey()
}

// installSessionConfirmedHeaderKey installs the SessionConfirmed header key
// into the header protector, if available.
func (h *SSU2Conn) installSessionConfirmedHeaderKey() error {
	return h.installHeaderKey(h.handshakeHandler.SessionConfirmedHeaderKey, "SessionConfirmedHeaderKey")
}

// installBothHeaderKeys installs both known handshake header keys.
// Each underlying install is a no-op if its key is not yet available.
func (h *SSU2Conn) installBothHeaderKeys() error {
	if err := h.installSessCreateHeaderKey(); err != nil {
		return err
	}
	if err := h.installSessionConfirmedHeaderKey(); err != nil {
		return err
	}
	return nil
}

// sendSessionConfirmed creates and sends SessionConfirmed fragments, then
// arranges for their retransmission until the peer's first data message.
func (h *SSU2Conn) sendSessionConfirmed(ctx context.Context) error {
	flog("sendSessionConfirmed", logger.Fields{"remoteConnectionID": h.remoteConnectionID.Load()}).Debug("Creating and sending SessionConfirmed fragments")
	// ssu2.rst §"RouterInfo" requires Alice to send her full RouterInfo in the
	// Session Confirmed. A 32-byte RouterHash is not a RouterInfo, so there is
	// no fallback: send the block only when the local RouterInfo is available.
	routerInfoBytes := h.config.LocalRouterInfo
	// ssu2.md §"Session Confirmed Fragmentation": each fragment's capacity is
	// "the MTU minus the IP header (20 or 40), minus the UDP header (8), minus
	// the SSU2 short header (16). Total per-packet overhead is 44 (IPv4) or 64
	// (IPv6)". Size the fragments from this session's effective MTU (our MTU
	// bounded by the peer's published mtu) and the peer's address family,
	// instead of always assuming the 1280-byte IPv6 minimum.
	h.handshakeHandler.SetFragmentMTU(h.effectiveMTU(), h.peerIsIPv4())
	fragments, err := h.handshakeHandler.CreateSessionConfirmedFragments(h.remoteConnectionID.Load(), 0, routerInfoBytes)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionConfirmed")
	}

	datagrams := make([][]byte, 0, len(fragments))
	for _, frag := range fragments {
		datagram, err := h.sendPacketDirectAndCapture(frag)
		if err != nil {
			return oops.Wrapf(err, "failed to send SessionConfirmed fragment")
		}
		datagrams = append(datagrams, datagram)
	}

	// ssu2.md §"Handshake Retransmission" -> §"Session Confirmed": "The
	// recommed implementation is option 2). Alice must retain the information
	// required to retransmit the Session Confirmed message." Retain the exact
	// bytes and start the retransmission, which stops as soon as a data message
	// arrives from the peer.
	// §"Total Timeout" caps the handshake as a whole, so the retransmissions
	// must not outlive the deadline this handshake is running under.
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	h.retainSessionConfirmed(datagrams, deadline)
	return nil
}

// retainSessionConfirmed stores the Session Confirmed datagrams for
// retransmission and starts the retransmission loop (spec option 2).
func (h *SSU2Conn) retainSessionConfirmed(datagrams [][]byte, deadline time.Time) {
	if !h.storeSessionConfirmed(datagrams) {
		return
	}
	h.wg.Add(1)
	go h.retransmitSessionConfirmedLoop(deadline)
}

// storeSessionConfirmed records the datagrams for retransmission and returns
// whether a retransmission loop should be started (false when a data message
// has already arrived, which is the spec's stop condition).
func (h *SSU2Conn) storeSessionConfirmed(datagrams [][]byte) bool {
	h.confirmedMutex.Lock()
	h.confirmedDatagrams = datagrams
	if h.confirmedAcked == nil {
		h.confirmedAcked = make(chan struct{})
	}
	acked := h.confirmedAcked
	h.confirmedMutex.Unlock()

	select {
	case <-acked:
		return false
	default:
		return true
	}
}

// retransmitSessionConfirmedLoop implements ssu2.md §"Handshake Retransmission"
// -> §"Session Confirmed" option 2: "send data messages immediately, but also
// retransmit Session Confirmed until a data message is received".
//
// Retransmission intervals are the section's "1.25, 2.5, and 5 seconds", and
// each retransmit is the identical datagram — §"Session Confirmed" requires the
// "same source and connection IDs, ephemeral key, and packet number", and
// forbids incrementing the packet number because "that would change the chained
// hash value which is an input for the split() function".
//
// §"Session Confirmed" also states "Alice should also retransmit all Data
// messages after the Session Confirmed message is retransmitted" — the
// data-phase retransmitLoop already covers those, and each SC retransmit
// refreshes nothing in its schedule, so the two mechanisms stay independent.
//
// The loop ends when a data message arrives (the spec's stop condition), the
// handshake total elapses, or the connection closes.
func (h *SSU2Conn) retransmitSessionConfirmedLoop(deadline time.Time) {
	defer h.wg.Done()

	// Already acked before the loop even started (a fast peer, or a
	// single-fragment SC that needed no retransmit): nothing to do.
	h.confirmedMutex.Lock()
	acked := h.confirmedAcked
	h.confirmedMutex.Unlock()
	if acked == nil {
		return
	}

	// A zero deadline means the caller set no handshake deadline; fall back to
	// the spec's recommended total so retransmission cannot run on forever.
	if deadline.IsZero() {
		deadline = time.Now().Add(h.handshakeTotalBudget())
	}

	for _, wait := range retransmitSchedule(MessageTypeSessionConfirmed) {
		timer := time.NewTimer(wait)
		select {
		case <-acked:
			timer.Stop()
			return
		case <-h.closeChan:
			timer.Stop()
			return
		case <-timer.C:
		}

		if !time.Now().After(deadline) {
			if !h.retransmitSessionConfirmed() {
				return
			}
		}
	}
}

// retransmitSessionConfirmed writes the retained Session Confirmed datagrams
// again, byte for byte. Returns false when there is nothing to resend.
func (h *SSU2Conn) retransmitSessionConfirmed() bool {
	h.confirmedMutex.Lock()
	datagrams := h.confirmedDatagrams
	h.confirmedMutex.Unlock()

	if len(datagrams) == 0 {
		return false
	}

	h.remoteAddrLock.RLock()
	addr := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	if addr == nil {
		return false
	}

	for _, datagram := range datagrams {
		if _, err := h.underlying.WriteTo(datagram, addr); err != nil {
			flog("retransmitSessionConfirmed", logger.Fields{"error": err.Error()}).
				Debug("Session Confirmed retransmit failed")
			return false
		}
	}
	flog("retransmitSessionConfirmed").Debug("retransmitted Session Confirmed")
	return true
}

// markSessionConfirmedAcked stops the Session Confirmed retransmissions. Called
// when the first data message arrives from the peer — the spec's stop condition
// for option 2 (§"Handshake Retransmission" -> §"Session Confirmed").
func (h *SSU2Conn) markSessionConfirmedAcked() {
	h.confirmedMutex.Lock()
	acked := h.confirmedAcked
	h.confirmedDatagrams = nil
	h.confirmedMutex.Unlock()

	if acked == nil {
		return
	}
	h.confirmedAckedOnce.Do(func() { close(acked) })
}

// handshakeResponder performs the responder side of XK handshake.
// handshakeResponder performs the responder side of XK handshake.
func (h *SSU2Conn) handshakeResponder(ctx context.Context) error {
	flog("handshakeResponder").Debug("Starting SSU2 handshake as responder")
	// Establish a single deadline for the entire responder handshake.
	// Each receiveHandshakeWithRetransmit call would otherwise start a fresh
	// HandshakeTimeout window; a stalling initiator can extend the total window
	// to N × HandshakeTimeout without this guard.
	var cancel context.CancelFunc
	ctx, cancel = h.ensureHandshakeDeadline(ctx)
	if cancel != nil {
		defer cancel()
	}
	initiatorConnID, err := h.receiveSessionRequest(ctx)
	if err != nil {
		return err
	}

	sessionCreated, err := h.createAndSendSessionCreated(initiatorConnID)
	if err != nil {
		return err
	}

	if err := h.receiveAndProcessSessionConfirmed(ctx, sessionCreated); err != nil {
		return err
	}

	return h.finalizeHandshake()
}

// receiveSessionRequest waits for and processes a SessionRequest, returning
// the initiator's connection ID.
// receiveSessionRequest waits for and processes a SessionRequest, returning
// the initiator's connection ID.
func (h *SSU2Conn) receiveSessionRequest(ctx context.Context) (uint64, error) {
	flog("receiveSessionRequest", logger.Fields{"timeout": h.config.HandshakeTimeout}).Debug("Waiting for SessionRequest")
	// TIMEOUT-3: When ctx already carries a deadline (set by handshakeResponder),
	// passing h.config.HandshakeTimeout as a second timer to receivePacketWithTimeout
	// is redundant. More critically, when HandshakeTimeout == 0 the explicit
	// time.NewTimer(0) fires immediately, causing the responder to time out
	// before the first packet even arrives. Use the remaining ctx deadline time,
	// or a generous fallback when no deadline is set.
	timeout := h.config.HandshakeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	} else if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	sessionRequest, err := h.receivePacketWithTimeout(ctx, timeout)
	if err != nil {
		return 0, oops.Wrapf(err, "failed to receive SessionRequest")
	}

	if sessionRequest.MessageType != MessageTypeSessionRequest {
		return 0, oops.Errorf("expected SessionRequest, got type %d", sessionRequest.MessageType)
	}

	if _, err = h.handshakeHandler.ProcessSessionRequest(sessionRequest); err != nil {
		return 0, oops.Wrapf(err, "failed to process SessionRequest")
	}
	h.setInboundReplayMaterial(
		h.handshakeHandler.GetPeerEphemeralKey(),
		h.handshakeHandler.GetReplayToken(),
	)

	var initiatorConnID uint64
	if len(sessionRequest.Header) >= 24 {
		initiatorConnID = binary.BigEndian.Uint64(sessionRequest.Header[16:24])
	}
	h.remoteConnectionID.Store(initiatorConnID)

	// Record the Destination Connection ID Alice generated for her Session
	// Request (header bytes 0-7). ssu2.md §"Session Created" requires it to be
	// echoed back as the SessionCreated Source Connection ID, and it is the ID
	// Alice routes her Session Confirmed and data-phase packets to.
	//
	// A multiplexing listener that already pinned this session's routing ID
	// (because Alice's destination ID was zero or claimed by another session)
	// keeps its own value: echoing a colliding ID would make two sessions
	// indistinguishable on the wire, which §"Connection ID Numbering" forbids.
	if !h.responderConnIDPinned.Load() && len(sessionRequest.Header) >= 8 {
		h.responderSourceConnID.Store(binary.BigEndian.Uint64(sessionRequest.Header[0:8]))
	}

	if err := h.installBothHeaderKeys(); err != nil {
		return 0, err
	}

	return initiatorConnID, nil
}

// responderEchoConnID returns the connection ID this responder identifies
// itself with on the wire: the Destination Connection ID Alice put in the
// Session Request we are answering, which ssu2.md §"Session Created" requires
// us to echo as the SessionCreated Source Connection ID. It falls back to the
// locally configured ID before a Session Request has been seen, or when the
// learned value is not usable as a routing key (zero, or identical to Alice's
// own source ID, which §"Connection ID Numbering" forbids).
func (h *SSU2Conn) responderEchoConnID() uint64 {
	if echo := h.responderSourceConnID.Load(); echo != 0 && echo != h.remoteConnectionID.Load() {
		return echo
	}
	return h.config.ConnectionID
}

// SetResponderRoutingConnID pins the connection ID this responder uses as its
// own identity on the wire -- both the SessionCreated Source Connection ID echo
// (ssu2.md §"Session Created") and the key inbound packets are demultiplexed
// by. A multiplexing listener calls this with the ID it chose for the session,
// because Alice's Session Request Destination Connection ID may have been zero
// or already claimed by another session; §"Connection ID Numbering" forbids two
// live sessions sharing one ID, so the listener's choice must win over the value
// read from the header.
//
// Call before the handshake runs. A zero ID is ignored, keeping the configured
// value.
func (h *SSU2Conn) SetResponderRoutingConnID(connID uint64) {
	if connID == 0 {
		return
	}
	h.responderSourceConnID.Store(connID)
	h.responderConnIDPinned.Store(true)
}

// createAndSendSessionCreated creates and sends a SessionCreated response,
// installing the SessionConfirmed header key afterward.
func (h *SSU2Conn) createAndSendSessionCreated(initiatorConnID uint64) (*SSU2Packet, error) {
	flog("createAndSendSessionCreated", logger.Fields{"connectionID": h.config.ConnectionID, "initiatorConnID": initiatorConnID}).Debug("Creating and sending SessionCreated")

	// Record the peer's observed endpoint so the SessionCreated payload can
	// carry the mandatory Address block. ssu2.rst §"SessionCreated" ->
	// §"Payload" lists "DateTime block / Address block / Options block
	// (optional) / ..." with no "(optional)" marker on Address, and §"Address"
	// describes it as "Alice's address, sent to Alice by Bob" -- the responder
	// echoing the initiator's own observed IP and UDP source port back to it.
	//
	// The conn's remote address IS that observed endpoint: it is the UDP source
	// the SessionRequest arrived from (and it is updated as packets arrive), so
	// no separate plumbing is needed. Without this the handler's peerAddress
	// stays nil, the Address block is silently omitted, and a conformant
	// initiator sees a message-2 payload that does not match the spec.
	h.remoteAddrLock.RLock()
	remote := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	if remote != nil {
		h.handshakeHandler.SetPeerAddress(remote.IP, uint16(remote.Port))
	}

	// ssu2.md §"Session Created" header table: "Source Connection ID :: The
	// Destination Connection ID received from Alice in Session Request". The
	// value on the wire is therefore Alice's Session Request destination ID
	// (header bytes 0-7, captured in receiveSessionRequest), NOT our own
	// locally configured connection ID. Java does the same:
	// PacketBuilder2.buildSessionCreatedPacket() passes state.getRcvConnID()
	// (read from the Session Request header at InboundEstablishState2:99) as
	// the source ID.
	//
	// Alice enforces the echo: ssu2.md §"Session Created" -> §"Notes" says
	// "Alice must drop the message if the Destination and Source Connection IDs
	// do not match the Source and Destination Connection IDs of the Session
	// Request", and our own initiator checks it in
	// ssu2/handshake/session_created.go before MixHash. A responder that put its
	// own ID there instead could not complete a handshake with any conformant
	// peer, including i2pd and the Java router.
	//
	// The configured ID is used only when the echo is unusable: zero (not a
	// valid routing key) or equal to Alice's source ID, which §"Connection ID
	// Numbering" forbids ("Source and Destination IDs must NOT be identical").
	// The listener path is unaffected: ssu2/server/listener.go adopts Alice's
	// destination ID as the session's connection ID in the first place, so
	// responderSourceConnID == config.ConnectionID there.
	sessionCreated, err := h.handshakeHandler.CreateSessionCreated(h.responderEchoConnID(), initiatorConnID)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionCreated")
	}

	if err := h.installBothHeaderKeys(); err != nil {
		return nil, err
	}

	// Notify the listener's AcceptedSessionRegistry with the SessionConfirmed
	// inbound protector (k_header_1=introKey, k_header_2=sessionConfirmedHeader2).
	// This must happen BEFORE sending SessionCreated and before the initiator
	// can reply with SessionConfirmed, so the listener can decode it.
	h.notifySessConfirmedKey()

	if err := h.sendPacketDirect(sessionCreated); err != nil {
		return nil, oops.Wrapf(err, "failed to send SessionCreated")
	}
	return sessionCreated, nil
}

// receiveAndProcessSessionConfirmed handles receipt of SessionConfirmed,
// including multi-fragment reassembly.
// receiveAndProcessSessionConfirmed handles receipt of SessionConfirmed,
// including multi-fragment reassembly.
func (h *SSU2Conn) receiveAndProcessSessionConfirmed(ctx context.Context, sessionCreated *SSU2Packet) error {
	flog("receiveAndProcessSessionConfirmed").Debug("Waiting for SessionConfirmed")
	sessionConfirmed, err := h.receiveHandshakeWithRetransmit(ctx, sessionCreated, h.handshakeWaitBudget(MessageTypeSessionCreated),
		MessageTypeSessionConfirmed)
	if err != nil {
		return oops.Wrapf(err, "failed to receive SessionConfirmed")
	}

	if sessionConfirmed.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed, got type %d", sessionConfirmed.MessageType)
	}

	fragments, err := h.collectConfirmedFragments(ctx, sessionConfirmed)
	if err != nil {
		return err
	}

	// Alice's Session Confirmed consumed packet number 0 in her numbering space
	// (ssu2.md §"Packet Numbering"); record it as delivered so the data path
	// never treats a retransmission or a peer data packet 0 as new.
	h.markPeerConfirmedPacketSeen(fragments)

	return oops.Wrapf(
		h.handshakeHandler.ProcessSessionConfirmedFragments(fragments),
		"failed to process SessionConfirmed",
	)
}

// collectConfirmedFragments collects all SessionConfirmed fragments if the
// first packet indicates fragmentation. Returns all fragments sorted by index.
// collectConfirmedFragments collects all SessionConfirmed fragments if the
// first packet indicates fragmentation. Returns all fragments sorted by index.
func (h *SSU2Conn) collectConfirmedFragments(ctx context.Context, first *SSU2Packet) ([]*SSU2Packet, error) {
	flog("collectConfirmedFragments").Debug("Collecting SessionConfirmed fragments")
	fragments := []*SSU2Packet{first}
	if len(first.Header) < 14 {
		return fragments, nil
	}

	_, totalFrags := extractFragmentInfo(first.Header[13])
	if totalFrags < 1 || totalFrags > 15 {
		return nil, oops.Errorf("invalid SessionConfirmed total fragment count: %d (must be 1-15)", totalFrags)
	}
	if totalFrags == 1 {
		return fragments, nil
	}

	seen := make(map[int]bool)
	firstIdx, _ := extractFragmentInfo(first.Header[13])
	seen[firstIdx] = true

	// Use a single deadline for all fragments to prevent a peer from
	// multiplying the timeout by stalling. Each fragment gets a proportional share
	// of the handshake timeout, rather than a fresh full timeout per fragment.
	// Calculate deadline once at the start of fragment collection.
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		// Use existing context deadline (set by handshakeInitiator/handshakeResponder)
		deadline = d
	} else {
		// Fallback: use HandshakeTimeout if ctx has no deadline
		deadline = time.Now().Add(h.config.HandshakeTimeout)
	}

	for len(seen) < totalFrags {
		// Calculate remaining time and use smaller of ctx remaining or a safety margin
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, oops.Errorf("fragment collection timeout: context deadline reached (%d of %d received)", len(seen), totalFrags)
		}

		frag, err := h.receivePacketWithTimeout(ctx, remaining)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to receive SessionConfirmed fragment (%d of %d received)", len(seen), totalFrags)
		}
		if err := h.validateConfirmedFragment(frag, totalFrags); err != nil {
			return nil, err
		}
		fragIdx, _ := extractFragmentInfo(frag.Header[13])
		if seen[fragIdx] {
			continue
		}
		seen[fragIdx] = true
		fragments = append(fragments, frag)
	}

	sortFragmentsByIndex(fragments)
	return fragments, nil
}

// validateConfirmedFragment validates a single SessionConfirmed fragment.
// validateConfirmedFragment validates a single SessionConfirmed fragment.
func (h *SSU2Conn) validateConfirmedFragment(frag *SSU2Packet, expectedTotal int) error {
	flog("validateConfirmedFragment", logger.Fields{"messageType": frag.MessageType, "expectedTotal": expectedTotal}).Debug("Validating fragment")
	if frag.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed fragment, got type %d", frag.MessageType)
	}
	if len(frag.Header) < 14 {
		return oops.Errorf("SessionConfirmed fragment has truncated header")
	}
	_, fragTotal := extractFragmentInfo(frag.Header[13])
	if fragTotal != expectedTotal {
		return oops.Errorf("SessionConfirmed fragment total mismatch: first=%d, got=%d", expectedTotal, fragTotal)
	}
	return nil
}

// finalizeHandshake checks completion, installs cipher states, transitions to
// established, and starts data loops. Shared by both initiator and responder.
// finalizeHandshake checks completion, installs cipher states, transitions to
// established, and starts data loops. Shared by both initiator and responder.
func (h *SSU2Conn) finalizeHandshake() error {
	flog("finalizeHandshake").Debug("Finalizing SSU2 handshake")
	if !h.handshakeHandler.IsHandshakeComplete() {
		return oops.Errorf("handshake not complete after SessionConfirmed")
	}
	if err := h.installCipherStates(); err != nil {
		return oops.Wrapf(err, "failed to install cipher states")
	}

	// deriveDataPhaseKeys installs the ChaCha20 header-protection key schedule.
	// SSU2 has no data-phase length obfuscation, so the returned kHeader2
	// values are not fed into any SipHash chain.
	if _, _, err := h.deriveDataPhaseKeys(); err != nil {
		return err
	}

	h.stateMutex.Lock()
	h.state = StateEstablished
	h.stateMutex.Unlock()

	h.applyNegotiatedPadding()
	h.startDataLoops()

	// ssu2.rst §"Session Confirmed ACK": "Bob sends an ACK of packet 0, which
	// acknowledges the Session Confirmed message and allows Alice to proceed to
	// the data phase, and discard the large Session Confirmed message being
	// saved for possible retransmission... Bob should send an ACK as soon as
	// possible after receiving the Session Confirmed message."
	//
	// §"Packet Numbering" makes this Bob's *first* Data packet, numbered 0:
	// "For Bob, outbound packet numbering starts at 0 with first Data packet,
	// which should be an ACK of the Session Confirmed." Without it Alice never
	// gets her Session Confirmed acknowledged and keeps retransmitting it.
	//
	// Must run after installCipherStates/deriveDataPhaseKeys so the ACK is
	// sealed with the data-phase key and protected with the data-phase header
	// keys.
	if !h.initiator {
		h.sendSessionConfirmedACK()
	}

	return nil
}

// sendSessionConfirmedACK emits Bob's packet-0 ACK Data message, together with
// the New Token block when this router issues tokens.
func (h *SSU2Conn) sendSessionConfirmedACK() {
	flog("sendSessionConfirmedACK").Debug("sending Session Confirmed ACK (packet 0)")

	// The Session Confirmed arrived as packet 0 of Alice's numbering; record it
	// so the ACK's "ack through" field is 0 with acnt 0, exactly the
	// "Ack-through = 0, acnt = 0" example in ssu2.rst §"Ack".
	h.ackHandler.RecordReceived(0)

	// ssu2.md §"Tokens": "New Token blocks … would typically be sent at least
	// once, during or soon after session establishment. Due to validation checks
	// of the RouterInfo in the Session Confirmed message, Bob should not send a
	// New Token block in the Session Created message, it may be sent with the
	// ACK 0 and Router Info after the Session Confirmed is received and
	// validated." installCipherStates() — which validates the RouterInfo and
	// extracts the introduction key — has already run at this point, so this is
	// exactly the "after … received and validated" moment, and the ACK-0 packet
	// is the one the spec names.
	//
	// Without it, Alice can never present a token in a later Session Request
	// (§"Session Request": "Token :: 0 if not previously received from Bob") and
	// every reconnection pays a Token Request / Retry round trip.
	blocks := h.newTokenBlockForPeer()

	// sendACKWithExtraBlocks allocates the next send sequence, which is 0 for
	// the responder at this point, and AEAD-seals + header-protects the packet.
	h.sendACKWithExtraBlocks(blocks)
}

// savedTokenOption returns the Session Request create option carrying a token
// previously received from this peer, or nil when none is stored.
func (h *SSU2Conn) savedTokenOption() []SessionRequestCreateOption {
	store := h.config.SessionTokens
	if store == nil {
		return nil
	}

	h.remoteAddrLock.RLock()
	dest := h.remoteAddr
	h.remoteAddrLock.RUnlock()

	local := h.localUDPAddr()
	token, ok := store.Get(local, dest)
	if !ok {
		return nil
	}
	// The option itself is only applied inside CreateSessionRequest, so the
	// on-wire constraints (8 bytes, nonzero per §"Session Request") are checked
	// here: a stored token that cannot be presented must not stall the
	// handshake, it is dropped and the connection proceeds token-less.
	if len(token) != wire.TokenSize || isAllZeroBytes(token) {
		flog("savedTokenOption", logger.Fields{"token_len": len(token)}).
			Debug("discarding a stored session token that cannot be presented")
		store.Delete(local, dest)
		return nil
	}
	return []SessionRequestCreateOption{sessionRequestRetryTokenOption(token)}
}

// localUDPAddr returns the underlying socket's local UDP endpoint, which a
// token is bound to: ssu2.md §"Tokens" — "A token is bound to the combination of
// source IP/port and destination IP/port."
func (h *SSU2Conn) localUDPAddr() *net.UDPAddr {
	if addr, ok := h.underlying.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

// newTokenBlockForPeer issues (or reuses) this session's token and encodes it as
// a New Token block, or returns nil when this config cannot issue tokens.
func (h *SSU2Conn) newTokenBlockForPeer() []*SSU2Block {
	if h.config.TokenIssuer == nil {
		return nil
	}

	lifetime := h.config.SessionTokenLifetime
	if lifetime <= 0 {
		lifetime = wire.DefaultSessionTokenLifetime
	}

	h.remoteAddrLock.RLock()
	remote := h.remoteAddr
	h.remoteAddrLock.RUnlock()
	if remote == nil {
		return nil
	}

	token, expires, err := h.config.TokenIssuer.IssueSessionToken(remote, h.localUDPAddr(), lifetime)
	if err != nil {
		flog("newTokenBlockForPeer", logger.Fields{"error": err.Error()}).
			Debug("unable to issue a session token")
		return nil
	}

	block, err := NewNewTokenBlock(expires, token)
	if err != nil {
		flog("newTokenBlockForPeer", logger.Fields{"error": err.Error()}).
			Warn("issued token could not be encoded as a New Token block")
		return nil
	}
	return []*SSU2Block{block}
}

// deriveDataPhaseKeys installs KDF-derived header protection keys and returns
// the send/receive kHeader2 values for SipHash derivation.
func (h *SSU2Conn) deriveDataPhaseKeys() (sendKHeader2, recvKHeader2 []byte, err error) {
	flog("deriveDataPhaseKeys").Debug("Deriving data-phase header protection keys")
	sendKHeader2, recvKHeader2, err = h.handshakeHandler.DeriveHeaderKeys()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive data-phase keys")
	}

	if h.headerProtector != nil {
		if err := h.headerProtector.SetKDFKeys(sendKHeader2, recvKHeader2); err != nil {
			return nil, nil, oops.Wrapf(err, "failed to set header protection KDF keys")
		}
	}

	// Notify the listener's AcceptedSessionRegistry with the inbound Data
	// HeaderProtector (k_header_1=introKey, k_header_2=recvDataHeader2).
	// Fires for both initiator and responder connections sharing a listener socket.
	h.notifyRecvDataKey()

	return sendKHeader2, recvKHeader2, nil
}

// applyNegotiatedPadding updates padding config from peer options negotiation.
func (h *SSU2Conn) applyNegotiatedPadding() {
	flog("applyNegotiatedPadding").Debug("Applying negotiated padding configuration")
	localOpts := h.handshakeHandler.LocalOptions()
	peerOpts := h.handshakeHandler.PeerOptions()
	h.logOptionsNegotiationWarnings(localOpts, peerOpts)

	negotiated := h.handshakeHandler.NegotiatedPadding()
	if negotiated == nil {
		return
	}

	h.config.PaddingRatio = negotiated.TMaxRatio
	if negotiated.TMinRatio > 0 {
		minBytes := int(negotiated.TMinRatio * float64(h.config.MTU))
		if minBytes > h.config.MinPaddingSize {
			h.config.MinPaddingSize = minBytes
		}
	}

	h.pushNegotiatedPaddingToModifier(negotiated)
}

// logOptionsNegotiationWarnings logs warnings when options negotiation is one-sided.
func (h *SSU2Conn) logOptionsNegotiationWarnings(localOpts, peerOpts *OptionsParams) {
	h.remoteAddrLock.RLock()
	remoteAddrStr := h.remoteAddr.String()
	h.remoteAddrLock.RUnlock()

	if localOpts != nil && peerOpts == nil {
		flog("logOptionsNegotiationWarnings", logger.Fields{"side": "local_only", "peer": remoteAddrStr}).Warn("Options negotiation one-sided: local options set but peer did not send Options block")
	} else if localOpts == nil && peerOpts != nil {
		flog("logOptionsNegotiationWarnings", logger.Fields{"side": "peer_only", "peer": remoteAddrStr}).Warn("Options negotiation one-sided: peer sent Options but no local options configured")
	}
}

// pushNegotiatedPaddingToModifier updates the live SSU2PaddingModifier
// with negotiated values so data-phase padding reflects the agreement.
func (h *SSU2Conn) pushNegotiatedPaddingToModifier(negotiated *OptionsParams) {
	flog("pushNegotiatedPaddingToModifier", logger.Fields{"maxRatio": negotiated.TMaxRatio}).Debug("Updating padding modifier with negotiated values")
	for _, mod := range h.config.Modifiers {
		if pm, ok := mod.(*SSU2PaddingModifier); ok {
			maxBytes := h.config.MaxPaddingSize
			if negotiated.TMaxRatio > 0 {
				maxBytes = int(negotiated.TMaxRatio * float64(h.config.MTU))
			}
			_ = pm.UpdatePaddingParams(h.config.MinPaddingSize, maxBytes, negotiated.TMaxRatio)
			break
		}
	}
}

// extractRetryToken authenticates a Retry message and returns its 8-byte token.
//
// Per ssu2.rst §"KDF for Retry" the Retry payload is ChaCha20-Poly1305 sealed
// with the responder's intro key, the cleartext 32-byte header as associated
// data, and the header packet number as the nonce; the token itself is header
// bytes 24-31 (it is NOT carried in a New Token block).
//
// The AEAD check is what makes a Retry trustworthy: header obfuscation alone
// only masks the connection ID, so without this the dest-conn-ID comparison in
// handleRetryResponse would be the only (forgeable) guard against an injected
// Retry carrying an attacker-chosen token.
func (h *SSU2Conn) extractRetryToken(retry *SSU2Packet) ([]byte, error) {
	introKey := h.config.RemoteIntroKey
	if len(introKey) != HeaderKeySize {
		return nil, oops.
			Code("RETRY_INTRO_KEY_MISSING").
			In("session").
			Errorf("cannot authenticate Retry: responder intro key (32 bytes) not configured")
	}
	if len(retry.Header) < LongHeaderSize {
		return nil, oops.
			Code("RETRY_HEADER_TOO_SHORT").
			In("session").
			With("header_len", len(retry.Header)).
			Errorf("Retry header must be %d bytes", LongHeaderSize)
	}
	if len(retry.Payload) < MinPayloadSize {
		return nil, oops.
			Code("RETRY_PAYLOAD_TOO_SHORT").
			In("session").
			With("payload_len", len(retry.Payload)).
			Errorf("Retry ciphertext payload too short")
	}

	plaintext, err := DecryptIntroKeyAEAD(
		introKey, retry.Header, retry.Payload, retry.MAC, retry.PacketNumber,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "Retry failed AEAD authentication")
	}

	// Sanity-check the authenticated payload carries the blocks the spec
	// requires (DateTime + Address); a Retry without them is malformed.
	blocks, err := DeserializeBlocks(plaintext)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse Retry payload blocks")
	}
	dateTimeBlock := FindBlockByType(blocks, BlockTypeDateTime)
	if dateTimeBlock == nil {
		return nil, oops.Errorf("Retry payload missing required DateTime block")
	}

	// Validate the Retry's timestamp against the local clock.
	//
	// ssu2.md §"Replay Prevention": "Both Alice and Bob validate that the time for
	// these messages is within a valid skew" (the recommended window is +/- 2
	// minutes, §"Recommended Constants"). §"Retry" -> §"Payload" lists the DateTime
	// block as required, so the value it carries must actually be checked rather
	// than only its presence.
	if err := h.validateBlockTimestampSkew(dateTimeBlock); err != nil {
		return nil, oops.Wrapf(err, "Retry rejected")
	}

	token := make([]byte, 8)
	copy(token, retry.Header[24:32])
	if isAllZeroBytes(token) {
		return nil, oops.Errorf("Retry token is zero (session rejected without a token)")
	}
	return token, nil
}

// isAllZeroBytes reports whether every byte in b is zero.
func isAllZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// receivePacketWithTimeout waits for a packet with timeout.
// It checks for context cancellation immediately before waiting on the timer,
// so cancellation is detected promptly even when the timeout is large.
func (h *SSU2Conn) receivePacketWithTimeout(ctx context.Context, timeout time.Duration) (*SSU2Packet, error) {
	// Check if context is already canceled before entering the wait
	select {
	case <-ctx.Done():
		return nil, oops.Wrapf(ctx.Err(), "context cancelled")
	default:
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case packet := <-h.recvQueue:
		return packet, nil
	case <-timer.C:
		return nil, oops.Errorf("timeout waiting for packet")
	case <-ctx.Done():
		return nil, oops.Wrapf(ctx.Err(), "context cancelled")
	case <-h.closeChan:
		return nil, oops.Errorf("connection closed")
	}
}

// receiveHandshakeWithRetransmit waits for the next handshake message, retransmitting
// lastSent if no response arrives within a per-attempt interval.
// Per spec: handshake packets MUST be retransmitted with the same packet number
// and identical encrypted contents.
//
// The spec recommends specific retransmission intervals:
//   - Session Request: 1.25s, 2.5s, 5s
//   - Session Created: 1s, 2s, 4s
//
// handshakeWaitBudget returns the total time to wait for the reply to the given
// handshake message, applying the per-message totals the spec recommends in
// §"Handshake Retransmission" (Session Created: 12 s; Session Request / Session
// Confirmed: 15 s) rather than one blanket HandshakeTimeout for all three.
//
// The configured HandshakeTimeout still caps the budget, so a caller that
// deliberately shortens it gets the shorter value, never a longer one.
func (h *SSU2Conn) handshakeWaitBudget(msgType uint8) time.Duration {
	var budget time.Duration
	switch msgType {
	case MessageTypeSessionCreated:
		budget = DefaultSessionCreatedTimeout
	default:
		budget = DefaultHandshakeTimeout
	}
	if configured := h.config.HandshakeTimeout; configured > 0 && configured < budget {
		return configured
	}
	return budget
}

// retransmitSchedule returns the spec-recommended exponential backoff intervals
// for the given handshake message type.
func retransmitSchedule(msgType uint8) []time.Duration {
	flog("retransmitSchedule", logger.Fields{"messageType": msgType}).Debug("Determining retransmit intervals")
	if msgType == MessageTypeSessionCreated {
		return []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	}
	return []time.Duration{1250 * time.Millisecond, 2500 * time.Millisecond, 5 * time.Second}
}

// retransmitWait returns the wait duration for the given attempt, capping at the remaining time.
func retransmitWait(attempt int, intervals []time.Duration, remaining time.Duration) time.Duration {
	flog("retransmitWait", logger.Fields{"attempt": attempt, "remaining": remaining}).Debug("Calculating wait duration")
	var wait time.Duration
	if attempt < len(intervals) {
		wait = intervals[attempt]
	} else {
		wait = remaining
	}
	if wait > remaining {
		wait = remaining
	}
	return wait
}

// receiveHandshakeWithRetransmit waits for the next handshake message, retransmitting
// lastSent if no response arrives within a per-attempt interval.
// Per spec: handshake packets MUST be retransmitted with the same packet number
// and identical encrypted contents.
//
// The spec recommends specific retransmission intervals:
//   - Session Request: 1.25s, 2.5s, 5s
//   - Session Created: 1s, 2s, 4s
//
// If expectedTypes is non-empty, packets of other types are silently
// discarded from the queue without consuming a retransmit attempt. This prevents
// a queue pre-filled with retransmitted SessionRequests from blocking receipt of
// the subsequent SessionConfirmed.
func (h *SSU2Conn) receiveHandshakeWithRetransmit(ctx context.Context, lastSent *SSU2Packet, totalTimeout time.Duration, expectedTypes ...uint8) (*SSU2Packet, error) {
	intervals := retransmitSchedule(lastSent.MessageType)
	// Use the context deadline when available so that the total
	// handshake budget is shared across all phases rather than each phase
	// starting a fresh totalTimeout window.  If the caller (handshakeInitiator /
	// handshakeResponder) has wrapped ctx with context.WithTimeout, the deadline
	// is already set and we inherit it here.  Fall back to a per-call deadline
	// only when no context deadline is present (e.g., standalone callers).
	// The phase gets its own spec budget (totalTimeout), but never beyond the
	// deadline of the handshake as a whole: §"Total Timeout" caps everything,
	// while §"Session Created" ("Recommended timeout: 12 seconds total") and the
	// other per-message sections cap each phase inside it.
	deadline := time.Now().Add(totalTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	for attempt := 0; attempt <= len(intervals); attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := retransmitWait(attempt, intervals, remaining)

		pkt, err := h.receivePacketWithTimeout(ctx, wait)
		if err == nil {
			// Discard stale packets of unexpected type (e.g., retransmitted
			// SessionRequests still in the queue when we are awaiting SessionConfirmed).
			// Do NOT count this as a retransmit attempt so the budget is preserved.
			if len(expectedTypes) > 0 && !matchesAny(pkt.MessageType, expectedTypes) {
				flog("receiveHandshakeWithRetransmit", logger.Fields{"got_type": pkt.MessageType}).Debug("discarding stale packet of unexpected type")
				attempt-- // don't consume this attempt
				continue
			}
			return pkt, nil
		}

		if err := h.checkHandshakeCancelled(ctx); err != nil {
			return nil, err
		}

		if attempt < len(intervals) {
			if sendErr := h.sendPacketDirect(lastSent); sendErr != nil {
				// Surface the failure for operational visibility. The retransmit
				// loop still continues (the next attempt will retry the send),
				// but silently dropping this signal previously hid send-path
				// failures (e.g. socket errors) during network partitions.
				flog("receiveHandshakeWithRetransmit", logger.Fields{"error": sendErr, "attempt": attempt}).Warn("retransmit send failed")
			}
		}
	}
	return nil, oops.Errorf("handshake timeout after %d retransmits", len(intervals))
}

// matchesAny returns true if t equals one of the types in accepted.
// This is intentionally a linear scan because accepted is handshake-local and
// bounded to a tiny list (typically 1-2 message types).
func matchesAny(t uint8, accepted []uint8) bool {
	for _, a := range accepted {
		if t == a {
			return true
		}
	}
	return false
}

// checkHandshakeCancelled returns an error if the context or connection is closed.
func (h *SSU2Conn) checkHandshakeCancelled(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return oops.Wrapf(ctx.Err(), "context cancelled during handshake retransmit")
	case <-h.closeChan:
		return oops.Errorf("connection closed during handshake retransmit")
	default:
		return nil
	}
}

// nextSendSequence returns the next packet sequence number.
// When the sequence crosses rekeyThreshold, it fires a one-shot
// NextNonce rekey so the cipher is refreshed before the 32-bit
// counter wraps. Per SSU2 spec, the packet number must not wrap
// around to zero; if the counter reaches 0xFFFFFFFF the
// connection is closed.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
// sortFragmentsByIndex sorts SessionConfirmed fragments by their fragment
// index (bits 7-4 of header byte 13). This ensures ProcessSessionConfirmedFragments
// receives fragments in the correct order regardless of arrival order.
func sortFragmentsByIndex(fragments []*SSU2Packet) {
	sort.Slice(fragments, func(i, j int) bool {
		idxI, _ := extractFragmentInfo(fragments[i].Header[13])
		idxJ, _ := extractFragmentInfo(fragments[j].Header[13])
		return idxI < idxJ
	})
}

func extractFragmentInfo(b byte) (index, total int) {
	return int((b >> 4) & 0x0F), int(b & 0x0F)
}

// installHeaderKey installs a derived header key into the header protector,
// if available. Consolidates nil-check, key getter call, empty-key check,
// and error wrapping for key installation.
func (h *SSU2Conn) installHeaderKey(keyGetter func() []byte, keyType string) error {
	flog("installHeaderKey", logger.Fields{"key_type": keyType}).Debug("Installing header key")
	if h.headerProtector == nil {
		return nil
	}
	k := keyGetter()
	if len(k) == 0 {
		return nil
	}
	switch keyType {
	case "SessCreateHeaderKey":
		return oops.Wrapf(
			h.headerProtector.SetSessCreateHeaderKey(k),
			"failed to set %s", keyType,
		)
	case "SessionConfirmedHeaderKey":
		return oops.Wrapf(
			h.headerProtector.SetSessionConfirmedHeaderKey(k),
			"failed to set %s", keyType,
		)
	default:
		return oops.Errorf("unknown key type: %s", keyType)
	}
}

// ensureHandshakeDeadline wraps the context with the whole-handshake deadline.
//
// ssu2.md §"Handshake Retransmission" -> §"Total Timeout": "Recommended total
// timeout for the handshake is 20 seconds." That is config.HandshakeTotalTimeout,
// which is deliberately separate from config.HandshakeTimeout — the per-message
// budget of §"Session Request" ("Recommended timeout: 15 seconds total"). The
// phases are sequential (Token Request, then Session Request, then Session
// Created each carry their own budget), so applying the per-message value here
// truncated the handshake to less than the recommended total and abandoned
// sessions a compliant peer was still retransmitting.
//
// A deadline already on the caller's context is honoured when it is sooner than
// the configured total, so a caller that shortens the window still wins.
// Returns (ctx, cancel); cancel is nil when no new deadline was added.
func (h *SSU2Conn) ensureHandshakeDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	total := h.handshakeTotalBudget()
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining <= total {
			return ctx, nil
		}
	}
	return context.WithTimeout(ctx, total)
}

// handshakeTotalBudget resolves the whole-handshake deadline.
//
// An explicitly configured HandshakeTotalTimeout wins. Otherwise the value is
// derived: a caller that set HandshakeTimeout below its 15 s default asked for
// faster failure, so that shorter window becomes the total and the handshake
// does not silently take longer than requested; with plain defaults the spec's
// recommended 20 s total applies.
func (h *SSU2Conn) handshakeTotalBudget() time.Duration {
	if total := h.config.HandshakeTotalTimeout; total > 0 {
		return total
	}
	if per := h.config.HandshakeTimeout; per > 0 && per < DefaultHandshakeTimeout {
		return per
	}
	return DefaultHandshakeTotalTimeout
}

// validateBlockTimestampSkew checks a DateTime block's timestamp against the
// local clock, using the configured MaxClockSkew window.
func (h *SSU2Conn) validateBlockTimestampSkew(block *SSU2Block) error {
	if block == nil || len(block.Data) < 4 {
		return oops.Errorf("DateTime block too short to carry a timestamp")
	}
	window := h.config.MaxClockSkew
	if window <= 0 {
		window = DefaultMaxClockSkew
	}
	remote := time.Unix(int64(binary.BigEndian.Uint32(block.Data[:4])), 0)
	skew := time.Since(remote)
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return oops.
			Code("CLOCK_SKEW").
			In("session").
			With("skew", skew.String()).
			With("max_skew", window.String()).
			Errorf("timestamp skew %s exceeds the maximum %s", skew, window)
	}
	return nil
}
