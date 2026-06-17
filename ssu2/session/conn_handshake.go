package session

import (
	"context"
	"encoding/binary"
	"time"

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
	log.WithFields(logger.Fields{"pkg": "session", "func": "Handshake"}).Debug("Starting SSU2 handshake")
	h.stateMutex.Lock()
	if h.state != StateInit {
		h.stateMutex.Unlock()
		// AUDIT 3.1: Return a specific error code for concurrent Handshake calls
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
	// processInboundPacket → recvQueue. Starting recvLoop here would cause two
	// goroutines reading the same socket, violating the SSU2 concurrent-reader
	// multiplexing invariant (AUDIT 1.2).
	// Started here rather than in the constructor so that callers who create
	// a conn but never call Handshake or Close don't leak a goroutine.
	if h.readsOwnSocket {
		h.wg.Add(1)
		go h.recvLoop()
	}

	// Ensure recvLoop is cleaned up if handshake fails. The CloseWithReason
	// call is idempotent (via closeOnce), so it's safe to call again later.
	// This prevents goroutine leaks when the handshake fails before
	// finalizeHandshake calls startDataLoops. (AUDIT H-8)
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
// handshakeInitiator performs the initiator side of XK handshake.
func (h *SSU2Conn) handshakeInitiator(ctx context.Context) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handshakeInitiator"}).Debug("Starting SSU2 handshake as initiator")
	// AUDIT 4.1: Establish a single deadline for the entire initiator handshake.
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

	if err := h.sendSessionConfirmed(); err != nil {
		return err
	}

	return h.finalizeHandshake()
}

// sendSessionRequest creates a SessionRequest, installs the SessCreateHeader
// key, sends the packet, and returns the raw request for retransmission.
// sendSessionRequest creates a SessionRequest, installs the SessCreateHeader
// key, sends the packet, and returns the raw request for retransmission.
func (h *SSU2Conn) sendSessionRequest() (*SSU2Packet, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "sendSessionRequest", "connectionID": h.config.ConnectionID}).Debug("Creating and sending SessionRequest")
	sessionRequest, err := h.handshakeHandler.CreateSessionRequest(h.config.ConnectionID, 0)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionRequest")
	}

	if err := h.installSessCreateHeaderKey(); err != nil {
		return nil, err
	}

	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return nil, oops.Wrapf(err, "failed to send SessionRequest")
	}
	return sessionRequest, nil
}

// awaitSessionCreated waits for a SessionCreated response, handling Retry
// flow if the responder requires a token.
// awaitSessionCreated waits for a SessionCreated response, handling Retry
// flow if the responder requires a token.
func (h *SSU2Conn) awaitSessionCreated(ctx context.Context, sessionRequest *SSU2Packet) (*SSU2Packet, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "awaitSessionCreated", "timeout": h.config.HandshakeTimeout}).Debug("Waiting for SessionCreated response")
	response, err := h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.config.HandshakeTimeout,
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
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleRetryResponse"}).Debug("Processing Retry and resending SessionRequest with token")
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
		h.config.ConnectionID, 0, token,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionRequest with Retry token")
	}

	if err := h.installSessCreateHeaderKey(); err != nil {
		return nil, err
	}

	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return nil, oops.Wrapf(err, "failed to send SessionRequest with token")
	}

	created, err := h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.config.HandshakeTimeout,
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

// processSessionCreated validates and processes the SessionCreated response,
// extracts the remote connection ID, and installs the SessionConfirmed header key.
// processSessionCreated validates and processes the SessionCreated response,
// extracts the remote connection ID, and installs the SessionConfirmed header key.
func (h *SSU2Conn) processSessionCreated(response *SSU2Packet) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "processSessionCreated", "messageType": response.MessageType}).Debug("Validating and processing SessionCreated")
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

// sendSessionConfirmed creates and sends SessionConfirmed fragments.
// sendSessionConfirmed creates and sends SessionConfirmed fragments.
func (h *SSU2Conn) sendSessionConfirmed() error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "sendSessionConfirmed", "remoteConnectionID": h.remoteConnectionID.Load()}).Debug("Creating and sending SessionConfirmed fragments")
	// Use LocalRouterInfo if provided; fall back to RouterHash for backward compatibility.
	// Note: passing RouterHash instead of a full RouterInfo will fail strict static key verification.
	routerInfoBytes := h.config.LocalRouterInfo
	if len(routerInfoBytes) == 0 {
		// Legacy fallback: transmit RouterHash (32 bytes) instead of full RouterInfo.
		// This maintains backward compatibility but will not pass verifyPeerRouterInfoStaticKey.
		routerInfoBytes = h.config.RouterHash[:]
	}
	fragments, err := h.handshakeHandler.CreateSessionConfirmedFragments(h.remoteConnectionID.Load(), 0, routerInfoBytes)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionConfirmed")
	}

	for _, frag := range fragments {
		if err := h.sendPacketDirect(frag); err != nil {
			return oops.Wrapf(err, "failed to send SessionConfirmed fragment")
		}
	}
	return nil
}

// handshakeResponder performs the responder side of XK handshake.
// handshakeResponder performs the responder side of XK handshake.
func (h *SSU2Conn) handshakeResponder(ctx context.Context) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handshakeResponder"}).Debug("Starting SSU2 handshake as responder")
	// AUDIT 4.1: Establish a single deadline for the entire responder handshake.
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
	log.WithFields(logger.Fields{"pkg": "session", "func": "receiveSessionRequest", "timeout": h.config.HandshakeTimeout}).Debug("Waiting for SessionRequest")
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

	var initiatorConnID uint64
	if len(sessionRequest.Header) >= 24 {
		initiatorConnID = binary.BigEndian.Uint64(sessionRequest.Header[16:24])
	}
	h.remoteConnectionID.Store(initiatorConnID)

	if err := h.installSessCreateHeaderKey(); err != nil {
		return 0, err
	}

	return initiatorConnID, nil
}

// createAndSendSessionCreated creates and sends a SessionCreated response,
// installing the SessionConfirmed header key afterward.
// createAndSendSessionCreated creates and sends a SessionCreated response,
// installing the SessionConfirmed header key afterward.
func (h *SSU2Conn) createAndSendSessionCreated(initiatorConnID uint64) (*SSU2Packet, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "createAndSendSessionCreated", "connectionID": h.config.ConnectionID, "initiatorConnID": initiatorConnID}).Debug("Creating and sending SessionCreated")
	sessionCreated, err := h.handshakeHandler.CreateSessionCreated(h.config.ConnectionID, initiatorConnID)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionCreated")
	}

	if err := h.installSessionConfirmedHeaderKey(); err != nil {
		return nil, err
	}

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
	log.WithFields(logger.Fields{"pkg": "session", "func": "receiveAndProcessSessionConfirmed"}).Debug("Waiting for SessionConfirmed")
	sessionConfirmed, err := h.receiveHandshakeWithRetransmit(ctx, sessionCreated, h.config.HandshakeTimeout,
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
	log.WithFields(logger.Fields{"pkg": "session", "func": "collectConfirmedFragments"}).Debug("Collecting SessionConfirmed fragments")
	fragments := []*SSU2Packet{first}
	if len(first.Header) < 14 {
		return fragments, nil
	}

	totalFrags := int(first.Header[13] & 0x0F)
	if totalFrags < 1 || totalFrags > 15 {
		return nil, oops.Errorf("invalid SessionConfirmed total fragment count: %d (must be 1-15)", totalFrags)
	}
	if totalFrags == 1 {
		return fragments, nil
	}

	seen := make(map[int]bool)
	firstIdx := int((first.Header[13] >> 4) & 0x0F)
	seen[firstIdx] = true

	// AUDIT 4.2: Use a single deadline for all fragments to prevent a peer from
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
		fragIdx := int((frag.Header[13] >> 4) & 0x0F)
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
	log.WithFields(logger.Fields{"pkg": "session", "func": "validateConfirmedFragment", "messageType": frag.MessageType, "expectedTotal": expectedTotal}).Debug("Validating fragment")
	if frag.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed fragment, got type %d", frag.MessageType)
	}
	if len(frag.Header) < 14 {
		return oops.Errorf("SessionConfirmed fragment has truncated header")
	}
	fragTotal := int(frag.Header[13] & 0x0F)
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
	log.WithFields(logger.Fields{"pkg": "session", "func": "finalizeHandshake"}).Debug("Finalizing SSU2 handshake")
	if !h.handshakeHandler.IsHandshakeComplete() {
		return oops.Errorf("handshake not complete after SessionConfirmed")
	}
	if err := h.installCipherStates(); err != nil {
		return oops.Wrapf(err, "failed to install cipher states")
	}

	// deriveDataPhaseKeys installs the ChaCha20 header-protection key schedule.
	// H-1: SSU2 has no data-phase length obfuscation, so the returned kHeader2
	// values are not fed into any SipHash chain.
	if _, _, err := h.deriveDataPhaseKeys(); err != nil {
		return err
	}

	h.stateMutex.Lock()
	h.state = StateEstablished
	h.stateMutex.Unlock()

	h.applyNegotiatedPadding()
	h.startDataLoops()
	return nil
}

// deriveDataPhaseKeys installs KDF-derived header protection keys and returns
// the send/receive kHeader2 values for SipHash derivation.
func (h *SSU2Conn) deriveDataPhaseKeys() (sendKHeader2, recvKHeader2 []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "deriveDataPhaseKeys"}).Debug("Deriving data-phase header protection keys")
	sendKHeader2, recvKHeader2, err = h.handshakeHandler.DeriveHeaderKeys()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive data-phase keys")
	}

	if h.headerProtector != nil {
		if err := h.headerProtector.SetKDFKeys(sendKHeader2, recvKHeader2); err != nil {
			return nil, nil, oops.Wrapf(err, "failed to set header protection KDF keys")
		}
	}

	return sendKHeader2, recvKHeader2, nil
}

// applyNegotiatedPadding updates padding config from peer options negotiation.
func (h *SSU2Conn) applyNegotiatedPadding() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "applyNegotiatedPadding"}).Debug("Applying negotiated padding configuration")
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

// logOptionsNegotiationWarnings logs M-3 warnings when options negotiation is one-sided.
func (h *SSU2Conn) logOptionsNegotiationWarnings(localOpts, peerOpts *OptionsParams) {
	h.remoteAddrLock.RLock()
	remoteAddrStr := h.remoteAddr.String()
	h.remoteAddrLock.RUnlock()

	if localOpts != nil && peerOpts == nil {
		log.WithFields(logger.Fields{
			"pkg":  "ssu2",
			"func": "logOptionsNegotiationWarnings",
			"side": "local_only",
			"peer": remoteAddrStr,
		}).Warn("Options negotiation one-sided: local options set but peer did not send Options block (M-3)")
	} else if localOpts == nil && peerOpts != nil {
		log.WithFields(logger.Fields{
			"pkg":  "ssu2",
			"func": "logOptionsNegotiationWarnings",
			"side": "peer_only",
			"peer": remoteAddrStr,
		}).Warn("Options negotiation one-sided: peer sent Options but no local options configured (M-3)")
	}
}

// pushNegotiatedPaddingToModifier updates the live SSU2PaddingModifier
// with negotiated values so data-phase padding reflects the agreement.
func (h *SSU2Conn) pushNegotiatedPaddingToModifier(negotiated *OptionsParams) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "pushNegotiatedPaddingToModifier", "maxRatio": negotiated.TMaxRatio}).Debug("Updating padding modifier with negotiated values")
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

// startDataLoops starts background goroutines for data transport.
// Called after handshake completes to avoid wasting resources on failed connections.
// extractRetryToken parses a Retry message and returns the 8-byte token.
func (h *SSU2Conn) extractRetryToken(retry *SSU2Packet) ([]byte, error) {
	blocks, err := DeserializeBlocks(retry.Payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse Retry payload")
	}
	tokenBlock := FindBlockByType(blocks, BlockTypeNewToken)
	if tokenBlock == nil {
		return nil, oops.Errorf("Retry message missing NewToken block")
	}
	parsed, err := ParseNewTokenBlock(tokenBlock)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse NewToken block from Retry")
	}
	return parsed.Token, nil
}

// receivePacketWithTimeout waits for a packet with timeout.
// AUDIT 4.4: Check context cancellation immediately before waiting on timer,
// so context cancellation is detected promptly even if the timeout is large.
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
// retransmitSchedule returns the spec-recommended exponential backoff intervals
// for the given handshake message type.
func retransmitSchedule(msgType uint8) []time.Duration {
	log.WithFields(logger.Fields{"pkg": "session", "func": "retransmitSchedule", "messageType": msgType}).Debug("Determining retransmit intervals")
	if msgType == MessageTypeSessionCreated {
		return []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	}
	return []time.Duration{1250 * time.Millisecond, 2500 * time.Millisecond, 5 * time.Second}
}

// retransmitWait returns the wait duration for the given attempt, capping at the remaining time.
func retransmitWait(attempt int, intervals []time.Duration, remaining time.Duration) time.Duration {
	log.WithFields(logger.Fields{"pkg": "session", "func": "retransmitWait", "attempt": attempt, "remaining": remaining}).Debug("Calculating wait duration")
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
// BUG-SM-3: if expectedTypes is non-empty, packets of other types are silently
// discarded from the queue without consuming a retransmit attempt. This prevents
// a queue pre-filled with retransmitted SessionRequests from blocking receipt of
// the subsequent SessionConfirmed.
func (h *SSU2Conn) receiveHandshakeWithRetransmit(ctx context.Context, lastSent *SSU2Packet, totalTimeout time.Duration, expectedTypes ...uint8) (*SSU2Packet, error) {
	intervals := retransmitSchedule(lastSent.MessageType)
	// AUDIT 4.1: Use the context deadline when available so that the total
	// handshake budget is shared across all phases rather than each phase
	// starting a fresh totalTimeout window.  If the caller (handshakeInitiator /
	// handshakeResponder) has wrapped ctx with context.WithTimeout, the deadline
	// is already set and we inherit it here.  Fall back to a per-call deadline
	// only when no context deadline is present (e.g., standalone callers).
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(totalTimeout)
	}

	for attempt := 0; attempt <= len(intervals); attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := retransmitWait(attempt, intervals, remaining)

		pkt, err := h.receivePacketWithTimeout(ctx, wait)
		if err == nil {
			// BUG-SM-3: discard stale packets of unexpected type (e.g., retransmitted
			// SessionRequests still in the queue when we are awaiting SessionConfirmed).
			// Do NOT count this as a retransmit attempt so the budget is preserved.
			if len(expectedTypes) > 0 && !matchesAny(pkt.MessageType, expectedTypes) {
				log.WithFields(logger.Fields{
					"pkg":      "session",
					"func":     "receiveHandshakeWithRetransmit",
					"got_type": pkt.MessageType,
				}).Debug("discarding stale packet of unexpected type")
				attempt-- // don't consume this attempt
				continue
			}
			return pkt, nil
		}

		if err := h.checkHandshakeCancelled(ctx); err != nil {
			return nil, err
		}

		if attempt < len(intervals) {
			_ = h.sendPacketDirect(lastSent)
		}
	}
	return nil, oops.Errorf("handshake timeout after %d retransmits", len(intervals))
}

// matchesAny returns true if t equals one of the types in accepted.
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
// around to zero (G-1); if the counter reaches 0xFFFFFFFF the
// connection is closed.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
// sortFragmentsByIndex sorts SessionConfirmed fragments by their fragment
// index (bits 7-4 of header byte 13). This ensures ProcessSessionConfirmedFragments
// receives fragments in the correct order regardless of arrival order.
func sortFragmentsByIndex(fragments []*SSU2Packet) {
	for i := 1; i < len(fragments); i++ {
		for j := i; j > 0; j-- {
			idxJ := int((fragments[j].Header[13] >> 4) & 0x0F)
			idxPrev := int((fragments[j-1].Header[13] >> 4) & 0x0F)
			if idxJ < idxPrev {
				fragments[j], fragments[j-1] = fragments[j-1], fragments[j]
			} else {
				break
			}
		}
	}
}

// installHeaderKey installs a derived header key into the header protector,
// if available. Consolidates nil-check, key getter call, empty-key check,
// and error wrapping for key installation.
func (h *SSU2Conn) installHeaderKey(keyGetter func() []byte, keyType string) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "installHeaderKey", "key_type": keyType}).Debug("Installing header key")
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

// ensureHandshakeDeadline wraps the context with a handshake deadline if needed.
// If config.HandshakeTimeout is set, uses it; otherwise checks for existing deadline
// on ctx; if neither, applies defaultHandshakeTimeout. Returns (ctx, cancel) where
// cancel may be nil if no new deadline was added.
func (h *SSU2Conn) ensureHandshakeDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := h.config.HandshakeTimeout
	if timeout <= 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			timeout = defaultHandshakeTimeout
		}
	}
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, nil
}
