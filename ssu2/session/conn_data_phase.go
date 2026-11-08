package session

import (
	"net"
	"time"

	"github.com/go-i2p/logger"
)

// This file holds what happens after the last handshake message: the condition
// that turns a unilateral handshake into a session, and the datagrams that
// arrive before the data-phase keys exist to read them.
//
// Both exist because of finding 012. Handshake() returned success as soon as
// Session Confirmed had been written, so an initiator never learned that the
// peer had rejected it: the session reported itself established, the router
// considered the peer connected and never redialled, and everything queued into
// it was retransmitted into that void indefinitely.

// pendingHandshakeDatagram is one raw datagram kept during the handshake.
//
// It is kept as bytes, not as a parsed packet, because header obfuscation is not
// self-validating: deobfuscating under the wrong key yields a structurally valid
// header full of garbage rather than an error, so a parsed packet taken too early
// cannot be trusted. The AEAD open is what authenticates, and that needs the
// header — so the only sound retry is to redo the whole pipeline once the real
// keys are installed.
type pendingHandshakeDatagram struct {
	data []byte
	addr net.Addr
}

// dataPhaseDeadline returns how long this connection waits for the peer's first
// data-phase packet after the initiator half of the handshake. A negative
// configured value disables the deadline; zero selects the default.
func (h *SSU2Conn) dataPhaseDeadline() time.Duration {
	if h.config != nil && h.config.DataPhaseTimeout != 0 {
		return h.config.DataPhaseTimeout
	}
	return dataPhaseWaitTimeout
}

// startDataPhaseWatchdog arms the deadline for the peer's first data-phase
// packet. Only the initiator needs it: the responder has already received
// Session Confirmed, which is the peer's proof of life, and it is the responder
// that must then send the ACK of packet 0 rather than wait for one.
//
// Called from finalizeHandshake after the data-phase keys are installed and
// after any datagram retained during the handshake has been replayed, so a peer
// that answered immediately is not waited for.
func (h *SSU2Conn) startDataPhaseWatchdog() {
	if !h.initiator {
		return
	}
	if h.dataPhaseDeadline() <= 0 {
		return
	}
	if h.peerDataSeen.Load() {
		return
	}

	h.dataPhaseDeadlineLock.Lock()
	if h.dataPhaseDeadlineTimer == nil {
		h.dataPhaseDeadlineTimer = time.AfterFunc(h.dataPhaseDeadline(), h.teardownUnconfirmedSession)
	}
	h.dataPhaseDeadlineLock.Unlock()
}

// teardownUnconfirmedSession closes a session whose handshake the peer never
// completed. It is a timer callback, so it re-checks the condition: a data
// packet that landed between arming and firing cancels the teardown.
func (h *SSU2Conn) teardownUnconfirmedSession() {
	if h.peerDataSeen.Load() {
		return
	}
	flog("dataPhaseDeadline", logger.Fields{
		"timeout": h.dataPhaseDeadline().String(),
	}).Warn("SSU2 handshake never completed: no data-phase packet from peer, closing session")
	// TerminationSessionConfirmedError (13) is the spec's code for a peer
	// problem with the Session Confirmed we sent, which is exactly the inference
	// from silence: it either rejected it or never received it.
	//
	// CloseWithReason waits the DestroyTimeout, and a session that never got a
	// data packet has no peer waiting, so the wait buys nothing — but it is the
	// spec's closing exchange and other implementations expect it, so it is kept
	// and run off this goroutine.
	go func() {
		if err := h.CloseWithReason(TerminationSessionConfirmedError, nil); err != nil {
			flog("dataPhaseDeadline", logger.Fields{"error": err.Error()}).
				Debug("failed to close session that never received a data packet")
		}
	}()
}

// cancelDataPhaseWatchdog releases the timer once the condition it waits for has
// been met, so a healthy session does not keep a pending callback armed for its
// whole lifetime.
func (h *SSU2Conn) cancelDataPhaseWatchdog() {
	h.dataPhaseDeadlineLock.Lock()
	defer h.dataPhaseDeadlineLock.Unlock()
	if h.dataPhaseDeadlineTimer != nil {
		h.dataPhaseDeadlineTimer.Stop()
		h.dataPhaseDeadlineTimer = nil
	}
}

// PeerDataReceived reports whether the peer has sent a data-phase packet this
// connection authenticated.
//
// A handshake is bilateral: ssu2.md §"Handshake Retransmission" ->
// §"Session Confirmed" makes the peer's first data message the event that ends
// Session Confirmed retransmission, so until one arrives the peer has not
// acknowledged the handshake at all. A caller deciding whether to use or keep a
// session should treat false as "the peer has not accepted it yet" rather than as
// a slow start: holding such a session costs a slot, CPU, and retransmission
// traffic for nothing, and it prevents the redial that would have a chance of
// succeeding.
func (h *SSU2Conn) PeerDataReceived() bool {
	return h.peerDataSeen.Load()
}

// notePeerDataPacket records the arrival of an authenticated data-phase packet
// and returns whether this call was the first one.
func (h *SSU2Conn) notePeerDataPacket() bool {
	if !h.peerDataSeen.CompareAndSwap(false, true) {
		return false
	}
	h.cancelDataPhaseWatchdog()
	// The Session Confirmed retransmission stop condition is the arrival of a
	// data message (§"Handshake Retransmission" -> §"Session Confirmed" option
	// 2). markSessionConfirmedAcked is idempotent, and calling it here as well as
	// from handleReadyDataPacket means a packet replayed from the handshake
	// buffer counts too.
	h.markSessionConfirmedAcked()
	return true
}

// retainHandshakeDatagram keeps a datagram this handshaking initiator could not
// parse, so finalizeHandshake can try again with the data-phase keys.
//
// SSU2 puts no data on the wire during the handshake, so the only way one gets
// here is a peer answering Session Confirmed immediately — which i2pd and Java
// I2P both do, because ssu2.rst §"Packet Numbering" tells the responder "outbound
// packet numbering starts at 0 with first Data packet, which should be an ACK of
// the Session Confirmed". Dropping it is not free: the responder does not reset
// its packet counter, so that number is gone for the life of the session, and the
// peer must reach its own retransmission path before anything lands.
//
// Only an initiator that has not yet completed the handshake retains anything. A
// session in any other state has no future key install to wait for, so a packet
// it cannot parse stays dropped, exactly as before.
//
// Returns whether the datagram was retained, so the caller can log the ordinary
// drop when it was not.
func (h *SSU2Conn) retainHandshakeDatagram(data []byte, addr net.Addr) bool {
	// data is nil on a read path that decided not to copy, because the state can
	// change between that check and this one. Nothing to retain in that case: the
	// keys are installed, so the parse that failed was a real failure.
	if len(data) == 0 || !h.awaitingDataPhaseKeys() {
		return false
	}
	return h.retainBounded(data, addr)
}

// retainBounded copies the datagram into the bounded race-window buffer. It
// applies no state or role check of its own — each caller decides what it is safe
// to hold, because the two entry points differ in exactly that respect.
func (h *SSU2Conn) retainBounded(data []byte, addr net.Addr) bool {
	raw := make([]byte, len(data))
	copy(raw, data)

	h.pendingHandshakeDataMutex.Lock()
	defer h.pendingHandshakeDataMutex.Unlock()
	if len(h.pendingHandshakeDatagrams) >= pendingHandshakeDataMax {
		// Bounded on purpose: this is a race-window buffer, not a queue. Once it
		// is full the peer is retransmitting anyway, and a new number will parse.
		return false
	}
	h.pendingHandshakeDatagrams = append(h.pendingHandshakeDatagrams, pendingHandshakeDatagram{
		data: raw,
		addr: addr,
	})
	h.handshakeRetained.Add(1)
	return true
}

// awaitingDataPhaseKeys reports whether this connection is an initiator whose
// handshake is still finalising — the one moment a datagram can arrive that the
// keys installed a moment later would have been able to read.
//
// Initiator only, deliberately. A responder is waiting for Session Confirmed, and
// while it is still handshaking its own parse uses the Session Request header
// schedule, so an inbound Session Confirmed does NOT parse — retaining it would
// buffer the very packet finalizeHandshake is blocked on, since the flush happens
// inside finalizeHandshake. The deadlock is worth more than the coverage: a
// responder's data keys are derived when it receives Session Confirmed, and a peer
// cannot send data before it has received that same message.
func (h *SSU2Conn) awaitingDataPhaseKeys() bool {
	if h == nil || !h.initiator {
		return false
	}
	return h.handshakeStillRunning()
}

// handshakeStillRunning reports whether the handshake has not finalised yet, i.e.
// the data-phase keys may still be a moment away.
func (h *SSU2Conn) handshakeStillRunning() bool {
	h.stateMutex.RLock()
	defer h.stateMutex.RUnlock()
	return h.state == StateHandshaking || h.state == StateInit
}

// RetainListenerDatagram keeps a datagram the listener could not deobfuscate
// because this session's data-phase header protector is not installed yet, and
// replays it through the normal inbound path once finalizeHandshake derives it.
//
// This is the listener-socket counterpart of the retention the connection's own
// read loop does for itself (readOnePacket). go-i2p's real dial path,
// DialSSU2ViaListener, never runs recvLoop — one goroutine owns the shared socket
// and it is the listener's — so without this hook the race is uncovered on exactly
// the path routers use, for both the session it dialled and the sessions dialling
// it.
//
// The buffer is drained inside finalizeHandshake, so a packet held here must never
// be one that handshake is still waiting to read — otherwise the handshake would
// block on its own buffer. That rules out Session Created (for an initiator) and
// Session Confirmed (for a responder), and both are excluded by one condition: the
// Noise cipher states only exist once the final handshake message has been
// processed, so requiring IsHandshakeComplete means every handshake message this
// connection could still be waiting for has already arrived. A datagram that fails
// every protector stage AND finds the handshake complete can only be a data-phase
// packet whose keys are a moment away.
//
// Returns whether the datagram was retained, so the listener can log the ordinary
// drop when it was not.
func (h *SSU2Conn) RetainListenerDatagram(data []byte, addr net.Addr) bool {
	// A datagram shorter than a short header plus the 24-byte header-protection
	// sample cannot be a data-phase packet, so retaining it would only let a flood
	// fill the buffer.
	if h == nil || len(data) < ShortHeaderSize+24 {
		return false
	}
	if !h.handshakeStillRunning() {
		// No data-phase keys are pending installation, so nothing replayed here
		// could ever be read: drop as before.
		return false
	}
	// The handshake has processed every message it can still be waiting for, so
	// what we are holding cannot strand it.
	if h.handshakeHandler == nil || !h.handshakeHandler.IsHandshakeComplete() {
		return false
	}
	return h.retainBounded(data, addr)
}

// flushPendingHandshakeDatagrams replays what was retained during the handshake.
// Called from finalizeHandshake after the data-phase keys are installed.
//
// Replaying through the normal path costs a second header deobfuscation attempt
// that will usually fail: the datagram is then parsed under the handshake-phase
// schedule and dropped by the AEAD open, which is the sound outcome for a packet
// that really was a stray. A packet that is genuinely the peer's first Data
// message opens under the data-phase keys and is delivered.
func (h *SSU2Conn) flushPendingHandshakeDatagrams() {
	h.pendingHandshakeDataMutex.Lock()
	buffered := h.pendingHandshakeDatagrams
	h.pendingHandshakeDatagrams = nil
	h.pendingHandshakeDataMutex.Unlock()

	for _, pending := range buffered {
		packet := h.parseInboundPacket(pending.data, pending.addr)
		if packet == nil {
			continue
		}
		flog("flushPendingHandshakeDatagrams", logger.Fields{"msg_type": packet.MessageType}).
			Debug("replaying datagram received during handshake")
		h.ProcessInboundPacket(packet)
	}
}
