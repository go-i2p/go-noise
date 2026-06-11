package session

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

func (h *SSU2Conn) Close() error {
	return h.CloseWithReason(TerminationNormalClose, nil)
}

// CloseImmediate closes the connection without waiting the DestroyTimeout
// Termination period. It is intended for sessions that are being abandoned
// before they were ever established (e.g. when the accept queue is full or a
// duplicate connection ID is detected), where waiting to drain a Termination
// handshake is pointless and would block the caller (AUDIT 2.1).
func (h *SSU2Conn) CloseImmediate() error {
	h.destroySkip.Store(true)
	return h.CloseWithReason(TerminationNormalClose, nil)
}

// CloseWithReason sends a Termination block with the given reason code
// and optional additional data, then closes the connection.
// Per spec §Termination, the data is: validDataPacketsReceived (8 bytes)
// + reason (1 byte) + additional data (optional).
// CloseWithReason sends a Termination block with the given reason code
// and optional additional data, then closes the connection.
// Per spec §Termination, the data is: validDataPacketsReceived (8 bytes)
// + reason (1 byte) + additional data (optional).
func (h *SSU2Conn) CloseWithReason(reason TerminationReason, additionalData []byte) error {
	h.closeOnce.Do(func() {
		log.WithFields(logger.Fields{"pkg": "session", "func": "CloseWithReason", "reason": reason}).Debug("Closing SSU2 connection")
		// Update state first
		h.stateMutex.Lock()
		h.state = StateClosing
		h.stateMutex.Unlock()

		// Send Termination block (best effort)
		// Spec §Termination: validDataPacketsReceived(8 bytes, big-endian) + reason(1 byte) + additionalData
		termData := make([]byte, 9+len(additionalData))
		binary.BigEndian.PutUint64(termData[0:8], h.validDataPacketsReceived.Load())
		termData[8] = byte(reason)
		if len(additionalData) > 0 {
			copy(termData[9:], additionalData)
		}
		termBlock := &SSU2Block{
			Type: BlockTypeTermination,
			Data: termData,
		}

		// Create Data packet with termination block
		pktNum := h.nextSendSequence()
		hdr := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID.Load())
		binary.BigEndian.PutUint32(hdr[8:12], pktNum)
		packet := &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: pktNum,
			Header:       hdr,
			MAC:          make([]byte, MACSize),
		}
		payload, err := SerializeBlocks([]*SSU2Block{termBlock})
		socketDead := false // AUDIT 5.4: Track if socket is dead
		if err == nil {
			packet.Payload = payload
			// AUDIT 5.4: Capture send error into debug log instead of discarding.
			// If socket is dead, short-circuit the destroy wait.
			if err := h.sendPacketDirect(packet); err != nil {
				log.WithFields(logger.Fields{
					"pkg":   "session",
					"func":  "CloseWithReason",
					"error": err.Error(),
				}).Debug("failed to send Termination block (best effort)")
				// Check if error indicates socket is already dead (e.g., broken pipe, connection refused)
				// This lets us skip the destroy wait since there's no peer to respond anyway.
				socketDead = isSocketDeadError(err)
			}
		}

		// Per spec §Termination: wait briefly for the peer's Termination
		// response before tearing down the session. This avoids lingering
		// half-open state on the remote side. Use a timer instead of
		// time.Sleep so future callers could cancel via a context or
		// additional signal channel.
		// AUDIT 3.2: Also listen on forceDestroy channel so listener.Close()
		// can cancel all pending destroys in parallel rather than serially.
		// AUDIT 5.4: Skip destroy wait if socket is already dead.
		if h.config.DestroyTimeout > 0 && !h.destroySkip.Load() && !socketDead {
			timeout := h.config.DestroyTimeout
			const maxDestroyTimeout = 30 * time.Second
			if timeout > maxDestroyTimeout {
				timeout = maxDestroyTimeout
			}
			timer := time.NewTimer(timeout)
			select {
			case <-timer.C:
				// Timeout expired, proceed with teardown
			case <-h.closeChan:
				// Connection already closing via normal path
				timer.Stop()
			case <-h.forceDestroy:
				// AUDIT 3.2: Listener is shutting down, cancel wait
				timer.Stop()
			}
		}

		// Stop keepalive timer
		if h.keepaliveTimer != nil {
			h.keepaliveTimer.Stop()
		}

		// Stop fragment reaper
		if h.dataHandler != nil {
			h.dataHandler.Close()
		}

		// Stop replay cache cleanup goroutine
		if h.handshakeHandler != nil {
			h.handshakeHandler.Close()
		}

		// Zero pending message buffer to avoid lingering data in memory.
		// See MEDIUM-1 audit finding.
		if len(h.pendingMessage) > 0 {
			// We can't use securemem here without adding a dependency,
			// but zeroing via slice assignment is sufficient for this buffer.
			for i := range h.pendingMessage {
				h.pendingMessage[i] = 0
			}
			h.pendingMessage = nil
		}

		// Close channels to signal goroutines to exit
		close(h.closeChan)

		// Wait for background goroutines to complete
		h.wg.Wait()

		// Close the underlying PacketConn if this connection owns it
		// (created via DialSSU2). Shared sockets (DialSSU2WithConn,
		// listener-accepted) are not closed here.
		if h.ownsUnderlying && h.underlying != nil {
			h.closeErr = h.underlying.Close()
		}

		// Update final state
		h.stateMutex.Lock()
		h.state = StateClosed
		h.stateMutex.Unlock()

		// Deregister from any external routing maps (listener/router). Run
		// after teardown so no inbound packet can be routed to a half-torn-down
		// session (AUDIT 2.2).
		h.closeHookMu.Lock()
		hook := h.closeHook
		h.closeHookMu.Unlock()
		if hook != nil {
			hook()
		}
	})

	h.closeMutex.Lock()
	defer h.closeMutex.Unlock()
	return h.closeErr
}

// LocalAddr implements net.Conn.LocalAddr.
// LocalAddr implements net.Conn.LocalAddr.
func (h *SSU2Conn) LocalAddr() net.Addr {
	if localUDPAddr, ok := h.underlying.LocalAddr().(*net.UDPAddr); ok {
		role := "initiator"
		if !h.initiator {
			role = "responder"
		}
		addr, err := NewSSU2Addr(localUDPAddr, h.config.RouterHash, h.config.ConnectionID, role)
		if err == nil {
			return addr
		}
	}
	return h.underlying.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr.
// RemoteAddr implements net.Conn.RemoteAddr.
func (h *SSU2Conn) RemoteAddr() net.Addr {
	return h.ssu2Addr
}

// SendToAddress sends a block to a specific UDP address (implements PathValidationConn).
// SendToAddress sends a block to a specific UDP address (implements PathValidationConn).
func (h *SSU2Conn) SendToAddress(block *SSU2Block, addr *net.UDPAddr) error {
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID.Load())
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "failed to serialize block for path validation")
	}
	packet.Payload = payload
	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet for path validation")
	}
	_, err = h.underlying.WriteTo(data, addr)
	return err
}

// GetRemoteAddr returns the current remote UDP address (implements PathValidationConn).
// GetRemoteAddr returns the current remote UDP address (implements PathValidationConn).
func (h *SSU2Conn) GetRemoteAddr() *net.UDPAddr {
	h.remoteAddrLock.RLock()
	defer h.remoteAddrLock.RUnlock()
	return h.remoteAddr
}

// SetRemoteAddr updates the remote address after successful path validation (implements PathValidationConn).
// SetRemoteAddr updates the remote address after successful path validation (implements PathValidationConn).
func (h *SSU2Conn) SetRemoteAddr(addr *net.UDPAddr) error {
	if addr == nil {
		return oops.Errorf("address is nil")
	}
	h.remoteAddrLock.Lock()
	defer h.remoteAddrLock.Unlock()
	h.remoteAddr = addr
	return nil
}

// SetDeadline implements net.Conn.SetDeadline.
// SetDeadline implements net.Conn.SetDeadline.
func (h *SSU2Conn) SetDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	h.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
// SetReadDeadline implements net.Conn.SetReadDeadline.
func (h *SSU2Conn) SetReadDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (h *SSU2Conn) SetWriteDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.writeDeadline = t
	return nil
}

// GetState returns the current connection state.
// GetState returns the current connection state.
func (h *SSU2Conn) GetState() ConnState {
	h.stateMutex.RLock()
	defer h.stateMutex.RUnlock()
	return h.state
}

// RecvStats returns error counters from the receive loop for observability.
// Keys: "read_errors", "parse_errors", "decrypt_errors".
// RecvStats returns error counters from the receive loop for observability.
// Keys: "read_errors", "parse_errors", "decrypt_errors".
func (h *SSU2Conn) RecvStats() map[string]uint64 {
	return map[string]uint64{
		"read_errors":    h.readErrors.Load(),
		"parse_errors":   h.parseErrors.Load(),
		"decrypt_errors": h.decryptErrors.Load(),
	}
}

// SetDataHandlerCallbacks wires application-level callbacks for SSU2 block types
// received during the data phase. Call before Handshake() completes to ensure
// callbacks are active from the first data packet. Safe to call concurrently
// with an active connection; updates take effect on the next inbound packet.
// SetDataHandlerCallbacks wires application-level callbacks for SSU2 block types
// received during the data phase. Call before Handshake() completes to ensure
// callbacks are active from the first data packet. Safe to call concurrently
// with an active connection; updates take effect on the next inbound packet.
func (h *SSU2Conn) SetDataHandlerCallbacks(cbs DataHandlerCallbacks) {
	h.dataHandler.SetCallbacks(cbs)
}

// SetOwnsUnderlying marks whether this connection owns the underlying
// PacketConn. When true, CloseWithReason will close the PacketConn.
// When false (shared socket scenarios), the PacketConn is left open.
func (h *SSU2Conn) SetOwnsUnderlying(v bool) {
	h.ownsUnderlying = v
}

// SetReadsOwnSocket marks whether this connection is responsible for reading
// from the underlying PacketConn. When true (default for DialSSU2), the connection
// starts recvLoop during Handshake() to read packets. When false (listener-accepted
// connections), recvLoop is not started and packets are fed via RoutePacket from
// the listener's receiveLoop into recvQueue.
// AUDIT 1.2: Gate recvLoop startup to prevent multiple readers on the same socket.
func (h *SSU2Conn) SetReadsOwnSocket(v bool) {
	h.readsOwnSocket = v
}

// SetCloseHook registers a callback invoked once during CloseWithReason,
// after the connection's goroutines are torn down. The listener uses this
// to deregister the session from its routing maps when the connection
// closes, preventing unbounded session accumulation (AUDIT 2.2). The hook
// must not call CloseWithReason on this connection.
func (h *SSU2Conn) SetCloseHook(hook func()) {
	h.closeHookMu.Lock()
	h.closeHook = hook
	h.closeHookMu.Unlock()
}

// GetSSU2Addr returns the SSU2 address associated with this connection.
// It exposes the otherwise-unexported ssu2Addr field for use by outer
// packages such as ssu2/server tests.
func (h *SSU2Conn) GetSSU2Addr() *SSU2Addr {
	return h.ssu2Addr
}

// IsInitiator reports whether this connection was created as the initiating side
// of the SSU2 handshake.
func (h *SSU2Conn) IsInitiator() bool {
	return h.initiator
}

// isSocketDeadError checks whether an error indicates the underlying socket
// is dead or unreachable (e.g., broken pipe, connection refused, no such host).
// AUDIT 5.4: Used to short-circuit the destroy wait when sending Termination
// fails because the socket is already dead.
func isSocketDeadError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common socket-dead error conditions
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Broken pipe, connection refused, no such host, etc.
		switch opErr.Op {
		case "write", "WriteTo", "sendto":
			// These operations indicate socket-level failures
			return true
		}
		// Also check the underlying error
		if opErr.Err != nil {
			errStr := opErr.Err.Error()
			switch errStr {
			case "connection refused", "broken pipe", "connection reset by peer",
				"no such host", "connection timed out":
				return true
			}
		}
	}

	// Check for simple string patterns in error message (fallback)
	errStr := err.Error()
	deadPatterns := []string{
		"broken pipe",
		"connection refused",
		"connection reset",
		"no such host",
		"connection timed out",
		"use of closed network connection",
	}
	for _, pattern := range deadPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// NewMockSSU2Conn creates a minimal SSU2Conn with the given connectionID in
// StateEstablished. The connection has no underlying PacketConn and must not
// be used for actual I/O. Intended for unit tests that need to inject mock
// sessions (e.g. testing SessionCount or graceful shutdown).
