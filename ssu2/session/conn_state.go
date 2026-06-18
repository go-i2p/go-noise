package session

import (
	"github.com/go-i2p/logger"
)

// expectedInboundHeaderType returns the header type to use when decrypting
// inbound packets, based on the current connection state.
// expectedInboundHeaderType returns the header type to use when decrypting
// inbound packets, based on the current connection state.
func (h *SSU2Conn) expectedInboundHeaderType() HeaderType {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()
	flog("expectedInboundHeaderType", logger.Fields{"state": state, "initiator": h.initiator}).Debug("Determining inbound header type")

	if state == StateEstablished {
		return HeaderTypeData
	}
	// During handshake, use intro-key-based types.
	if h.initiator {
		return HeaderTypeSessionCreated
	}
	return HeaderTypeSessionRequest
}

// Handshake performs the SSU2 XK pattern handshake.
// For initiators: sends SessionRequest, receives SessionCreated, sends SessionConfirmed
// For responders: receives SessionRequest, sends SessionCreated, receives SessionConfirmed
//
// After successful handshake, connection state transitions to StateEstablished.
// Close implements net.Conn.Close.
// Sends a Termination block with reason NormalClose and closes the connection.
