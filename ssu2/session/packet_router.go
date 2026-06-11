package session

import (
	"encoding/binary"
	"net"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PacketRouter routes incoming SSU2 packets to appropriate connection sessions
// based on connection ID or creates new sessions for handshake packets.
//
// Design rationale:
// - SSU2 uses connection IDs to multiplex multiple sessions over a single UDP socket
// - The router extracts the destination connection ID from the encrypted header
// - Handshake packets (SessionRequest) may have connection ID 0 and trigger new sessions
// - Data packets are routed to existing sessions by connection ID
//
// Thread Safety: All methods are thread-safe via the sessionMutex.
type PacketRouter struct {
	// sessions maps connection ID to SSU2Conn instances
	// Protected by sessionMutex for concurrent access
	sessions map[uint64]*SSU2Conn

	// sessionMutex protects the sessions map
	sessionMutex sync.RWMutex

	// newSessionHandler is called when a handshake packet arrives with no existing session
	// Returns the newly created session or an error
	newSessionHandler func(remoteAddr *net.UDPAddr, packet *SSU2Packet) (*SSU2Conn, error)
}

// NewPacketRouter creates a new packet router with an empty session table.
// The newSessionHandler callback is invoked when handshake packets arrive
// for unknown connection IDs, allowing the listener to create new sessions.
//
// Parameters:
//   - newSessionHandler: Callback to create new sessions for handshake packets.
//     May be nil if the router only handles existing sessions.
//
// Returns a new PacketRouter ready to route packets.
func NewPacketRouter(newSessionHandler func(*net.UDPAddr, *SSU2Packet) (*SSU2Conn, error)) *PacketRouter {
	log.WithFields(logger.Fields{"pkg": "session", "func": "NewPacketRouter"}).Debug("Creating new PacketRouter")
	return &PacketRouter{
		sessions:          make(map[uint64]*SSU2Conn),
		newSessionHandler: newSessionHandler,
	}
}

// AddSession registers a connection in the routing table.
// The connection's connection ID is used as the routing key.
//
// Parameters:
//   - conn: The SSU2Conn to register
//
// Returns error if the connection ID is already registered.
func (pr *PacketRouter) AddSession(conn *SSU2Conn) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "AddSession"}).Debug("Adding session to packet router")
	if conn == nil {
		return oops.
			Code("INVALID_SESSION").
			In("packet_router").
			Errorf("connection cannot be nil")
	}

	if conn.ssu2Addr == nil {
		return oops.
			Code("INVALID_SESSION_ADDR").
			In("packet_router").
			Errorf("connection must have SSU2Addr")
	}

	connID := conn.ssu2Addr.ConnectionID()

	pr.sessionMutex.Lock()
	defer pr.sessionMutex.Unlock()

	if _, exists := pr.sessions[connID]; exists {
		return oops.
			Code("DUPLICATE_CONNECTION_ID").
			In("packet_router").
			With("connection_id", connID).
			Errorf("connection ID already registered")
	}

	pr.sessions[connID] = conn
	return nil
}

// RemoveSession unregisters a connection from the routing table.
// This should be called when a connection closes.
//
// Parameters:
//   - connID: The connection ID to remove
func (pr *PacketRouter) RemoveSession(connID uint64) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "RemoveSession", "connID": connID}).Debug("Removing session from packet router")
	pr.sessionMutex.Lock()
	defer pr.sessionMutex.Unlock()

	delete(pr.sessions, connID)
}

// GetSession retrieves a connection by its connection ID.
// Returns nil if no session exists for the given ID.
//
// Parameters:
//   - connID: The connection ID to look up
//
// Returns the SSU2Conn or nil if not found.
func (pr *PacketRouter) GetSession(connID uint64) *SSU2Conn {
	pr.sessionMutex.RLock()
	defer pr.sessionMutex.RUnlock()

	return pr.sessions[connID]
}

// RoutePacket routes an incoming packet to the appropriate session.
// For handshake packets with unknown connection IDs, invokes newSessionHandler.
// For data packets, routes to existing session or returns error.
//
// Parameters:
//   - packet: The SSU2Packet to route
//   - remoteAddr: The UDP address the packet was received from
//
// Returns error if routing fails or session doesn't exist.
func (pr *PacketRouter) RoutePacket(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "RoutePacket"}).Debug("Routing incoming packet")
	if packet == nil {
		return oops.
			Code("INVALID_PACKET").
			In("packet_router").
			Errorf("packet cannot be nil")
	}

	if remoteAddr == nil {
		return oops.
			Code("INVALID_REMOTE_ADDR").
			In("packet_router").
			Errorf("remote address cannot be nil")
	}

	// Extract connection ID from header (assuming header is decrypted)
	connID, err := pr.ExtractConnectionID(packet.Header)
	if err != nil {
		return oops.Wrapf(err, "failed to extract connection ID")
	}

	// Try to find existing session
	conn := pr.GetSession(connID)

	// If no session exists
	if conn == nil {
		// Check if this is a handshake packet that can create a new session
		if pr.IsHandshakePacket(packet.MessageType) {
			if pr.newSessionHandler == nil {
				return oops.
					Code("NO_SESSION_HANDLER").
					In("packet_router").
					Errorf("no handler registered for new sessions")
			}

			// Create new session via callback
			newConn, err := pr.newSessionHandler(remoteAddr, packet)
			if err != nil {
				return oops.Wrapf(err, "failed to create new session")
			}

			// Register the new session
			if err := pr.AddSession(newConn); err != nil {
				// AUDIT 2.3: the newSessionHandler (listener) already
				// registered and queued newConn before we got here. If we
				// cannot add it to the router table we must tear it down so
				// its map entry and per-session goroutines do not leak. The
				// connection's close hook deregisters it from the listener
				// and router maps. CloseImmediate avoids blocking this packet
				// worker for the Termination wait.
				_ = newConn.CloseImmediate()
				return oops.Wrapf(err, "failed to register new session")
			}

			// AUDIT 1.2: Feed the triggering handshake packet to the newly created session.
			// For listener-accepted responders, this is the entry point for the handshake
			// reader. The listener's receiveLoop has captured this packet; after registration,
			// the listener must feed it to the session via processInboundPacket so that
			// receivePacketWithTimeout in the handshake can retrieve it from recvQueue.
			// For initiators (unlikely path), this ensures the first msg-1 is not lost.
			newConn.processInboundPacket(packet)

			return nil
		}

		// Non-handshake packet with no session
		return oops.
			Code("SESSION_NOT_FOUND").
			In("packet_router").
			With("connection_id", connID).
			With("message_type", packet.MessageType).
			Errorf("no session found for connection ID")
	}

	// Route packet to existing session
	conn.processInboundPacket(packet)

	return nil
}

// ExtractConnectionID extracts the destination connection ID from an encrypted header.
//
// Design: The connection ID location depends on the header format per ssu2.rst.
// For short headers (16 bytes): bytes 8-15 contain the destination connection ID
// For long headers (32 bytes): bytes 8-15 contain the destination connection ID
//
// Note: The header must already be decrypted before calling this method.
// The connection ID is encoded in network byte order (big-endian).
//
// Parameters:
//   - header: The decrypted header bytes
//
// Returns:
//   - uint64: The destination connection ID
//   - error: If header is invalid or too short
func (pr *PacketRouter) ExtractConnectionID(header []byte) (uint64, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "ExtractConnectionID", "headerLen": len(header)}).Debug("ExtractConnectionID: extracting connection ID from header")
	// Validate header size
	if len(header) < ShortHeaderSize {
		return 0, oops.
			Code("INVALID_HEADER_SIZE").
			In("packet_router").
			With("size", len(header)).
			Errorf("header too short (minimum %d bytes)", ShortHeaderSize)
	}

	// Extract 8-byte destination connection ID from bytes 0-7
	// per SSU2 spec: bytes 0-7 hold the destination connection ID in both
	// short (16-byte) and long (32-byte) headers.
	connID := binary.BigEndian.Uint64(header[0:8])

	return connID, nil
}

// IsHandshakePacket returns true if the message type represents a handshake packet
// that can initiate a new connection session.
//
// Handshake packets per ssu2.rst:
// - SessionRequest (0): Initial handshake message
// - TokenRequest (10): Request for retry token
//
// SessionCreated (1) and SessionConfirmed (2) are not included because they
// require an existing session initiated by SessionRequest.
//
// Parameters:
//   - msgType: The SSU2 message type (0-11)
//
// Returns true if this message type can create a new session.
func (pr *PacketRouter) IsHandshakePacket(msgType uint8) bool {
	switch msgType {
	case MessageTypeSessionRequest, MessageTypeTokenRequest:
		return true
	default:
		return false
	}
}

// SessionCount returns the current number of registered sessions.
// Useful for monitoring and debugging.
func (pr *PacketRouter) SessionCount() int {
	pr.sessionMutex.RLock()
	defer pr.sessionMutex.RUnlock()

	return len(pr.sessions)
}

// GetAllSessions returns a snapshot of all registered sessions.
// The returned slice is a copy of the session list at the time of the call.
// Used by listener.Close() to trigger parallel teardown of all sessions (AUDIT 3.2).
func (pr *PacketRouter) GetAllSessions() []*SSU2Conn {
	pr.sessionMutex.RLock()
	defer pr.sessionMutex.RUnlock()

	sessions := make([]*SSU2Conn, 0, len(pr.sessions))
	for _, conn := range pr.sessions {
		sessions = append(sessions, conn)
	}
	return sessions
}
