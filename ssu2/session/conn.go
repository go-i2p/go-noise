package session

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/mod"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// ConnState is an alias for mod.ConnState, the shared connection lifecycle
// type. SSU2 uses mod.ConnState directly, including the StateClosing state
// which mod now provides for graceful-shutdown semantics (e.g. the SSU2
// Termination block wait period per spec §Termination).
type ConnState = mod.ConnState

const (
	// StateInit is the initial state before handshake.
	StateInit = mod.StateInit
	// StateHandshaking is during the XK handshake.
	StateHandshaking = mod.StateHandshaking
	// StateEstablished means handshake complete, ready for data.
	StateEstablished = mod.StateEstablished
	// StateClosing is graceful shutdown in progress — corresponds to the
	// Termination block wait period (SSU2 spec §Termination).
	StateClosing = mod.StateClosing
	// StateClosed means connection is fully closed.
	StateClosed = mod.StateClosed
)

const (
	// rekeyThreshold is the send-sequence value at which we initiate a
	// NextNonce rekey. Per the SSU2 spec the 32-bit packet number must
	// not wrap, so we start the rekey handshake well before 0xFFFFFFFF.
	// The 256-packet gap (0xFFFFFFFF - 0xFFFFFF00) provides enough lead
	// time for the NextNonce block to be sent, acknowledged, and for both
	// sides to switch to the new key before the counter is exhausted.
	//
	// WARNING: NextNonce (block type 11) is based on an UNFINALIZED spec
	// area (see SSU2 spec §3.7 "NextNonce") with size "TBD".
	// UNFINALIZED_SPEC: This threshold and the rekey mechanism may need
	// revision for interoperability when the spec is finalized (M-2).
	// Only enabled via SSU2Config.EnableNextNonce (default: false).
	rekeyThreshold uint32 = 0xFFFF_FF00

	// maxPacketRetries is the maximum number of retransmission attempts
	// before a pending packet is dropped.
	maxPacketRetries = 5

	// retransmitInterval is how often the retransmit loop checks for
	// expired pending packets.
	retransmitInterval = 250 * time.Millisecond

	// handshakeEnqueueTimeout bounds how long processInboundPacket will block
	// trying to hand a handshake packet to the handshake reader when the
	// recvQueue is transiently full, before dropping it (AUDIT 4.2).
	handshakeEnqueueTimeout = 250 * time.Millisecond

	// destroyTimeout is the default time to wait after sending a Termination
	// block before releasing session resources. Per spec §Termination:
	// "Wait for 11 seconds (the maximum RTO)" after sending a Termination
	// block. Can be overridden via SSU2Config.DestroyTimeout (M-4).
	destroyTimeout = 11 * time.Second
)

// SSU2Conn implements net.Conn for SSU2 transport connections over UDP.
// It integrates HandshakeHandler, DataHandler, and ACKHandler to provide
// a complete connection implementation following the SSU2 protocol.
//
// SSU2Conn handles:
// - XK pattern handshake (SessionRequest/Created/Confirmed)
// - Reliable ordered data delivery with ACKs
// - Fragment reassembly for large messages
// - Out-of-order packet buffering
// - RTT estimation and congestion control
// - Keepalive mechanism
//
// Thread Safety: All public methods are thread-safe.
type SSU2Conn struct {
	// underlying is the UDP connection for sending/receiving packets
	underlying net.PacketConn

	// remoteAddr is the UDP address of the peer
	remoteAddr     *net.UDPAddr
	remoteAddrLock sync.RWMutex

	// ssu2Addr contains SSU2-specific addressing info
	ssu2Addr *SSU2Addr

	// config holds connection configuration
	config *SSU2Config

	// initiator indicates if we initiated the connection
	initiator bool

	// Protocol handlers
	handshakeHandler     *HandshakeHandler
	dataHandler          *DataHandler
	ackHandler           *ACKHandler
	rttEstimator         *RTTEstimator
	recvWindow           *ReceiveWindow
	congestionController *CongestionController

	// Header protection (nil = disabled)
	headerProtector *HeaderProtectorManager

	// Path validation for connection migration (G-7)
	pathValidator *PathValidator

	// Connection state
	state      ConnState
	stateMutex sync.RWMutex
	closeChan  chan struct{}
	closeOnce  sync.Once
	closeErr   error
	closeMutex sync.Mutex

	// forceDestroy is closed by listener.Close() during parallel teardown to
	// cancel the DestroyTimeout wait in CloseWithReason, preventing serial
	// blocking when the listener shuts down multiple sessions. AUDIT 3.2.
	forceDestroy chan struct{}

	// Cipher states for transport phase (after handshake)
	sendCipher  *noise.CipherState
	recvCipher  *noise.CipherState
	cipherMutex sync.RWMutex

	// Packet management
	sendQueue    chan *SSU2Packet
	recvQueue    chan *SSU2Packet
	sendSequence uint32
	sendSeqMutex sync.Mutex

	// Pending outbound packets awaiting ACK
	pendingPackets map[uint32]*PendingPacket
	pendingMutex   sync.RWMutex

	// Deadlines
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMutex sync.RWMutex

	// readMutex serializes Read calls to safely manage pending message buffer.
	// Protects pendingMessage and the DataHandler.MessageChan read.
	readMutex sync.Mutex

	// pendingMessage holds the unread remainder of a message when the caller's
	// buffer is smaller than the message. Subsequent Read calls drain from this
	// buffer first. This mirrors conn.Conn.pendingPlaintext to maintain net.Conn
	// compatibility. See MEDIUM-1 audit finding.
	pendingMessage []byte

	// readModeCalled tracks whether Read() has been called on this connection.
	// Used to enforce mutual exclusivity with MessageChan(). See MEDIUM-1.
	readModeCalled atomic.Bool

	// messageChanModeCalled tracks whether MessageChan() has been called on this connection.
	// Used to enforce mutual exclusivity with Read(). See MEDIUM-1.
	messageChanModeCalled atomic.Bool

	// closedMessageChan is a closed channel returned as a sentinel by MessageChan()
	// when Read() has already been called, enforcing mutual exclusivity. See MEDIUM-1.
	closedMessageChan chan []byte

	// Keepalive
	lastActivity     time.Time
	lastActivityLock sync.RWMutex
	keepaliveTimer   *time.Timer

	// remoteConnectionID is the peer's connection ID, learned during
	// the handshake. Outbound data-phase packets must use this value
	// as the Destination Connection ID per SSU2 spec.
	// AUDIT 1.4: Use atomic.Uint64 for thread-safe access without explicit locks,
	// consistent with other protocol fields. Written once during handshake,
	// then read from all send paths.
	remoteConnectionID atomic.Uint64

	// Nonce rekeying: tracks whether a NextNonce block has been sent
	// for the current send cipher. Reset after rekey completes.
	rekeyInFlight atomic.Bool

	// ownsUnderlying indicates whether this connection created (and therefore
	// owns) the underlying PacketConn. When true, CloseWithReason closes
	// the PacketConn. When false (e.g. DialSSU2WithConn or listener-accepted
	// connections), the PacketConn is shared and must not be closed here.
	ownsUnderlying bool

	// readsOwnSocket indicates whether this connection is responsible for reading
	// from the underlying PacketConn. When true, the connection starts and owns
	// recvLoop during Handshake(). When false (listener-accepted connections),
	// the listener's receiveLoop reads the socket and feeds packets via RoutePacket
	// to recvQueue, and recvLoop is not started.
	// This is independent of ownsUnderlying: DialSSU2WithConn may have ownsUnderlying=false
	// but readsOwnSocket=true (the dial caller is the sole reader and responsible
	// for not co-locating a listener on the same socket).
	// AUDIT 1.2: Gate recvLoop startup on this flag to prevent listener and
	// responder from both reading the same shared socket.
	readsOwnSocket bool

	// closeHook, if set, is invoked once during CloseWithReason after the
	// connection's goroutines have been torn down. The listener wires this
	// to deregister the session from its routing maps so that closed
	// sessions do not accumulate forever (AUDIT 2.2). It must not call back
	// into CloseWithReason (which would deadlock on closeOnce).
	closeHook   func()
	closeHookMu sync.Mutex

	// destroySkip, when set, causes CloseWithReason to skip the
	// DestroyTimeout Termination-wait. Used by CloseImmediate for sessions
	// that are being abandoned before they were ever established, so a
	// cleanup close cannot block a packet worker for up to DestroyTimeout
	// (AUDIT 2.1).
	destroySkip atomic.Bool

	// Background goroutines coordination
	wg sync.WaitGroup

	// Error counters for observability (recvLoop)
	readErrors    atomic.Uint64
	parseErrors   atomic.Uint64
	decryptErrors atomic.Uint64

	// validDataPacketsReceived counts successfully received data-phase packets.
	// Included in the Termination block per spec §Termination.
	validDataPacketsReceived atomic.Uint64

	// validDataPacketsSent counts successfully sent data-phase packets.
	// Compared against the peer's reported count in Termination blocks
	// to detect packet loss during close (G-7).
	validDataPacketsSent atomic.Uint64
}

// PendingPacket tracks an outbound packet awaiting acknowledgment.
type PendingPacket struct {
	Packet           *SSU2Packet
	PlaintextPayload []byte // pre-encryption payload for retransmit
	SentTime         time.Time
	Retries          int
	NextRetry        time.Time
}

// NewSSU2Conn creates a new SSU2 connection.
// The connection starts in StateInit and must call Handshake() before data transfer.
//
// Parameters:
// - underlying: UDP PacketConn for sending/receiving
// - remoteAddr: Peer's UDP address
// - config: SSU2 configuration (validated before use)
// - initiator: true if we initiate handshake, false if responding
// - staticKey: our static X25519 private key (32 bytes)
// - remoteStaticKey: peer's static public key (32 bytes, required for initiator)
// NewSSU2Conn creates a new SSU2 connection.
// The connection starts in StateInit and must call Handshake() before data transfer.
//
// Parameters:
// - underlying: UDP PacketConn for sending/receiving
// - remoteAddr: Peer's UDP address
// - config: SSU2 configuration (validated before use)
// - initiator: true if we initiate handshake, false if responding
// - staticKey: our static X25519 private key (32 bytes)
// - remoteStaticKey: peer's static public key (32 bytes, required for initiator)
func NewSSU2Conn(
	underlying net.PacketConn,
	remoteAddr *net.UDPAddr,
	config *SSU2Config,
	initiator bool,
	staticKey []byte,
	remoteStaticKey []byte,
) (*SSU2Conn, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "NewSSU2Conn", "remote_addr": remoteAddr}).Debug("Creating new SSU2 connection")
	if err := validateConnInputs(underlying, remoteAddr, config); err != nil {
		return nil, err
	}

	connID, err := resolveConnectionID(config)
	if err != nil {
		return nil, err
	}

	if config.InitiatorConnectionID != 0 && config.InitiatorConnectionID == connID {
		return nil, oops.Errorf("connection ID collision: source and destination IDs are identical (%d)", connID)
	}

	handshakeHandler, err := buildHandshakeHandler(initiator, staticKey, remoteStaticKey, config)
	if err != nil {
		return nil, err
	}

	ssu2Addr, err := newSSU2AddrForConn(remoteAddr, config.RouterHash, connID, initiator)
	if err != nil {
		handshakeHandler.Close()
		return nil, err
	}

	conn := assembleSSU2Conn(underlying, remoteAddr, ssu2Addr, config, initiator, handshakeHandler)

	if err := conn.initHeaderProtection(config, initiator); err != nil {
		handshakeHandler.Close()
		return nil, err
	}

	return conn, nil
}

func validateConnInputs(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "validateConnInputs", "remote_addr": remoteAddr}).Debug("Validating connection parameters")
	if underlying == nil {
		return oops.Errorf("underlying PacketConn is nil")
	}
	if remoteAddr == nil {
		return oops.Errorf("remoteAddr is nil")
	}
	if config == nil {
		return oops.Errorf("config is nil")
	}
	if err := config.Validate(); err != nil {
		return oops.Wrapf(err, "invalid config")
	}
	return nil
}

func resolveConnectionID(config *SSU2Config) (uint64, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "resolveConnectionID", "configured_id": config.ConnectionID}).Debug("Resolving connection ID")
	connID := config.ConnectionID
	if connID == 0 {
		var err error
		connID, err = GenerateConnectionID()
		if err != nil {
			return 0, oops.Wrapf(err, "failed to generate connection ID")
		}
	}
	return connID, nil
}

func buildHandshakeHandler(initiator bool, staticKey, remoteStaticKey []byte, config *SSU2Config) (*HandshakeHandler, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "buildHandshakeHandler", "initiator": initiator, "has_remote_key": len(remoteStaticKey) > 0}).Debug("Creating handshake handler")
	prologue := []byte(nil) // SSU2 spec: null prologue (MixHash(h) with empty data)
	handler, err := NewHandshakeHandler(initiator, staticKey, remoteStaticKey, prologue)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake handler")
	}

	if config.ReplayCacheTTL > 0 && !initiator {
		handler.ReconfigureReplayCache(config.ReplayCacheTTL)
	}
	handler.SetMaxClockSkew(config.MaxClockSkew)
	handler.SetLocalOptions(&OptionsParams{
		TMinRatio: 0,
		TMaxRatio: config.PaddingRatio,
		RMinRatio: 0,
		RMaxRatio: config.PaddingRatio,
	})
	return handler, nil
}

func newSSU2AddrForConn(remoteAddr *net.UDPAddr, routerHash data.Hash, connID uint64, initiator bool) (*SSU2Addr, error) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "newSSU2AddrForConn", "remote_addr": remoteAddr, "conn_id": connID, "initiator": initiator}).Debug("Building SSU2 address")
	role := "initiator"
	if !initiator {
		role = "responder"
	}
	addr, err := NewSSU2Addr(remoteAddr, routerHash, connID, role)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 address")
	}
	return addr, nil
}

func assembleSSU2Conn(
	underlying net.PacketConn,
	remoteAddr *net.UDPAddr,
	ssu2Addr *SSU2Addr,
	config *SSU2Config,
	initiator bool,
	handshakeHandler *HandshakeHandler,
) *SSU2Conn {
	log.WithFields(logger.Fields{"pkg": "session", "func": "assembleSSU2Conn", "remote_addr": remoteAddr, "initiator": initiator, "mtu": config.MTU}).Debug("Assembling connection struct")
	rttEst := NewRTTEstimator()

	// Create a closed channel sentinel for MessageChan() to return when Read() has been called,
	// enforcing mutual exclusivity per MEDIUM-1 audit finding.
	closedChan := make(chan []byte)
	close(closedChan)

	conn := &SSU2Conn{
		underlying:           underlying,
		remoteAddr:           remoteAddr,
		ssu2Addr:             ssu2Addr,
		config:               config,
		initiator:            initiator,
		handshakeHandler:     handshakeHandler,
		dataHandler:          newDataHandlerFromConfig(config),
		ackHandler:           NewACKHandler(),
		rttEstimator:         rttEst,
		congestionController: NewCongestionControllerWithMTU(rttEst, config.MTU),
		recvWindow:           NewReceiveWindow(0, config.ReceiveWindowSize),
		state:                StateInit,
		closeChan:            make(chan struct{}),
		forceDestroy:         make(chan struct{}),
		closedMessageChan:    closedChan,
		sendQueue:            make(chan *SSU2Packet, 64),
		recvQueue:            make(chan *SSU2Packet, 64),
		pendingPackets:       make(map[uint32]*PendingPacket),
		lastActivity:         time.Now(),
		readsOwnSocket:       true, // AUDIT 1.2: default for dial paths; responders set to false
	}

	conn.pathValidator = NewPathValidator(conn)
	conn.pathValidator.SetCongestionController(conn.congestionController)
	return conn
}

func (c *SSU2Conn) initHeaderProtection(config *SSU2Config, initiator bool) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "initHeaderProtection", "has_intro_key": len(config.IntroKey) == HeaderKeySize, "initiator": initiator}).Debug("Initializing header protection")
	if len(config.IntroKey) == HeaderKeySize {
		hpm, err := NewHeaderProtectorManager(config.IntroKey, config.RemoteIntroKey, initiator)
		if err != nil {
			return oops.Wrapf(err, "failed to create header protector")
		}
		c.headerProtector = hpm
	}
	return nil
}

// messageTypeToHeaderType maps an SSU2 message type to the corresponding
// header protection type used for key selection.
// messageTypeToHeaderType maps an SSU2 message type to the corresponding
// header protection type used for key selection.
func messageTypeToHeaderType(msgType uint8) HeaderType {
	log.WithFields(logger.Fields{"pkg": "session", "func": "messageTypeToHeaderType", "msg_type": msgType}).Debug("Mapping message type to header type")
	switch msgType {
	case MessageTypeSessionRequest:
		return HeaderTypeSessionRequest
	case MessageTypeSessionCreated:
		return HeaderTypeSessionCreated
	case MessageTypeSessionConfirmed:
		// SessionConfirmed uses KDF-derived keys per spec.
		return HeaderTypeSessionConfirmed
	case MessageTypeRetry:
		return HeaderTypeRetry
	case MessageTypeTokenRequest:
		return HeaderTypeTokenRequest
	case MessageTypePeerTest:
		return HeaderTypePeerTest
	case MessageTypeHolePunch:
		return HeaderTypeHolePunch
	default:
		return HeaderTypeData
	}
}

func NewMockSSU2Conn(connID uint64) *SSU2Conn {
	closedChan := make(chan []byte)
	close(closedChan)
	return &SSU2Conn{
		ssu2Addr:          NewMockSSU2Addr(connID),
		state:             StateEstablished,
		closeChan:         make(chan struct{}),
		forceDestroy:      make(chan struct{}),
		closedMessageChan: closedChan,
	}
}

// TriggerForceDestroy closes the forceDestroy channel to signal cancellation
// of the DestroyTimeout wait in CloseWithReason. Used by listener.Close()
// during parallel teardown to avoid serial blocking (AUDIT 3.2).
// Safe to call multiple times (idempotent via select/default pattern).
func (h *SSU2Conn) TriggerForceDestroy() {
	select {
	case <-h.forceDestroy:
		// Already closed
	default:
		close(h.forceDestroy)
	}
}

// sendLoop handles outbound packet transmission.

// copyBytes returns a copy of src, or nil if src is nil.
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
