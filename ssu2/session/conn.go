package session

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/mod"
	"github.com/go-i2p/go-noise/ssu2/wire"
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

// ReadDeliveryMode tracks which delivery path has been used for reading messages.
// Used to enforce mutual exclusivity between Read() and MessageChan() delivery paths.
// Using a single atomic mode word prevents TOCTOU races where
// both paths could concurrently observe the other path's flag as unset.
type ReadDeliveryMode int32

const (
	// ReadDeliveryModeUnset means neither Read() nor MessageChan() has been called yet.
	ReadDeliveryModeUnset ReadDeliveryMode = iota
	// ReadDeliveryModeRead means Read() has been called and is the active path.
	ReadDeliveryModeRead
	// ReadDeliveryModeChan means MessageChan() has been called and is the active path.
	ReadDeliveryModeChan
)

const (
	// rekeyThreshold is the send-sequence value at which we initiate a
	// rekeyThreshold is the send-sequence value at which we initiate a
	// NextNonce rekey. Per the SSU2 spec the 32-bit packet number must
	// not wrap, so we start the rekey handshake well before 0xFFFFFFFF.
	// The 256-packet gap (0xFFFFFFFF - 0xFFFFFF00) provides enough lead
	// time for the NextNonce block to be sent, acknowledged, and for both
	// sides to switch to the new key before the counter is exhausted.
	//
	// WARNING: NextNonce (block type 11) is based on an UNFINALIZED spec
	// area (see ssu2.rst "NextNonce", marked "TODO only if we rotate keys"
	// with the block size listed as "TBD").
	// This threshold and the rekey mechanism may need
	// revision for interoperability when the spec is finalized.
	// Only enabled via SSU2Config.EnableNextNonce (default: false).
	rekeyThreshold uint32 = 0xFFFF_FF00

	// maxPacketRetries is the maximum number of retransmission attempts
	// before a pending packet is dropped.
	maxPacketRetries = 5

	// retransmitInterval is how often the retransmit loop checks for
	// expired pending packets.
	retransmitInterval = 250 * time.Millisecond

	// handshakeEnqueueTimeout bounds how long ProcessInboundPacket will block
	// trying to hand a handshake packet to the handshake reader when the
	// recvQueue is transiently full, before dropping it.
	// The value is kept short (10 ms) so that all 8 packetWorker
	// goroutines do not simultaneously block for long, which would
	// stall established-session datagrams by filling packetQueue.
	handshakeEnqueueTimeout = 10 * time.Millisecond

	// defaultHandshakeTimeout is the fallback deadline for SSU2 handshakes
	// when neither SSU2Config.HandshakeTimeout is set nor the caller's
	// context carries a deadline (LEAK-2 / TIMEOUT-1). A stalling peer
	// would otherwise hold the handshake goroutine open indefinitely.
	defaultHandshakeTimeout = 30 * time.Second
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

	// peerMTU is the MTU published by the peer in its RouterInfo SSU2 address
	// ("mtu" option), 0 when unpublished. ssu2.md §"MTU": "Routers must publish
	// a non-default MTU in each SSU or SSU2 router address." Guarded by
	// remoteAddrLock alongside the address it constrains.
	peerMTU int

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

	// Path validation for connection migration
	pathValidator *PathValidator

	// Connection state
	state      ConnState
	stateMutex sync.RWMutex
	closeChan  chan struct{}
	closeOnce  sync.Once
	closeErr   error
	// closeReason records the Termination reason this session closed with, so a
	// caller can tell a superseded session (reason 22, ssu2.md §"Multiple
	// Sessions") from an idle timeout or a normal close. closeReasonSet is the
	// validity flag: reason 0 is itself a legal code ("NormalClose"), so it cannot
	// double as "not closed".
	closeReason    atomic.Uint32
	closeReasonSet atomic.Bool
	closeMutex     sync.Mutex

	// forceDestroy is closed by listener.Close() during parallel teardown to
	// cancel the DestroyTimeout wait in CloseWithReason, preventing serial
	// blocking when the listener shuts down multiple sessions.
	forceDestroy chan struct{}
	// forceDestroyOnce guards the close(forceDestroy) call so that concurrent
	// calls to TriggerForceDestroy() cannot both observe the channel as
	// not-yet-closed and both call close(), which would panic.
	forceDestroyOnce sync.Once

	// Cipher states for transport phase (after handshake)
	sendCipher  *noise.CipherState
	recvCipher  *noise.CipherState
	cipherMutex sync.RWMutex

	// Packet management
	sendQueue chan *SSU2Packet
	recvQueue chan *SSU2Packet
	// sendSequence is the next outbound data-phase packet number. For a
	// responder it starts at 0; for an initiator it starts at 1 because
	// Session Confirmed already consumed number 0. See
	// [SSU2Conn.reserveInitiatorDataSequence] and ssu2.md §"Packet Numbering".
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
	// compatibility.
	pendingMessage []byte

	// readDeliveryMode tracks which delivery path has been used for reading messages.
	// Uses atomic CAS to atomically check and set the mode, preventing TOCTOU races
	// where both Read() and MessageChan() could both observe the mode as unset.
	// One of {ReadDeliveryModeUnset, ReadDeliveryModeRead, ReadDeliveryModeChan}.
	readDeliveryMode atomic.Int32

	// closedMessageChan is a closed channel returned as a sentinel by MessageChan()
	// when Read() has already been called, enforcing mutual exclusivity.
	closedMessageChan chan []byte

	// Keepalive
	lastActivity     time.Time
	lastActivityLock sync.RWMutex
	keepaliveTimer   *time.Timer

	// remoteConnectionID is the peer's connection ID, learned during
	// the handshake. Outbound data-phase packets must use this value
	// as the Destination Connection ID per SSU2 spec.
	// Use atomic.Uint64 for thread-safe access without explicit locks,
	// consistent with other protocol fields. Written once during handshake,
	// then read from all send paths.
	remoteConnectionID atomic.Uint64

	// initiatorDestConnID is the Destination Connection ID this initiator
	// generated for its Session Request ("Randomly generated by Alice",
	// ssu2.md §"Session Request"). It is retained so the post-Retry Session
	// Request retransmits the identical destination ID (connection IDs "remain
	// constant from the first message ... even after a Retry message",
	// §"Connection ID Numbering"). Only meaningful on the initiator.
	initiatorDestConnID uint64

	// responderSourceConnID is the Destination Connection ID Alice put in the
	// Session Request we are answering (header bytes 0-7), learned in
	// receiveSessionRequest. ssu2.md §"Session Created" requires "Source
	// Connection ID :: The Destination Connection ID received from Alice in
	// Session Request", so SessionCreated bytes 16-23 MUST carry this value --
	// not our own locally chosen connection ID. It is also the ID Alice routes
	// her Session Confirmed and data-phase packets to, so it is adopted as this
	// connection's inbound routing key.
	//
	// A multiplexing listener may pin a different value via
	// SetResponderRoutingConnID when Alice's destination ID is already claimed
	// by another session (ssu2.md §"Connection ID Numbering" forbids two
	// sessions sharing an ID); the pinned value then wins, and the wire echo
	// matches the demux key. Only meaningful on the responder.
	//
	// Stored atomically: it is written during the handshake goroutine and read
	// from LocalAddr()/send paths on other goroutines.
	responderSourceConnID atomic.Uint64

	// responderConnIDPinned records that a listener chose this session's
	// inbound routing/echo connection ID explicitly, so the value learned from
	// the Session Request header must not override it.
	responderConnIDPinned atomic.Bool

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
	// Gate recvLoop startup on this flag to prevent listener and
	// responder from both reading the same shared socket.
	readsOwnSocket bool

	// sessCreateKeyNotifyCh, when non-nil, receives the SessionCreated
	// HeaderProtector once SessCreateHeaderKey has been derived during
	// sendSessionRequest.  DialSSU2ViaListener sets this before calling
	// Handshake so it can install the real protector into the pending
	// outbound registry before the responder's SessionCreated reply arrives.
	// The channel has capacity 1; the send is non-blocking (best-effort).
	sessCreateKeyNotifyCh chan *wire.HeaderProtector

	// sessConfirmedKeyNotifyCh, when non-nil, receives the inbound
	// SessionConfirmed HeaderProtector (k_header_1 = our intro key,
	// k_header_2 = KDF-derived sessionConfirmedHeader2) once the responder
	// derives it in createAndSendSessionCreated. The listener's
	// AcceptedSessionRegistry uses this to deobfuscate inbound
	// SessionConfirmed packets.  Capacity 1; send is non-blocking.
	sessConfirmedKeyNotifyCh chan *wire.HeaderProtector

	// recvDataKeyNotifyCh, when non-nil, receives the inbound Data-phase
	// HeaderProtector (k_header_1 = our intro key, k_header_2 = recvDataHeader2)
	// once finalizeHandshake derives data-phase keys. The listener's
	// AcceptedSessionRegistry uses this to deobfuscate inbound Data packets
	// for all sessions (initiator and responder) sharing the listener socket.
	// Capacity 1; send is non-blocking.
	recvDataKeyNotifyCh chan *wire.HeaderProtector

	// migration records the outbound I2NP packets this session has not had
	// acknowledged, so a replacement session can take them over when ssu2.md
	// §"Multiple Sessions" retires this one. Guarded by migrationMutex because
	// the write path records while the listener drains it from another goroutine.
	migration      *migrationTracker
	migrationMutex sync.Mutex

	// establishedHook, if set, runs once when this responder's handshake
	// completes — the moment §"Multiple Sessions" names for superseding an older
	// session with the same peer. The listener wires it to its own replacement
	// logic; it must not block for long, since it runs inline with finalization.
	establishedHook   func(*SSU2Conn)
	establishedHookMu sync.Mutex

	// closeHook, if set, is invoked once during CloseWithReason after the
	// connection's goroutines have been torn down. The listener wires this
	// to deregister the session from its routing maps so that closed
	// sessions do not accumulate forever. It must not call back
	// into CloseWithReason (which would deadlock on closeOnce).
	closeHook   func()
	closeHookMu sync.Mutex

	// destroySkip, when set, causes CloseWithReason to skip the
	// DestroyTimeout Termination-wait. Used by CloseImmediate for sessions
	// that are being abandoned before they were ever established, so a
	// cleanup close cannot block a packet worker for up to DestroyTimeout.
	destroySkip atomic.Bool

	// Background goroutines coordination
	wg sync.WaitGroup

	// Error counters for observability (recvLoop)
	readErrors    atomic.Uint64
	parseErrors   atomic.Uint64
	decryptErrors atomic.Uint64

	// writeErrors counts UDP write failures in sendLoop.
	writeErrors atomic.Uint64

	// validDataPacketsReceived counts successfully received data-phase packets.
	// Included in the Termination block per spec §Termination.
	validDataPacketsReceived atomic.Uint64

	// validDataPacketsSent counts successfully sent data-phase packets.
	// Compared against the peer's reported count in Termination blocks
	// to detect packet loss during close.
	validDataPacketsSent atomic.Uint64

	// handshakeMaterialMutex protects access to inbound handshake replay material.
	handshakeMaterialMutex sync.RWMutex

	// peerEphemeralKey is the initiator ephemeral key from the validated inbound
	// SessionRequest (responder side only).
	peerEphemeralKey []byte

	// replayToken is the deterministic token derived from the validated inbound
	// SessionRequest and suitable for replay cache checks.
	replayToken []byte

	// confirmedDatagrams are the exact wire bytes of the Session Confirmed
	// fragment(s) this initiator sent, retained for retransmission.
	//
	// ssu2.md §"Handshake Retransmission" -> §"Session Confirmed" recommends
	// option 2: "send data messages immediately, but also retransmit Session
	// Confirmed until a data message is received", and adds "Alice must retain
	// the information required to retransmit the Session Confirmed message."
	// The bytes — not a re-sealed packet — are what must be retained: the same
	// section requires "same source and connection IDs, ephemeral key, and
	// packet number", because "Packet number must not be incremented, because
	// that would change the chained hash value which is an input for the
	// split() function."
	//
	// Guarded by confirmedMutex.
	confirmedDatagrams [][]byte

	// confirmedMutex guards confirmedDatagrams.
	confirmedMutex sync.Mutex

	// confirmedAcked is closed once a data message has arrived, which is the
	// spec's condition for stopping the Session Confirmed retransmissions.
	// Created with the retention so an early arrival is not missed.
	confirmedAcked chan struct{}

	// confirmedAckedOnce guards the close of confirmedAcked.
	confirmedAckedOnce sync.Once

	// closingDatagram is the exact wire bytes of the Termination packet this
	// session sent when it entered the closing phase, retained so the closing
	// state can answer further inbound packets with "the exact same packet with
	// the same packet number as-is" (ssu2.md §"Session Termination" -> §"Data
	// phase").
	//
	// closingResponses counts how many of those answers have been emitted, and
	// closingSeen counts received packets since the last one, which is how the
	// spec's "limit the rate at which it generates packets in the closing state"
	// is satisfied. All three are guarded by closingMutex.
	closingDatagram  []byte
	closingResponses int
	closingSeen      uint32
	closingMutex     sync.Mutex

	// closingPeerAcked is set when the peer answers our Termination with reason
	// "Termination Received", which §"Session Termination" says lets the session
	// "exit the closing phase" — after that, no further retransmissions.
	closingPeerAcked atomic.Bool

	// windowSignal wakes a sender parked in waitForWindow when the congestion
	// window gains room. Guarded by windowMutex.
	windowSignal chan struct{}
	windowMutex  sync.Mutex
}

// PendingPacket tracks an outbound packet awaiting acknowledgment.
type PendingPacket struct {
	Packet           *SSU2Packet
	PlaintextPayload []byte // pre-encryption payload for retransmit
	SentTime         time.Time
	Retries          int
	NextRetry        time.Time

	// WireSize is the datagram length that went on the wire, in bytes.
	//
	// ssu2.md §"Congestion Control": "It is recommended that the congestion
	// control be based on byte count, not packet count." Bytes in flight can
	// only be accounted if each outstanding packet carries its wire size.
	//
	// AckOnly marks a packet that carried nothing but non-data blocks (an ACK,
	// DateTime, Address or Padding packet). §"Congestion Control" requires
	// "ACK-only data packets should not count for bytes or packets in-flight and
	// are not congestion-controlled."
	WireSize int
	AckOnly  bool

	// LossReported marks that this packet has already been counted as lost, so
	// repeated NACKs and RTO expiries of the same packet do not each trigger a
	// fresh congestion event.
	LossReported bool
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
	flog("NewSSU2Conn", logger.Fields{"remote_addr": remoteAddr}).Debug("Creating new SSU2 connection")
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
	flog("validateConnInputs", logger.Fields{"remote_addr": remoteAddr}).Debug("Validating connection parameters")
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
	flog("resolveConnectionID", logger.Fields{"configured_id": config.ConnectionID}).Debug("Resolving connection ID")
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
	flog("buildHandshakeHandler", logger.Fields{"initiator": initiator, "has_remote_key": len(remoteStaticKey) > 0}).Debug("Creating handshake handler")
	prologue := []byte(nil) // SSU2 spec: null prologue (MixHash(h) with empty data)
	handler, err := NewHandshakeHandler(initiator, staticKey, remoteStaticKey, prologue)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake handler")
	}

	if config.ReplayCacheTTL > 0 && !initiator {
		handler.ReconfigureReplayCache(config.ReplayCacheTTL)
	}
	handler.SetMaxClockSkew(config.MaxClockSkew)
	handler.SetNetworkID(config.NetworkID)
	handler.SetLocalOptions(&OptionsParams{
		TMinRatio: 0,
		TMaxRatio: config.PaddingRatio,
		RMinRatio: 0,
		RMaxRatio: config.PaddingRatio,
	})
	return handler, nil
}

func newSSU2AddrForConn(remoteAddr *net.UDPAddr, routerHash data.Hash, connID uint64, initiator bool) (*SSU2Addr, error) {
	flog("newSSU2AddrForConn", logger.Fields{"remote_addr": remoteAddr, "conn_id": connID, "initiator": initiator}).Debug("Building SSU2 address")
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
	flog("assembleSSU2Conn", logger.Fields{"remote_addr": remoteAddr, "initiator": initiator, "mtu": config.MTU}).Debug("Assembling connection struct")
	rttEst := NewRTTEstimator()

	// Create a closed channel sentinel for MessageChan() to return when Read() has been called,
	// enforcing mutual exclusivity.
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
		readsOwnSocket:       true, // default for dial paths; responders set to false
	}

	conn.pathValidator = NewPathValidator(conn)
	conn.pathValidator.SetCongestionController(conn.congestionController)
	return conn
}

func (c *SSU2Conn) initHeaderProtection(config *SSU2Config, initiator bool) error {
	flog("initHeaderProtection", logger.Fields{"has_intro_key": len(config.IntroKey) == HeaderKeySize, "initiator": initiator}).Debug("Initializing header protection")
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
	flog("messageTypeToHeaderType", logger.Fields{"msg_type": msgType}).Debug("Mapping message type to header type")
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
// of the DestroyTimeout wait in CloseWithReason. It is used by listener.Close()
// during parallel teardown to avoid serial blocking.
// Safe to call multiple times (idempotent via sync.Once, not a TOCTOU-prone
// select/default check).
func (h *SSU2Conn) TriggerForceDestroy() {
	h.forceDestroyOnce.Do(func() {
		close(h.forceDestroy)
	})
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
