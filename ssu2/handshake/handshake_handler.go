package handshake

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/internal/cryptorand"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/go-noise/mod/replaycache"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// SSU2ProtocolName is the Noise protocol name for SSU2, as defined in the
// I2P SSU2 specification. It indicates the XK pattern with ChaCha20
// obfuscation and three modified handshake messages.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
const SSU2ProtocolName = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"

// HandshakeHandler manages SSU2 handshake message processing using the XK
// pattern. The XK pattern provides forward secrecy and responder
// authentication:
//
// Pre-message: ← s (responder's static key known to initiator)
//
// Initiator (Alice)          Responder (Bob)
// SessionRequest ─────────────────────────>
//
//	(→ e, es)
//	                 <───────────────────── SessionCreated
//	                           (← e, ee)
//
// SessionConfirmed ───────────────────────>
//
//	(→ s, se)
//	(transport phase begins)
//
// The handshake establishes a secure channel with:
//   - Forward secrecy via ephemeral keys
//   - Responder authentication via Bob's static key
//   - DPI resistance via header encryption
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for
// details on the XK pattern.
type HandshakeHandler struct {
	// initiator determines if we initiate (true) or respond (false)
	initiator bool

	// staticKey is our static X25519 private key (32 bytes)
	staticKey []byte

	// remoteStaticKey is the peer's static public key (32 bytes)
	// Required for initiator, learned during handshake for responder
	remoteStaticKey []byte

	// handshakeState manages the Noise protocol state machine
	handshakeState *noise.HandshakeState

	// cipherStates store the transport cipher states after handshake
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState

	// sessCreateHeaderKey is k_header_2 for SessionCreated, derived from
	// chainKey after message 1 (→ e, es) with info "SessCreateHeader".
	sessCreateHeaderKey []byte

	// sessionConfirmedHeaderKey is k_header_2 for SessionConfirmed, derived
	// from chainKey after message 2 (← e, ee) with info "SessionConfirmed".
	sessionConfirmedHeaderKey []byte

	// replayCache detects replayed handshake messages per SSU2 spec.
	// Only used by responders to protect ProcessSessionRequest.
	replayCache *replaycache.TTLCache

	// localOptions are this peer's padding parameters, sent in Options blocks.
	localOptions *OptionsParams

	// peerOptions are the remote peer's padding parameters, parsed from
	// received Options blocks during handshake.
	peerOptions *OptionsParams

	// peerRouterInfo stores the raw RouterInfo block received during
	// SessionConfirmed processing. Used for post-handshake validation
	// against the Noise-authenticated static key.
	peerRouterInfo []byte

	// maxClockSkew is the maximum allowed difference between local and
	// remote timestamps. validateHandshakeBlocks rejects DateTime blocks
	// whose timestamp differs from local time by more than this value.
	// Set from SSU2Config.MaxClockSkew; never zero, because ssu2.md
	// §"Replay Prevention" makes the check mandatory (see DefaultMaxClockSkew).
	maxClockSkew time.Duration

	// peerAddress is the observed source IP of the peer, reported back to it in
	// the Address block of an outbound SessionCreated / Retry.
	// Zero when unknown; ssu2.md §"Session Created" -> §"Payload" makes the
	// Address block mandatory in message 2.
	peerAddress net.IP
	// peerPort is the observed UDP source port of the peer (see peerAddress).
	peerPort uint16

	// peerSessionRequestEphemeral is the inbound initiator ephemeral key from
	// the most recently validated SessionRequest (responder side only).
	peerSessionRequestEphemeral []byte

	// peerSessionRequestReplayToken is the deterministic replay token derived
	// from the most recently validated SessionRequest.
	peerSessionRequestReplayToken []byte

	// sentSourceConnID / sentDestConnID record the connection IDs the initiator
	// placed in its outbound SessionRequest, so ProcessSessionCreated can verify
	// that the responder echoed them back swapped.
	//
	// Spec ref: ssu2.md §"Session Created" -> §"Notes": "Alice must drop the message
	// if the Destination and Source Connection IDs do not match the Source and
	// Destination Connection IDs of the Session Request." The header table defines
	// Destination Connection ID as "The Source Connection ID received from Alice in
	// Session Request" and Source Connection ID as "The Destination Connection ID
	// received from Alice in Session Request".
	sentSourceConnID uint64
	sentDestConnID   uint64
	// sessionRequestSent marks that the IDs above were recorded, so the check is
	// not applied to a SessionCreated that was preceded by no SessionRequest.
	sessionRequestSent bool

	// expectedPeerAddr is the UDP source address the SessionRequest was received
	// from / the SessionCreated is expected to arrive from, on the responder side
	// it is the peer's observed endpoint.
	//
	// Spec ref: ssu2.md §"Session Created" -> §"Notes": "Alice must drop the message
	// if the source IP and port do not match the destination IP and port of the
	// Session Request."
	expectedPeerAddr *net.UDPAddr

	// networkID is header byte 14 for outbound long-header messages, and the
	// value required of inbound ones. Zero means MainNetworkID (2). See
	// SetNetworkID.
	networkID uint8
}

// buildSSU2Prologue returns the Noise prologue for SSU2 handshakes.
// Per the SSU2 specification, the prologue is null (empty):
//
//	// MixHash(null prologue)
//	h = SHA256(h);
//
// The connection ID is NOT part of the prologue; it is bound to the
// handshake via header MixHash operations for each message.
//
// For Retry sessions, the retry token is placed in the Session Request
// header (bytes 24-31) and bound via MixHash(header), not via the
// prologue. The spec confirms: "mixHash() the header (except for Retry)"
// — meaning the Retry message itself skips MixHash, but the subsequent
// Session Request (with token) does MixHash its header, binding the token.
func buildSSU2Prologue() []byte {
	flog("buildSSU2Prologue").Debug("returning null prologue per SSU2 spec")
	return nil
}

// NewHandshakeHandler creates a new SSU2 handshake handler.
//
//   - For initiators, remoteStaticKey must be provided (the responder's
//     public key).
//   - For responders, remoteStaticKey is nil and will be learned during
//     the handshake.
//   - The prologue binds the Noise handshake to SSU2 session context;
//     pass nil to omit.
func NewHandshakeHandler(initiator bool, staticKey, remoteStaticKey, prologue []byte) (*HandshakeHandler, error) {
	flog("NewHandshakeHandler", logger.Fields{"initiator": initiator}).Debug("Creating new HandshakeHandler")
	if len(staticKey) != 32 {
		return nil, oops.Errorf("static key must be 32 bytes, got %d", len(staticKey))
	}

	if initiator && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("initiator requires remote static key (32 bytes), got %d", len(remoteStaticKey))
	}

	if !initiator && remoteStaticKey != nil && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("remote static key must be 32 bytes if provided, got %d", len(remoteStaticKey))
	}

	// Create Noise handshake state for XK pattern
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	pub, err := derivePublicKey(staticKey)
	if err != nil {
		return nil, oops.Wrapf(err, "derive local static public key")
	}

	config := noise.Config{
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    initiator,
		Prologue:     prologue,
		ProtocolName: []byte(SSU2ProtocolName),
		StaticKeypair: noise.DHKey{
			Private: copyBytes(staticKey),
			Public:  pub,
		},
	}

	// For initiator, set the responder's static public key
	if initiator && remoteStaticKey != nil {
		config.PeerStatic = copyBytes(remoteStaticKey)
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake state")
	}

	handler := &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKey),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}

	// Responders need a replay cache to protect against replayed SessionRequests
	if !initiator {
		handler.replayCache = replaycache.New(replaycache.Config{
			TTL:             4 * time.Minute,
			MaxSize:         1024,
			CleanupInterval: 30 * time.Second,
		})
	}

	return handler, nil
}

// NewHandshakeHandlerWithKeys creates a new SSU2 handshake handler with a
// full DHKey. This is useful when you already have a generated keypair
// from noise.DH25519.GenerateKeypair().
//
//   - For initiators, remoteStaticKey must be provided (the responder's
//     public key).
//   - For responders, remoteStaticKey is nil and will be learned during
//     the handshake.
//   - The prologue binds the Noise handshake to SSU2 session context;
//     pass nil to omit.
func NewHandshakeHandlerWithKeys(initiator bool, staticKeypair noise.DHKey, remoteStaticKey, prologue []byte) (*HandshakeHandler, error) {
	flog("NewHandshakeHandlerWithKeys", logger.Fields{"initiator": initiator}).Debug("Creating new HandshakeHandler with keys")
	if len(staticKeypair.Private) != 32 {
		return nil, oops.Errorf("static private key must be 32 bytes, got %d", len(staticKeypair.Private))
	}

	if len(staticKeypair.Public) != 32 {
		return nil, oops.Errorf("static public key must be 32 bytes, got %d", len(staticKeypair.Public))
	}

	if initiator && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("initiator requires remote static key (32 bytes), got %d", len(remoteStaticKey))
	}

	if !initiator && remoteStaticKey != nil && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("remote static key must be 32 bytes if provided, got %d", len(remoteStaticKey))
	}

	// Create Noise handshake state for XK pattern
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	config := noise.Config{
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    initiator,
		Prologue:     prologue,
		ProtocolName: []byte(SSU2ProtocolName),
		StaticKeypair: noise.DHKey{
			Private: copyBytes(staticKeypair.Private),
			Public:  copyBytes(staticKeypair.Public),
		},
	}

	// For initiator, set the responder's static public key
	if initiator && remoteStaticKey != nil {
		config.PeerStatic = copyBytes(remoteStaticKey)
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake state")
	}

	handler := &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKeypair.Private),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}

	// Responders need a replay cache to protect against replayed SessionRequests
	if !initiator {
		handler.replayCache = replaycache.New(replaycache.Config{
			TTL:             4 * time.Minute,
			MaxSize:         1024,
			CleanupInterval: 30 * time.Second,
		})
	}

	return handler, nil
}

// IsHandshakeComplete returns true if the handshake has finished and
// transport cipher states are available. For the XK pattern this requires
// all three messages (SessionRequest, SessionCreated, SessionConfirmed).
func (h *HandshakeHandler) IsHandshakeComplete() bool {
	flog("IsHandshakeComplete").Debug("checking cipher state availability")
	return h.sendCipher != nil && h.recvCipher != nil
}

// GetCipherStates returns the transport cipher states after successful handshake.
// Returns error if handshake is not complete.
func (h *HandshakeHandler) GetCipherStates() (*noise.CipherState, *noise.CipherState, error) {
	flog("GetCipherStates").Debug("retrieving transport cipher states")
	if !h.IsHandshakeComplete() {
		return nil, nil, oops.Errorf("handshake not complete")
	}
	return h.sendCipher, h.recvCipher, nil
}

// GetRemoteStaticKey returns the peer's static public key.
// For initiators, this is known before handshake.
// For responders, this is learned during SessionRequest processing.
func (h *HandshakeHandler) GetRemoteStaticKey() []byte {
	flog("GetRemoteStaticKey").Debug("returning remote static public key")
	return copyBytes(h.remoteStaticKey)
}

// SetLocalOptions sets the local padding parameters that will be advertised
// in outbound Options blocks during handshake.
func (h *HandshakeHandler) SetLocalOptions(opts *OptionsParams) {
	flog("SetLocalOptions").Debug("updating local padding options")
	h.localOptions = opts
}

// DefaultMaxClockSkew is the skew window applied when a handler is created
// without an explicit configuration.
//
// ssu2.md §"Replay Prevention": "Both Alice and Bob validate that the time for
// these messages is within a valid skew (recommended +/- 2 minutes)."
// ssu2.md §"Session Request" -> §"Notes" names the window "D" and requires both
// the timestamp rejection and the 2*D replay cache derived from it, so the
// validation is mandatory and only its width is configurable.
//
// Reference: i2pd computes the same window from its config default of 120 s
// (libi2pd/SSU2Session.cpp ProcessSessionRequest ->
// `if (i2p::context.GetClockSkew () ...)` / SSU2_MAX_SKEW usage), and Java I2P
// enforces ±2 minutes in net.i2p.crypto.handshake.HandshakeState /
// SSU2Payload.DateTimeBlock consumers (see EstablishmentManager's
// `MAX_SKEW = 2 * 60 * 1000`).
const DefaultMaxClockSkew = 2 * time.Minute

// SetMaxClockSkew configures the maximum allowed clock skew for DateTime validation.
// A zero or negative value restores the spec default of DefaultMaxClockSkew
// (±2 minutes, ssu2.md §"Replay Prevention"); it does not disable validation,
// because the spec makes the DateTime check mandatory. Use a deliberately huge
// duration if a deployment truly needs to accept arbitrary timestamps.
func (h *HandshakeHandler) SetMaxClockSkew(d time.Duration) {
	if d <= 0 {
		d = DefaultMaxClockSkew
	}
	h.maxClockSkew = d
}

// SetNetworkID configures the I2P network ID written into header byte 14 of
// outbound long-header messages and required of inbound ones. A zero value
// selects the main-network ID (2), so an unset config stays compliant.
//
// ssu2.md §"Header" fixes 2 for the main network; proposal 147 assigns other
// values to test networks precisely so that "cross-network connections … fail
// the test" instead of mixing traffic.
func (h *HandshakeHandler) SetNetworkID(id uint8) {
	if id == 0 {
		id = MainNetworkID
	}
	h.networkID = id
}

// NetworkID returns the configured network ID, defaulting to the main network.
func (h *HandshakeHandler) NetworkID() uint8 {
	if h.networkID == 0 {
		return MainNetworkID
	}
	return h.networkID
}

// validateNetworkID rejects a long-header message whose recorded network ID
// differs from ours. Short-header messages carry no network ID field, so the
// wire layer leaves NetworkID zero; those are checked by the session's AEAD and
// header-protection keys instead.
func (h *HandshakeHandler) validateNetworkID(packet *SSU2Packet) error {
	if packet.NetworkID == 0 || packet.NetworkID == h.NetworkID() {
		return nil
	}
	return oops.
		Code("WRONG_NETWORK_ID").
		In("ssu2").
		With("got", packet.NetworkID).
		With("expected", h.NetworkID()).
		Errorf("packet network ID %d does not match ours %d; peer is on a different I2P network (proposal 147)",
			packet.NetworkID, h.NetworkID())
}

// PeerOptions returns the remote peer's Options parameters parsed during
// the handshake, or nil if no Options block was received.
func (h *HandshakeHandler) PeerOptions() *OptionsParams {
	return h.peerOptions
}

// LocalOptions returns the locally configured Options parameters, or nil
// if none were set via SetLocalOptions.
func (h *HandshakeHandler) LocalOptions() *OptionsParams {
	return h.localOptions
}

// NegotiatedPadding returns the padding parameters that both peers agree on.
// Per SSU2 spec, the initiator's transmit ratios are the responder's receive
// constraints and vice versa. The negotiated range is the intersection of
// both peers' preferences: max of minimums, min of maximums.
// Returns nil if either side has not provided options.
func (h *HandshakeHandler) NegotiatedPadding() *OptionsParams {
	return NegotiatedPadding(h.localOptions, h.peerOptions)
}

// extractPeerOptions scans deserialized handshake blocks for an Options block
// and stores the parsed result in h.peerOptions.
func (h *HandshakeHandler) extractPeerOptions(blocks []*SSU2Block) {
	for _, block := range blocks {
		if block.Type == BlockTypeOptions && len(block.Data) >= 12 {
			opts, err := ParseOptionsBlock(block.Data)
			if err == nil {
				h.peerOptions = opts
			}
			return
		}
	}
}

// extractPeerRouterInfo parses the decrypted SessionConfirmed payload and
// stores the RouterInfo block data for later validation.
// Returns an error if the payload is non-empty but cannot be deserialized.
func (h *HandshakeHandler) extractPeerRouterInfo(payload []byte) error {
	routerInfo, err := extractPeerRouterInfo(payload)
	if err != nil {
		return err
	}
	h.peerRouterInfo = routerInfo
	return nil
}

// verifyPeerRouterInfoStaticKey checks that the RouterInfo received in
// SessionConfirmed advertises the same Curve25519 static key that the Noise
// XK handshake authenticated. This binds the claimed I2P identity to the
// Noise transcript, preventing peer impersonation.
//
// The check uses an I2P-base64 substring scan consistent with the NTCP2
// implementation. It is skipped when either peerRouterInfo or remoteStaticKey
// is absent (e.g. tests that omit RouterInfo).
//
// Returns an error tagged TerminationSParamMissing on mismatch.
func (h *HandshakeHandler) verifyPeerRouterInfoStaticKey() error {
	return verifyPeerRouterInfoStaticKey(h.peerRouterInfo, h.remoteStaticKey)
}

// GetPeerRouterInfo returns the raw RouterInfo block received during
// the SessionConfirmed handshake message. Returns nil if no RouterInfo
// was received (e.g. initiator side, or tests without RouterInfo).
func (h *HandshakeHandler) GetPeerRouterInfo() []byte {
	if h.peerRouterInfo == nil {
		return nil
	}
	copied := make([]byte, len(h.peerRouterInfo))
	copy(copied, h.peerRouterInfo)
	return copied
}

// GetPeerEphemeralKey returns the initiator ephemeral key from the most
// recently validated inbound SessionRequest. For initiators, this is always nil.
func (h *HandshakeHandler) GetPeerEphemeralKey() []byte {
	return copyBytes(h.peerSessionRequestEphemeral)
}

// GetReplayToken returns the deterministic replay token from the most recently
// validated inbound SessionRequest. For initiators, this is always nil.
func (h *HandshakeHandler) GetReplayToken() []byte {
	return copyBytes(h.peerSessionRequestReplayToken)
}

// SetPeerAddress records the peer's observed source IP and UDP port so that an
// outbound SessionCreated can report it back in the mandatory Address block.
//
// ssu2.md §"Session Created" -> §"Payload": "DateTime block / Address block /
// Relay Tag block (optional) / ...". §"Address": "Alice's address, sent to Alice
// by Bob". Reference: Java PacketBuilder2.encryptSessionCreated() always adds
// `new SSU2Payload.AddressBlock(ip, port)` to the message-2 block list
// (router/java/src/net/i2p/router/transport/udp/PacketBuilder2.java,
// buildSessionCreatedPacket passing state.getSentIP()/getSentPort()).
func (h *HandshakeHandler) SetPeerAddress(ip net.IP, port uint16) {
	if len(ip) == 0 {
		return
	}
	h.peerAddress = append(net.IP(nil), ip...)
	h.peerPort = port
}

// SetExpectedPeerAddr records the destination IP and UDP port the Session
// Request was sent to. A Session Created must arrive from exactly that
// endpoint.
//
// Spec ref: ssu2.md §"Session Created" -> §"Notes": "Alice must drop the
// message if the source IP and port do not match the destination IP and port of
// the Session Request." §"Header Encryption Keys" relies on the same property
// ("This design relies on endpoints retaining a stable address for the duration
// of the handshake"), and §"Connection Migration" states migration "is defined
// only for the data phase", so no address change is legitimate mid-handshake.
//
// A nil address disables the check, which is correct for a session that has not
// sent a Session Request yet.
func (h *HandshakeHandler) SetExpectedPeerAddr(addr *net.UDPAddr) {
	if addr == nil {
		h.expectedPeerAddr = nil
		return
	}
	h.expectedPeerAddr = &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port}
}

// validatePeerAddress enforces the Session Created source-address rule for an
// initiator. It is a no-op when no Session Request address was recorded.
//
// Checked before MixHash(header), per ssu2.md §"Duplicates and Error Handling":
// a message that must be rejected has to be discarded before it is folded into
// the transcript, otherwise the handshake hash is unrecoverably corrupted.
func (h *HandshakeHandler) validatePeerAddress(packet *SSU2Packet) error {
	if !h.initiator || h.expectedPeerAddr == nil {
		return nil
	}
	src, ok := packet.Source.(*net.UDPAddr)
	if !ok || src == nil {
		// No source recorded (e.g. a caller feeding packets directly). The
		// spec rule is about the observed UDP source; without one there is
		// nothing to compare, and inventing a failure would break in-process
		// tests that drive the handler without a socket.
		return nil
	}
	if !h.expectedPeerAddr.IP.Equal(src.IP) || h.expectedPeerAddr.Port != src.Port {
		return oops.
			Code("SESSION_CREATED_WRONG_SOURCE").
			In("ssu2").
			With("source", src.String()).
			With("expected", h.expectedPeerAddr.String()).
			Errorf("Session Created arrived from %s but the Session Request was sent to %s; dropping per ssu2.md §\"Session Created\" Notes",
				src.String(), h.expectedPeerAddr.String())
	}

	return nil
}

// createHandshakeBlocks creates the standard blocks for handshake messages.
// Currently creates DateTime block with current timestamp.
func (h *HandshakeHandler) createHandshakeBlocks(messageType uint8) []*SSU2Block {
	flog("createHandshakeBlocks", logger.Fields{"messageType": messageType}).Debug("building standard handshake blocks")
	blocks := make([]*SSU2Block, 0, 3)

	// DateTime block (Type 0) - required in SessionRequest and SessionCreated
	// Format: 4 bytes - seconds since epoch (big-endian uint32)
	dateTimeData := make([]byte, 4)
	binary.BigEndian.PutUint32(dateTimeData, uint32(time.Now().Unix()))

	blocks = append(blocks, NewSSU2Block(BlockTypeDateTime, dateTimeData))

	// Address block (Type 13) - required in SessionCreated and Retry, optional
	// elsewhere. ssu2.md §"Session Created" -> §"Payload" lists "DateTime block /
	// Address block / ..." with no "(optional)" marker on Address, and §"Retry"
	// -> §"Payload" does the same; §"Session Request" -> §"Payload" does NOT list
	// an Address block, so message 1 must not carry one.
	//
	// Reference: Java PacketBuilder2.encryptSessionCreated() and encryptRetry()
	// both append an AddressBlock built from the peer's observed IP/port.
	if messageType == MessageTypeSessionCreated && h.peerAddress != nil {
		blocks = append(blocks, EncodeAddressBlock(h.peerAddress, h.peerPort))
	}

	// Options block (Type 1) - SHOULD be included per SSU2 spec
	// Communicates version and padding negotiation parameters.
	// If localOptions has been set, encode those values; otherwise send zeroes.
	if h.localOptions != nil {
		blocks = append(blocks, NewSSU2Block(BlockTypeOptions, h.localOptions.Serialize()))
	} else {
		// Default 12-byte Options block per ssu2.rst "Options" (Block Specifications).
		optData := make([]byte, 12)
		blocks = append(blocks, NewSSU2Block(BlockTypeOptions, optData))
	}

	return blocks
}

// validateHandshakeBlocks validates that required blocks are present.
func (h *HandshakeHandler) validateHandshakeBlocks(blocks []*SSU2Block, messageType uint8) error {
	flog("validateHandshakeBlocks", logger.Fields{"messageType": messageType, "blockCount": len(blocks)}).Debug("validating required blocks")
	hasDateTime := false
	hasAddress := false

	for _, block := range blocks {
		if block.Type == BlockTypeDateTime {
			hasDateTime = true
			if len(block.Data) < 4 {
				return oops.Errorf("DateTime block too short: %d bytes", len(block.Data))
			}
			if err := h.validateTimestampSkew(block.Data); err != nil {
				return err
			}
		}
		if block.Type == BlockTypeAddress {
			hasAddress = true
		}
	}

	// Per spec §Session Request/Created, DateTime is required.
	if !hasDateTime {
		return oops.Errorf("DateTime block required in message type %d per SSU2 spec", messageType)
	}

	// ssu2.md §"Session Created" -> §"Payload" lists "DateTime block / Address
	// block / Relay Tag block (optional) / ..." — Address carries no
	// "(optional)" marker, and the section's own note ("Since the DateTime and
	// Address blocks total more than that, the requirement is met with only
	// those two blocks") treats both as present. §"Session Created" opening line
	// likewise says "Noise payload: DateTime, Address, and other blocks".
	// Reference: Java PacketBuilder2.encryptSessionCreated() unconditionally adds
	// new SSU2Payload.AddressBlock(ip, port).
	//
	// The same requirement does not apply to SessionRequest: §"Session Request"
	// -> §"Payload" lists only DateTime / Options (optional) / Relay Tag Request
	// (optional) / Padding (optional).
	if messageType == MessageTypeSessionCreated && !hasAddress {
		return oops.Errorf("Address block required in SessionCreated per SSU2 spec §\"Session Created\" -> §\"Payload\"")
	}

	return nil
}

// validateTimestampSkew checks that the remote timestamp is within maxClockSkew
// of local time.
//
// ssu2.md §"Replay Prevention": "Both Alice and Bob validate that the time for
// these messages is within a valid skew (recommended +/- 2 minutes)." The check
// is mandatory, so an unset window falls back to DefaultMaxClockSkew rather than
// disabling validation (audit finding F-07: previously `maxClockSkew <= 0`
// silently skipped the check, so inbound handshake messages were accepted with
// arbitrary DateTime values).
func (h *HandshakeHandler) validateTimestampSkew(dateTimeData []byte) error {
	window := h.maxClockSkew
	if window <= 0 {
		window = DefaultMaxClockSkew
	}
	remoteTime := time.Unix(int64(binary.BigEndian.Uint32(dateTimeData[:4])), 0)
	skew := time.Since(remoteTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return oops.Errorf("clock skew %s exceeds maximum %s", skew, window)
	}
	return nil
}

// buildHandshakePacket serializes blocks, builds the long header, calls
// MixHash(header) per the SSU2 specification, runs the Noise WriteMessage,
// extracts the ephemeral key, and assembles an SSU2Packet.
// token may be nil for initial requests, or an 8-byte slice for Retry sessions.
func (h *HandshakeHandler) buildHandshakePacket(blocks []*SSU2Block, msgType uint8, sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	// Per SSU2 spec §Session Request: destConnID=0 is only valid for
	// the initial SessionRequest. Reject zero for all other message types.
	if destConnID == 0 && msgType != MessageTypeSessionRequest {
		return nil, oops.Errorf("destConnID=0 is only allowed for SessionRequest (type %d), got type %d", MessageTypeSessionRequest, msgType)
	}

	// ssu2.rst §"Session Request" / §"Session Created": "Source Connection ID ::
	// Randomly generated ... must not be equal to Destination Connection ID".
	// A session whose source and destination IDs collide cannot be demultiplexed
	// by the peer's packet router, so reject it before it is put on the wire.
	if sourceConnID == destConnID {
		return nil, oops.
			With("connection_id", sourceConnID).
			With("message_type", msgType).
			Errorf("source and destination connection IDs must not be equal")
	}

	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize handshake blocks")
	}

	// ssu2.md §"SessionRequest (Type 0)" / §"SessionCreated (Type 1)" ->
	// §"Payload": "The minimum payload size is 8 bytes." The standard block sets
	// already clear the floor (DateTime + Options >= 22 bytes), so PadPayloadToMin
	// is a no-op for them; it only appends a Padding block if a caller supplies an
	// unusually small block list. The floor is a sender obligation: header
	// protection extracts its IV from the last 24 bytes of the packet, so a
	// sub-floor message would be undecryptable by a conformant receiver.
	payload, err = PadPayloadToMin(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to pad handshake payload to minimum size")
	}

	// Build the 32-byte long header per ssu2.rst "Packet Header":
	// dest_conn_id(0-7), pkt_num(8-11), type(12), ver(13), id(14),
	// flag(15), src_conn_id(16-23), token(24-31).
	//
	// ssu2.rst §"Packet Numbering" lists Session Request and Session Created
	// among the messages that "contain a random packet number that is ignored",
	// so this is fresh randomness rather than a data-phase counter. The header
	// is MixHash'd below, so the value is still bound into the transcript and
	// cannot be silently altered in flight.
	packetNumber, err := cryptorand.RandInRange(1, int64(MaxPacketNumber))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate handshake packet number")
	}

	header := make([]byte, 32)
	binary.BigEndian.PutUint64(header[0:8], destConnID)
	binary.BigEndian.PutUint32(header[8:12], uint32(packetNumber))
	header[12] = msgType
	header[13] = SSU2ProtocolVersion // ver=2
	header[14] = h.NetworkID()       // id: 2 on the main network, per proposal 147
	header[15] = 0                   // flag=0
	binary.BigEndian.PutUint64(header[16:24], sourceConnID)
	// bytes 24-31 = token (zero for initial SessionRequest, populated by retries)
	if len(token) == 8 {
		copy(header[24:32], token)
	}

	// MixHash(header) binds the encrypted header into the handshake hash
	// (h = SHA256(h || header)), preventing header substitution attacks.
	h.handshakeState.MixHash(header)

	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	if len(ciphertext) < 32 {
		return nil, oops.Errorf("invalid handshake message: too short (%d bytes)", len(ciphertext))
	}

	// Derive intermediate header keys from the chaining key at this point
	// in the handshake. These keys are used for header protection of the
	// NEXT message type in the handshake flow:
	// - After message 1 (SessionRequest, → e, es): derive "SessCreateHeader"
	// - After message 2 (SessionCreated, ← e, ee): derive "SessionConfirmed"
	switch msgType {
	case MessageTypeSessionRequest:
		h.sessCreateHeaderKey = deriveIntermediateHeaderKey(
			h.handshakeState.ChainingKey(), "SessCreateHeader",
		)
	case MessageTypeSessionCreated:
		h.sessionConfirmedHeaderKey = deriveIntermediateHeaderKey(
			h.handshakeState.ChainingKey(), "SessionConfirmed",
		)
	}

	// For SessionRequest (msg 1, → e, es) and SessionCreated (msg 2, ← e, ee),
	// the noise library's WriteMessage returns the complete Noise message:
	//   ciphertext = [ephemeral_key:32 || AEAD_ciphertext]
	// where AEAD_ciphertext = encrypted_data || Poly1305_MAC(16).
	//
	// We split it into the SSU2 wire format fields:
	//   EphemeralKey = ciphertext[:32]  (the ephemeral public key)
	//   Payload      = AEAD_ciphertext without the trailing MAC
	//   MAC          = last 16 bytes of AEAD_ciphertext (real Poly1305 tag)
	//
	// This matches the SSU2 wire format: Header || EphemeralKey || Payload || MAC
	// and ensures external implementations can verify the MAC correctly.
	aead := ciphertext[32:]
	var pktPayload, mac []byte
	if len(aead) >= 16 {
		pktPayload = aead[:len(aead)-16]
		mac = aead[len(aead)-16:]
	} else {
		pktPayload = aead
		mac = make([]byte, 16)
	}
	packet := &SSU2Packet{
		Header:       header,
		EphemeralKey: copyBytes(ciphertext[:32]),
		Payload:      pktPayload,
		MAC:          mac,
		MessageType:  msgType,
		PacketNumber: 0,
	}
	return packet, nil
}

// updateCipherStates updates the send/receive cipher states when available.
func (h *HandshakeHandler) updateCipherStates(cs1, cs2 *noise.CipherState) {
	if cs1 != nil && cs2 != nil {
		if h.initiator {
			h.sendCipher = cs1
			h.recvCipher = cs2
		} else {
			h.sendCipher = cs2
			h.recvCipher = cs1
		}
	}
}

// DeriveHeaderKeys derives data-phase keys from the completed handshake per
// the SSU2 specification:
//
//	keydata = HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
//	k_data       = keydata[0:32]
//	k_header_2   = keydata[32:64]
//
// where "key" is the split cipher key for each direction (k_ab or k_ba).
// This method installs k_data into each cipher state (replacing the raw
// split key) so that data-phase AEAD uses the spec-mandated derived key.
// Returns the send-direction k_header_2 and recv-direction k_header_2.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
func (h *HandshakeHandler) DeriveHeaderKeys() (sendKHeader2, recvKHeader2 []byte, err error) {
	return DeriveHeaderKeys(h.sendCipher, h.recvCipher)
}

// SessCreateHeaderKey returns the k_header_2 for SessionCreated, derived from
// the chaining key after handshake message 1 (→ e, es) using the info string
// "SessCreateHeader". Returns nil if the key has not yet been derived.
func (h *HandshakeHandler) SessCreateHeaderKey() []byte {
	if h.sessCreateHeaderKey == nil {
		return nil
	}
	copied := make([]byte, len(h.sessCreateHeaderKey))
	copy(copied, h.sessCreateHeaderKey)
	return copied
}

// SessionConfirmedHeaderKey returns the k_header_2 for SessionConfirmed,
// derived from the chaining key after handshake message 2 (← e, ee) using
// the info string "SessionConfirmed". Returns nil if not yet derived.
func (h *HandshakeHandler) SessionConfirmedHeaderKey() []byte {
	if h.sessionConfirmedHeaderKey == nil {
		return nil
	}
	copied := make([]byte, len(h.sessionConfirmedHeaderKey))
	copy(copied, h.sessionConfirmedHeaderKey)
	return copied
}

// Close releases resources held by the HandshakeHandler and zeroes its key
// material.
//
// ssu2.md §"Session Termination" -> §"Cleanup": "Upon any normal or abnormal
// termination, routers should zero-out any in-memory ephemeral data, including
// handshake ephemeral keys, symmetric crypto keys, and related information."
//
// The handler owns the Noise handshake state, the two transport cipher states,
// and the intermediate header-protection keys derived at each handshake step, so
// all of them are erased here rather than merely dropped for the garbage
// collector (Go zeroes neither, and the bytes stay reachable until the buffer is
// reused).
func (h *HandshakeHandler) Close() {
	flog("Close").Debug("Closing HandshakeHandler")
	if h.replayCache != nil {
		h.replayCache.Close()
	}

	// Transport cipher keys. ZeroKey also marks the state invalid, so a
	// post-close Encrypt/Decrypt fails loudly instead of using a zero key.
	if h.sendCipher != nil {
		h.sendCipher.ZeroKey()
	}
	if h.recvCipher != nil {
		h.recvCipher.ZeroKey()
	}

	// Local static private key and the intermediate header keys (SessCreateHeader
	// / SessionConfirmed), which are symmetric key material.
	securemem.SecureZero(h.staticKey)
	securemem.SecureZero(h.sessCreateHeaderKey)
	securemem.SecureZero(h.sessionConfirmedHeaderKey)
	h.staticKey = nil
	h.sessCreateHeaderKey = nil
	h.sessionConfirmedHeaderKey = nil

	// The handshake state itself holds the ephemeral key pair (e) and the
	// chaining key; drop the reference so it can be collected, and nil the
	// cipher states so any later use fails rather than reading zeroed keys.
	h.handshakeState = nil
	h.sendCipher = nil
	h.recvCipher = nil
}

// ReconfigureReplayCache replaces the replay cache with one using the
// given TTL. This allows callers to override the default 4-minute TTL
// from SSU2Config.
func (h *HandshakeHandler) ReconfigureReplayCache(ttl time.Duration) {
	if h.replayCache != nil {
		h.replayCache.Close()
	}
	h.replayCache = replaycache.New(replaycache.Config{
		TTL:             ttl,
		MaxSize:         1024,
		CleanupInterval: 30 * time.Second,
	})
}

// derivePublicKey computes the Curve25519 public key that corresponds to the
// given private key by performing a scalar multiplication with the base point.
// This is required when constructing a noise.DHKey for use in handshake states
// that need to send or hash the local static public key (e.g. XK message 3).
// Returns an error rather than panicking on invalid input, so that an internal
// programmer error cannot crash the host process.
func derivePublicKey(priv []byte) ([]byte, error) {
	privKey, err := curve25519.NewCurve25519PrivateKey(priv)
	if err != nil {
		return nil, oops.Wrapf(err, "create Curve25519 private key")
	}
	pubKey, err := privKey.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "derive public key from private scalar")
	}
	return pubKey.Bytes(), nil
}
