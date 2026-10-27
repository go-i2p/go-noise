package session

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
	i2phkdf "github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// startDataLoops starts background goroutines for data transport.
// It is called after the handshake completes, so resources are not wasted on
// failed connections. The fragment reaper is started here rather than in
// NewSSU2Conn to avoid leaking goroutines if the handshake is never completed
// or Close is never called.
func (h *SSU2Conn) startDataLoops() {
	flog("startDataLoops").Debug("Starting send, keepalive, retransmit, and reaper loops")
	h.dataHandler.StartReaper()
	h.wg.Add(3)
	go h.sendLoop()
	go h.keepaliveLoop()
	go h.retransmitLoop()
}

// installCipherStates transfers transport cipher states from the handshake handler.
func (h *SSU2Conn) installCipherStates() error {
	flog("installCipherStates").Debug("Transferring cipher states from handshake")
	send, recv, err := h.handshakeHandler.GetCipherStates()
	if err != nil {
		return err
	}
	h.cipherMutex.Lock()
	h.sendCipher = send
	h.recvCipher = recv
	h.cipherMutex.Unlock()

	h.wireDataCallbacks()

	if err := h.validatePeerRouterInfo(); err != nil {
		return err
	}

	if err := h.installPeerIntroKey(); err != nil {
		return err
	}

	return nil
}

// installPeerIntroKey extracts the peer's introduction key "i" from the
// RouterInfo received in Session Confirmed and installs it as the data-phase
// k_header_1 for outbound packets.
//
// ssu2.md §"KDF for data phase": "k_header_1 = Receiver's intro key (aik or
// bik)", and §"Session Confirmed" → §"Notes": "The introduction key "i" in the
// RI must be extracted and valid, to be used in the data phase." Bob learns
// Alice's aik only from her RouterInfo, so without this step a responder that
// was not pre-configured with RemoteIntroKey can receive but never send Data
// packets.
//
// §"Published Addresses" makes s, i and v mandatory, so a RouterInfo that
// parses but carries no usable SSU2 address is a validation failure: "On any
// error, including AEAD, RI, DH, timestamp, or key validation failure, Bob
// must halt further message processing and close the connection without
// responding."
func (h *SSU2Conn) installPeerIntroKey() error {
	if h.initiator || h.headerProtector == nil {
		return nil
	}

	peerRI := h.handshakeHandler.GetPeerRouterInfo()
	if len(peerRI) == 0 {
		// No RouterInfo was supplied (hidden / unpublished peer). The
		// responder cannot derive k_header_1 and therefore cannot send
		// data-phase packets on this session.
		return oops.
			Code("PEER_ROUTER_INFO_MISSING").
			In("ssu2").
			Errorf("Session Confirmed carried no RouterInfo; cannot extract the peer introduction key required for data-phase k_header_1")
	}

	ri, err := wire.ReadRouterInfo(peerRI)
	if err != nil {
		return oops.Wrapf(err, "failed to parse peer RouterInfo for introduction key extraction")
	}

	params, err := wire.ExtractSSU2AddressParams(ri)
	if err != nil {
		return oops.Wrapf(err, "peer RouterInfo has no usable SSU2 introduction key")
	}

	if err := h.headerProtector.SetRemoteIntroKey(params.IntroKey); err != nil {
		return oops.Wrapf(err, "failed to install peer introduction key")
	}

	if params.HasMTU {
		h.setPeerMTU(params.MTU)
	}

	return nil
}

// wireDataCallbacks wires internal handler callbacks for data-phase processing.
func (h *SSU2Conn) wireDataCallbacks() {
	flog("wireDataCallbacks", logger.Fields{"next_nonce_enabled": h.config.EnableNextNonce}).Debug("Wiring data-phase callbacks")
	cbs := h.dataHandler.getCallbacks()

	// Warn if signature verification callbacks are not configured.
	h.warnMissingSignatureVerifiers(&cbs)

	// Wire NextNonce callback only if enabled.
	if h.config.EnableNextNonce {
		cbs.OnNextNonce = h.handlePeerNextNonce
	}
	cbs.OnCongestion = h.handleCongestionBlock
	cbs.OnPathChallenge = h.handlePathChallengeData
	cbs.OnPathResponse = h.handlePathResponseData

	if cbs.OnAddress == nil {
		cbs.OnAddress = h.handleAddressBlock
	}

	h.wrapTerminationCallback(&cbs)
	h.wrapNewTokenCallback(&cbs)
	h.dataHandler.SetCallbacks(cbs)
}

// wrapNewTokenCallback stores a New Token block's token so a later Session
// Request to that peer can present it.
//
// ssu2.md §"Tokens": "A token sent in a New Token block in an established
// session may be used in a subsequent connection, and it expires at the time
// specified in that block." §"Session Request" then reads "Token :: 0 if not
// previously received from Bob" — a token that is received but never saved can
// never be used, which leaves every reconnection on the Token Request / Retry
// path.
//
// The block is 4 bytes of unsigned big-endian expiry followed by the 8-byte
// token (§"New Token"). §"Tokens" also says "Routers should assume that only the
// last token received is valid", which SessionTokenStore.Save implements by
// replacing the entry for the same destination.
//
// Any callback the caller already installed still runs.
func (h *SSU2Conn) wrapNewTokenCallback(cbs *DataHandlerCallbacks) {
	existing := cbs.OnNewToken
	cbs.OnNewToken = func(data []byte) {
		if h.config.SessionTokens != nil && len(data) >= 12 {
			expires := time.Unix(int64(binary.BigEndian.Uint32(data[0:4])), 0)
			token := data[4:12]
			h.remoteAddrLock.RLock()
			dest := h.remoteAddr
			h.remoteAddrLock.RUnlock()
			if err := h.config.SessionTokens.Save(h.localUDPAddr(), dest, token, expires); err != nil {
				flog("wrapNewTokenCallback", logger.Fields{"error": err.Error()}).
					Debug("received a New Token block we could not store")
			}
		}
		if existing != nil {
			existing(data)
		}
	}
}

// warnMissingSignatureVerifiers logs warnings for unset signature verifiers.
//
// Per ssu2.rst, PeerTest / RelayRequest / RelayResponse / RelayIntro
// signatures MUST be verified before the block is acted on. The handlers are
// therefore fail-closed: when a signature is present but no verifier callback
// is registered, the block is rejected (VERIFIER_MISSING) rather than
// processed. This warning is emitted early so an operator learns at session
// setup — not on the first inbound signed block — that those features cannot
// function until the router layer registers the verifiers.
func (h *SSU2Conn) warnMissingSignatureVerifiers(cbs *DataHandlerCallbacks) {
	if cbs.VerifyPeerTestSignature == nil {
		flog("warnMissingSignatureVerifiers").Warn("PeerTest signature verifier not configured; signature verification will be SKIPPED for peer test messages")
	}
	if cbs.VerifyRelayRequestSignature == nil {
		flog("warnMissingSignatureVerifiers").Warn("RelayRequest signature verifier not configured; signature verification will be SKIPPED for relay requests")
	}
	if cbs.VerifyRelayResponseSignature == nil {
		flog("warnMissingSignatureVerifiers").Warn("RelayResponse signature verifier not configured; signature verification will be SKIPPED for signed relay responses")
	}
	if cbs.VerifyRelayIntroSignature == nil {
		flog("warnMissingSignatureVerifiers").Warn("RelayIntro signature verifier not configured; signature verification will be SKIPPED for relay intros")
	}
	// Warn about missing application-level dispatch callbacks: these are the
	// handlers that actually implement NAT detection and relay coordination.
	// Without them the respective blocks are silently dropped after verification.
	if cbs.OnPeerTest == nil {
		flog("warnMissingSignatureVerifiers").Warn("OnPeerTest callback not configured; peer test blocks will be silently dropped (NAT detection will not function)")
	}
	if cbs.OnRelayRequest == nil {
		flog("warnMissingSignatureVerifiers").Warn("OnRelayRequest callback not configured; relay request blocks will be silently dropped (relay coordination will not function)")
	}
}

// wrapTerminationCallback wraps the Termination callback to send the mandatory
// "Termination Received" acknowledgement and log packet-loss diagnostics.
//
// ssu2.rst §"Session Termination" / Data phase: "When receiving a Termination
// block with any reason except \"Termination Received\", the peer responds with
// a data message containing a Termination block with the reason \"Termination
// Received\"." Without that reply the sender cannot distinguish a lost
// termination packet from an ignored one, and it keeps retransmitting.
//
// The reply is emitted BEFORE the application callback runs: the callback for a
// terminated session typically cancels and detaches the conn, after which the
// write would fail and the ack would never go out.
func (h *SSU2Conn) wrapTerminationCallback(cbs *DataHandlerCallbacks) {
	existingOnTermination := cbs.OnTermination
	cbs.OnTermination = func(peerReceived uint64, reason uint8, additionalData []byte) {
		sent := h.validDataPacketsSent.Load()
		if sent > 0 {
			lost := int64(sent) - int64(peerReceived)
			flog("wrapTerminationCallback", logger.Fields{"sent": sent, "peerReceived": peerReceived, "lost": lost, "reason": reason}).Info("Termination packet loss summary")
		}
		if TerminationReason(reason) != TerminationReceived {
			h.sendTerminationReceived()
		} else {
			// §"Session Termination": "After receiving a Termination block with
			// the reason \"Termination Received\", the session may exit the
			// closing phase." Record it so the closing state stops re-sending its
			// Termination packet in response to further inbound traffic.
			h.closingPeerAcked.Store(true)
		}
		if existingOnTermination != nil {
			existingOnTermination(peerReceived, reason, additionalData)
		}
	}
}

// sendTerminationReceived emits the §"Session Termination" acknowledgement: a
// Data message carrying a Termination block with reason 1 ("Termination
// Received") whose count field reports the valid data packets we received.
//
// Best-effort by design. The session is already being torn down, so a failure
// here (socket closed, peer unreachable) is logged and ignored rather than
// propagated -- the spec makes no attempt to retransmit this message, and the
// peer's own closing-state retransmits cover the loss.
func (h *SSU2Conn) sendTerminationReceived() {
	// §"Session Termination": the message is not ack-eliciting, and a session
	// already in the closing phase has acknowledged the termination by other
	// means; do not add a second one.
	h.stateMutex.Lock()
	state := h.state
	h.stateMutex.Unlock()
	if state != StateEstablished {
		return
	}

	termData := make([]byte, 9)
	binary.BigEndian.PutUint64(termData[0:8], h.validDataPacketsReceived.Load())
	termData[8] = byte(TerminationReceived)

	// §"Session Termination" -> §"Data phase": a data message carrying a
	// Termination block "should also include an ACK block". §"Block Ordering
	// Rules" requires Termination to be the last block except Padding, so the ACK
	// goes first.
	blocks := make([]*SSU2Block, 0, 2)
	if ackBlock, ackErr := h.ackHandler.GenerateACK(); ackErr == nil && ackBlock != nil {
		blocks = append(blocks, ackBlock)
	}
	blocks = append(blocks, &SSU2Block{Type: BlockTypeTermination, Data: termData})

	packet := h.newDataPacket()
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		flog("sendTerminationReceived", logger.Fields{"error": err.Error()}).Debug("could not serialize termination ack")
		return
	}
	packet.Payload = payload
	// sendPacketDirect already accounts the packet in validDataPacketsSent for
	// MessageTypeData, so no counter update is needed here.
	if err := h.sendPacketDirect(packet); err != nil {
		flog("sendTerminationReceived", logger.Fields{"error": err.Error()}).Debug("could not send termination ack")
	}
}

// validatePeerRouterInfo validates the peer's RouterInfo against the Noise-authenticated
// static key per ssu2.rst "Session Confirmed": "Bob must verify that Alice's
// static key received in the first frame matches the static key in the Router Info."
func (h *SSU2Conn) validatePeerRouterInfo() error {
	peerKey := h.handshakeHandler.GetRemoteStaticKey()
	if len(peerKey) != 32 {
		return nil
	}
	hash := sha256.Sum256(peerKey)
	h.ssu2Addr.UpdateRouterHash(data.NewHash(hash))

	if h.config.RouterInfoValidator == nil {
		return nil
	}
	ri := h.handshakeHandler.GetPeerRouterInfo()
	if len(ri) == 0 {
		return nil
	}
	if err := h.config.RouterInfoValidator(ri, peerKey); err != nil {
		return oops.Wrapf(err, "RouterInfo validation failed against authenticated static key")
	}
	return nil
}

// deriveRekeyKey derives a new cipher key from the current cipher state
// using HKDF: newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
// The ssu2.rst "NextNonce" section is marked "TODO only if we rotate keys" with the
// block contents "TBD", so the label and derivation follow the i2pd reference
// implementation rather than the spec text.
func deriveRekeyKey(cs *noise.CipherState) ([32]byte, error) {
	key := cs.UnsafeKey()
	deriver := i2phkdf.NewHKDF()
	derived, err := deriver.Derive(nil, key[:], []byte("WrapCipherKey"), 32)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "HKDF rekey derivation failed")
	}
	var newKey [32]byte
	copy(newKey[:], derived)
	return newKey, nil
}
