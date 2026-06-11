package session

import (
	"crypto/sha256"

	"github.com/go-i2p/common/data"
	i2phkdf "github.com/go-i2p/crypto/hkdf"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// startDataLoops starts background goroutines for data transport.
// Called after handshake completes to avoid wasting resources on failed connections.
// AUDIT 2.1: Start the fragment reaper here, not in NewSSU2Conn, to avoid leaking
// goroutines if the handshake is never completed or Close is never called.
func (h *SSU2Conn) startDataLoops() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "startDataLoops"}).Debug("Starting send, keepalive, retransmit, and reaper loops")
	h.dataHandler.StartReaper()
	h.wg.Add(3)
	go h.sendLoop()
	go h.keepaliveLoop()
	go h.retransmitLoop()
}

// installCipherStates transfers transport cipher states from the handshake handler.
func (h *SSU2Conn) installCipherStates() error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "installCipherStates"}).Debug("Transferring cipher states from handshake")
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

	return nil
}

// wireDataCallbacks wires internal handler callbacks for data-phase processing.
func (h *SSU2Conn) wireDataCallbacks() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "wireDataCallbacks", "next_nonce_enabled": h.config.EnableNextNonce}).Debug("Wiring data-phase callbacks")
	cbs := h.dataHandler.getCallbacks()

	// G-2: Warn if signature verification callbacks are not configured.
	h.warnMissingSignatureVerifiers(&cbs)

	// Wire NextNonce callback only if enabled (G-1).
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
	h.dataHandler.SetCallbacks(cbs)
}

// warnMissingSignatureVerifiers logs warnings for unset signature verifiers (G-2).
func (h *SSU2Conn) warnMissingSignatureVerifiers(cbs *DataHandlerCallbacks) {
	if cbs.VerifyPeerTestSignature == nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "warnMissingSignatureVerifiers"}).Warn("PeerTest signature verifier not configured; peer test messages will be rejected (G-2)")
	}
	if cbs.VerifyRelayRequestSignature == nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "warnMissingSignatureVerifiers"}).Warn("RelayRequest signature verifier not configured; relay requests will be rejected (G-2)")
	}
	if cbs.VerifyRelayResponseSignature == nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "warnMissingSignatureVerifiers"}).Warn("RelayResponse signature verifier not configured; signed relay responses will be rejected (G-2)")
	}
	if cbs.VerifyRelayIntroSignature == nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "warnMissingSignatureVerifiers"}).Warn("RelayIntro signature verifier not configured; relay intros will be rejected (G-2)")
	}
}

// wrapTerminationCallback wraps the Termination callback to log packet-loss diagnostics (G-7).
func (h *SSU2Conn) wrapTerminationCallback(cbs *DataHandlerCallbacks) {
	existingOnTermination := cbs.OnTermination
	cbs.OnTermination = func(peerReceived uint64, reason uint8, additionalData []byte) {
		sent := h.validDataPacketsSent.Load()
		if sent > 0 {
			lost := int64(sent) - int64(peerReceived)
			log.WithFields(logger.Fields{
				"pkg":          "ssu2",
				"func":         "wrapTerminationCallback",
				"sent":         sent,
				"peerReceived": peerReceived,
				"lost":         lost,
				"reason":       reason,
			}).Info("Termination packet loss summary (G-7)")
		}
		if existingOnTermination != nil {
			existingOnTermination(peerReceived, reason, additionalData)
		}
	}
}

// validatePeerRouterInfo validates the peer's RouterInfo against the Noise-authenticated
// static key per SSU2 spec §Session Confirmed (C-2).
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
// using HKDF per SSU2 spec §NextNonce: newKey = HKDF(currentKey, ZEROLEN, "WrapCipherKey", 32).
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
