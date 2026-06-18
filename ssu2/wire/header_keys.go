package wire

import (
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// HeaderProtectorManager manages header protection for different phases of SSU2.
// It tracks the current phase and provides appropriate header protection based on state.
type HeaderProtectorManager struct {
	mu sync.RWMutex

	// introKey is the local router's intro key (used for incoming packets)
	introKey []byte

	// remoteIntroKey is the remote router's intro key (used for outgoing packets)
	remoteIntroKey []byte

	// sendDataHeader2 is k_header_2 for outbound Data packets, derived per
	// "HKDFSSU2DataKeys" from the send cipher key (k_ab for initiator).
	sendDataHeader2 []byte

	// recvDataHeader2 is k_header_2 for inbound Data packets, derived per
	// "HKDFSSU2DataKeys" from the recv cipher key (k_ba for initiator).
	recvDataHeader2 []byte

	// sessCreateHeader2 is k_header_2 for SessionCreated, derived from
	// chainKey after message 1 with info \"SessCreateHeader\"
	sessCreateHeader2 []byte

	// sessionConfirmedHeader2 is k_header_2 for SessionConfirmed, derived
	// from chainKey after message 2 with info \"SessionConfirmed\"
	sessionConfirmedHeader2 []byte

	// current is the current header protector
	current *HeaderProtector

	// isInitiator indicates if we are the handshake initiator
	isInitiator bool
}

// NewHeaderProtectorManager creates a new header protector manager.
// introKey is the local router's intro key.
// remoteIntroKey is the remote peer's intro key (can be nil for listeners).
// isInitiator indicates whether we are initiating the handshake.
func NewHeaderProtectorManager(introKey, remoteIntroKey []byte, isInitiator bool) (*HeaderProtectorManager, error) {
	flog("NewHeaderProtectorManager", logger.Fields{"isInitiator": isInitiator}).Debug("Creating header protector manager")
	if len(introKey) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("expected", HeaderKeySize).
			With("actual", len(introKey)).
			Errorf("intro key must be exactly %d bytes", HeaderKeySize)
	}

	// Make defensive copies
	intro := make([]byte, HeaderKeySize)
	copy(intro, introKey)

	var remote []byte
	if len(remoteIntroKey) == HeaderKeySize {
		remote = make([]byte, HeaderKeySize)
		copy(remote, remoteIntroKey)
	}

	return &HeaderProtectorManager{
		introKey:       intro,
		remoteIntroKey: remote,
		isInitiator:    isInitiator,
	}, nil
}

// GetProtectorForType returns a header protector configured for the given packet type.
// This creates a new protector with the appropriate keys based on the packet type
// and whether we are the initiator or responder.
func (hpm *HeaderProtectorManager) GetProtectorForType(headerType HeaderType) (*HeaderProtector, error) {
	flog("GetProtectorForType", logger.Fields{"headerType": headerType}).Debug("Selecting header protector for packet type")
	hpm.mu.RLock()
	defer hpm.mu.RUnlock()

	var k1, k2 []byte
	var err error

	switch headerType {
	case HeaderTypeSessionRequest, HeaderTypeTokenRequest:
		k1, k2, err = hpm.keysForIntroProtected()
	case HeaderTypeHolePunch:
		// Per spec: "Both header encryption keys are the receiver's intro key"
		// The receiver is always the remote peer, so use remoteIntroKey (G-8).
		k1, k2, err = hpm.keysForHolePunch()
	case HeaderTypeSessionCreated, HeaderTypeRetry:
		k1, k2, err = hpm.keysForSessionCreatedRetry(headerType)
	case HeaderTypeSessionConfirmed, HeaderTypeData:
		k1, k2, err = hpm.keysForKDFProtected(headerType)
	case HeaderTypePeerTest:
		return nil, oops.
			Code("PEER_TEST_NOT_SUPPORTED").
			In("ssu2").
			Errorf("Peer Test requires target's intro key - use GetProtectorForType with explicit keys")
	default:
		return nil, oops.
			Code("UNKNOWN_HEADER_TYPE").
			In("ssu2").
			With("header_type", headerType).
			Errorf("unknown header type")
	}

	if err != nil {
		return nil, err
	}
	return NewHeaderProtector(k1, k2, headerType)
}

// keysForIntroProtected returns keys for packets protected solely by intro keys
// (SessionRequest, TokenRequest).
func (hpm *HeaderProtectorManager) keysForIntroProtected() (k1, k2 []byte, err error) {
	flog("keysForIntroProtected", logger.Fields{"isInitiator": hpm.isInitiator}).Debug("Resolving intro-protected header keys")
	if hpm.isInitiator {
		if len(hpm.remoteIntroKey) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_REMOTE_INTRO_KEY").
				In("ssu2").
				Errorf("remote intro key required for Session Request")
		}
		return hpm.remoteIntroKey, hpm.remoteIntroKey, nil
	}
	return hpm.introKey, hpm.introKey, nil
}

// keysForHolePunch returns keys for HolePunch packets.
// Per spec §HolePunch: "Both header encryption keys are the receiver's intro key."
// The receiver is always the remote peer, so we always use remoteIntroKey (G-8).
func (hpm *HeaderProtectorManager) keysForHolePunch() (k1, k2 []byte, err error) {
	if len(hpm.remoteIntroKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_REMOTE_INTRO_KEY").
			In("ssu2").
			Errorf("remote intro key required for HolePunch header protection")
	}
	return hpm.remoteIntroKey, hpm.remoteIntroKey, nil
}

// keysForSessionCreatedRetry returns keys for SessionCreated or Retry packets.
// Retry uses the sender's intro key for both k1 and k2.
// SessionCreated uses the intro key for k1 and requires KDF-derived k2 per spec.
func (hpm *HeaderProtectorManager) keysForSessionCreatedRetry(headerType HeaderType) (k1, k2 []byte, err error) {
	base := hpm.introKey
	if hpm.isInitiator {
		if len(hpm.remoteIntroKey) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_REMOTE_INTRO_KEY").
				In("ssu2").
				Errorf("remote intro key required for Session Created/Retry")
		}
		base = hpm.remoteIntroKey
	}

	k1 = base
	if headerType == HeaderTypeRetry {
		k2 = base
	} else if len(hpm.sessCreateHeader2) == HeaderKeySize {
		k2 = hpm.sessCreateHeader2
	} else {
		return nil, nil, oops.
			Code("MISSING_KDF_KEY").
			In("ssu2").
			Errorf("SessCreateHeader k_header_2 required for SessionCreated per spec")
	}
	return k1, k2, nil
}

// keysForKDFProtected returns keys for packets protected by KDF-derived keys
// (SessionConfirmed, Data).
func (hpm *HeaderProtectorManager) keysForKDFProtected(headerType HeaderType) (k1, k2 []byte, err error) {
	if headerType == HeaderTypeSessionConfirmed {
		// Spec: SessionConfirmed uses k_header_1 = Bob's intro key (bik),
		// k_header_2 = KDF-derived from SessionCreated.
		if hpm.isInitiator {
			if len(hpm.remoteIntroKey) != HeaderKeySize {
				return nil, nil, oops.
					Code("MISSING_REMOTE_INTRO_KEY").
					In("ssu2").
					Errorf("remote intro key (bik) required for SessionConfirmed k_header_1")
			}
			k1 = hpm.remoteIntroKey
		} else {
			k1 = hpm.introKey
		}
		if len(hpm.sessionConfirmedHeader2) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_KDF_KEY").
				In("ssu2").
				Errorf("SessionConfirmed k_header_2 required (from \"SessionConfirmed\" KDF)")
		}
		return k1, hpm.sessionConfirmedHeader2, nil
	}

	// Data phase: k_header_1 = receiver's intro key per spec.
	// Direction-dependent keys are returned for the outbound (encrypt) path.
	// For inbound, getDataInboundKeys() is used directly.
	if len(hpm.remoteIntroKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_REMOTE_INTRO_KEY").
			In("ssu2").
			Errorf("remote intro key required for Data phase k_header_1")
	}
	if len(hpm.sendDataHeader2) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_KDF_KEYS").
			In("ssu2").
			Errorf("send data k_header_2 required for Data packets")
	}
	return hpm.remoteIntroKey, hpm.sendDataHeader2, nil
}

// SetKDFKeys sets the KDF-derived header protection keys for the data phase.
// sendKH2 is the k_header_2 for outbound Data packets.
// recvKH2 is the k_header_2 for inbound Data packets.
func (hpm *HeaderProtectorManager) SetKDFKeys(sendKH2, recvKH2 []byte) error {
	if len(sendKH2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "sendKH2").
			Errorf("sendKH2 must be exactly %d bytes", HeaderKeySize)
	}
	if len(recvKH2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "recvKH2").
			Errorf("recvKH2 must be exactly %d bytes", HeaderKeySize)
	}

	hpm.mu.Lock()
	defer hpm.mu.Unlock()

	hpm.sendDataHeader2 = make([]byte, HeaderKeySize)
	hpm.recvDataHeader2 = make([]byte, HeaderKeySize)
	copy(hpm.sendDataHeader2, sendKH2)
	copy(hpm.recvDataHeader2, recvKH2)

	return nil
}

// setHeaderKey validates, copies, and stores a header key into the
// specified destination slice pointer. Caller must NOT hold hpm.mu.
func (hpm *HeaderProtectorManager) setHeaderKey(dst *[]byte, key []byte, label string) error {
	if len(key) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			Errorf("%s key must be exactly %d bytes", label, HeaderKeySize)
	}
	hpm.mu.Lock()
	defer hpm.mu.Unlock()
	*dst = make([]byte, HeaderKeySize)
	copy(*dst, key)
	return nil
}

// SetSessCreateHeaderKey sets the k_header_2 for SessionCreated header
// protection, derived from the chainKey after handshake message 1 using
// info string "SessCreateHeader".
func (hpm *HeaderProtectorManager) SetSessCreateHeaderKey(key []byte) error {
	return hpm.setHeaderKey(&hpm.sessCreateHeader2, key, "SessCreateHeader")
}

// SetSessionConfirmedHeaderKey sets the k_header_2 for SessionConfirmed
// header protection, derived from the chainKey after handshake message 2
// using info string "SessionConfirmed".
func (hpm *HeaderProtectorManager) SetSessionConfirmedHeaderKey(key []byte) error {
	return hpm.setHeaderKey(&hpm.sessionConfirmedHeader2, key, "SessionConfirmed")
}

// SetRemoteIntroKey sets the remote peer's intro key.
// This is typically learned during connection establishment.
func (hpm *HeaderProtectorManager) SetRemoteIntroKey(remoteIntroKey []byte) error {
	if len(remoteIntroKey) != HeaderKeySize {
		return oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("expected", HeaderKeySize).
			With("actual", len(remoteIntroKey)).
			Errorf("remote intro key must be exactly %d bytes", HeaderKeySize)
	}

	hpm.mu.Lock()
	defer hpm.mu.Unlock()

	hpm.remoteIntroKey = make([]byte, HeaderKeySize)
	copy(hpm.remoteIntroKey, remoteIntroKey)

	return nil
}

// EncryptOutboundHeader encrypts the header of an outbound packet.
// Automatically selects the correct keys based on header type.
func (hpm *HeaderProtectorManager) EncryptOutboundHeader(packet []byte, headerType HeaderType) error {
	protector, err := hpm.GetProtectorForType(headerType)
	if err != nil {
		return err
	}
	return protector.EncryptHeader(packet)
}

// DecryptInboundHeader decrypts the header of an inbound packet.
// For Data packets, uses direction-aware inbound keys (introKey + recvDataHeader2).
// For other types, uses the standard key selection via GetProtectorForType.
func (hpm *HeaderProtectorManager) DecryptInboundHeader(packet []byte, headerType HeaderType) error {
	if headerType == HeaderTypeData {
		hpm.mu.RLock()
		k1, k2, err := hpm.getDataInboundKeys()
		hpm.mu.RUnlock()
		if err != nil {
			return err
		}
		protector, err := NewHeaderProtector(k1, k2, headerType)
		if err != nil {
			return err
		}
		return protector.DecryptHeader(packet)
	}
	protector, err := hpm.GetProtectorForType(headerType)
	if err != nil {
		return err
	}
	return protector.DecryptHeader(packet)
}

// getDataInboundKeys returns the keys for decrypting inbound Data packets.
// k_header_1 = our intro key (we are the receiver), k_header_2 = recv-direction KDF key.
// Must be called with hpm.mu held (at least RLock).
func (hpm *HeaderProtectorManager) getDataInboundKeys() (k1, k2 []byte, err error) {
	if len(hpm.introKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_INTRO_KEY").
			In("ssu2").
			Errorf("own intro key required for inbound Data k_header_1")
	}
	if len(hpm.recvDataHeader2) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_KDF_KEYS").
			In("ssu2").
			Errorf("recv data k_header_2 required for inbound Data packets")
	}
	return hpm.introKey, hpm.recvDataHeader2, nil
}

// ExtractConnectionID extracts the destination connection ID from a decrypted header.
// This reads bytes 0-7 as a big-endian uint64.
