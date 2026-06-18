package ratchet

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// fillRecvKeyCache pre-derives ES message keys for counters in [session.recvFillMark, upTo)
// and stores them in session.recvKeyCache.  The receiving symmetric ratchet is advanced
// once per counter, so the chain key stays in sync with the sender's sending chain.
//
// Must be called with session.mu held.
// Returns an error if RecvSymmetricRatchet is nil rather than silently falling back to
// the send-direction SymmetricRatchet, which would permanently desynchronise outgoing crypto.
// Spec ref: ratchet.md §"Existing Session" — symmetric ratchet advances once per message.
func fillRecvKeyCache(session *Session, upTo uint32) error {
	flog("fillRecvKeyCache", logger.Fields{"up_to": upTo, "fill_mark": session.recvFillMark}).Debug("pre-deriving recv message keys")
	recvRatchet := session.RecvSymmetricRatchet
	if recvRatchet == nil {
		return oops.Errorf("RecvSymmetricRatchet is nil: session ratchet state is uninitialised; " +
			"cannot derive recv keys without a valid recv ratchet")
	}
	for session.recvFillMark < upTo {
		key, _, err := recvRatchet.DeriveMessageKeyAndAdvance(session.recvFillMark)
		if err != nil {
			return oops.Wrapf(err, "failed to pre-derive recv key for counter %d", session.recvFillMark)
		}
		session.recvKeyCache[session.recvFillMark] = key
		session.recvFillMark++
	}
	return nil
}

// resetRecvWindow reinitialises the receive-window fields after an NSR replaces
// the session ratchet state.  Must be called with session.mu held.
func resetRecvWindow(session *Session) {
	flog("resetRecvWindow").Debug("reinitialising receive-window fields")
	session.recvWindowBase = 1
	session.recvFillMark = 1
	session.nextRecvTagCounter = 1
	// Zero all pre-derived keys in the old cache before discarding to prevent
	// recovery from memory dumps. The ratchet's forward secrecy guarantees rely
	// on securely destroying keys after use.
	for counter := range session.recvKeyCache {
		var zeroKey [32]byte
		session.recvKeyCache[counter] = zeroKey
	}
	// Clear the old key cache so stale keys cannot be replayed.
	session.recvKeyCache = make(map[uint32][32]byte)
}

// trimRecvWindowByPN removes pre-derived message keys from the receive window
// that are above the PN (previous tag set message count) value received in a
// MessageNumber block. Per ratchet.md §"Message Numbers", when a peer signals
// PN it indicates the last message counter used in the previous tag set. Keys
// for counters beyond PN in that range will never arrive, so they can be
// deleted to bound memory usage.
//
// This is safe to call from outside session.mu — it acquires the lock itself.
func trimRecvWindowByPN(session *Session, pn uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()

	pn32 := uint32(pn)
	trimmed := 0
	for counter := range session.recvKeyCache {
		if counter > pn32 && counter < session.recvWindowBase {
			// Keys below recvWindowBase that are above PN belong to the
			// previous tag set and will never be used.
			delete(session.recvKeyCache, counter)
			trimmed++
		}
	}

	if trimmed > 0 {
		flog("trimRecvWindowByPN", logger.Fields{"pn":      pn, "trimmed": trimmed}).Debug("Trimmed stale recv window keys above PN")
	}
}
