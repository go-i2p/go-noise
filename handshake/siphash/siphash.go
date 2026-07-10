// Package siphash implements the SipHash-2-4 length obfuscation modifier
// shared by NTCP2 and SSU2. Both transports use the identical algorithm with
// per-direction keys derived from their respective KDFs.
//
// The canonical implementation lives here; both ntcp2 and ssu2 re-export the
// type and constructors as package-level aliases so callers only ever import
// one concrete type.
package siphash

import (
	"encoding/binary"
	"sync"

	gocrypto_siphash "github.com/go-i2p/crypto/siphash"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// LengthFieldSize is the 2-byte length field used in both NTCP2 and SSU2.
const LengthFieldSize = 2

// IVSize is the byte size of a SipHash IV (uint64 = 8 bytes).
const IVSize = 8

// Compile-time assertions that *LengthModifier implements the interfaces it
// is documented and relied upon (by ntcp2/ssu2) to satisfy.
var (
	_ handshake.HandshakeModifier = (*LengthModifier)(nil)
	_ handshake.ModifierCloner    = (*LengthModifier)(nil)
)

// NextMask computes the next SipHash-2-4 mask value. It updates the IV
// in place and returns the low 16 bits of the hash as the mask.
//
// This implements the shared core of the SipHash length obfuscation chain used
// by both NTCP2 and SSU2:
//
//	IV[n] = SipHash-2-4(k1, k2, IV[n-1])
//	mask  = uint16(IV[n] & 0xFFFF)
//
// Endianness (intentional, spec-mandated, not a bug): the wire length field
// masked by applyMask is big-endian, while the IV fed into the next
// SipHash-2-4 call is serialized little-endian. This matches the NTCP2 spec
// verbatim (https://i2p.net/en/docs/specs/ntcp2, "Data Phase" > "SipHash
// obfuscated length"):
//
//	"length is big endian."
//	"If you use a SipHash library function that returns an unsigned long
//	 integer, use the least significant two bytes as the Mask. Convert the
//	 long integer to the next IV as little endian."
//
// SSU2 (see i2p.net/en/docs/specs/ssu2) reuses the identical NTCP2 SipHash
// length-obfuscation construction, so the same endianness rules apply there
// too. See TestSipHash_OfficialReferenceVectors and TestNextMask_FixedVector
// in siphash_test.go for vector-pinned regression coverage of this behavior.
func NextMask(keys [2]uint64, iv *uint64) uint16 {
	var input [8]byte
	binary.LittleEndian.PutUint64(input[:], *iv)
	hash := gocrypto_siphash.Hash(keys[0], keys[1], input[:])
	*iv = hash
	return uint16(hash & 0xFFFF)
}

// LengthModifier implements SipHash-2-4 length obfuscation for
// data-phase packet/frame lengths. Both NTCP2 and SSU2 use this identical
// algorithm with per-direction keys derived from their respective KDFs.
//
// After Close() (or ZeroKeys()) is called, ModifyOutbound and ModifyInbound
// return an error instead of silently computing a deterministic all-zero-key
// mask sequence, mirroring XORModifier's use-after-close contract. The
// lower-level NextOutboundMask/NextInboundMask accessors do not error after
// Close() (see their doc comments for why) — use Closed() to check state
// explicitly if calling those directly.
type LengthModifier struct {
	mu           sync.Mutex
	name         string
	outboundKeys [2]uint64
	inboundKeys  [2]uint64
	outboundIV   uint64
	inboundIV    uint64
	closed       bool
}

// NewLengthModifier creates a new SipHash length modifier with shared
// keys for both directions.
func NewLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *LengthModifier {
	flog("NewLengthModifier", logger.Fields{"name": name}).Debug("Creating SipHash length modifier")
	return &LengthModifier{
		name:         name,
		outboundKeys: sipKeys,
		inboundKeys:  sipKeys,
		outboundIV:   initialIV,
		inboundIV:    initialIV,
	}
}

// NewLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the NTCP2 and SSU2 specifications.
func NewLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *LengthModifier {
	flog("NewLengthModifierDirectional", logger.Fields{"name": name}).Debug("Creating directional SipHash length modifier")
	return &LengthModifier{
		name:         name,
		outboundKeys: outKeys,
		inboundKeys:  inKeys,
		outboundIV:   outIV,
		inboundIV:    inIV,
	}
}

// ModifyOutbound obfuscates a 2-byte length field using SipHash.
func (slm *LengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("LengthModifier.ModifyOutbound", logger.Fields{"name": slm.name, "phase": phase, "data_len": len(data)}).Debug("SipHash ModifyOutbound")
	return slm.applyMask(phase, data, slm.getNextOutboundMask)
}

// ModifyInbound deobfuscates a 2-byte length field using SipHash.
func (slm *LengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	flog("LengthModifier.ModifyInbound", logger.Fields{"name": slm.name, "phase": phase, "data_len": len(data)}).Debug("SipHash ModifyInbound")
	return slm.applyMask(phase, data, slm.getNextInboundMask)
}

func (slm *LengthModifier) applyMask(phase handshake.HandshakePhase, data []byte, maskFunc func() uint16) ([]byte, error) {
	if phase < handshake.PhaseData || len(data) != LengthFieldSize {
		return data, nil
	}

	slm.mu.Lock()
	if slm.closed {
		slm.mu.Unlock()
		return nil, oops.
			Code("MODIFIER_CLOSED").
			In("handshake/siphash").
			With("modifier_name", slm.name).
			Errorf("LengthModifier has been closed")
	}
	mask := maskFunc()
	slm.mu.Unlock()

	length := binary.BigEndian.Uint16(data)
	maskedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, maskedLength)
	return result, nil
}

func (slm *LengthModifier) computeNextMask(keys [2]uint64, iv *uint64) uint16 {
	return NextMask(keys, iv)
}

// getNextOutboundMask returns the next outbound mask. Caller must hold slm.mu.
func (slm *LengthModifier) getNextOutboundMask() uint16 {
	return slm.computeNextMask(slm.outboundKeys, &slm.outboundIV)
}

// getNextInboundMask returns the next inbound mask. Caller must hold slm.mu.
func (slm *LengthModifier) getNextInboundMask() uint16 {
	return slm.computeNextMask(slm.inboundKeys, &slm.inboundIV)
}

// NextInboundMask returns the next SipHash mask for the inbound direction.
//
// Unlike ModifyOutbound/ModifyInbound, this method's signature is unchanged
// after Close(): it is a hot-path accessor called directly per-frame by
// ntcp2/conn_framing.go, bypassing the HandshakeModifier interface, and
// changing it to return an error would be a breaking API change for a
// narrow-precondition issue (a caller bug continuing to use the modifier
// after the connection that owns it has already been torn down). Callers
// are responsible for not invoking this after Close(); use Closed() to
// check state defensively if needed.
func (slm *LengthModifier) NextInboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextInboundMask()
	slm.mu.Unlock()
	return mask
}

// NextOutboundMask returns the next SipHash mask for the outbound direction.
// See NextInboundMask's doc comment for why this does not error after Close().
func (slm *LengthModifier) NextOutboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextOutboundMask()
	slm.mu.Unlock()
	return mask
}

// Closed reports whether Close() (or ZeroKeys()) has been called on this
// modifier. Callers of NextInboundMask/NextOutboundMask that need to guard
// against post-close use can check this explicitly.
func (slm *LengthModifier) Closed() bool {
	slm.mu.Lock()
	defer slm.mu.Unlock()
	return slm.closed
}

// PeekOutboundIV returns the current outbound SipHash IV without advancing
// the mask chain. Intended for diagnostic logging only.
func (slm *LengthModifier) PeekOutboundIV() uint64 {
	slm.mu.Lock()
	iv := slm.outboundIV
	slm.mu.Unlock()
	return iv
}

// PeekInboundIV returns the current inbound SipHash IV without advancing
// the mask chain. Intended for diagnostic logging only.
func (slm *LengthModifier) PeekInboundIV() uint64 {
	slm.mu.Lock()
	iv := slm.inboundIV
	slm.mu.Unlock()
	return iv
}

// PeekOutboundKeys returns a copy of the outbound SipHash keys. Diagnostic only.
func (slm *LengthModifier) PeekOutboundKeys() [2]uint64 {
	slm.mu.Lock()
	k := slm.outboundKeys
	slm.mu.Unlock()
	return k
}

// PeekInboundKeys returns a copy of the inbound SipHash keys. Diagnostic only.
func (slm *LengthModifier) PeekInboundKeys() [2]uint64 {
	slm.mu.Lock()
	k := slm.inboundKeys
	slm.mu.Unlock()
	return k
}

// ZeroKeys zeroes all SipHash key material and IVs, and marks the modifier
// closed. After this call, ModifyOutbound/ModifyInbound return an error
// instead of silently computing a deterministic all-zero-key mask sequence.
func (slm *LengthModifier) ZeroKeys() {
	log.WithField("name", slm.name).Debug("Zeroing SipHash key material")
	slm.mu.Lock()
	slm.outboundKeys[0] = 0
	slm.outboundKeys[1] = 0
	slm.inboundKeys[0] = 0
	slm.inboundKeys[1] = 0
	slm.outboundIV = 0
	slm.inboundIV = 0
	slm.closed = true
	slm.mu.Unlock()
}

// Name returns the modifier name.
func (slm *LengthModifier) Name() string {
	return slm.name
}

// Clone returns an independent copy of the modifier with the same keys and IV
// state. It implements handshake.ModifierCloner so that callers which need a
// per-connection instance (e.g. listeners accepting concurrent connections) can
// obtain a private copy rather than sharing the stateful IV chain. Because the
// IVs advance with use, callers should Clone from an unused template modifier so
// each copy starts from the same initial IV.
func (slm *LengthModifier) Clone() handshake.HandshakeModifier {
	slm.mu.Lock()
	defer slm.mu.Unlock()
	return &LengthModifier{
		name:         slm.name,
		outboundKeys: slm.outboundKeys,
		inboundKeys:  slm.inboundKeys,
		outboundIV:   slm.outboundIV,
		inboundIV:    slm.inboundIV,
		closed:       slm.closed,
	}
}

// Close zeroes all SipHash key material and IVs.
func (slm *LengthModifier) Close() error {
	log.WithField("name", slm.name).Debug("Closing SipHash length modifier")
	slm.ZeroKeys()
	return nil
}
