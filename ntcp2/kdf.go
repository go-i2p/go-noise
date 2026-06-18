package ntcp2

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/hmac"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DeriveSipHashKeys derives per-direction SipHash-2-4 keys and initial IVs
// from the Noise handshake hash and ask_master secret per the I2P NTCP2 spec.
//
// The derivation follows the spec's 5-step HMAC-SHA256 chain:
//
//	Step 1: temp_key   = HMAC-SHA256(key=ask_master, data=h || "siphash")
//	Step 2: sip_master = HMAC-SHA256(key=temp_key,   data=byte(0x01))
//	Step 3: temp_key   = HMAC-SHA256(key=sip_master, data=zerolen)
//	Step 4: sipkeys_ab = HMAC-SHA256(key=temp_key,   data=byte(0x01))[0:24]
//	Step 5: sipkeys_ba = HMAC-SHA256(key=temp_key,   data=sipkeys_ab[0:32] || byte(0x02))[0:24]
//
// NOTE: Step 5 uses the full 32-byte HMAC output from step 4 as its input prefix,
// not just the 24 bytes extracted for sipkeys_ab. This matches the i2pd reference
// implementation (m_Sipkeysab is 32 bytes; m_Sipkeysab[32]=2 before HMAC call).
//
// Each 24-byte output is split into (sipk1, sipk2, sipiv) as little-endian uint64s.
//
// Parameters:
//   - askMaster: the ask_master secret from the Noise handshake (32 bytes)
//   - handshakeHash: the handshake hash (h) from the completed Noise session (32 bytes)
//
// Returns:
//   - sipKeysAB: [2]uint64{sipk1, sipk2} for direction A→B (initiator→responder)
//   - sipIVAB: initial IV for A→B SipHash length obfuscation chain
//   - sipKeysBA: [2]uint64{sipk1, sipk2} for direction B→A (responder→initiator)
//   - sipIVBA: initial IV for B→A SipHash length obfuscation chain
//   - err: non-nil if derivation fails
func DeriveSipHashKeys(askMaster, handshakeHash []byte) (
	sipKeysAB [2]uint64, sipIVAB uint64,
	sipKeysBA [2]uint64, sipIVBA uint64,
	err error,
) {
	flog("DeriveSipHashKeys").Debug("Deriving SipHash keys from handshake")
	if len(askMaster) != StaticKeySize {
		flog("DeriveSipHashKeys", logger.Fields{"length": len(askMaster)}).Error("Invalid ask_master length")
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_ASK_MASTER").
			In("ntcp2").
			With("length", len(askMaster)).
			Errorf("ask_master must be exactly %d bytes", StaticKeySize)
	}

	if len(handshakeHash) != StaticKeySize {
		flog("DeriveSipHashKeys", logger.Fields{"length": len(handshakeHash)}).Error("Invalid handshake hash length")
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_HANDSHAKE_HASH").
			In("ntcp2").
			With("length", len(handshakeHash)).
			Errorf("handshake hash must be exactly %d bytes", StaticKeySize)
	}

	// Step 1: temp_key = HMAC-SHA256(key=ask_master, data=h || "siphash")
	hData := make([]byte, len(handshakeHash)+len("siphash"))
	copy(hData, handshakeHash)
	copy(hData[len(handshakeHash):], "siphash")
	tempKey := hmac.HMACSHA256(askMaster, hData)

	// Step 2: sip_master = HMAC-SHA256(key=temp_key, data=byte(0x01))
	sipMaster := hmac.HMACSHA256(tempKey[:], []byte{0x01})

	// Step 3: temp_key = HMAC-SHA256(key=sip_master, data=zerolen)
	tempKey = hmac.HMACSHA256(sipMaster[:], []byte{})

	// Step 4: sipkeys_ab = HMAC-SHA256(key=temp_key, data=byte(0x01))[0:24]
	fullAB := hmac.HMACSHA256(tempKey[:], []byte{0x01})
	if len(fullAB) < 32 {
		flog("DeriveSipHashKeys", logger.Fields{"length": len(fullAB)}).Error("Unexpected HMAC output length for sipkeys_ab")
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_HMAC_OUTPUT").
			In("ntcp2").
			With("length", len(fullAB)).
			Errorf("HMAC-SHA256 output must be at least 32 bytes, got %d", len(fullAB))
	}
	sipKeysAB[0] = binary.LittleEndian.Uint64(fullAB[0:8])
	sipKeysAB[1] = binary.LittleEndian.Uint64(fullAB[8:16])
	sipIVAB = binary.LittleEndian.Uint64(fullAB[16:24])

	// Step 5: sipkeys_ba = HMAC-SHA256(key=temp_key, data=sipkeys_ab[0:32] || byte(0x02))[0:24]
	// Per the i2pd reference implementation, the full 32-byte HMAC output from step 4
	// (not just the 24 extracted bytes) is used as the input prefix. In i2pd, m_Sipkeysab
	// holds 32 bytes and m_Sipkeysab[32]=0x02 is set before passing 33 bytes to HMAC.
	step5Data := make([]byte, len(fullAB[:])+1)
	copy(step5Data, fullAB[:])
	step5Data[len(fullAB[:])] = 0x02
	fullBA := hmac.HMACSHA256(tempKey[:], step5Data)
	if len(fullBA) < 32 {
		flog("DeriveSipHashKeys", logger.Fields{"length": len(fullBA)}).Error("Unexpected HMAC output length for sipkeys_ba")
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_HMAC_OUTPUT").
			In("ntcp2").
			With("length", len(fullBA)).
			Errorf("HMAC-SHA256 output must be at least 32 bytes, got %d", len(fullBA))
	}
	sipKeysBA[0] = binary.LittleEndian.Uint64(fullBA[0:8])
	sipKeysBA[1] = binary.LittleEndian.Uint64(fullBA[8:16])
	sipIVBA = binary.LittleEndian.Uint64(fullBA[16:24])

	// Per NTCP2 spec: zero all intermediate key material after use.
	// "overwrite ask_master in memory, no longer needed"
	// "overwrite sip_master in memory, no longer needed"
	// "overwrite the temp_key in memory, no longer needed"
	securemem.SecureZero(hData)
	securemem.SecureZero(tempKey[:])
	securemem.SecureZero(sipMaster[:])
	securemem.SecureZero(fullAB[:])
	securemem.SecureZero(step5Data)
	securemem.SecureZero(fullBA[:])

	flog("DeriveSipHashKeys").Debug("SipHash key derivation completed successfully")
	return sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, nil
}
