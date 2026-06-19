package wire

import (
	"encoding/binary"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// HeaderType indicates the type of SSU2 packet for header protection purposes.
// Different packet types use different header protection key phases.
type HeaderType int

const (
	// HeaderTypeSessionRequest is for Session Request packets (Message 1)
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeSessionRequest HeaderType = iota

	// HeaderTypeSessionCreated is for Session Created packets (Message 2)
	// Uses: k_header_1 = sender's intro key, k_header_2 = derived from handshake KDF
	HeaderTypeSessionCreated

	// HeaderTypeRetry is for Retry packets
	// Uses: k_header_1 = sender's intro key, k_header_2 = sender's intro key
	HeaderTypeRetry

	// HeaderTypeTokenRequest is for Token Request packets
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeTokenRequest

	// HeaderTypeSessionConfirmed is for Session Confirmed packets (Message 3)
	// Uses: k_header_1 = k_header_1 from KDF, k_header_2 = k_header_2 from KDF
	HeaderTypeSessionConfirmed

	// HeaderTypeData is for Data phase packets
	// Uses: k_header_1 = k_header_1 from KDF, k_header_2 = k_header_2 from KDF
	HeaderTypeData

	// HeaderTypePeerTest is for Peer Test packets
	// Uses: k_header_1 = intro key of test target, k_header_2 = intro key of test target
	HeaderTypePeerTest

	// HeaderTypeHolePunch is for Hole Punch packets
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeHolePunch
)

// HeaderSize constants per SSU2 specification
const (
	// HeaderKeySize is the size of header protection keys (ChaCha20 key)
	HeaderKeySize = 32

	// MinPacketSizeForEncryption is the minimum packet size to have valid IV extraction
	// We need at least 24 bytes after the header for IV extraction
	MinPacketSizeForEncryption = 56
)

// HeaderProtector implements SSU2 header encryption and decryption per the I2P SSU2 spec.
// It uses ChaCha20 to generate XOR masks from keys and IVs extracted from packet data.
//
// Header Encryption Algorithm (from spec):
//  1. Extract IV from last 24 bytes of packet (iv1 = packet[len-24:len-12], iv2 = packet[len-12:len])
//  2. Generate mask using ChaCha20.encrypt(key, iv, zeros)
//  3. XOR header bytes 0-7 with first mask
//  4. XOR header bytes 8-15 with second mask
//
// 5. For long headers: encrypt bytes 16-63 with ChaCha20(k_header_2, iv=zeros) per spec
type HeaderProtector struct {
	// mu protects concurrent access to the protector
	mu sync.RWMutex

	// kHeader1 is the first header protection key (for bytes 0-7)
	kHeader1 []byte

	// kHeader2 is the second header protection key (for bytes 8-15)
	kHeader2 []byte

	// headerType determines whether we use long or short header encryption
	headerType HeaderType
}

// NewHeaderProtector creates a new HeaderProtector with the given keys.
// Both keys must be exactly 32 bytes (ChaCha20 key size).
// headerType determines the packet type for appropriate header size handling.
func NewHeaderProtector(kHeader1, kHeader2 []byte, headerType HeaderType) (*HeaderProtector, error) {
	flog("NewHeaderProtector", logger.Fields{"headerType": headerType}).Debug("Creating new HeaderProtector")
	if len(kHeader1) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader1").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader1)).
			Errorf("kHeader1 must be exactly %d bytes", HeaderKeySize)
	}

	if len(kHeader2) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader2").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader2)).
			Errorf("kHeader2 must be exactly %d bytes", HeaderKeySize)
	}

	// Make defensive copies
	k1 := make([]byte, HeaderKeySize)
	k2 := make([]byte, HeaderKeySize)
	copy(k1, kHeader1)
	copy(k2, kHeader2)

	return &HeaderProtector{
		kHeader1:   k1,
		kHeader2:   k2,
		headerType: headerType,
	}, nil
}

// NewHeaderProtectorFromIntroKey creates a HeaderProtector using an intro key for both keys.
// This is used for Session Request, Retry, Token Request, Peer Test, and Hole Punch packets
// where both k_header_1 and k_header_2 are the same (receiver's intro key).
func NewHeaderProtectorFromIntroKey(introKey []byte, headerType HeaderType) (*HeaderProtector, error) {
	flog("NewHeaderProtectorFromIntroKey", logger.Fields{"headerType": headerType}).Debug("Creating protector with intro key for both keys")
	return NewHeaderProtector(introKey, introKey, headerType)
}

// EncryptHeader encrypts the header bytes of an SSU2 packet in place.
// The packet must be the complete SSU2 packet including header, payload, and MAC.
// Per SSU2 spec, encryption order: ChaCha20 extension first, then XOR masks.
// This order is intentionally asymmetric with DecryptHeader because the XOR
// masks derive from packet tail bytes that are part of the ciphertext layout.
func (hp *HeaderProtector) EncryptHeader(packet []byte) error {
	flog("EncryptHeader", logger.Fields{"packetLen": len(packet)}).Debug("Encrypting header")
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if err := hp.validatePacketSize(packet); err != nil {
		return err
	}

	// Step 1: Encrypt long header extension (+ ephemeral key) with ChaCha20
	// This must happen before XOR masks so that the IVs (from packet tail)
	// are in a consistent state for both encrypt and decrypt.
	if hp.isLongHeader() && len(packet) >= LongHeaderSize {
		if err := hp.encryptLongHeaderExtension(packet); err != nil {
			return oops.Wrapf(err, "failed to encrypt long header extension")
		}
	}

	// Step 2: Apply XOR masks to bytes 0-15
	return hp.applyXORMasks(packet)
}

// DecryptHeader decrypts the header bytes of an SSU2 packet in place.
// Per SSU2 spec, decryption order: XOR masks first, then ChaCha20 extension.
// Reversing this order would use masked bytes as ChaCha input and produce an
// invalid long-header extension.
func (hp *HeaderProtector) DecryptHeader(packet []byte) error {
	flog("DecryptHeader", logger.Fields{"packetLen": len(packet)}).Debug("Decrypting header")
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if err := hp.validatePacketSize(packet); err != nil {
		return err
	}

	// Step 1: Remove XOR masks from bytes 0-15
	if err := hp.applyXORMasks(packet); err != nil {
		return err
	}

	// Step 2: Decrypt long header extension (+ ephemeral key) with ChaCha20
	if hp.isLongHeader() && len(packet) >= LongHeaderSize {
		if err := hp.encryptLongHeaderExtension(packet); err != nil {
			return oops.Wrapf(err, "failed to decrypt long header extension")
		}
	}

	return nil
}

// validatePacketSize checks that the packet is large enough for header protection.
func (hp *HeaderProtector) validatePacketSize(packet []byte) error {
	flog("validatePacketSize", logger.Fields{"packetLen": len(packet)}).Debug("Checking minimum packet size")
	headerSize := hp.getHeaderSize()
	minSize := headerSize + 24
	if len(packet) < minSize {
		return oops.
			Code("PACKET_TOO_SMALL").
			In("ssu2").
			With("packet_size", len(packet)).
			With("min_size", minSize).
			With("header_type", hp.headerType).
			Errorf("packet too small for header protection: need at least %d bytes", minSize)
	}
	return nil
}

// applyXORMasks applies or removes XOR masks on header bytes 0-15.
// XOR is symmetric so this works for both encrypt and decrypt.
//
// SECURITY NOTE: IV derivation and collision resistance.
// The ChaCha20 IVs (nonces) for header protection are derived from the packet tail
// (the last 24 bytes, which overlap with the AEAD MAC). Specifically:
//   - IV1 = packet[len-24:len-12] (12 bytes) for bytes 0-7
//   - IV2 = packet[len-12:len]    (12 bytes) for bytes 8-15
//
// This construction ensures that each packet has a unique IV as long as the MAC is unique,
// which is guaranteed by the AEAD construction (ChaCha20-Poly1305) that produces unique MACs
// for distinct plaintexts or nonces. The inner packet number (part of the AEAD-protected
// payload) provides additional differentiation even if plaintext headers are identical.
//
// Theoretical concern: If two packets had (a) identical plaintext headers, (b) identical
// AEAD MACs (cryptographically negligible probability), and (c) identical obfuscated lengths,
// then the header protection keystream would repeat. However, AEAD MAC collision is
// computationally infeasible (negligible probability), and the inner packet counter ensures
// distinct AEAD inputs. Thus, practical exploitability is zero.
//
// This design follows the SSU2 spec §"Header Protection" IV derivation requirements.
func (hp *HeaderProtector) applyXORMasks(packet []byte) error {
	flog("applyXORMasks", logger.Fields{"packetLen": len(packet)}).Debug("Applying XOR masks to header bytes 0-15")
	// SSU2 spec §"Header Protection": IV1 = packet[len-24 : len-12] (12 bytes).
	iv1Start := len(packet) - 24
	iv1 := make([]byte, 12)
	copy(iv1, packet[iv1Start:iv1Start+12])

	// Generate first mask using ChaCha20(kHeader1, iv1, zeros)
	mask1, err := hp.generateMask(hp.kHeader1, iv1)
	if err != nil {
		return oops.Wrapf(err, "failed to generate first header mask")
	}

	// XOR bytes 0-7 with mask1[0:8]
	for i := 0; i < 8; i++ {
		packet[i] ^= mask1[i]
	}

	// SSU2 spec §"Header Protection": IV2 = packet[len-12 : len] (12 bytes).
	iv2Start := len(packet) - 12
	iv2 := make([]byte, 12)
	copy(iv2, packet[iv2Start:iv2Start+12])

	// Generate second mask using ChaCha20(kHeader2, iv2, zeros)
	mask2, err := hp.generateMask(hp.kHeader2, iv2)
	if err != nil {
		return oops.Wrapf(err, "failed to generate second header mask")
	}

	// XOR bytes 8-15 with mask2[0:8]
	for i := 8; i < 16; i++ {
		packet[i] ^= mask2[i-8]
	}

	return nil
}

// IsLongHeader returns true if this is a long header type (32 bytes).
func (hp *HeaderProtector) IsLongHeader() bool {
	return hp.isLongHeader()
}

// GenerateMask exposes the internal generateMask for testing.
func (hp *HeaderProtector) GenerateMask(key, nonce []byte) ([]byte, error) {
	return hp.generateMask(key, nonce)
}

// isLongHeader returns true if this is a long header type (32 bytes).
func (hp *HeaderProtector) isLongHeader() bool {
	switch hp.headerType {
	case HeaderTypeSessionRequest, HeaderTypeSessionCreated, HeaderTypeRetry,
		HeaderTypeTokenRequest, HeaderTypePeerTest, HeaderTypeHolePunch:
		return true
	default:
		return false
	}
}

// getHeaderSize returns the header size based on header type.
func (hp *HeaderProtector) getHeaderSize() int {
	if hp.isLongHeader() {
		return LongHeaderSize
	}
	return ShortHeaderSize
}

// generateMask generates an 8-byte XOR mask using ChaCha20.
// The mask is generated by encrypting 8 zero bytes with ChaCha20.
func (hp *HeaderProtector) generateMask(key, nonce []byte) ([]byte, error) {
	flog("generateMask").Debug("Generating 8-byte XOR mask via ChaCha20")
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to initialize ChaCha20 cipher")
	}

	// Generate mask by encrypting zeros
	zeros := make([]byte, 8)
	mask := make([]byte, 8)
	cipher.XORKeyStream(mask, zeros)

	return mask, nil
}

// encryptLongHeaderExtension encrypts the long header extension and optional
// ephemeral key per the SSU2 spec. Uses ChaCha20 with kHeader2 at counter
// position n=1 per spec ("key: Bob's intro key, n: 1, data: 48 bytes").
// For SessionRequest/SessionCreated (which include a 32-byte ephemeral key),
// encrypts bytes 16-63 (48 bytes) as one ChaCha20 operation.
// For other long header types, encrypts bytes 16-31 (16 bytes).
func (hp *HeaderProtector) encryptLongHeaderExtension(packet []byte) error {
	flog("encryptLongHeaderExtension", logger.Fields{"headerType": hp.headerType}).Debug("Encrypting long header extension with ChaCha20")
	if len(packet) < LongHeaderSize {
		return nil // Nothing to encrypt
	}

	// SSU2 spec: ChaCha20.encrypt(k_header_2, n=1, packet[16:63])
	nonce := make([]byte, 12) // all-zero nonce; counter set to 1 below
	cipher, err := chacha20.NewUnauthenticatedCipher(hp.kHeader2, nonce)
	if err != nil {
		return oops.Wrapf(err, "failed to initialize ChaCha20 for header extension")
	}
	// SSU2 spec requires n=1 (counter position 1, skipping the first 64 bytes)
	cipher.SetCounter(1)

	// For packets with ephemeral keys, encrypt 48 bytes (header[16:64])
	hasEphemeral := hp.headerType == HeaderTypeSessionRequest ||
		hp.headerType == HeaderTypeSessionCreated
	if hasEphemeral && len(packet) >= LongHeaderSize+EphemeralKeySize {
		cipher.XORKeyStream(packet[16:64], packet[16:64])
	} else {
		cipher.XORKeyStream(packet[16:32], packet[16:32])
	}

	return nil
}

// UpdateKeys updates the header protection keys.
// This is used when transitioning between handshake phases.
// Both keys must be exactly 32 bytes.
func (hp *HeaderProtector) UpdateKeys(kHeader1, kHeader2 []byte) error {
	flog("UpdateKeys").Debug("Updating header protection keys")
	if len(kHeader1) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader1").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader1)).
			Errorf("kHeader1 must be exactly %d bytes", HeaderKeySize)
	}

	if len(kHeader2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader2").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader2)).
			Errorf("kHeader2 must be exactly %d bytes", HeaderKeySize)
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()

	copy(hp.kHeader1, kHeader1)
	copy(hp.kHeader2, kHeader2)

	return nil
}

// SetHeaderType updates the header type.
// This affects whether long or short header encryption is used.
func (hp *HeaderProtector) SetHeaderType(headerType HeaderType) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.headerType = headerType
}

// GetHeaderType returns the current header type.
func (hp *HeaderProtector) GetHeaderType() HeaderType {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.headerType
}

func ExtractConnectionID(header []byte) (uint64, error) {
	if len(header) < 8 {
		return 0, oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 8 bytes to extract connection ID")
	}
	return binary.BigEndian.Uint64(header[0:8]), nil
}

// EncodeConnectionID encodes a connection ID into header bytes 0-7.
func EncodeConnectionID(header []byte, connID uint64) error {
	if len(header) < 8 {
		return oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 8 bytes to encode connection ID")
	}
	binary.BigEndian.PutUint64(header[0:8], connID)
	return nil
}

// ExtractPacketNumber extracts the packet number from a decrypted header.
// This reads bytes 8-11 as a big-endian uint32.
func ExtractPacketNumber(header []byte) (uint32, error) {
	if len(header) < 12 {
		return 0, oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 12 bytes to extract packet number")
	}
	return binary.BigEndian.Uint32(header[8:12]), nil
}

// EncodePacketNumber encodes a packet number into header bytes 8-11.
func EncodePacketNumber(header []byte, pktNum uint32) error {
	if len(header) < 12 {
		return oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 12 bytes to encode packet number")
	}
	binary.BigEndian.PutUint32(header[8:12], pktNum)
	return nil
}
