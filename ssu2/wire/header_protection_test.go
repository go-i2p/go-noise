package wire

import (
	"bytes"
	"testing"
)

func fixedKey(b byte) []byte {
	k := make([]byte, HeaderKeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestNewHeaderProtector_InvalidKeySizes(t *testing.T) {
	valid := fixedKey(1)
	short := make([]byte, HeaderKeySize-1)

	if _, err := NewHeaderProtector(short, valid, HeaderTypeData); err == nil {
		t.Error("expected error for short kHeader1")
	}
	if _, err := NewHeaderProtector(valid, short, HeaderTypeData); err == nil {
		t.Error("expected error for short kHeader2")
	}
	if _, err := NewHeaderProtector(valid, valid, HeaderTypeData); err != nil {
		t.Errorf("unexpected error for valid keys: %v", err)
	}
}

func TestNewHeaderProtectorFromIntroKey(t *testing.T) {
	key := fixedKey(7)
	hp, err := NewHeaderProtectorFromIntroKey(key, HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hp.IsLongHeader() {
		t.Error("expected SessionRequest to be a long header type")
	}
}

// buildProtectablePacket returns a packet buffer of the given total size,
// with the tail 24 bytes populated with distinguishable, non-zero content
// so IV derivation is exercised meaningfully rather than against all-zero bytes.
func buildProtectablePacket(size int) []byte {
	packet := make([]byte, size)
	for i := range packet {
		packet[i] = byte(i)
	}
	return packet
}

func TestHeaderProtector_EncryptDecryptRoundTrip_ShortHeader(t *testing.T) {
	k1 := fixedKey(0x11)
	k2 := fixedKey(0x22)
	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	original := buildProtectablePacket(ShortHeaderSize + 24)
	packet := append([]byte{}, original...)

	if err := hp.EncryptHeader(packet); err != nil {
		t.Fatalf("EncryptHeader error = %v", err)
	}
	if bytes.Equal(packet[:16], original[:16]) {
		t.Error("expected header bytes 0-15 to change after encryption")
	}
	// Bytes after the header (the IV-source tail) must be untouched by header protection.
	if !bytes.Equal(packet[16:], original[16:]) {
		t.Error("expected non-header bytes to remain unchanged")
	}

	if err := hp.DecryptHeader(packet); err != nil {
		t.Fatalf("DecryptHeader error = %v", err)
	}
	if !bytes.Equal(packet, original) {
		t.Errorf("round-trip mismatch: got %x, want %x", packet, original)
	}
}

func TestHeaderProtector_EncryptDecryptRoundTrip_LongHeaderWithEphemeralKey(t *testing.T) {
	k1 := fixedKey(0x33)
	k2 := fixedKey(0x44)
	hp, err := NewHeaderProtector(k1, k2, HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	// Long header (32) + ephemeral key region (32 more, total 64) + 24-byte
	// IV-source tail.
	original := buildProtectablePacket(LongHeaderSize + EphemeralKeySize + 24)
	packet := append([]byte{}, original...)

	if err := hp.EncryptHeader(packet); err != nil {
		t.Fatalf("EncryptHeader error = %v", err)
	}
	if bytes.Equal(packet[:64], original[:64]) {
		t.Error("expected header+ephemeral-key region to change after encryption")
	}

	if err := hp.DecryptHeader(packet); err != nil {
		t.Fatalf("DecryptHeader error = %v", err)
	}
	if !bytes.Equal(packet, original) {
		t.Errorf("round-trip mismatch: got %x, want %x", packet, original)
	}
}

func TestHeaderProtector_EncryptDecryptRoundTrip_AllHeaderTypes(t *testing.T) {
	types := []HeaderType{
		HeaderTypeSessionRequest, HeaderTypeSessionCreated, HeaderTypeRetry,
		HeaderTypeTokenRequest, HeaderTypeSessionConfirmed, HeaderTypeData,
		HeaderTypePeerTest, HeaderTypeHolePunch,
	}
	for _, ht := range types {
		hp, err := NewHeaderProtector(fixedKey(0x55), fixedKey(0x66), ht)
		if err != nil {
			t.Fatalf("headerType %v: NewHeaderProtector error = %v", ht, err)
		}

		size := hp.getHeaderSize() + 24
		if hp.IsLongHeader() {
			size += EphemeralKeySize // exercise the largest plausible size for long headers too
		}
		original := buildProtectablePacket(size)
		packet := append([]byte{}, original...)

		if err := hp.EncryptHeader(packet); err != nil {
			t.Fatalf("headerType %v: EncryptHeader error = %v", ht, err)
		}
		if err := hp.DecryptHeader(packet); err != nil {
			t.Fatalf("headerType %v: DecryptHeader error = %v", ht, err)
		}
		if !bytes.Equal(packet, original) {
			t.Errorf("headerType %v: round-trip mismatch: got %x, want %x", ht, packet, original)
		}
	}
}

func TestHeaderProtector_PacketTooSmall(t *testing.T) {
	hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), HeaderTypeData)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	// ShortHeaderSize(16) + 24 = 40 is the minimum; one byte short must fail.
	tooSmall := make([]byte, ShortHeaderSize+24-1)
	if err := hp.EncryptHeader(tooSmall); err == nil {
		t.Error("expected error for packet below minimum size")
	}
	if err := hp.DecryptHeader(tooSmall); err == nil {
		t.Error("expected error for packet below minimum size")
	}
}

func TestHeaderProtector_MinPacketSizeForEncryption_Boundary(t *testing.T) {
	// MinPacketSizeForEncryption (56) is documented as the minimum for long
	// headers to have valid IV extraction room; verify at-boundary and
	// one-below behavior for a long-header type.
	hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), HeaderTypeRetry)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	atMin := buildProtectablePacket(hp.getHeaderSize() + 24) // 32+24=56
	if len(atMin) != MinPacketSizeForEncryption {
		t.Fatalf("test setup error: expected %d bytes, got %d", MinPacketSizeForEncryption, len(atMin))
	}
	if err := hp.EncryptHeader(atMin); err != nil {
		t.Errorf("EncryptHeader at MinPacketSizeForEncryption boundary: unexpected error: %v", err)
	}

	belowMin := buildProtectablePacket(MinPacketSizeForEncryption - 1)
	if err := hp.EncryptHeader(belowMin); err == nil {
		t.Error("expected error one byte below MinPacketSizeForEncryption")
	}
}

func TestHeaderProtector_IsLongHeader(t *testing.T) {
	longTypes := []HeaderType{
		HeaderTypeSessionRequest, HeaderTypeSessionCreated, HeaderTypeRetry,
		HeaderTypeTokenRequest, HeaderTypePeerTest, HeaderTypeHolePunch,
	}
	shortTypes := []HeaderType{HeaderTypeSessionConfirmed, HeaderTypeData}

	for _, ht := range longTypes {
		hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), ht)
		if err != nil {
			t.Fatalf("headerType %v: error = %v", ht, err)
		}
		if !hp.IsLongHeader() {
			t.Errorf("headerType %v: expected IsLongHeader() = true", ht)
		}
	}
	for _, ht := range shortTypes {
		hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), ht)
		if err != nil {
			t.Fatalf("headerType %v: error = %v", ht, err)
		}
		if hp.IsLongHeader() {
			t.Errorf("headerType %v: expected IsLongHeader() = false", ht)
		}
	}
}

func TestHeaderProtector_GenerateMask_Deterministic(t *testing.T) {
	hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), HeaderTypeData)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	key := fixedKey(9)
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	mask1, err := hp.GenerateMask(key, nonce)
	if err != nil {
		t.Fatalf("GenerateMask error = %v", err)
	}
	mask2, err := hp.GenerateMask(key, nonce)
	if err != nil {
		t.Fatalf("GenerateMask error = %v", err)
	}
	if !bytes.Equal(mask1, mask2) {
		t.Error("expected GenerateMask to be deterministic for the same key/nonce")
	}
	if len(mask1) != 8 {
		t.Errorf("expected 8-byte mask, got %d bytes", len(mask1))
	}

	differentNonce := make([]byte, 12)
	differentNonce[0] = 0xFF
	mask3, err := hp.GenerateMask(key, differentNonce)
	if err != nil {
		t.Fatalf("GenerateMask error = %v", err)
	}
	if bytes.Equal(mask1, mask3) {
		t.Error("expected different nonces to produce different masks")
	}
}

func TestHeaderProtector_UpdateKeys(t *testing.T) {
	hp, err := NewHeaderProtector(fixedKey(1), fixedKey(2), HeaderTypeData)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}

	newK1 := fixedKey(0xAA)
	newK2 := fixedKey(0xBB)
	if err := hp.UpdateKeys(newK1, newK2); err != nil {
		t.Fatalf("UpdateKeys error = %v", err)
	}

	if err := hp.UpdateKeys(make([]byte, HeaderKeySize-1), newK2); err == nil {
		t.Error("expected error for invalid key size in UpdateKeys")
	}
}
