package ssu2

import (
	"bytes"
	"github.com/go-i2p/crypto/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a test packet with enough data for header protection
func createTestPacket(headerSize, totalSize int) []byte {
	if totalSize < headerSize+24 {
		totalSize = headerSize + 24
	}
	packet := make([]byte, totalSize)
	rand.Read(packet)
	return packet
}

// Helper to create test keys
func createTestKey() []byte {
	key := make([]byte, HeaderKeySize)
	rand.Read(key)
	return key
}

func TestNewHeaderProtector_ValidKeys(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeData, hp.GetHeaderType())
}

func TestNewHeaderProtector_InvalidK1Size(t *testing.T) {
	k1 := make([]byte, 16) // Wrong size
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "kHeader1 must be exactly 32 bytes")
}

func TestNewHeaderProtector_InvalidK2Size(t *testing.T) {
	k1 := createTestKey()
	k2 := make([]byte, 64) // Wrong size

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "kHeader2 must be exactly 32 bytes")
}

func TestNewHeaderProtectorFromIntroKey(t *testing.T) {
	introKey := createTestKey()

	hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeSessionRequest, hp.GetHeaderType())
}

func TestHeaderProtector_EncryptDecrypt_ShortHeader(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	require.NoError(t, err)

	// Create a test packet with short header (16 bytes)
	original := createTestPacket(ShortHeaderSize, 100)
	packet := make([]byte, len(original))
	copy(packet, original)

	// Encrypt header
	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	// Verify bytes 0-15 are modified (header is encrypted)
	assert.NotEqual(t, original[:16], packet[:16], "header should be encrypted")

	// Verify rest of packet is unchanged
	assert.Equal(t, original[16:], packet[16:], "payload should be unchanged")

	// Decrypt header
	err = hp.DecryptHeader(packet)
	require.NoError(t, err)

	// Verify header is restored
	assert.Equal(t, original[:16], packet[:16], "header should be decrypted to original")
}

func TestHeaderProtector_EncryptDecrypt_LongHeader(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Create a test packet with long header (32 bytes) + ephemeral key area (32 bytes) + payload
	original := createTestPacket(LongHeaderSize, 128)
	packet := make([]byte, len(original))
	copy(packet, original)

	// Encrypt header
	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	// Per SSU2 spec: for SessionRequest, bytes 16-63 are encrypted with ChaCha20(k2, iv=zeros)
	// So bytes 0-63 should be modified (header + ephemeral key area)
	assert.NotEqual(t, original[:LongHeaderSize], packet[:LongHeaderSize], "long header should be encrypted")

	// Verify bytes 64+ are unchanged (payload beyond ephemeral key)
	assert.Equal(t, original[64:], packet[64:], "payload beyond ephemeral key should be unchanged")

	// Decrypt header
	err = hp.DecryptHeader(packet)
	require.NoError(t, err)

	// Verify full header + ephemeral key area is restored
	assert.Equal(t, original[:64], packet[:64], "long header + ephemeral key should be decrypted to original")
}

func TestHeaderProtector_PacketTooSmall(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	require.NoError(t, err)

	// Packet too small for short header (need 16 + 24 = 40 bytes minimum)
	smallPacket := make([]byte, 30)

	err = hp.EncryptHeader(smallPacket)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "packet too small")
}

func TestHeaderProtector_LongHeader_PacketTooSmall(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Packet too small for long header (need 32 + 24 = 56 bytes minimum)
	smallPacket := make([]byte, 50)

	err = hp.EncryptHeader(smallPacket)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "packet too small")
}

func TestHeaderProtector_XORSymmetry(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	require.NoError(t, err)

	original := createTestPacket(ShortHeaderSize, 100)

	// Test that double-encryption returns to original (XOR symmetry)
	packet := make([]byte, len(original))
	copy(packet, original)

	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	err = hp.EncryptHeader(packet) // Encrypt again (should decrypt)
	require.NoError(t, err)

	assert.Equal(t, original, packet, "double encryption should return to original")
}

func TestHeaderProtector_DifferentKeysProduceDifferentOutput(t *testing.T) {
	k1a := createTestKey()
	k2a := createTestKey()
	k1b := createTestKey()
	k2b := createTestKey()

	hp1, _ := NewHeaderProtector(k1a, k2a, HeaderTypeData)
	hp2, _ := NewHeaderProtector(k1b, k2b, HeaderTypeData)

	original := createTestPacket(ShortHeaderSize, 100)

	packet1 := make([]byte, len(original))
	copy(packet1, original)
	hp1.EncryptHeader(packet1)

	packet2 := make([]byte, len(original))
	copy(packet2, original)
	hp2.EncryptHeader(packet2)

	assert.NotEqual(t, packet1[:16], packet2[:16], "different keys should produce different encrypted headers")
}

func TestHeaderProtector_UpdateKeys(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, err := NewHeaderProtector(k1, k2, HeaderTypeData)
	require.NoError(t, err)

	original := createTestPacket(ShortHeaderSize, 100)
	packet1 := make([]byte, len(original))
	copy(packet1, original)
	hp.EncryptHeader(packet1)

	// Update keys
	newK1 := createTestKey()
	newK2 := createTestKey()
	err = hp.UpdateKeys(newK1, newK2)
	require.NoError(t, err)

	packet2 := make([]byte, len(original))
	copy(packet2, original)
	hp.EncryptHeader(packet2)

	// Should produce different encryption with new keys
	assert.NotEqual(t, packet1[:16], packet2[:16], "updated keys should produce different encrypted headers")
}

func TestHeaderProtector_UpdateKeys_InvalidSize(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeData)

	err := hp.UpdateKeys(make([]byte, 16), k2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kHeader1")

	err = hp.UpdateKeys(k1, make([]byte, 48))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kHeader2")
}

func TestHeaderProtector_SetHeaderType(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeData)
	assert.Equal(t, HeaderTypeData, hp.GetHeaderType())

	hp.SetHeaderType(HeaderTypeSessionConfirmed)
	assert.Equal(t, HeaderTypeSessionConfirmed, hp.GetHeaderType())
}

func TestHeaderProtector_IsLongHeader(t *testing.T) {
	tests := []struct {
		headerType HeaderType
		isLong     bool
	}{
		{HeaderTypeSessionRequest, true},
		{HeaderTypeSessionCreated, true},
		{HeaderTypeRetry, true},
		{HeaderTypeTokenRequest, true},
		{HeaderTypePeerTest, true},
		{HeaderTypeHolePunch, true},
		{HeaderTypeSessionConfirmed, false},
		{HeaderTypeData, false},
	}

	k1 := createTestKey()
	k2 := createTestKey()

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			hp, _ := NewHeaderProtector(k1, k2, tt.headerType)
			assert.Equal(t, tt.isLong, hp.IsLongHeader())
		})
	}
}

func TestHeaderProtector_ConcurrentAccess(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeData)

	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			packet := createTestPacket(ShortHeaderSize, 100)
			original := make([]byte, len(packet))
			copy(original, packet)

			hp.EncryptHeader(packet)
			hp.DecryptHeader(packet)

			assert.Equal(t, original, packet)
		}()
	}

	wg.Wait()
}

func TestNewHeaderProtectorManager_ValidIntroKey(t *testing.T) {
	introKey := createTestKey()

	hpm, err := NewHeaderProtectorManager(introKey, nil, true)
	require.NoError(t, err)
	require.NotNil(t, hpm)
}

func TestNewHeaderProtectorManager_InvalidIntroKey(t *testing.T) {
	shortKey := make([]byte, 16)

	hpm, err := NewHeaderProtectorManager(shortKey, nil, true)
	assert.Error(t, err)
	assert.Nil(t, hpm)
	assert.Contains(t, err.Error(), "intro key must be exactly 32 bytes")
}

func TestHeaderProtectorManager_GetProtectorForType_SessionRequest_Initiator(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	hp, err := hpm.GetProtectorForType(HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeSessionRequest, hp.GetHeaderType())
}

func TestHeaderProtectorManager_GetProtectorForType_SessionRequest_MissingRemoteKey(t *testing.T) {
	introKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, nil, true)

	hp, err := hpm.GetProtectorForType(HeaderTypeSessionRequest)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "remote intro key required")
}

func TestHeaderProtectorManager_GetProtectorForType_SessionCreated(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	// SessionCreated requires SessCreateHeader key per spec
	sessCreateKey := createTestKey()
	require.NoError(t, hpm.SetSessCreateHeaderKey(sessCreateKey))

	hp, err := hpm.GetProtectorForType(HeaderTypeSessionCreated)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeSessionCreated, hp.GetHeaderType())
}

func TestHeaderProtectorManager_GetProtectorForType_SessionCreated_MissingKDFKeys(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	hp, err := hpm.GetProtectorForType(HeaderTypeSessionCreated)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "SessCreateHeader k_header_2 required")
}

func TestHeaderProtectorManager_GetProtectorForType_Data_MissingKDFKeys(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	hp, err := hpm.GetProtectorForType(HeaderTypeData)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "send data k_header_2 required")
}

func TestHeaderProtectorManager_SetKDFKeys(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	kdf1 := createTestKey()
	kdf2 := createTestKey()

	err := hpm.SetKDFKeys(kdf1, kdf2)
	require.NoError(t, err)

	// Now Data type should work (outbound uses remoteIntroKey + sendDataHeader2)
	hp, err := hpm.GetProtectorForType(HeaderTypeData)
	require.NoError(t, err)
	require.NotNil(t, hp)
}

func TestHeaderProtectorManager_SetKDFKeys_InvalidSize(t *testing.T) {
	introKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, nil, true)

	err := hpm.SetKDFKeys(make([]byte, 16), createTestKey())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sendKH2")

	err = hpm.SetKDFKeys(createTestKey(), make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recvKH2")
}

func TestHeaderProtectorManager_SetRemoteIntroKey(t *testing.T) {
	introKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, nil, true)

	// Without remote key, session request fails
	_, err := hpm.GetProtectorForType(HeaderTypeSessionRequest)
	assert.Error(t, err)

	// Set remote key
	remoteKey := createTestKey()
	err = hpm.SetRemoteIntroKey(remoteKey)
	require.NoError(t, err)

	// Now should work
	hp, err := hpm.GetProtectorForType(HeaderTypeSessionRequest)
	require.NoError(t, err)
	require.NotNil(t, hp)
}

func TestHeaderProtectorManager_SetRemoteIntroKey_InvalidSize(t *testing.T) {
	introKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, nil, true)

	err := hpm.SetRemoteIntroKey(make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "remote intro key must be exactly 32 bytes")
}

func TestHeaderProtectorManager_EncryptDecryptOutboundInbound(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	original := createTestPacket(LongHeaderSize, 128)
	packet := make([]byte, len(original))
	copy(packet, original)

	// Encrypt outbound
	err := hpm.EncryptOutboundHeader(packet, HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Create receiver's manager
	receiverHPM, _ := NewHeaderProtectorManager(remoteIntroKey, introKey, false)

	// Decrypt inbound
	err = receiverHPM.DecryptInboundHeader(packet, HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Verify header is restored
	assert.Equal(t, original, packet, "decrypted should match original")
}

func TestHeaderProtectorManager_GetProtectorForType_PeerTest(t *testing.T) {
	introKey := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, nil, true)

	// Peer Test is not supported via GetProtectorForType
	hp, err := hpm.GetProtectorForType(HeaderTypePeerTest)
	assert.Error(t, err)
	assert.Nil(t, hp)
	assert.Contains(t, err.Error(), "Peer Test requires target's intro key")
}

func TestHeaderProtectorManager_GetProtectorForType_Responder(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	// Responder (listener)
	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, false)

	// Retry as responder uses our intro key
	hp, err := hpm.GetProtectorForType(HeaderTypeRetry)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeRetry, hp.GetHeaderType())
}

func TestExtractConnectionID(t *testing.T) {
	header := make([]byte, 16)
	header[0] = 0x12
	header[1] = 0x34
	header[2] = 0x56
	header[3] = 0x78
	header[4] = 0x9A
	header[5] = 0xBC
	header[6] = 0xDE
	header[7] = 0xF0

	connID, err := ExtractConnectionID(header)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x123456789ABCDEF0), connID)
}

func TestExtractConnectionID_HeaderTooShort(t *testing.T) {
	header := make([]byte, 4)

	_, err := ExtractConnectionID(header)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header must be at least 8 bytes")
}

func TestEncodeConnectionID(t *testing.T) {
	header := make([]byte, 16)

	err := EncodeConnectionID(header, 0x123456789ABCDEF0)
	require.NoError(t, err)

	expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	assert.Equal(t, expected, header[:8])
}

func TestEncodeConnectionID_HeaderTooShort(t *testing.T) {
	header := make([]byte, 4)

	err := EncodeConnectionID(header, 0x123456789ABCDEF0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header must be at least 8 bytes")
}

func TestExtractPacketNumber(t *testing.T) {
	header := make([]byte, 16)
	header[8] = 0x12
	header[9] = 0x34
	header[10] = 0x56
	header[11] = 0x78

	pktNum, err := ExtractPacketNumber(header)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x12345678), pktNum)
}

func TestExtractPacketNumber_HeaderTooShort(t *testing.T) {
	header := make([]byte, 8)

	_, err := ExtractPacketNumber(header)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header must be at least 12 bytes")
}

func TestEncodePacketNumber(t *testing.T) {
	header := make([]byte, 16)

	err := EncodePacketNumber(header, 0x12345678)
	require.NoError(t, err)

	expected := []byte{0x12, 0x34, 0x56, 0x78}
	assert.Equal(t, expected, header[8:12])
}

func TestEncodePacketNumber_HeaderTooShort(t *testing.T) {
	header := make([]byte, 8)

	err := EncodePacketNumber(header, 0x12345678)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header must be at least 12 bytes")
}

func TestHeaderProtector_DeterministicOutput(t *testing.T) {
	// Same keys + same packet = same encryption
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	for i := range k1 {
		k1[i] = byte(i)
		k2[i] = byte(255 - i)
	}

	hp1, _ := NewHeaderProtector(k1, k2, HeaderTypeData)
	hp2, _ := NewHeaderProtector(k1, k2, HeaderTypeData)

	// Create identical packets
	packet1 := make([]byte, 100)
	packet2 := make([]byte, 100)
	for i := range packet1 {
		packet1[i] = byte(i)
		packet2[i] = byte(i)
	}

	hp1.EncryptHeader(packet1)
	hp2.EncryptHeader(packet2)

	assert.Equal(t, packet1, packet2, "same keys and packet should produce same encryption")
}

func TestHeaderProtector_AllHeaderTypes_Roundtrip(t *testing.T) {
	headerTypes := []HeaderType{
		HeaderTypeSessionRequest,
		HeaderTypeSessionCreated,
		HeaderTypeRetry,
		HeaderTypeTokenRequest,
		HeaderTypeSessionConfirmed,
		HeaderTypeData,
		HeaderTypePeerTest,
		HeaderTypeHolePunch,
	}

	k1 := createTestKey()
	k2 := createTestKey()

	for _, ht := range headerTypes {
		t.Run("", func(t *testing.T) {
			hp, err := NewHeaderProtector(k1, k2, ht)
			require.NoError(t, err)

			headerSize := ShortHeaderSize
			if hp.IsLongHeader() {
				headerSize = LongHeaderSize
			}

			original := createTestPacket(headerSize, headerSize+50)
			packet := make([]byte, len(original))
			copy(packet, original)

			err = hp.EncryptHeader(packet)
			require.NoError(t, err)

			err = hp.DecryptHeader(packet)
			require.NoError(t, err)

			assert.Equal(t, original, packet, "roundtrip should preserve packet")
		})
	}
}

func TestHeaderProtector_LongHeader_FullEncryption(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeSessionRequest)

	// Create packet with recognizable pattern in header bytes 16-31
	packet := createTestPacket(LongHeaderSize, 128)
	for i := 16; i < 32; i++ {
		packet[i] = 0xAA // Set a pattern we can detect
	}
	original := make([]byte, len(packet))
	copy(original, packet)

	hp.EncryptHeader(packet)

	// Check that bytes 16-31 are encrypted (not 0xAA anymore)
	allAA := true
	for i := 16; i < 32; i++ {
		if packet[i] != 0xAA {
			allAA = false
			break
		}
	}
	assert.False(t, allAA, "bytes 16-31 should be encrypted")
}

func TestGenerateMask(t *testing.T) {
	k := createTestKey()
	hp, _ := NewHeaderProtector(k, k, HeaderTypeData)

	nonce := make([]byte, 12)
	mask1, err := hp.GenerateMask(k, nonce)
	require.NoError(t, err)
	assert.Len(t, mask1, 8)

	// Same key + nonce = same mask
	mask2, err := hp.GenerateMask(k, nonce)
	require.NoError(t, err)
	assert.Equal(t, mask1, mask2)

	// Different nonce = different mask
	differentNonce := make([]byte, 12)
	differentNonce[0] = 1
	mask3, err := hp.GenerateMask(k, differentNonce)
	require.NoError(t, err)
	assert.NotEqual(t, mask1, mask3)
}

func TestHeaderProtector_IVExtraction(t *testing.T) {
	// This test verifies that IV extraction from packet produces consistent encryption
	k1 := createTestKey()
	k2 := createTestKey()

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeData)

	// Create two packets with same header but different IV positions (last 24 bytes)
	packet1 := createTestPacket(ShortHeaderSize, 100)
	packet2 := make([]byte, len(packet1))
	copy(packet2, packet1)

	// Modify the last 24 bytes (IV source)
	for i := len(packet1) - 24; i < len(packet1); i++ {
		packet2[i] = packet1[i] ^ 0xFF
	}

	original1 := make([]byte, len(packet1))
	copy(original1, packet1)
	original2 := make([]byte, len(packet2))
	copy(original2, packet2)

	hp.EncryptHeader(packet1)
	hp.EncryptHeader(packet2)

	// Encrypted headers should be different because IVs are different
	assert.NotEqual(t, packet1[:16], packet2[:16], "different IVs should produce different encryptions")

	// But both should decrypt correctly
	hp.DecryptHeader(packet1)
	hp.DecryptHeader(packet2)

	assert.Equal(t, original1, packet1)
	assert.Equal(t, original2, packet2)
}

func TestHeaderProtectorManager_Retry_Responder(t *testing.T) {
	introKey := createTestKey()

	// As responder (not initiator)
	hpm, _ := NewHeaderProtectorManager(introKey, nil, false)

	// Should be able to get protector for Retry (uses our intro key)
	hp, err := hpm.GetProtectorForType(HeaderTypeRetry)
	require.NoError(t, err)
	require.NotNil(t, hp)
}

func TestHeaderProtectorManager_SessionConfirmed_WithKDFKeys(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()

	// Initiator: k_header_1 = remoteIntroKey (bik per spec)
	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, true)

	// Set KDF keys for data phase
	kdf1 := createTestKey()
	kdf2 := createTestKey()
	hpm.SetKDFKeys(kdf1, kdf2)
	// Set SessionConfirmed header key (derived from "SessionConfirmed" KDF per spec)
	sessConfKey := createTestKey()
	hpm.SetSessionConfirmedHeaderKey(sessConfKey)

	hp, err := hpm.GetProtectorForType(HeaderTypeSessionConfirmed)
	require.NoError(t, err)
	require.NotNil(t, hp)
	assert.Equal(t, HeaderTypeSessionConfirmed, hp.GetHeaderType())

	// Responder: k_header_1 = introKey (own intro key = bik per spec)
	hpmResp, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, false)
	hpmResp.SetKDFKeys(kdf1, kdf2)
	hpmResp.SetSessionConfirmedHeaderKey(sessConfKey)

	hpResp, err := hpmResp.GetProtectorForType(HeaderTypeSessionConfirmed)
	require.NoError(t, err)
	require.NotNil(t, hpResp)
	assert.Equal(t, HeaderTypeSessionConfirmed, hpResp.GetHeaderType())
}

func TestHeaderProtector_DefensiveCopy(t *testing.T) {
	k1 := createTestKey()
	k2 := createTestKey()
	origK1 := make([]byte, len(k1))
	copy(origK1, k1)

	hp, _ := NewHeaderProtector(k1, k2, HeaderTypeData)

	// Modify original key
	k1[0] = 0xFF

	// Encrypt should still work with original key value
	packet := createTestPacket(ShortHeaderSize, 100)
	original := make([]byte, len(packet))
	copy(original, packet)

	hp.EncryptHeader(packet)

	// Create new protector with original key value to verify
	hp2, _ := NewHeaderProtector(origK1, k2, HeaderTypeData)
	packet2 := make([]byte, len(original))
	copy(packet2, original)
	hp2.EncryptHeader(packet2)

	// Should match because hp has a copy of the original key
	assert.True(t, bytes.Equal(packet, packet2), "defensive copy should preserve key")
}

func TestHeaderProtectorManager_AllTypes_Responder(t *testing.T) {
	introKey := createTestKey()
	remoteIntroKey := createTestKey()
	kdf1 := createTestKey()
	kdf2 := createTestKey()

	hpm, _ := NewHeaderProtectorManager(introKey, remoteIntroKey, false)
	hpm.SetKDFKeys(kdf1, kdf2)
	// Set intermediate header keys per spec
	hpm.SetSessCreateHeaderKey(createTestKey())
	hpm.SetSessionConfirmedHeaderKey(createTestKey())

	// Session Request as responder (receiving)
	hp, err := hpm.GetProtectorForType(HeaderTypeSessionRequest)
	require.NoError(t, err)
	assert.NotNil(t, hp)

	// Session Created as responder (sending)
	hp, err = hpm.GetProtectorForType(HeaderTypeSessionCreated)
	require.NoError(t, err)
	assert.NotNil(t, hp)

	// Data as responder
	hp, err = hpm.GetProtectorForType(HeaderTypeData)
	require.NoError(t, err)
	assert.NotNil(t, hp)
}

func TestHeaderProtector_MinimumPacketSize(t *testing.T) {
	k := createTestKey()

	// Short header: needs 16 + 24 = 40 bytes minimum
	hpShort, _ := NewHeaderProtector(k, k, HeaderTypeData)
	packetExact := make([]byte, ShortHeaderSize+24)
	err := hpShort.EncryptHeader(packetExact)
	assert.NoError(t, err, "exact minimum size should work")

	packetTooSmall := make([]byte, ShortHeaderSize+23)
	err = hpShort.EncryptHeader(packetTooSmall)
	assert.Error(t, err, "one byte less than minimum should fail")

	// Long header: needs 32 + 24 = 56 bytes minimum
	hpLong, _ := NewHeaderProtector(k, k, HeaderTypeSessionRequest)
	packetExactLong := make([]byte, LongHeaderSize+24)
	err = hpLong.EncryptHeader(packetExactLong)
	assert.NoError(t, err, "exact minimum size for long header should work")

	packetTooSmallLong := make([]byte, LongHeaderSize+23)
	err = hpLong.EncryptHeader(packetTooSmallLong)
	assert.Error(t, err, "one byte less than minimum should fail for long header")
}
