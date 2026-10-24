package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIntroKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func testRetryHeader() []byte {
	header := make([]byte, LongHeaderSize)
	header[12] = MessageTypeRetry
	header[13] = SSU2ProtocolVersion
	header[14] = SSU2NetworkID
	return header
}

func TestEncryptIntroKeyAEAD_RoundTrip(t *testing.T) {
	key := testIntroKey()
	header := testRetryHeader()
	payload := []byte("datetime+address blocks go here")
	const pktNum = uint32(0x11223344)

	ct, mac, err := EncryptIntroKeyAEAD(key[:], header, payload, pktNum)
	require.NoError(t, err)
	assert.Len(t, mac, MACSize)
	assert.Len(t, ct, len(payload))

	got, err := DecryptIntroKeyAEAD(key[:], header, ct, mac, pktNum)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestEncryptIntroKeyAEAD_HeaderIsAssociatedData pins the ssu2.rst §"KDF for
// Retry" contract that ad is the cleartext header: any header tamper must fail
// authentication.
func TestEncryptIntroKeyAEAD_HeaderIsAssociatedData(t *testing.T) {
	key := testIntroKey()
	header := testRetryHeader()
	payload := []byte("payload bytes here ok")

	ct, mac, err := EncryptIntroKeyAEAD(key[:], header, payload, 7)
	require.NoError(t, err)

	tampered := make([]byte, len(header))
	copy(tampered, header)
	tampered[0] ^= 0x01

	_, err = DecryptIntroKeyAEAD(key[:], tampered, ct, mac, 7)
	assert.Error(t, err, "header is AEAD-associated data and must not be tamperable")
}

// TestEncryptIntroKeyAEAD_PacketNumberIsNonce verifies the 4-byte header packet
// number is the nonce, so a retry replayed with a different number fails.
func TestEncryptIntroKeyAEAD_PacketNumberIsNonce(t *testing.T) {
	key := testIntroKey()
	header := testRetryHeader()
	payload := []byte("payload bytes here ok")

	ct, mac, err := EncryptIntroKeyAEAD(key[:], header, payload, 1)
	require.NoError(t, err)

	_, err = DecryptIntroKeyAEAD(key[:], header, ct, mac, 2)
	assert.Error(t, err, "packet number is the AEAD nonce")
}

func TestEncryptIntroKeyAEAD_WrongKeyFails(t *testing.T) {
	key := testIntroKey()
	header := testRetryHeader()
	payload := []byte("payload bytes here ok")

	ct, mac, err := EncryptIntroKeyAEAD(key[:], header, payload, 3)
	require.NoError(t, err)

	var other [32]byte
	other[0] = 0xff
	_, err = DecryptIntroKeyAEAD(other[:], header, ct, mac, 3)
	assert.Error(t, err)
}

func TestEncryptIntroKeyAEAD_ValidatesInputs(t *testing.T) {
	key := testIntroKey()
	header := testRetryHeader()
	payload := []byte("payload")

	_, _, err := EncryptIntroKeyAEAD(make([]byte, 16), header, payload, 1)
	assert.Error(t, err, "intro key must be 32 bytes")

	_, _, err = EncryptIntroKeyAEAD(key[:], make([]byte, ShortHeaderSize), payload, 1)
	assert.Error(t, err, "associated data must be the 32-byte long header")

	_, err = DecryptIntroKeyAEAD(key[:], header, payload, make([]byte, 8), 1)
	assert.Error(t, err, "MAC must be 16 bytes")
}

func TestRetryAEADNonce_Layout(t *testing.T) {
	// Four leading zero bytes then the counter little-endian, matching
	// noise.BuildNonce (the convention the data-phase AEAD uses).
	nonce := retryAEADNonce(0x01020304)
	assert.Equal(t, []byte{0, 0, 0, 0, 4, 3, 2, 1, 0, 0, 0, 0}, nonce)
}
