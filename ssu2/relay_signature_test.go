package ssu2

import (
	"crypto/ed25519"
	"github.com/go-i2p/crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRelayRequestSignedData(t *testing.T) {
	var bobHash data.Hash
	var charlieHash data.Hash
	for i := range bobHash {
		bobHash[i] = byte(i)
		charlieHash[i] = byte(i + 32)
	}

	result, err := BuildRelayRequestSignedData(
		bobHash, charlieHash,
		0x12345678, 0xAABBCCDD, 0x60000000,
		2, 8080, net.IPv4(192, 168, 1, 1),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + chash(32) + nonce(4) + tag(4) + ts(4) + ver(1) + asz(1) + port(2) + ip(4) = 100
	assert.Equal(t, 100, len(result))
	assert.Equal(t, RelayRequestPrologue, string(result[:16]))
	assert.Equal(t, bobHash[:], result[16:48])
	assert.Equal(t, charlieHash[:], result[48:80])
}

func TestBuildRelayRequestSignedDataIPv6(t *testing.T) {
	var bobHash data.Hash
	var charlieHash data.Hash

	result, err := BuildRelayRequestSignedData(
		bobHash, charlieHash,
		1, 2, 3, 2, 8080,
		net.ParseIP("2001:db8::1"),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + chash(32) + nonce(4) + tag(4) + ts(4) + ver(1) + asz(1) + port(2) + ip(16) = 112
	assert.Equal(t, 112, len(result))
}

func TestBuildRelayRequestSignedDataInvalidHash(t *testing.T) {
	// With data.Hash as [32]byte, both hashes are always valid 32 bytes.
	// This test now just verifies the function works with zero hashes.
	_, err := BuildRelayRequestSignedData(
		data.Hash{}, data.Hash{},
		1, 2, 3, 2, 8080, net.IPv4(1, 2, 3, 4),
	)
	assert.NoError(t, err)
}

func TestSignAndVerifyRelayRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bobHash := generateRandomHash()
	charlieHash := generateRandomHash()
	now := uint32(time.Now().Unix())

	sig, err := SignRelayRequest(
		priv, bobHash, charlieHash,
		42, 100, now, 2, 9000,
		net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.Equal(t, ed25519.SignatureSize, len(sig))

	valid, err := VerifyRelayRequestSignature(
		pub, sig, bobHash, charlieHash,
		42, 100, now, 2, 9000,
		net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyRelayRequestWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	bobHash := generateRandomHash()
	charlieHash := generateRandomHash()

	sig, err := SignRelayRequest(
		priv, bobHash, charlieHash,
		1, 2, 3, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)

	valid, err := VerifyRelayRequestSignature(
		otherPub, sig, bobHash, charlieHash,
		1, 2, 3, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestBuildRelayResponseSignedData(t *testing.T) {
	bobHash := generateRandomHash()

	result, err := BuildRelayResponseSignedData(
		bobHash, 1, 2, 2, 8080, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + nonce(4) + ts(4) + ver(1) + csz(1) + port(2) + ip(4) = 64
	assert.Equal(t, 64, len(result))
	assert.Equal(t, RelayAgreementPrologue, string(result[:16]))
}

func TestBuildRelayResponseSignedDataNoAddress(t *testing.T) {
	bobHash := generateRandomHash()

	result, err := BuildRelayResponseSignedData(
		bobHash, 1, 2, 2, 0, nil,
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + nonce(4) + ts(4) + ver(1) + csz(1) = 58
	assert.Equal(t, 58, len(result))
}

func TestSignAndVerifyRelayResponse(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bobHash := generateRandomHash()
	now := uint32(time.Now().Unix())

	sig, err := SignRelayResponse(
		priv, bobHash,
		42, now, 2, 9000,
		net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.Equal(t, ed25519.SignatureSize, len(sig))

	valid, err := VerifyRelayResponseSignature(
		pub, sig, bobHash,
		42, now, 2, 9000,
		net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestRelayPrologueConstants(t *testing.T) {
	assert.Equal(t, 16, len(RelayRequestPrologue))
	assert.Equal(t, 16, len(RelayAgreementPrologue))
}
