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

func TestPeerTestPrologueLength(t *testing.T) {
	assert.Equal(t, 16, len(PeerTestPrologue))
}

func TestBuildPeerTestSignedDataMsg1(t *testing.T) {
	var bobHash data.Hash
	for i := range bobHash {
		bobHash[i] = byte(i)
	}

	data, err := BuildPeerTestSignedData(
		bobHash, nil,
		2, 0x12345678, 0x60000000,
		8080, net.IPv4(192, 168, 1, 1),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + ver(1) + nonce(4) + ts(4) + asz(1) + port(2) + ip(4) = 64
	assert.Equal(t, 64, len(data))
	assert.Equal(t, PeerTestPrologue, string(data[:16]))
	assert.Equal(t, bobHash[:], data[16:48])
}

func TestBuildPeerTestSignedDataMsg3WithAliceHash(t *testing.T) {
	var bobHash data.Hash
	var aliceHash data.Hash
	for i := range aliceHash {
		aliceHash[i] = byte(i + 100)
	}

	data, err := BuildPeerTestSignedData(
		bobHash, &aliceHash,
		2, 1, 2,
		8080, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + ahash(32) + ver(1) + nonce(4) + ts(4) + asz(1) + port(2) + ip(4) = 96
	assert.Equal(t, 96, len(data))
	assert.Equal(t, aliceHash[:], data[48:80])
}

func TestBuildPeerTestSignedDataIPv6(t *testing.T) {
	var bobHash data.Hash

	data, err := BuildPeerTestSignedData(
		bobHash, nil,
		2, 1, 2,
		8080, net.ParseIP("2001:db8::1"),
	)
	require.NoError(t, err)

	// prologue(16) + bhash(32) + ver(1) + nonce(4) + ts(4) + asz(1) + port(2) + ip(16) = 76
	assert.Equal(t, 76, len(data))
}

func TestSignAndVerifyPeerTestMsg1(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bobHash := generateRandomHash()
	now := uint32(time.Now().Unix())

	sig, err := SignPeerTest(
		priv, bobHash, nil,
		2, 42, now,
		9000, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.Equal(t, ed25519.SignatureSize, len(sig))

	valid, err := VerifyPeerTestSignature(
		pub, sig, bobHash, nil,
		2, 42, now,
		9000, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestSignAndVerifyPeerTestMsg3(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bobHash := generateRandomHash()
	aliceHash := generateRandomHash()
	now := uint32(time.Now().Unix())

	sig, err := SignPeerTest(
		priv, bobHash, &aliceHash,
		2, 42, now,
		9000, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)

	valid, err := VerifyPeerTestSignature(
		pub, sig, bobHash, &aliceHash,
		2, 42, now,
		9000, net.IPv4(10, 0, 0, 1),
	)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyPeerTestWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	bobHash := generateRandomHash()

	sig, err := SignPeerTest(
		priv, bobHash, nil,
		2, 1, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)

	valid, err := VerifyPeerTestSignature(
		otherPub, sig, bobHash, nil,
		2, 1, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyPeerTestMismatchedAliceHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	bobHash := generateRandomHash()
	aliceHash := generateRandomHash()
	wrongHash := generateRandomHash()
	wrongHash[0] = 0xFF

	sig, err := SignPeerTest(
		priv, bobHash, &aliceHash,
		2, 1, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)

	valid, err := VerifyPeerTestSignature(
		pub, sig, bobHash, &wrongHash,
		2, 1, 2, 80, net.IPv4(1, 2, 3, 4),
	)
	require.NoError(t, err)
	assert.False(t, valid)
}
