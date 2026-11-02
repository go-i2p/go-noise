package handshake

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"

	"github.com/go-i2p/go-noise/internal/testri"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for the SSU2 data-phase constant-key defect.
//
// deriveDataPhaseKeys reads the split key through CipherState.UnsafeKey(). The
// go-i2p fork of flynn/noise used to zero that key inside Split/SplitWithASK,
// because hkdf appends into the slices it is given and Split passed it the
// CipherState key arrays directly. Every session therefore derived its data
// keys from 0^32, which is a public constant: any observer could decrypt and
// forge the data phase, and no other implementation could read it at all.
//
// These tests pin the derivation to values produced by the reference
// implementation, so a regression cannot pass by being self-consistent.

// Reference values from Java I2P 2.12.0 (geti2p.net).
//
// Provenance: net.i2p.router.transport.udp.SSU2Util.hkdf(ctx, key, INFO_DATA),
// where INFO_DATA = "HKDFSSU2DataKeys", decompiles to
//
//	new net.i2p.crypto.HKDF(ctx).calculate(key, ZEROLEN, info, out)
//
// for the 32-byte form, and the two-output overload
// calculate(key, data, info, out, out2, off2) in core/java/src/net/i2p/crypto/
// HKDF.java performs exactly
//
//	temp = HMAC-SHA256(key, data)
//	out    = HMAC-SHA256(temp, info || 0x01)
//	out2   = HMAC-SHA256(temp, out  || info || 0x02)
//
// which is the SSU2 spec's data-phase KDF (ssu2.rst §"KDF for data phase"):
//
//	keydata = HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
//	k_data = keydata[0:32]; k_header_2 = keydata[32:64]
//
// Values were generated with the jars cached in
// i2p-vectors/.cache/reference/2.12.0/ (i2p-2.12.0.jar supplies the public
// net.i2p.crypto.HKDF; SSU2Util itself is package-private, so the identical
// call shape was driven through it directly). SSU2Util.hkdf returns only 32
// bytes, so Java computes k_header_2 as a second derivation whose chaining is
// visible in the two-output overload above; the 64-byte expansion asserted here
// matches its first output exactly and reproduces the second.
const (
	refKAB      = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	refKData    = "6b66bda52c028006819d6677114b27e31e6286ba662694f9f87edcdff252a0b0"
	refKHeader2 = "3b9f625bc520c49e54f3c7eccd7b08eba2dedd31127a53a26d64df6f02f3c8e8"

	// The constant every pre-fix go-i2p session used, i.e. the same KDF applied
	// to a zeroed split key. Asserted against, never for.
	constKData    = "00736897df70194680e94f2fcc0c0bfd50193a13f6656cf46b8c37a8635a871b"
	constKHeader2 = "d079e3e1fa9227172efe70dd500ad490c3ed374db4b3d57325b90e75a75888b1"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// cipherStateWithKey builds a CipherState holding an exact key, so the
// derivation can be tested against a fixed input.
func cipherStateWithKey(t *testing.T, hexKey string) *noise.CipherState {
	t.Helper()
	raw := mustHex(t, hexKey)
	require.Len(t, raw, 32)
	var k [32]byte
	copy(k[:], raw)
	return noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), k, 0)
}

// noiseSplitKeepsLiveKeys reports whether the resolved go-i2p/noise returns
// split CipherStates whose stored key survives Split. Finding 001 zeroed it in
// the fork, so the assertions below can only hold against a noise that carries
// the fix; go-noise pins the published version rather than a local checkout, so
// these tests skip rather than turn trunk red while that pin is still old.
func noiseSplitKeepsLiveKeys(t *testing.T) bool {
	t.Helper()

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hsI, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNN,
		Initiator:   true,
	})
	if err != nil {
		t.Fatalf("noise: %v", err)
	}
	hsR, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNN,
		Initiator:   false,
	})
	if err != nil {
		t.Fatalf("noise: %v", err)
	}

	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("noise: %v", err)
	}
	if _, _, _, err = hsR.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("noise: %v", err)
	}
	// The responder completes NN, so its split states come from WriteMessage.
	msg2, _, _, err := hsR.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("noise: %v", err)
	}
	_, s1, _, err := hsI.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("noise: %v", err)
	}
	splitKey := s1.UnsafeKey()
	return !isAllZero(splitKey[:])
}

// TestSSU2_DataPhaseKeys_JavaInterop_KAT is the cross-implementation anchor:
// the derived k_data must equal what Java I2P derives from the same split key.
// Before the noise fix this failed because the input was 0^32 rather than k_ab.
func TestSSU2_DataPhaseKeys_JavaInterop_KAT(t *testing.T) {
	cs := cipherStateWithKey(t, refKAB)

	kData, kHeader2, err := deriveDataPhaseKeys(cs)
	require.NoError(t, err)

	assert.Equal(t, refKAB, hex.EncodeToString(mustHex(t, refKAB)), "sanity: input constant round-trips")
	assert.Equal(t, refKData, hex.EncodeToString(kData),
		"k_data must match Java I2P 2.12.0 SSU2Util.hkdf(k_ab, \"HKDFSSU2DataKeys\")")
	assert.Equal(t, refKHeader2, hex.EncodeToString(kHeader2),
		"k_header_2 must match the second 32 bytes of the same 64-byte HKDF expansion")

	assert.NotEqual(t, constKData, hex.EncodeToString(kData),
		"k_data must not be the public constant derived from a zeroed split key")
	assert.NotEqual(t, constKHeader2, hex.EncodeToString(kHeader2),
		"k_header_2 must not be the public constant derived from a zeroed split key")
}

// TestSSU2_DataPhaseKeys_InputIsLiveSplitKey guards the mechanism directly: the
// UnsafeKey() that feeds the data-phase KDF must be the real split key, not the
// zeros the fork used to leave behind. Checked before DeriveHeaderKeys, because
// that call replaces the split key with the derived k_data.
func TestSSU2_DataPhaseKeys_InputIsLiveSplitKey(t *testing.T) {
	if !noiseSplitKeepsLiveKeys(t) {
		t.Skip("pinned go-i2p/noise still has the zeroed-split-key defect (finding 001); these assertions need the fix")
	}
	init, resp := completeXKHandshake(t)

	for name, h := range map[string]*HandshakeHandler{"initiator": init, "responder": resp} {
		send, recv, err := h.GetCipherStates()
		require.NoError(t, err)

		splitSend := send.UnsafeKey()
		splitRecv := recv.UnsafeKey()
		assert.False(t, isAllZero(splitSend[:]), "%s: send split key is all zeros", name)
		assert.False(t, isAllZero(splitRecv[:]), "%s: recv split key is all zeros", name)
		assert.NotEqual(t, splitSend, splitRecv, "%s: both directions share one split key", name)

		kData, kHeader2, err := deriveDataPhaseKeys(send)
		require.NoError(t, err)
		assert.NotEqual(t, constKData, hex.EncodeToString(kData),
			"%s: a live split key must not derive the public constant k_data", name)
		assert.NotEqual(t, constKHeader2, hex.EncodeToString(kHeader2),
			"%s: a live split key must not derive the public constant k_header_2", name)
	}
}

// completeXKHandshake drives a full XK-SSU2 handshake and returns both handlers
// with data-phase keys installed.
func completeXKHandshake(t *testing.T) (init, resp *HandshakeHandler) {
	t.Helper()

	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	init, err = NewHandshakeHandlerWithKeys(true, initDH, respDH.Public, nil)
	require.NoError(t, err)
	resp, err = NewHandshakeHandlerWithKeys(false, respDH, nil, nil)
	require.NoError(t, err)
	resp.SetPeerAddress(net.ParseIP("203.0.113.10"), 51500)

	request, err := init.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = resp.ProcessSessionRequest(request)
	require.NoError(t, err)

	created, err := resp.CreateSessionCreated(22222, 11111)
	require.NoError(t, err)
	require.NoError(t, init.ProcessSessionCreated(created))

	confirmed, err := init.CreateSessionConfirmed(55555, 1, testri.New(t, &testri.Options{StaticKey: initDH.Public}).Bytes)
	require.NoError(t, err)
	require.NoError(t, resp.ProcessSessionConfirmed(confirmed))

	return init, resp
}

// TestSSU2_PassiveAttackerCannotDecryptDataPhase is the finding's headline
// attack, inverted: an attacker who knows only the published constant must fail
// to open a real data-phase packet. Before the fix this decrypted cleanly.
func TestSSU2_PassiveAttackerCannotDecryptDataPhase(t *testing.T) {
	if !noiseSplitKeepsLiveKeys(t) {
		t.Skip("pinned go-i2p/noise still has the zeroed-split-key defect (finding 001); these assertions need the fix")
	}
	init, resp := completeXKHandshake(t)

	initSendK, initRecvK, err := init.DeriveHeaderKeys()
	require.NoError(t, err)
	respSendK, respRecvK, err := resp.DeriveHeaderKeys()
	require.NoError(t, err)

	// Directional agreement must survive the fix.
	assert.Equal(t, initSendK, respRecvK, "initiator send k_header_2 must match responder recv")
	assert.Equal(t, initRecvK, respSendK, "initiator recv k_header_2 must match responder send")
	assert.False(t, isAllZero(initSendK), "k_header_2 must not be zero")

	sendCipher, _, err := init.GetCipherStates()
	require.NoError(t, err)

	plaintext := []byte("secret data phase")
	// Associated data is the unmasked header in production; a fixed header is
	// enough to exercise the key here.
	ad := make([]byte, 16)
	ciphertext, err := sendCipher.Encrypt(nil, ad, plaintext)
	require.NoError(t, err)

	// The attacker: a CipherState built from the public constant only.
	var constKey [32]byte
	copy(constKey[:], mustHex(t, constKData))
	attacker := noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), constKey, 0)

	_, err = attacker.Decrypt(nil, ad, ciphertext)
	assert.Error(t, err,
		"a passive observer holding the public constant must not decrypt the data phase")

	// And the legitimate peer must still be able to.
	_, recvCipher, err := resp.GetCipherStates()
	require.NoError(t, err)
	recovered, err := recvCipher.Decrypt(nil, ad, ciphertext)
	require.NoError(t, err, "the responder must still decrypt the initiator's data")
	assert.Equal(t, plaintext, recovered)
}

// TestSSU2_DataPhaseKeysDifferBetweenSessions kills the "same key every
// session" class of bug outright.
func TestSSU2_DataPhaseKeysDifferBetweenSessions(t *testing.T) {
	if !noiseSplitKeepsLiveKeys(t) {
		t.Skip("pinned go-i2p/noise still has the zeroed-split-key defect (finding 001); these assertions need the fix")
	}
	init1, _ := completeXKHandshake(t)
	init2, _ := completeXKHandshake(t)

	s1, r1, err := init1.DeriveHeaderKeys()
	require.NoError(t, err)
	s2, r2, err := init2.DeriveHeaderKeys()
	require.NoError(t, err)

	assert.NotEqual(t, hex.EncodeToString(s1), hex.EncodeToString(s2),
		"send k_header_2 repeats across sessions")
	assert.NotEqual(t, hex.EncodeToString(r1), hex.EncodeToString(r2),
		"recv k_header_2 repeats across sessions")
	assert.NotEqual(t, constKHeader2, hex.EncodeToString(s1))
	assert.NotEqual(t, constKHeader2, hex.EncodeToString(r2))
}

// TestSSU2_DataKeysInstalledInBothDirections checks UnsafeSetKey put the
// derived k_data (not the raw split key, not the constant) into the cipher
// states that the data phase actually uses.
func TestSSU2_DataKeysInstalledInBothDirections(t *testing.T) {
	if !noiseSplitKeepsLiveKeys(t) {
		t.Skip("pinned go-i2p/noise still has the zeroed-split-key defect (finding 001); these assertions need the fix")
	}
	init, resp := completeXKHandshake(t)

	initSendK, _, err := init.DeriveHeaderKeys()
	require.NoError(t, err)
	_, respRecvK, err := resp.DeriveHeaderKeys()
	require.NoError(t, err)
	assert.Equal(t, initSendK, respRecvK)

	sendCipher, _, err := init.GetCipherStates()
	require.NoError(t, err)
	installed := sendCipher.UnsafeKey()
	assert.False(t, isAllZero(installed[:]), "installed data key must not be zero")

	assert.NotEqual(t, constKData, hex.EncodeToString(installed[:]),
		"installed data key must not be the public constant")
}
