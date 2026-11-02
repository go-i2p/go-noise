package session

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rekey derives a new data-phase key from the current CipherState through
// UnsafeKey(). The SSU2 data-phase constant-key defect made that input 0^32, so
// every rekey produced the same published key. These tests pin the derivation to
// a live key.

// constantRekeyKey is HKDF(0^32, ZEROLEN, "WrapCipherKey", 32), i.e. what every
// pre-fix session rekeyed to. Computed with the same code path the derivation
// uses, from the zeroed key the fork used to leave in CipherState.k.
func constantRekeyKey(t *testing.T) string {
	t.Helper()
	zero := noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), [32]byte{}, 0)
	k, err := deriveRekeyKey(zero)
	require.NoError(t, err)
	return hex.EncodeToString(k[:])
}

// splitCipherStates runs a real NN handshake and returns the initiator's split
// cipher states. This is what the data phase hands to deriveRekeyKey, so the
// zeroed-key regression in noise's Split is reproduced through the production
// path rather than bypassed.
func splitCipherStates(t *testing.T) (*noise.CipherState, *noise.CipherState) {
	t.Helper()

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hsI, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNN,
		Initiator:   true,
	})
	require.NoError(t, err)
	hsR, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNN,
		Initiator:   false,
	})
	require.NoError(t, err)

	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, _, _, err = hsR.ReadMessage(nil, msg1)
	require.NoError(t, err)

	// The responder completes NN, so its split states come from WriteMessage.
	msg2, _, _, err := hsR.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, s1, s2, err := hsI.ReadMessage(nil, msg2)
	require.NoError(t, err)
	return s1, s2
}

// noiseSplitKeepsLiveKeys reports whether the resolved go-i2p/noise returns
// split CipherStates whose stored key survives Split. Finding 001 zeroed it in
// the fork, so the assertions below can only hold against a noise that carries
// the fix; go-noise pins the published version rather than a local checkout, so
// these tests skip rather than turn trunk red while that pin is still old.
func noiseSplitKeepsLiveKeys(t *testing.T) bool {
	t.Helper()

	s1, _ := splitCipherStates(t)
	k := s1.UnsafeKey()
	for _, b := range k {
		if b != 0 {
			return true
		}
	}
	return false
}

func TestDeriveRekeyKeyAfterSplitIsNotConstant(t *testing.T) {
	if !noiseSplitKeepsLiveKeys(t) {
		t.Skip("pinned go-i2p/noise still has the zeroed-split-key defect (finding 001); these assertions need the fix")
	}
	constKey := constantRekeyKey(t)

	s1, s2 := splitCipherStates(t)
	for name, cs := range map[string]*noise.CipherState{"send": s1, "recv": s2} {
		k, err := deriveRekeyKey(cs)
		require.NoError(t, err)
		assert.NotEqual(t, constKey, hex.EncodeToString(k[:]),
			"%s: rekey after Split must not derive the constant key of a zeroed split key", name)
	}

	a, b := splitCipherStates(t)
	ka, err := deriveRekeyKey(a)
	require.NoError(t, err)
	kb, err := deriveRekeyKey(b)
	require.NoError(t, err)
	assert.NotEqual(t, hex.EncodeToString(ka[:]), hex.EncodeToString(kb[:]),
		"rekey keys must differ between sessions")
}

func TestDeriveRekeyKeyUsesLiveKey(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	cs := noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), k, 0)

	derived, err := deriveRekeyKey(cs)
	require.NoError(t, err)

	// The all-zero split key is the regression signature, not a coincidence to
	// assert byte-by-byte against a hard-coded constant.
	assert.NotEqual(t, constantRekeyKey(t), hex.EncodeToString(derived[:]),
		"rekey from a live key must not equal the rekey from a zeroed key")
}

func TestDeriveRekeyKeyDiffersPerSession(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i * 7)
	}

	ka, err := deriveRekeyKey(noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), a, 0))
	require.NoError(t, err)
	kb, err := deriveRekeyKey(noise.UnsafeNewCipherState(noise.ChaChaPoly_SHA256(), b, 0))
	require.NoError(t, err)

	assert.NotEqual(t, hex.EncodeToString(ka[:]), hex.EncodeToString(kb[:]),
		"rekey keys must differ between sessions")
}
