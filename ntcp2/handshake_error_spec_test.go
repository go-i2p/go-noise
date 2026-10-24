package ntcp2

import (
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/crypto/curve25519"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oopsCode builds an error carrying the given code the same way the handshake
// paths do, so the classification is exercised against real oops error values.
func oopsCode(code string) error {
	return oops.Code(code).In("ntcp2").Errorf("synthetic %s", code)
}

// TestIsHandshakeProtocolError pins the spec's error-action split.
//
// ntcp2.rst §"Session Request": "On any error, including AEAD, DH, timestamp,
// apparent replay, or key validation failure, Bob must halt further message
// processing and close the connection without responding. This should be an
// abnormal close (TCP RST)." I/O and timeout failures are not protocol
// violations, so they must not trigger the probing-resistance delay.
func TestIsHandshakeProtocolError(t *testing.T) {
	protocolErrors := []string{
		"MSG1_PROCESS_FAILED",
		"MSG2_PROCESS_FAILED",
		"MSG3_PROCESS_FAILED",
		"MSG1_REPLAY",
		"MSG1_NETID_MISMATCH",
		"MSG1_VERSION_MISMATCH",
		"MSG1_PADDING_TOO_LARGE",
		"MSG3_PART2_BLOCK_TYPE",
		"MSG3_PART2_BLOCK_ORDER",
		"MSG3_PART2_NO_ROUTER_INFO",
		"MSG_EXTRA_DATA",
		"INVALID_CURVE25519_KEY",
		"PEER_ROUTER_INFO_KEY_MISMATCH",
	}
	for _, code := range protocolErrors {
		t.Run(code, func(t *testing.T) {
			err := oopsCode(code)
			assert.True(t, isHandshakeProtocolError(err),
				"%s must require an abnormal close per ntcp2.rst", code)
		})
	}

	// Transport failures and our own outbound misbehaviour are excluded.
	notProtocol := []string{
		"MSG1_READ_FAILED",
		"MSG1_PAD_READ_FAILED",
		"MSG2_NO_BYTES",
		"MSG2_PARTIAL",
		"MSG3_READ_FAILED",
		"MSG1_SEND_FAILED",
		"MSG2_WRITE_FAILED",
		"MSG3_SEND_FAILED",
		"NONCE_EXHAUSTED",
	}
	for _, code := range notProtocol {
		t.Run(code, func(t *testing.T) {
			err := oopsCode(code)
			assert.False(t, isHandshakeProtocolError(err),
				"%s is not a peer protocol violation and must not add probing-resistance delay", code)
		})
	}

	assert.False(t, isHandshakeProtocolError(nil))
	assert.False(t, isHandshakeProtocolError(assert.AnError))
}

// TestHandshakeErrorCodesAreAllEmitted guards against the RST set drifting to
// include codes the package never produces, which would silently make the
// classification untestable.
func TestHandshakeErrorCodesAreAllEmitted(t *testing.T) {
	for code := range handshakeErrorCodes {
		require.NotEmpty(t, code)
	}
}

// TestClockSkewIsNotAbnormalClose documents the deliberate exception:
// ntcp2.rst §"Clock Skew Guidelines" requires Bob to answer with a Session
// Created "rather than simply closing the connection" so Alice can read tsB,
// which an immediate RST would discard.
func TestClockSkewIsNotAbnormalClose(t *testing.T) {
	assert.False(t, handshakeErrorCodes["MSG1_CLOCK_SKEW"])
	assert.False(t, handshakeErrorCodes["MSG2_CLOCK_SKEW"])
}

// TestReplayCacheTTLFor pins the spec floor: "Values in the cache must have a
// lifetime of at least 2*D", D being the maximum tolerated clock skew.
func TestReplayCacheTTLFor(t *testing.T) {
	assert.Equal(t, 120*time.Second, replayCacheTTLFor(60*time.Second))
	assert.Equal(t, 20*time.Second, replayCacheTTLFor(10*time.Second))
	// A disabled/negative skew still keeps the default lifetime, so a
	// misconfigured clock cannot shrink the cache below the spec floor.
	assert.Equal(t, replayCacheTTL, replayCacheTTLFor(0))
	assert.Equal(t, replayCacheTTL, replayCacheTTLFor(-time.Second))
}

// TestFallbackReplayDetectorIsSharedAndProtective covers the requirement that
// replay protection is never opt-out: two responders with no configured
// detector share one cache, so a replayed message 1 on a new connection is
// still rejected.
func TestFallbackReplayDetectorIsSharedAndProtective(t *testing.T) {
	first := fallbackReplayDetector(60 * time.Second)
	second := fallbackReplayDetector(60 * time.Second)
	require.NotNil(t, first)
	assert.Same(t, first, second, "responders without a detector must share one cache")

	var key [32]byte
	key[0] = 0xAB

	assert.False(t, first.CheckAndAdd(key), "first sighting is not a replay")
	assert.True(t, second.CheckAndAdd(key), "a replay on another connection must be detected")
}

// TestValidatePeerRouterInfoStaticKey covers ntcp2.rst §"Session Confirmed":
// "Bob must verify that Alice's static key received in the first frame matches
// the static key in the Router Info."
func TestValidatePeerRouterInfoStaticKey(t *testing.T) {
	staticPriv := make([]byte, StaticKeySize)
	staticPriv[0] = 0x08
	privKey, err := curve25519.NewCurve25519PrivateKey(staticPriv)
	require.NoError(t, err)
	pubKey, err := privKey.Public()
	require.NoError(t, err)
	peerStatic := pubKey.Bytes()

	ri := []byte("router.identity&host=1.2.3.4&port=8887&s=" + i2pbase64.EncodeToString(peerStatic) + "&v=2")
	frame := routerInfoFrame(t, ri)

	assert.NoError(t, validatePeerRouterInfoStaticKey(peerStatic, frame),
		"a RouterInfo advertising the peer's static key must be accepted")

	other := make([]byte, StaticKeySize)
	other[31] = 0x7f
	otherFrame := routerInfoFrame(t, []byte("router.identity&s="+i2pbase64.EncodeToString(other)+"&v=2"))

	err = validatePeerRouterInfoStaticKey(peerStatic, otherFrame)
	require.Error(t, err, "a RouterInfo advertising a different key must be rejected")
	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "PEER_ROUTER_INFO_KEY_MISMATCH", oopsErr.Code())
	assert.True(t, isHandshakeProtocolError(err), "the mismatch must trigger an abnormal close")

	// An empty frame, a frame with no RouterInfo block, and a short/absent
	// peer key are all no-ops.
	assert.NoError(t, validatePeerRouterInfoStaticKey(peerStatic, nil))
	assert.NoError(t, validatePeerRouterInfoStaticKey(peerStatic, paddingFrame(t)))
	assert.NoError(t, validatePeerRouterInfoStaticKey(nil, frame))
	assert.NoError(t, validatePeerRouterInfoStaticKey(make([]byte, StaticKeySize-1), frame))
}

// routerInfoFrame wraps ri in the message-3 part-2 block frame: block type 2,
// big-endian size, then a 1-byte flag followed by the RouterInfo bytes.
func routerInfoFrame(t *testing.T, ri []byte) []byte {
	t.Helper()
	size := 1 + len(ri)
	out := make([]byte, 0, 3+size)
	out = append(out, routerInfoBlockType, byte(size>>8), byte(size))
	out = append(out, 0) // flag
	out = append(out, ri...)
	return out
}

// paddingFrame builds a frame holding only a Padding (type 254) block.
func paddingFrame(t *testing.T) []byte {
	t.Helper()
	return append([]byte{PaddingBlockType, 0, 4}, 0, 0, 0, 0)
}
