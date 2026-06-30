package wire

import (
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeHash(b byte) []byte {
	h := make([]byte, introducerHashLen)
	for i := range h {
		h[i] = b
	}
	return h
}

func TestIntroducersRoundTrip(t *testing.T) {
	exp := time.Unix(time.Now().Add(time.Hour).Unix(), 0)
	in := []PublishedIntroducer{
		{RouterHash: makeHash(0x11), RelayTag: 123, ExpiresAt: exp},
		{RouterHash: makeHash(0x22), RelayTag: 456, ExpiresAt: exp},
	}

	opts, err := IntroducersToRouterAddressOptions(in)
	require.NoError(t, err)

	// Verify wire keys are present and well-formed.
	assert.Equal(t, "123", opts["itag0"])
	assert.Equal(t, "456", opts["itag1"])
	assert.Equal(t, i2pbase64.I2PEncoding.EncodeToString(makeHash(0x11)), opts["ih0"])
	require.Contains(t, opts, "iexp0")

	out, err := IntroducersFromRouterAddress(opts)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, uint32(123), out[0].RelayTag)
	assert.Equal(t, makeHash(0x11), out[0].RouterHash)
	assert.True(t, exp.Equal(out[0].ExpiresAt))
	assert.Equal(t, uint32(456), out[1].RelayTag)
	assert.Equal(t, makeHash(0x22), out[1].RouterHash)
}

func TestIntroducersToOptions_SkipsInvalid(t *testing.T) {
	in := []PublishedIntroducer{
		{RouterHash: makeHash(0x11), RelayTag: 0},   // zero tag -> skipped
		{RouterHash: nil, RelayTag: 7},              // missing hash -> skipped
		{RouterHash: makeHash(0x00), RelayTag: 9},   // all-zero hash -> skipped
		{RouterHash: makeHash(0x33), RelayTag: 100}, // valid -> index 0
	}
	opts, err := IntroducersToRouterAddressOptions(in)
	require.NoError(t, err)
	assert.Equal(t, "100", opts["itag0"])
	assert.NotContains(t, opts, "itag1")
}

func TestIntroducersToOptions_CapsAtMax(t *testing.T) {
	var in []PublishedIntroducer
	for i := 0; i < 6; i++ {
		in = append(in, PublishedIntroducer{RouterHash: makeHash(byte(i + 1)), RelayTag: uint32(i + 1)})
	}
	opts, err := IntroducersToRouterAddressOptions(in)
	require.NoError(t, err)
	assert.Contains(t, opts, "itag0")
	assert.Contains(t, opts, "itag2")
	assert.NotContains(t, opts, "itag3", "should publish at most %d introducers", MaxPublishedIntroducers)
}

func TestIntroducersToOptions_BadHashLength(t *testing.T) {
	in := []PublishedIntroducer{{RouterHash: []byte{1, 2, 3}, RelayTag: 5}}
	_, err := IntroducersToRouterAddressOptions(in)
	require.Error(t, err)
}

func TestIntroducersToOptions_OmitsZeroExpiration(t *testing.T) {
	in := []PublishedIntroducer{{RouterHash: makeHash(0x44), RelayTag: 1}}
	opts, err := IntroducersToRouterAddressOptions(in)
	require.NoError(t, err)
	assert.NotContains(t, opts, "iexp0")
}

func TestIntroducersFromOptions_Empty(t *testing.T) {
	out, err := IntroducersFromRouterAddress(map[string]string{})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestIntroducersFromOptions_NoExpiration(t *testing.T) {
	opts := map[string]string{
		"itag0": "42",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x55)),
	}
	out, err := IntroducersFromRouterAddress(opts)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, uint32(42), out[0].RelayTag)
	assert.True(t, out[0].ExpiresAt.IsZero())
}

func TestIntroducersFromOptions_SkipsZeroTag(t *testing.T) {
	opts := map[string]string{
		"itag0": "0",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x55)),
	}
	out, err := IntroducersFromRouterAddress(opts)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestIntroducersFromOptions_AllowsGaps(t *testing.T) {
	opts := map[string]string{
		"itag0": "1",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x11)),
		"itag2": "3",
		"ih2":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x33)),
	}
	out, err := IntroducersFromRouterAddress(opts)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, uint32(1), out[0].RelayTag)
	assert.Equal(t, uint32(3), out[1].RelayTag)
}

func TestIntroducersFromOptions_MissingTag(t *testing.T) {
	opts := map[string]string{
		"ih0": i2pbase64.I2PEncoding.EncodeToString(makeHash(0x11)),
	}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}

func TestIntroducersFromOptions_MissingHash(t *testing.T) {
	opts := map[string]string{"itag0": "5"}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}

func TestIntroducersFromOptions_BadTag(t *testing.T) {
	opts := map[string]string{
		"itag0": "notanumber",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x11)),
	}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}

func TestIntroducersFromOptions_BadHashBase64(t *testing.T) {
	opts := map[string]string{
		"itag0": "5",
		"ih0":   "!!!notbase64!!!",
	}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}

func TestIntroducersFromOptions_BadHashLength(t *testing.T) {
	opts := map[string]string{
		"itag0": "5",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString([]byte{1, 2, 3}),
	}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}

func TestIntroducersFromOptions_BadExpiration(t *testing.T) {
	opts := map[string]string{
		"itag0": "5",
		"ih0":   i2pbase64.I2PEncoding.EncodeToString(makeHash(0x11)),
		"iexp0": "soon",
	}
	_, err := IntroducersFromRouterAddress(opts)
	require.Error(t, err)
}
