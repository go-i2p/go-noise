package wire

import (
	"testing"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GN-012: IntroKeyFromRouterAddress / StaticKeyFromRouterAddress parse
// untrusted RouterAddress option maps straight from the network database. The
// "i"/"s" values are attacker-influenced strings, so missing, empty, malformed
// Base64, and wrong-length cases must all be rejected without panicking.

func b64Key(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return i2pbase64.I2PEncoding.EncodeToString(k)
}

func TestIntroKeyFromRouterAddress(t *testing.T) {
	t.Run("valid i parameter", func(t *testing.T) {
		want := make([]byte, 32)
		for i := range want {
			want[i] = 0x42
		}
		opts := map[string]string{"i": i2pbase64.I2PEncoding.EncodeToString(want)}
		got, err := IntroKeyFromRouterAddress(opts)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("missing i", func(t *testing.T) {
		_, err := IntroKeyFromRouterAddress(map[string]string{"s": b64Key(1)})
		require.Error(t, err)
	})

	t.Run("empty i", func(t *testing.T) {
		_, err := IntroKeyFromRouterAddress(map[string]string{"i": ""})
		require.Error(t, err)
	})

	t.Run("nil map", func(t *testing.T) {
		_, err := IntroKeyFromRouterAddress(nil)
		require.Error(t, err)
	})

	t.Run("malformed base64", func(t *testing.T) {
		// "!!!" is not in the I2P base64 alphabet.
		_, err := IntroKeyFromRouterAddress(map[string]string{"i": "!!!"})
		require.Error(t, err)
	})

	t.Run("wrong decoded length", func(t *testing.T) {
		short := i2pbase64.I2PEncoding.EncodeToString([]byte{1, 2, 3})
		_, err := IntroKeyFromRouterAddress(map[string]string{"i": short})
		require.Error(t, err, "a 3-byte decoded key must be rejected")
	})
}

func TestStaticKeyFromRouterAddress(t *testing.T) {
	t.Run("valid s parameter", func(t *testing.T) {
		want := make([]byte, 32)
		for i := range want {
			want[i] = 0x7f
		}
		opts := map[string]string{"s": i2pbase64.I2PEncoding.EncodeToString(want)}
		got, err := StaticKeyFromRouterAddress(opts)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("missing s", func(t *testing.T) {
		_, err := StaticKeyFromRouterAddress(map[string]string{"i": b64Key(1)})
		require.Error(t, err)
	})

	t.Run("wrong decoded length", func(t *testing.T) {
		long := i2pbase64.I2PEncoding.EncodeToString(make([]byte, 31))
		_, err := StaticKeyFromRouterAddress(map[string]string{"s": long})
		require.Error(t, err)
	})
}

// keyFromRouterAddress is shared by both extractors; confirm the two params do
// not cross-wire (an "i" value must not satisfy a "s" lookup).
func TestKeyFromRouterAddress_ParamIsolation(t *testing.T) {
	opts := map[string]string{"i": b64Key(0x11)}
	_, err := StaticKeyFromRouterAddress(opts)
	require.Error(t, err, "static key lookup must not read the intro key param")
}
