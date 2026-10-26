package wire

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionTokenStore_BindsLocalAndDestination covers ssu2.md §"Tokens": "A
// token is bound to the combination of source IP/port and destination IP/port.
// A token received on IPv4 may not be used for IPv6 or vice versa."
func TestSessionTokenStore_BindsLocalAndDestination(t *testing.T) {
	store := NewSessionTokenStore(0)

	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 8888}
	local4 := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 9000}
	local6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9000}

	token := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	require.NoError(t, store.Save(local4, peer, token, time.Now().Add(time.Minute)))

	got, ok := store.Get(local4, peer)
	require.True(t, ok)
	assert.Equal(t, token, got)

	// Same peer, different local address: not usable.
	_, ok = store.Get(local6, peer)
	assert.False(t, ok, "a token obtained on one local address must not be used on another")
}

// TestSessionTokenStore_LastTokenWins covers §"Tokens": "Routers should assume
// that only the last token received is valid."
func TestSessionTokenStore_LastTokenWins(t *testing.T) {
	store := NewSessionTokenStore(0)
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 8888}
	local := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 9000}

	require.NoError(t, store.Save(local, peer, []byte{1, 1, 1, 1, 1, 1, 1, 1}, time.Now().Add(time.Minute)))
	require.NoError(t, store.Save(local, peer, []byte{2, 2, 2, 2, 2, 2, 2, 2}, time.Now().Add(time.Hour)))

	got, ok := store.Get(local, peer)
	require.True(t, ok)
	assert.Equal(t, []byte{2, 2, 2, 2, 2, 2, 2, 2}, got)
	assert.Equal(t, 1, store.Size(), "replacing must not add an entry")
}

// TestSessionTokenStore_ExpiryHonoursPublishedTime covers §"Tokens": a New Token
// block's token "expires at the time specified in that block".
func TestSessionTokenStore_ExpiryHonoursPublishedTime(t *testing.T) {
	store := NewSessionTokenStore(0)
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 8888}
	local := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 9000}

	require.NoError(t, store.Save(local, peer, []byte{9, 9, 9, 9, 9, 9, 9, 9}, time.Now().Add(-time.Second)))
	_, ok := store.Get(local, peer)
	assert.False(t, ok, "an expired token must not be presented")

	assert.Equal(t, 1, store.Cleanup(), "expired entries must be collectable")
	assert.Equal(t, 0, store.Size())
}

// TestSessionTokenStore_RejectsBadSize guards against storing something that
// could not be written into the 8-byte header field (§"Session Request":
// "Token :: 8 bytes, unsigned big endian integer").
func TestSessionTokenStore_RejectsBadSize(t *testing.T) {
	store := NewSessionTokenStore(0)
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 8888}
	local := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 9000}

	assert.Error(t, store.Save(local, nil, make([]byte, 8), time.Now().Add(time.Minute)), "nil destination")
	assert.Error(t, store.Save(local, peer, make([]byte, 7), time.Now().Add(time.Minute)), "short token")
}
