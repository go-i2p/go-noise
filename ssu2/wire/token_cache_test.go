package wire

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenCache_GenerateToken_SameAddressReturnsSameToken verifies that
// generating a token for the same address twice returns the same token,
// preventing retry-storm eviction of a valid token.
func TestTokenCache_GenerateToken_SameAddressReturnsSameToken(t *testing.T) {
	tc := NewTokenCache(60 * time.Second)

	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

	// Generate first token
	token1, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)
	require.Len(t, token1, TokenSize)

	// Generate second token for same address (simulating retry)
	token2, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)
	require.Len(t, token2, TokenSize)

	// Tokens should be identical
	assert.Equal(t, token1, token2,
		"Second GenerateToken call should return same token to prevent retry eviction")

	// Verify both tokens validate
	assert.True(t, tc.ValidateToken(token1, addr, nil))
	assert.True(t, tc.ValidateToken(token2, addr, nil))
}

// TestTokenCache_GenerateToken_DifferentAddressesReturnDifferentTokens verifies
// that different addresses get different tokens.
func TestTokenCache_GenerateToken_DifferentAddressesReturnDifferentTokens(t *testing.T) {
	tc := NewTokenCache(60 * time.Second)

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.101"), Port: 12346}

	token1, err := tc.GenerateToken(addr1, nil)
	require.NoError(t, err)

	token2, err := tc.GenerateToken(addr2, nil)
	require.NoError(t, err)

	// Tokens should be different
	assert.NotEqual(t, token1, token2,
		"Different addresses should get different tokens")

	// Each token should validate for its own address only
	assert.True(t, tc.ValidateToken(token1, addr1, nil))
	assert.False(t, tc.ValidateToken(token1, addr2, nil))
	assert.True(t, tc.ValidateToken(token2, addr2, nil))
	assert.False(t, tc.ValidateToken(token2, addr1, nil))
}

// TestTokenCache_GenerateToken_ExpiredTokenGeneratesNew verifies that
// after a token expires, a new one is generated.
func TestTokenCache_GenerateToken_ExpiredTokenGeneratesNew(t *testing.T) {
	tc := NewTokenCache(100 * time.Millisecond) // Short TTL for testing

	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

	// Generate first token
	token1, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)

	// Verify it validates
	assert.True(t, tc.ValidateToken(token1, addr, nil))

	// Wait for token to expire
	time.Sleep(150 * time.Millisecond)

	// Token should no longer validate
	assert.False(t, tc.ValidateToken(token1, addr, nil))

	// Generate new token - should be different since first expired
	token2, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)
	assert.NotEqual(t, token1, token2,
		"Expired token should be replaced with new one")

	// New token should validate
	assert.True(t, tc.ValidateToken(token2, addr, nil))
}

// TestTokenCache_ValidateToken_InvalidCases tests various invalid token scenarios.
func TestTokenCache_ValidateToken_InvalidCases(t *testing.T) {
	tc := NewTokenCache(60 * time.Second)

	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	token, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token []byte
		addr  *net.UDPAddr
		want  bool
	}{
		{
			name:  "nil address",
			token: token,
			addr:  nil,
			want:  false,
		},
		{
			name:  "wrong token length",
			token: []byte{1, 2, 3},
			addr:  addr,
			want:  false,
		},
		{
			name:  "wrong address",
			token: token,
			addr:  &net.UDPAddr{IP: net.ParseIP("192.168.1.101"), Port: 12345},
			want:  false,
		},
		{
			name:  "wrong token value",
			token: make([]byte, TokenSize),
			addr:  addr,
			want:  false,
		},
		{
			name:  "valid token",
			token: token,
			addr:  addr,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tc.ValidateToken(tt.token, tt.addr, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestTokenCache_ConsumeToken tests token consumption.
func TestTokenCache_ConsumeToken(t *testing.T) {
	tc := NewTokenCache(60 * time.Second)

	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	token, err := tc.GenerateToken(addr, nil)
	require.NoError(t, err)

	// First consume should succeed
	consumed := tc.ConsumeToken(token, addr, nil)
	assert.True(t, consumed, "First ConsumeToken should succeed")

	// Second consume should fail (token removed)
	consumed = tc.ConsumeToken(token, addr, nil)
	assert.False(t, consumed, "Second ConsumeToken should fail (token consumed)")

	// Validate should also fail
	assert.False(t, tc.ValidateToken(token, addr, nil))
}
