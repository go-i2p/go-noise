package server

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewTokenCacheFromConfig_RetryTTL proves the listener's retry-token cache
// uses the 9-second Retry-token lifetime required by ssu2.md §"Tokens" ("must
// be used immediately, and expires in a few seconds") and §"Recommended
// Constants" ("Timeout after sending retry: 9 seconds"), rather than the 60 s
// value it previously defaulted to.
func TestNewTokenCacheFromConfig_RetryTTL(t *testing.T) {
	tc := newTokenCacheFromConfig(nil)
	assert.Equal(t, RetryTokenTTL, tc.GetTTL())
	assert.Equal(t, 9*time.Second, tc.GetTTL())
}

// TestNewTokenCacheFromConfig_RespectsMaxSize proves the config override for
// cache size still applies (the cache stops growing past the configured cap via
// oldest-entry eviction) and does not disturb the retry TTL.
func TestNewTokenCacheFromConfig_RespectsMaxSize(t *testing.T) {
	config := &SSU2Config{TokenCacheMaxSize: 4}
	tc := newTokenCacheFromConfig(config)
	assert.Equal(t, RetryTokenTTL, tc.GetTTL())

	for i := 0; i < 10; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i)), Port: 1000 + i}
		if _, err := tc.GenerateToken(addr, addr); err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
	}
	assert.Equal(t, 4, tc.Size(), "cache must be bounded by the configured max size")
}
