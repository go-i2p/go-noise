package ssu2

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenCache(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		cache := NewTokenCache(0)
		require.NotNil(t, cache)
		assert.Equal(t, RetryTokenTTL, cache.GetTTL(), "Retry tokens expire in a few seconds per ssu2.md §\"Tokens\"")
		assert.Equal(t, 0, cache.Size())
	})

	t.Run("custom TTL", func(t *testing.T) {
		cache := NewTokenCache(30 * time.Second)
		require.NotNil(t, cache)
		assert.Equal(t, 30*time.Second, cache.GetTTL())
	})

	t.Run("negative TTL uses default", func(t *testing.T) {
		cache := NewTokenCache(-5 * time.Second)
		require.NotNil(t, cache)
		assert.Equal(t, RetryTokenTTL, cache.GetTTL(), "Retry tokens expire in a few seconds per ssu2.md §\"Tokens\"")
	})
}

func TestTokenCache_GenerateToken(t *testing.T) {
	cache := NewTokenCache(60 * time.Second)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

	t.Run("valid token generation", func(t *testing.T) {
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Equal(t, TokenSize, len(token))
		assert.Equal(t, 1, cache.Size())
	})

	t.Run("nil address", func(t *testing.T) {
		token, err := cache.GenerateToken(nil, nil)
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "address cannot be nil")
	})

	t.Run("unique tokens", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}
		addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}

		token1, err := cache.GenerateToken(addr1, nil)
		require.NoError(t, err)

		token2, err := cache.GenerateToken(addr2, nil)
		require.NoError(t, err)

		assert.NotEqual(t, token1, token2)
		assert.Equal(t, 2, cache.Size())
	})

	t.Run("overwrite existing token for same address", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		token1, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		token2, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		// Returns the same token to prevent retry-storm eviction.
		assert.Equal(t, token1, token2, "should return existing valid token, not generate new one")
		assert.Equal(t, 1, cache.Size())
	})
}

func TestTokenCache_ValidateToken(t *testing.T) {
	cache := NewTokenCache(100 * time.Millisecond)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

	t.Run("valid token", func(t *testing.T) {
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		valid := cache.ValidateToken(token, addr, nil)
		assert.True(t, valid)
	})

	t.Run("invalid token value", func(t *testing.T) {
		_, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		wrongToken := make([]byte, TokenSize)
		valid := cache.ValidateToken(wrongToken, addr, nil)
		assert.False(t, valid)
	})

	t.Run("wrong address", func(t *testing.T) {
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		wrongAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}
		valid := cache.ValidateToken(token, wrongAddr, nil)
		assert.False(t, valid)
	})

	t.Run("nil address", func(t *testing.T) {
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		valid := cache.ValidateToken(token, nil, nil)
		assert.False(t, valid)
	})

	t.Run("wrong token length", func(t *testing.T) {
		_, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		shortToken := make([]byte, 8)
		valid := cache.ValidateToken(shortToken, addr, nil)
		assert.False(t, valid)

		longToken := make([]byte, 32)
		valid = cache.ValidateToken(longToken, addr, nil)
		assert.False(t, valid)
	})

	t.Run("expired token", func(t *testing.T) {
		cache := NewTokenCache(50 * time.Millisecond)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(60 * time.Millisecond)

		valid := cache.ValidateToken(token, addr, nil)
		assert.False(t, valid)
	})

	t.Run("non-existent token", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		fakeToken := make([]byte, TokenSize)
		valid := cache.ValidateToken(fakeToken, addr, nil)
		assert.False(t, valid)
	})
}

func TestTokenCache_ConsumeToken(t *testing.T) {
	cache := NewTokenCache(100 * time.Millisecond)
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

	t.Run("valid token consumption", func(t *testing.T) {
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, cache.Size())

		consumed := cache.ConsumeToken(token, addr, nil)
		assert.True(t, consumed)
		assert.Equal(t, 0, cache.Size())

		// Token should not be valid after consumption
		valid := cache.ValidateToken(token, addr, nil)
		assert.False(t, valid)
	})

	t.Run("consume non-existent token", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		fakeToken := make([]byte, TokenSize)
		consumed := cache.ConsumeToken(fakeToken, addr, nil)
		assert.False(t, consumed)
	})

	t.Run("consume with wrong address", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		wrongAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}
		consumed := cache.ConsumeToken(token, wrongAddr, nil)
		assert.False(t, consumed)

		// Original token should still exist
		assert.Equal(t, 1, cache.Size())
	})

	t.Run("consume expired token", func(t *testing.T) {
		cache := NewTokenCache(50 * time.Millisecond)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(60 * time.Millisecond)

		consumed := cache.ConsumeToken(token, addr, nil)
		assert.False(t, consumed)
		assert.Equal(t, 0, cache.Size()) // Expired token should be removed
	})

	t.Run("consume with nil address", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		consumed := cache.ConsumeToken(token, nil, nil)
		assert.False(t, consumed)
	})

	t.Run("consume with wrong token length", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}

		_, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		shortToken := make([]byte, 8)
		consumed := cache.ConsumeToken(shortToken, addr, nil)
		assert.False(t, consumed)
	})
}

func TestTokenCache_Cleanup(t *testing.T) {
	t.Run("cleanup expired tokens", func(t *testing.T) {
		cache := NewTokenCache(50 * time.Millisecond)

		// Generate some tokens
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}
		addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}
		addr3 := &net.UDPAddr{IP: net.ParseIP("192.168.1.3"), Port: 9003}

		_, err := cache.GenerateToken(addr1, nil)
		require.NoError(t, err)
		_, err = cache.GenerateToken(addr2, nil)
		require.NoError(t, err)

		assert.Equal(t, 2, cache.Size())

		// Wait for tokens to expire
		time.Sleep(60 * time.Millisecond)

		// Add a fresh token
		_, err = cache.GenerateToken(addr3, nil)
		require.NoError(t, err)

		assert.Equal(t, 3, cache.Size())

		// Cleanup should remove only expired tokens
		removed := cache.Cleanup()
		assert.Equal(t, 2, removed)
		assert.Equal(t, 1, cache.Size())
	})

	t.Run("cleanup with no expired tokens", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)

		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}
		addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}

		_, err := cache.GenerateToken(addr1, nil)
		require.NoError(t, err)
		_, err = cache.GenerateToken(addr2, nil)
		require.NoError(t, err)

		removed := cache.Cleanup()
		assert.Equal(t, 0, removed)
		assert.Equal(t, 2, cache.Size())
	})

	t.Run("cleanup empty cache", func(t *testing.T) {
		cache := NewTokenCache(60 * time.Second)
		removed := cache.Cleanup()
		assert.Equal(t, 0, removed)
		assert.Equal(t, 0, cache.Size())
	})
}

func TestTokenCache_Size(t *testing.T) {
	cache := NewTokenCache(60 * time.Second)
	assert.Equal(t, 0, cache.Size())

	addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 9002}

	_, err := cache.GenerateToken(addr1, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Size())

	_, err = cache.GenerateToken(addr2, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

func TestTokenCache_Clear(t *testing.T) {
	cache := NewTokenCache(60 * time.Second)

	// Add some tokens
	for i := 0; i < 5; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001 + i}
		_, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

func TestTokenCache_Concurrent(t *testing.T) {
	cache := NewTokenCache(60 * time.Second)
	var wg sync.WaitGroup

	// Concurrent token generation
	t.Run("concurrent generation", func(t *testing.T) {
		cache.Clear()
		numGoroutines := 100

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001 + id}
				_, err := cache.GenerateToken(addr, nil)
				assert.NoError(t, err)
			}(i)
		}
		wg.Wait()

		assert.Equal(t, numGoroutines, cache.Size())
	})

	// Concurrent validation
	t.Run("concurrent validation", func(t *testing.T) {
		cache.Clear()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001}
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		numGoroutines := 50
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				valid := cache.ValidateToken(token, addr, nil)
				assert.True(t, valid)
			}()
		}
		wg.Wait()
	})

	// Concurrent cleanup
	t.Run("concurrent cleanup", func(t *testing.T) {
		cache.Clear()
		// Add tokens
		for i := 0; i < 50; i++ {
			addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9001 + i}
			_, err := cache.GenerateToken(addr, nil)
			require.NoError(t, err)
		}

		numGoroutines := 10
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				cache.Cleanup()
			}()
		}
		wg.Wait()
	})
}

func TestTokenCache_IPv6Addresses(t *testing.T) {
	cache := NewTokenCache(60 * time.Second)

	t.Run("IPv6 token generation", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9001}
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Equal(t, TokenSize, len(token))
	})

	t.Run("IPv6 token validation", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9001}
		token, err := cache.GenerateToken(addr, nil)
		require.NoError(t, err)

		valid := cache.ValidateToken(token, addr, nil)
		assert.True(t, valid)
	})
}

func TestTokenCache_GetTTL(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		cache := NewTokenCache(0)
		assert.Equal(t, RetryTokenTTL, cache.GetTTL(), "Retry tokens expire in a few seconds per ssu2.md §\"Tokens\"")
	})

	t.Run("custom TTL", func(t *testing.T) {
		cache := NewTokenCache(45 * time.Second)
		assert.Equal(t, 45*time.Second, cache.GetTTL())
	})
}
