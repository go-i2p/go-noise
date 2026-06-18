package server

import (
	"time"
)

// newTokenCacheFromConfig creates a TokenCache using SSU2Config values.
func newTokenCacheFromConfig(config *SSU2Config) *TokenCache {
	flog("newTokenCacheFromConfig").Debug("Creating token cache from config")
	maxSize := MaxTokenCacheSize
	if config != nil && config.TokenCacheMaxSize > 0 {
		maxSize = config.TokenCacheMaxSize
	}
	return NewTokenCacheWithMaxSize(60*time.Second, maxSize)
}
