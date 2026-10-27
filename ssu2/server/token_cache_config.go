package server

// newTokenCacheFromConfig creates the retry-token TokenCache using SSU2Config
// values.
//
// The TTL is RetryTokenTTL (9 s), not the 60 s this function previously used.
// ssu2.md §"Tokens": "A token sent from Bob to Alice in a Retry message must be
// used immediately, and expires in a few seconds", and §"Recommended Constants"
// gives "Timeout after sending retry: 9 seconds". i2pd sets
// SSU2_TOKEN_EXPIRATION_TIMEOUT = 9s (libi2pd/SSU2Session.h). This cache holds
// only Retry-issued tokens (established-session "New Token" blocks are a
// separate, longer-lived class handled by the session data handler), so the
// short retry TTL is correct here and is the mechanism that bounds how long the
// listener waits for the SessionRequest that follows a Retry.
func newTokenCacheFromConfig(config *SSU2Config) *TokenCache {
	flog("newTokenCacheFromConfig").Debug("Creating token cache from config")
	maxSize := MaxTokenCacheSize
	if config != nil && config.TokenCacheMaxSize > 0 {
		maxSize = config.TokenCacheMaxSize
	}
	return NewTokenCacheWithMaxSize(RetryTokenTTL, maxSize)
}

// sharedSessionTokenStore returns the outbound-token store for connections on
// this socket: the caller's if it configured one, otherwise a fresh store.
// Sharing one store across a socket's sessions is what makes a token received
// on an established session usable by the next Session Request to that peer,
// regardless of which connection object happens to be dialing.
func sharedSessionTokenStore(config *SSU2Config) *SessionTokenStore {
	if config != nil && config.SessionTokens != nil {
		return config.SessionTokens
	}
	return NewSessionTokenStore(0)
}
