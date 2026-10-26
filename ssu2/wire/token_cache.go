package wire

import (
	"crypto/subtle"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/go-noise/internal/eviction"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DefaultSessionTokenLifetime is the lifetime given to a token issued in a New
// Token block when the caller does not choose one.
//
// ssu2.md §"Tokens": "recommended values are several minutes minimum, one or
// more hours maximum, depending on desired maximum overhead of stored tokens."
// 30 minutes sits inside that band.
const DefaultSessionTokenLifetime = 30 * time.Minute

// RetryTokenTTL is the lifetime of a token issued in a Retry message.
// Spec ref: ssu2.md §"Tokens" - "expires in a few seconds".
// i2pd: SSU2_TOKEN_EXPIRATION_TIMEOUT = 9 (libi2pd/SSU2Session.h:SSU2_TOKEN_EXPIRATION_TIMEOUT).
const RetryTokenTTL = 9 * time.Second

// MaxTokenCacheSize is the maximum number of tokens that can be stored.
// This prevents unbounded growth from peers rapidly changing addresses.
const MaxTokenCacheSize = 10000

// TokenCache manages tokens for SSU2 retry mechanism.
// Tokens are used to prevent address spoofing attacks during connection establishment.
//
// A token is bound to the combination of source IP/port AND destination IP/port.
// ssu2.md §"Tokens": "A token is bound to the combination of source IP/port and
// destination IP/port. A token received on IPv4 may not be used for IPv6 or vice
// versa." and "If a router's IP or port changes, it must delete all saved tokens
// (both inbound and outbound) for the old IP or port, as they are no longer valid."
//
// The cache enforces a maximum size of MaxTokenCacheSize entries; when full, the
// oldest token is evicted.
//
// Retry tokens are short-lived - see RetryTokenTTL - not the 60 seconds previously
// used here. ssu2.md §"Tokens": "A token sent from Bob to Alice in a Retry message
// must be used immediately, and expires in a few seconds." i2pd's
// SSU2_TOKEN_EXPIRATION_TIMEOUT is 9 seconds (libi2pd/SSU2Session.h), which is what
// RetryTokenTTL takes; the longer "several minutes minimum, one or more hours
// maximum" lifetime in the same paragraph applies only to New Token blocks in
// established sessions, which are a different token class.
type TokenCache struct {
	tokens  map[string]*Token // Key: source + destination address pair, Value: token data
	ttl     time.Duration     // Token time-to-live
	maxSize int               // Maximum number of cached tokens
	mutex   sync.RWMutex
}

// Token represents a retry token issued to a specific address.
type Token struct {
	Value []byte // Token value (8 bytes)
	// ExpiresAt, when non-zero, overrides the cache-wide ttl for this entry.
	// Retry tokens use the cache ttl ("expires in a few seconds"); New Token
	// block tokens carry the expiration the sender published in the block
	// ("recommended values are several minutes minimum, one or more hours
	// maximum"), so the two classes can share one cache without one lifetime
	// being wrong for the other.
	ExpiresAt time.Time
	// Address is the peer (source) address the token was issued to.
	Address *net.UDPAddr
	// LocalAddress is the destination address (this router's IP/port) the token was
	// issued on. Spec ref: ssu2.md §"Tokens" - a token is bound to the combination of
	// source AND destination IP/port.
	LocalAddress *net.UDPAddr
	CreatedAt    time.Time // When token was created
}

// NewTokenCache creates a new token cache with the specified TTL.
// If ttl is zero or negative, defaults to RetryTokenTTL (9 seconds), the Retry-token
// lifetime required by ssu2.md §"Tokens".
// Uses the default maximum cache size MaxTokenCacheSize.
func NewTokenCache(ttl time.Duration) *TokenCache {
	flog("NewTokenCache", logger.Fields{"ttl": ttl}).Debug("Creating new TokenCache")
	return NewTokenCacheWithMaxSize(ttl, MaxTokenCacheSize)
}

// NewTokenCacheWithMaxSize creates a new token cache with the specified TTL and
// maximum size. If ttl is zero or negative, defaults to 60 seconds. If maxSize
// is zero or negative, defaults to MaxTokenCacheSize.
func NewTokenCacheWithMaxSize(ttl time.Duration, maxSize int) *TokenCache {
	flog("NewTokenCacheWithMaxSize", logger.Fields{"ttl": ttl, "maxSize": maxSize}).Debug("Creating new TokenCache with custom max size")
	if ttl <= 0 {
		ttl = RetryTokenTTL
	}
	if maxSize <= 0 {
		maxSize = MaxTokenCacheSize
	}

	return &TokenCache{
		tokens:  make(map[string]*Token),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// tokenKey builds the cache key binding a token to the source IP/port and the
// destination IP/port it was issued on.
//
// Spec ref: ssu2.md §"Tokens" - "A token is bound to the combination of source IP/port and
// destination IP/port. A token received on IPv4 may not be used for IPv6 or vice versa."
//
// localAddr may be nil for callers that have no destination address to assert (for example
// unit tests); the key then covers only the source, matching the previous behaviour.
func tokenKey(addr, localAddr *net.UDPAddr) string {
	if localAddr == nil {
		return addr.String()
	}
	return addr.String() + "|" + localAddr.String()
}

// GenerateToken creates a new token for the specified address.
// The token is cryptographically random and stored in the cache.
// Returns the token value.
// If a valid (non-expired) token already exists for this address, returns
// the existing token instead of generating a new one to prevent retry storms.
func (tc *TokenCache) GenerateToken(addr *net.UDPAddr, localAddr *net.UDPAddr) ([]byte, error) {
	flog("GenerateToken").Debug("Generating new token")
	if addr == nil {
		return nil, oops.
			Code("NIL_ADDRESS").
			In("wire").
			Errorf("address cannot be nil")
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	addrStr := tokenKey(addr, localAddr)

	// Check if valid token already exists for this address
	if existingToken, ok := tc.lookupToken(addrStr); ok && !tc.isExpired(existingToken) {
		flog("GenerateToken", logger.Fields{"addr": addrStr}).Debug("Returning existing valid token for address")
		return existingToken.Value, nil
	}

	// Generate 8-byte random token per SSU2 spec
	tokenValue := make([]byte, TokenSize)
	if _, err := rand.Read(tokenValue); err != nil {
		return nil, oops.
			Code("TOKEN_GENERATION_FAILED").
			In("wire").
			With("address", addr.String()).
			Wrapf(err, "failed to generate random token")
	}

	token := &Token{
		Value:        tokenValue,
		Address:      addr,
		LocalAddress: localAddr,
		CreatedAt:    time.Now(),
	}

	// Evict oldest token if at capacity
	if len(tc.tokens) >= tc.maxSize {
		tc.evictOldestLocked()
	}

	// Store token keyed by address string
	tc.tokens[addrStr] = token

	return tokenValue, nil
}

// ValidateToken checks if a token is valid for the specified address.
// Returns true if the token exists, matches the address, and hasn't expired.
func (tc *TokenCache) ValidateToken(tokenValue []byte, addr *net.UDPAddr, localAddr *net.UDPAddr) bool {
	flog("ValidateToken", logger.Fields{"addr": addr}).Debug("Validating token for address")
	if addr == nil || len(tokenValue) != TokenSize {
		return false
	}

	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	token, exists := tc.lookupToken(tokenKey(addr, localAddr))
	if !exists || tc.isExpired(token) {
		return false
	}

	// Compare token values using constant-time comparison
	return subtle.ConstantTimeCompare(token.Value, tokenValue) == 1
}

// ConsumeToken validates and removes a token from the cache.
// This should be called when a valid SessionRequest with token is received.
// Returns true if the token was valid and consumed.
func (tc *TokenCache) ConsumeToken(tokenValue []byte, addr *net.UDPAddr, localAddr *net.UDPAddr) bool {
	flog("ConsumeToken", logger.Fields{"addr": addr}).Debug("Validating and consuming token")
	if addr == nil || len(tokenValue) != TokenSize {
		return false
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	addrStr := tokenKey(addr, localAddr)
	token, exists := tc.lookupToken(addrStr)
	if !exists {
		return false
	}
	if tc.isExpired(token) {
		delete(tc.tokens, addrStr)
		return false
	}

	// Compare token values
	if subtle.ConstantTimeCompare(token.Value, tokenValue) != 1 {
		return false
	}

	// Token is valid, consume it (remove from cache)
	delete(tc.tokens, addrStr)
	return true
}

// DeleteToken discards the token outstanding for a source/destination pair.
//
// Spec ref: ssu2.md §"Handshake Retransmission" -> "### Retry" - "If a second Session
// Request message is received with a different but still-invalid token, drop the
// pending session and do not respond." Dropping the cached token is what drops the
// pending session's issuance state, so the peer cannot complete the handshake with
// the token it was previously given.
//
// Returns true if a token was removed.
func (tc *TokenCache) DeleteToken(addr, localAddr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	flog("DeleteToken", logger.Fields{"addr": addr.String()}).Debug("Dropping pending token")

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	key := tokenKey(addr, localAddr)
	if _, ok := tc.tokens[key]; !ok {
		return false
	}
	delete(tc.tokens, key)
	return true
}

// DeleteLocalTokens removes every token that was issued on the given local
// (destination) IP/port.
//
// Spec ref: ssu2.md §"Tokens" - "If a router's IP or port changes, it must delete all saved
// tokens (both inbound and outbound) for the old IP or port, as they are no longer valid."
//
// Returns the number of tokens removed.
func (tc *TokenCache) DeleteLocalTokens(localAddr *net.UDPAddr) int {
	if localAddr == nil {
		return 0
	}
	flog("DeleteLocalTokens", logger.Fields{"local_addr": localAddr.String()}).Debug("Deleting tokens bound to a retired local address")

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	suffix := "|" + localAddr.String()
	removed := 0
	for key, token := range tc.tokens {
		if strings.HasSuffix(key, suffix) || (token.LocalAddress != nil && token.LocalAddress.String() == localAddr.String()) {
			delete(tc.tokens, key)
			removed++
		}
	}
	return removed
}

// Cleanup removes expired tokens from the cache.
// This should be called periodically to prevent memory leaks.
func (tc *TokenCache) Cleanup() int {
	flog("Cleanup").Debug("Removing expired tokens")
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	now := time.Now()
	removed := 0

	for addrStr, token := range tc.tokens {
		if tc.expiredAt(token, now) {
			delete(tc.tokens, addrStr)
			removed++
		}
	}

	return removed
}

// Size returns the number of tokens currently in the cache.
func (tc *TokenCache) Size() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return len(tc.tokens)
}

// Clear removes all tokens from the cache.
func (tc *TokenCache) Clear() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.tokens = make(map[string]*Token)
}

// InvalidateAddress removes any token associated with the given address.
// Per spec, tokens are bound to an IP:port pair and must be invalidated
// when a connection migrates to a new address.
func (tc *TokenCache) InvalidateAddress(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	key := addr.String()
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	delete(tc.tokens, key)
}

// evictOldestLocked removes the oldest token from the cache.
// Caller must hold tc.mutex.
func (tc *TokenCache) evictOldestLocked() {
	_, _, _ = eviction.EvictOldestByTime(tc.tokens, func(token *Token) time.Time {
		return token.CreatedAt
	})
}

// GetTTL returns the token time-to-live duration.
func (tc *TokenCache) GetTTL() time.Duration {
	return tc.ttl
}

// lookupToken returns the token for addrStr and whether it exists.
// Must be called with tc.mutex held (read or write).
func (tc *TokenCache) lookupToken(addrStr string) (*Token, bool) {
	token, ok := tc.tokens[addrStr]
	return token, ok
}

// isExpired reports whether token has exceeded its lifetime: the per-token
// ExpiresAt when the issuer set one, otherwise the cache-wide ttl.
func (tc *TokenCache) isExpired(token *Token) bool {
	return tc.expiredAt(token, time.Now())
}

// expiredAt is isExpired with the clock supplied, so Cleanup's single
// time.Now() is not re-read per entry.
func (tc *TokenCache) expiredAt(token *Token, now time.Time) bool {
	if !token.ExpiresAt.IsZero() {
		return now.After(token.ExpiresAt)
	}
	return now.Sub(token.CreatedAt) > tc.ttl
}

// IssueSessionToken creates (or reuses) the long-lived token a peer may present
// in a later Session Request, and returns it with the expiry it was stored with.
//
// ssu2.md §"Tokens": "A token sent in a New Token block in an established
// session may be used in a subsequent connection, and it expires at the time
// specified in that block. Expiration is specified by the sender; recommended
// values are several minutes minimum, one or more hours maximum."
//
// Unlike GenerateToken, the lifetime is the caller's, not the cache's Retry
// TTL, and the result is meant to be published in a New Token block. A shorter
// lifetime is never silently replaced by a longer existing one: §"Tokens" also
// says "Routers should assume that only the last token received is valid", so
// re-issuing refreshes the entry.
func (tc *TokenCache) IssueSessionToken(addr, localAddr *net.UDPAddr, lifetime time.Duration) ([]byte, time.Time, error) {
	if addr == nil {
		return nil, time.Time{}, oops.
			Code("NIL_ADDRESS").
			In("wire").
			Errorf("address cannot be nil")
	}
	if lifetime <= 0 {
		lifetime = DefaultSessionTokenLifetime
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	addrStr := tokenKey(addr, localAddr)
	expires := time.Now().Add(lifetime)

	// Reuse the value already outstanding for this address when it is still
	// valid, only extending its lifetime. Replacing the value would invalidate a
	// Retry token the peer has not presented yet — §"Tokens" binds one token per
	// address pair, and §"Handshake Retransmission" -> §"Retry" expects that
	// token to keep working until it is used.
	if existing, ok := tc.tokens[addrStr]; ok && !tc.isExpired(existing) {
		existing.ExpiresAt = expires
		return existing.Value, expires, nil
	}

	value, err := newTokenBytes()
	if err != nil {
		return nil, time.Time{}, err
	}
	if _, exists := tc.tokens[addrStr]; !exists && len(tc.tokens) >= tc.maxSize {
		tc.evictOldestLocked()
	}
	tc.tokens[addrStr] = &Token{
		Value:        value,
		Address:      addr,
		LocalAddress: localAddr,
		CreatedAt:    time.Now(),
		ExpiresAt:    expires,
	}
	return value, expires, nil
}

// newTokenBytes returns a fresh 8-byte random token value (§"Tokens": the token
// is an 8-byte big-endian value on the wire).
func newTokenBytes() ([]byte, error) {
	value := make([]byte, TokenSize)
	if _, err := rand.Read(value); err != nil {
		return nil, oops.
			Code("TOKEN_GENERATION_FAILED").
			In("wire").
			Wrapf(err, "failed to generate session token")
	}
	return value, nil
}

// AdjustCreatedAtForTest ages every cached token by the given delta so expiry
// behaviour can be tested without sleeping. Test-only.
func (tc *TokenCache) AdjustCreatedAtForTest(delta time.Duration) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	for _, token := range tc.tokens {
		token.CreatedAt = token.CreatedAt.Add(delta)
	}
}
