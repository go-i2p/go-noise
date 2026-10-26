package wire

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal/eviction"
	"github.com/samber/oops"
)

// SessionTokenStore holds the tokens *received* from peers in New Token blocks,
// for use in a subsequent Session Request.
//
// ssu2.md §"Tokens": "A token sent in a New Token block in an established
// session may be used in a subsequent connection, and it expires at the time
// specified in that block." §"Session Request" then requires the token in
// header bytes 24-31: "Token :: 0 if not previously received from Bob".
//
// This is the outbound half of the token mechanism and is deliberately a
// separate store from the listener's TokenCache, which holds the tokens this
// router *issued* to peers. The two are keyed by the same
// (source IP/port, destination IP/port) pair from opposite sides, so sharing one
// map would let an inbound-issued token be replayed outbound.
//
// §"Tokens" also fixes the replacement and invalidation rules this implements:
// "Routers should assume that only the last token received is valid", and "If a
// router's IP or port changes, it must delete all saved tokens (both inbound and
// outbound) for the old IP or port, as they are no longer valid."
type SessionTokenStore struct {
	mutex   sync.RWMutex
	tokens  map[string]*sessionToken
	maxSize int
}

type sessionToken struct {
	value     []byte
	expiresAt time.Time
}

// NewSessionTokenStore creates a bounded store. A maxSize of 0 or less selects
// MaxTokenCacheSize, the same ceiling the retry-token cache uses.
func NewSessionTokenStore(maxSize int) *SessionTokenStore {
	if maxSize <= 0 {
		maxSize = MaxTokenCacheSize
	}
	return &SessionTokenStore{
		tokens:  make(map[string]*sessionToken),
		maxSize: maxSize,
	}
}

// sessionTokenKey binds a token to the (local, destination) pair it was
// obtained on.
//
// ssu2.md §"Tokens": "A token is bound to the combination of source IP/port and
// destination IP/port. A token received on IPv4 may not be used for IPv6 or vice
// versa." From the outbound side that pair is our local address plus the
// peer's, so both must be part of the key.
func sessionTokenKey(local, dest *net.UDPAddr) string {
	if local == nil {
		return dest.String()
	}
	return local.String() + "|" + dest.String()
}

// Save records token for destination dest, expiring at expiresAt. A later Save
// for the same destination replaces the earlier token — §"Tokens": "Routers
// should assume that only the last token received is valid."
func (s *SessionTokenStore) Save(local, dest *net.UDPAddr, token []byte, expiresAt time.Time) error {
	if dest == nil {
		return oops.Code("NIL_ADDRESS").In("wire").Errorf("destination address cannot be nil")
	}
	if len(token) != TokenSize {
		return oops.
			Code("INVALID_SESSION_TOKEN_SIZE").
			In("wire").
			With("length", len(token)).
			Errorf("session token must be %d bytes, got %d", TokenSize, len(token))
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	value := make([]byte, len(token))
	copy(value, token)

	key := sessionTokenKey(local, dest)
	if _, exists := s.tokens[key]; !exists && len(s.tokens) >= s.maxSize {
		eviction.EvictOldestByTime(s.tokens, func(t *sessionToken) time.Time { return t.expiresAt })
	}
	s.tokens[key] = &sessionToken{value: value, expiresAt: expiresAt}
	return nil
}

// Get returns a live token for the (local, dest) pair.
func (s *SessionTokenStore) Get(local, dest *net.UDPAddr) ([]byte, bool) {
	if dest == nil {
		return nil, false
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	t, ok := s.tokens[sessionTokenKey(local, dest)]
	if !ok || time.Now().After(t.expiresAt) {
		return nil, false
	}
	value := make([]byte, len(t.value))
	copy(value, t.value)
	return value, true
}

// Delete discards the saved token for a destination — e.g. after it has been
// presented and rejected. Returns true if a token was removed.
func (s *SessionTokenStore) Delete(local, dest *net.UDPAddr) bool {
	if dest == nil {
		return false
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	key := sessionTokenKey(local, dest)
	if _, ok := s.tokens[key]; !ok {
		return false
	}
	delete(s.tokens, key)
	return true
}

// Clear drops every saved token. §"Tokens" requires deleting all saved outbound
// tokens when the local IP or port changes; the keys here are destinations, so
// the conservative reading is to clear the whole set.
func (s *SessionTokenStore) Clear() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	n := len(s.tokens)
	s.tokens = make(map[string]*sessionToken, n)
	return n
}

// Cleanup removes expired tokens and returns how many were dropped.
func (s *SessionTokenStore) Cleanup() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	removed := 0
	for key, t := range s.tokens {
		if now.After(t.expiresAt) {
			delete(s.tokens, key)
			removed++
		}
	}
	return removed
}

// Size returns the number of stored tokens, expired ones included.
func (s *SessionTokenStore) Size() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.tokens)
}
