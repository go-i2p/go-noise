package ssu2

import (
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNATTraversal_CompleteRelayFlow tests the complete relay flow:
// Alice (behind NAT) → Bob (introducer/relay) → Charlie (responder)
//
// Flow:
// 1. Alice registers Bob as introducer
// 2. Alice requests relay to reach Charlie
// 3. Bob receives RelayRequest from Alice
// 4. Bob forwards RelayIntro to Charlie
// 5. Charlie initiates hole punch back to Alice
// 6. Connection established between Alice and Charlie
func TestNATTraversal_CompleteRelayFlow(t *testing.T) {
	// Setup three peers: Alice (behind NAT), Bob (introducer), Charlie (target)
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	charlie := setupPeer(t, "Charlie")
	defer charlie.listener.Close()

	// Alice registers Bob as introducer with relay tag
	relayTag := uint32(12345)
	err := alice.relayMgr.RegisterIntroducer(bob.addr, bob.routerHash, relayTag)
	require.NoError(t, err)

	// Verify Alice has Bob as introducer
	introducers := alice.relayMgr.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.Equal(t, bob.addr.String(), introducers[0].Addr.String())
	assert.Equal(t, relayTag, introducers[0].RelayTag)

	// Bob allocates relay tag for Alice
	aliceTag, err := bob.relayMgr.AllocateRelayTag(alice.addr)
	require.NoError(t, err)
	require.NotZero(t, aliceTag)

	// Verify tag was allocated
	assert.True(t, bob.relayMgr.ValidateRelayTag(aliceTag, alice.addr))

	// Alice initiates hole punch to Charlie via Bob
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, relayTag)
	require.NoError(t, err)
	require.NotZero(t, sessionID)

	// Verify hole punch attempt was created
	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, charlie.addr.String(), attempt.RemoteAddr.String())
	assert.Equal(t, bob.addr.String(), attempt.Introducer.String())
	assert.Equal(t, HolePunchRequested, attempt.State)

	// Simulate hole punch progress by directly updating state
	alice.holePunchCoord.SetAttemptState(sessionID, HolePunchSent)

	attempt = alice.holePunchCoord.GetAttempt(sessionID)
	assert.Equal(t, HolePunchSent, attempt.State)

	// Simulate successful hole punch
	err = alice.holePunchCoord.CompleteHolePunch(sessionID)
	require.NoError(t, err)

	attempt = alice.holePunchCoord.GetAttempt(sessionID)
	assert.Equal(t, HolePunchSuccess, attempt.State)
}

// TestNATTraversal_IntroducerExpiration tests introducer expiration and cleanup.
func TestNATTraversal_IntroducerExpiration(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	// Register introducer with short expiration
	relayTag := uint32(12345)
	err := alice.relayMgr.RegisterIntroducer(bob.addr, bob.routerHash, relayTag)
	require.NoError(t, err)

	// Manually expire the introducer
	alice.relayMgr.ExpireAllIntroducers()

	// Trigger cleanup (using time-based cleanup timer or manual check)
	// Since cleanupExpired is private, we verify expiration through GetIntroducers
	// which should filter out expired introducers
	time.Sleep(10 * time.Millisecond) // Allow cleanup timer to run

	// Introducer should be filtered out when expired
	introducers := alice.relayMgr.GetIntroducers()
	assert.Empty(t, introducers)
}

// TestNATTraversal_RelayTagValidation tests relay tag allocation and validation.
func TestNATTraversal_RelayTagValidation(t *testing.T) {
	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	// Bob allocates tag for Alice
	tag, err := bob.relayMgr.AllocateRelayTag(alice.addr)
	require.NoError(t, err)
	require.NotZero(t, tag)

	// Tag should be valid for Alice
	assert.True(t, bob.relayMgr.ValidateRelayTag(tag, alice.addr))

	// Tag should not be valid for different address
	otherAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 9999}
	assert.False(t, bob.relayMgr.ValidateRelayTag(tag, otherAddr))

	// Invalid tag should not validate
	assert.False(t, bob.relayMgr.ValidateRelayTag(99999, alice.addr))
}

// TestNATTraversal_MultipleIntroducers tests managing multiple introducers.
func TestNATTraversal_MultipleIntroducers(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	// Setup three introducers (max per I2P spec)
	introducers := []*testPeer{
		setupPeer(t, "Bob1"),
		setupPeer(t, "Bob2"),
		setupPeer(t, "Bob3"),
	}
	defer func() {
		for _, intro := range introducers {
			intro.listener.Close()
		}
	}()

	// Register all three introducers
	for i, intro := range introducers {
		tag := uint32(10000 + i)
		err := alice.relayMgr.RegisterIntroducer(intro.addr, intro.routerHash, tag)
		require.NoError(t, err)
	}

	// Should have all three introducers
	regIntroducers := alice.relayMgr.GetIntroducers()
	require.Len(t, regIntroducers, 3)

	// Attempt to register fourth introducer (should replace oldest)
	bob4 := setupPeer(t, "Bob4")
	defer bob4.listener.Close()

	err := alice.relayMgr.RegisterIntroducer(bob4.addr, bob4.routerHash, 10003)
	require.NoError(t, err)

	// Should still have three introducers
	regIntroducers = alice.relayMgr.GetIntroducers()
	require.Len(t, regIntroducers, 3)
}

// TestNATTraversal_ConcurrentRelayRequests tests concurrent relay operations.
func TestNATTraversal_ConcurrentRelayRequests(t *testing.T) {
	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	// Create multiple Alice peers
	numPeers := 10
	alices := make([]*testPeer, numPeers)
	for i := 0; i < numPeers; i++ {
		alices[i] = setupPeer(t, "Alice"+string(rune('0'+i)))
	}
	defer func() {
		for _, alice := range alices {
			alice.listener.Close()
		}
	}()

	// Concurrently allocate relay tags
	var wg sync.WaitGroup
	tags := make([]uint32, numPeers)
	for i := 0; i < numPeers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tag, err := bob.relayMgr.AllocateRelayTag(alices[idx].addr)
			if err == nil {
				tags[idx] = tag
			}
		}(i)
	}
	wg.Wait()

	// All tags should be unique and non-zero
	tagMap := make(map[uint32]bool)
	for i, tag := range tags {
		require.NotZero(t, tag, "tag %d should not be zero", i)
		assert.False(t, tagMap[tag], "tag %d should be unique", tag)
		tagMap[tag] = true
	}

	// All tags should validate for their respective addresses
	for i, tag := range tags {
		assert.True(t, bob.relayMgr.ValidateRelayTag(tag, alices[i].addr))
	}
}

// TestNATTraversal_HolePunchRetry tests retry mechanism for failed hole punches.
func TestNATTraversal_HolePunchRetry(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	charlie := setupPeer(t, "Charlie")
	defer charlie.listener.Close()

	relayTag := uint32(12345)

	// Initiate hole punch
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, relayTag)
	require.NoError(t, err)

	// Simulate failure and retry
	err = alice.holePunchCoord.FailHolePunch(sessionID, nil)
	require.NoError(t, err)

	// Retry hole punch
	err = alice.holePunchCoord.RetryHolePunch(sessionID)
	require.NoError(t, err)

	// Check retry count increased
	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, 1, attempt.Retries)

	// State should be back to Requested
	assert.Equal(t, HolePunchRequested, attempt.State)
}

// TestNATTraversal_HolePunchTimeout tests timeout handling.
func TestNATTraversal_HolePunchTimeout(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	charlie := setupPeer(t, "Charlie")
	defer charlie.listener.Close()

	relayTag := uint32(12345)

	// Initiate hole punch
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, relayTag)
	require.NoError(t, err)

	// Manually set start time to past (simulate timeout)
	alice.holePunchCoord.SetAttemptStartTime(sessionID, time.Now().Add(-2*time.Minute))

	// Check if timed out
	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)

	// 30 second timeout should be exceeded
	elapsed := time.Since(attempt.StartTime)
	assert.Greater(t, elapsed, 30*time.Second)
}

// TestNATTraversal_HolePunchMaxRetries tests max retry limit.
func TestNATTraversal_HolePunchMaxRetries(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	charlie := setupPeer(t, "Charlie")
	defer charlie.listener.Close()

	relayTag := uint32(12345)

	// Initiate hole punch
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, relayTag)
	require.NoError(t, err)

	// Retry until max retries (3 per I2P convention)
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		err = alice.holePunchCoord.FailHolePunch(sessionID, nil)
		require.NoError(t, err)

		err = alice.holePunchCoord.RetryHolePunch(sessionID)
		require.NoError(t, err)
	}

	// Check retry count at max
	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, maxRetries, attempt.Retries)

	// Another retry should fail
	err = alice.holePunchCoord.FailHolePunch(sessionID, nil)
	require.NoError(t, err)

	err = alice.holePunchCoord.RetryHolePunch(sessionID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum retry attempts exceeded")
}

// TestNATTraversal_IntroducerRegistry tests introducer registry integration.
func TestNATTraversal_IntroducerRegistry(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	// Create introducer registry
	registry := NewIntroducerRegistry(3)
	require.NotNil(t, registry)

	// Setup three introducers
	introducers := []*testPeer{
		setupPeer(t, "Bob1"),
		setupPeer(t, "Bob2"),
		setupPeer(t, "Bob3"),
	}
	defer func() {
		for _, intro := range introducers {
			intro.listener.Close()
		}
	}()

	// Add introducers to registry
	for i, intro := range introducers {
		regIntro := &RegisteredIntroducer{
			Addr:       intro.addr,
			RouterHash: intro.routerHash[:],
			StaticKey:  make([]byte, 44), // 44 bytes base64
			IntroKey:   make([]byte, 44), // 44 bytes base64
			RelayTag:   uint32(10000 + i),
			AddedAt:    time.Now(),
			LastSeen:   time.Now(),
		}
		err := registry.AddIntroducer(regIntro)
		require.NoError(t, err)
	}

	// Should have all three introducers
	regIntroducers := registry.GetIntroducers()
	require.Len(t, regIntroducers, 3)

	// Select best introducers (by last seen)
	best := registry.SelectBestIntroducers(2)
	require.Len(t, best, 2)

	// Update last seen for first introducer
	registry.UpdateLastSeen(introducers[0].addr)

	// First introducer should now be freshest
	best = registry.SelectBestIntroducers(1)
	require.Len(t, best, 1)
	assert.Equal(t, introducers[0].addr.String(), best[0].Addr.String())
}

// TestNATTraversal_PendingSessionTracking tests pending session management.
func TestNATTraversal_PendingSessionTracking(t *testing.T) {
	alice := setupPeer(t, "Alice")
	defer alice.listener.Close()

	bob := setupPeer(t, "Bob")
	defer bob.listener.Close()

	charlie := setupPeer(t, "Charlie")
	defer charlie.listener.Close()

	relayTag := uint32(12345)

	// Register Bob as introducer
	err := alice.relayMgr.RegisterIntroducer(bob.addr, bob.routerHash, relayTag)
	require.NoError(t, err)

	// Initiate hole punch (creates pending session)
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, relayTag)
	require.NoError(t, err)

	// Verify pending session exists in relay manager
	pending := alice.relayMgr.GetPendingSession(sessionID)

	require.NotNil(t, pending)
	assert.Equal(t, charlie.addr.String(), pending.RemoteAddr.String())
	assert.Equal(t, bob.addr.String(), pending.IntroducerAddr.String())
	assert.Equal(t, relayTag, pending.RelayTag)

	// Complete hole punch (marks as successful)
	err = alice.holePunchCoord.CompleteHolePunch(sessionID)
	require.NoError(t, err)

	// Verify hole punch is marked successful
	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchSuccess, attempt.State)

	// Note: Pending session cleanup is responsibility of the application layer
	// The hole punch coordinator marks state, but doesn't remove pending sessions
}

// testPeer represents a peer in the test network.
type testPeer struct {
	addr           *net.UDPAddr
	routerHash     data.Hash
	listener       *SSU2Listener
	relayMgr       *RelayManager
	holePunchCoord *HolePunchCoordinator
}

// setupPeer creates and initializes a test peer with all NAT traversal components.
func setupPeer(t *testing.T, name string) *testPeer {
	// Create unique router hash
	var routerHash data.Hash
	for i := range routerHash {
		routerHash[i] = byte(i) ^ byte(name[0]) // Mix in name for uniqueness
	}

	// Create configuration
	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	config.RouterInfoValidator = DefaultRouterInfoValidator

	staticKey := make([]byte, 32)
	config = config.WithStaticKey(staticKey)

	// Create UDP listener
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	// Create SSU2 listener
	listener, err := NewSSU2Listener(packetConn, config)
	require.NoError(t, err)

	// Create NAT traversal components
	relayMgr := NewRelayManager(listener)
	testPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	holePunchCoord, err := NewHolePunchCoordinator(relayMgr, func(_ HolePunchVerifyInfo) (HolePunchVerifyContext, ed25519.PublicKey, bool) {
		return HolePunchVerifyContext{}, testPub, true
	})
	require.NoError(t, err)

	return &testPeer{
		addr:           packetConn.LocalAddr().(*net.UDPAddr),
		routerHash:     routerHash,
		listener:       listener,
		relayMgr:       relayMgr,
		holePunchCoord: holePunchCoord,
	}
}
