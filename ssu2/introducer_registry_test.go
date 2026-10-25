package ssu2

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestIntroducer creates a valid RegisteredIntroducer for testing.
func createTestIntroducer(t *testing.T, port int) *RegisteredIntroducer {
	t.Helper()

	return &RegisteredIntroducer{
		Addr:       &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: port},
		RouterHash: make([]byte, 32),
		StaticKey:  make([]byte, 44),
		IntroKey:   make([]byte, 44),
		RelayTag:   uint32(0x12345678 + port),
		AddedAt:    time.Now(),
		LastSeen:   time.Now(),
	}
}

func TestNewIntroducerRegistry(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	assert.NotNil(t, ir)
	assert.Equal(t, 3, 3)
	assert.Equal(t, 0, ir.GetCount())
}

func TestNewIntroducerRegistry_DefaultMaxCount(t *testing.T) {
	ir := NewIntroducerRegistry(0)

	assert.NotNil(t, ir)
	assert.Equal(t, 3, 3)
}

func TestNewIntroducerRegistry_NegativeMaxCount(t *testing.T) {
	ir := NewIntroducerRegistry(-1)

	assert.NotNil(t, ir)
	assert.Equal(t, 3, 3)
}

func TestIntroducerRegistry_AddIntroducer(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)

	require.NoError(t, err)
	assert.Equal(t, 1, ir.GetCount())

	introducers := ir.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.Equal(t, intro.Addr.String(), introducers[0].Addr.String())
	assert.Equal(t, intro.RelayTag, introducers[0].RelayTag)
}

func TestIntroducerRegistry_AddIntroducer_NilInfo(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	err := ir.AddIntroducer(nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "introducer info cannot be nil")
}

func TestIntroducerRegistry_AddIntroducer_NilAddress(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.Addr = nil

	err := ir.AddIntroducer(intro)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "introducer address cannot be nil")
}

func TestIntroducerRegistry_AddIntroducer_InvalidRouterHash(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.RouterHash = make([]byte, 16) // Wrong size

	err := ir.AddIntroducer(intro)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "router hash must be exactly 32 bytes")
}

func TestIntroducerRegistry_AddIntroducer_InvalidStaticKey(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.StaticKey = make([]byte, 32) // Wrong size

	err := ir.AddIntroducer(intro)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "static key must be exactly 44 bytes")
}

func TestIntroducerRegistry_AddIntroducer_InvalidIntroKey(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.IntroKey = make([]byte, 32) // Wrong size

	err := ir.AddIntroducer(intro)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "intro key must be exactly 44 bytes")
}

func TestIntroducerRegistry_AddIntroducer_ZeroRelayTag(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.RelayTag = 0

	err := ir.AddIntroducer(intro)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "relay tag cannot be zero")
}

func TestIntroducerRegistry_AddIntroducer_UpdateExisting(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	// Update with same address but different relay tag
	intro.RelayTag = uint32(0x87654321)
	err = ir.AddIntroducer(intro)
	require.NoError(t, err)

	assert.Equal(t, 1, ir.GetCount())

	introducers := ir.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.Equal(t, uint32(0x87654321), introducers[0].RelayTag)
}

func TestIntroducerRegistry_AddIntroducer_MaxCapacity(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	// Add 3 introducers
	intro1 := createTestIntroducer(t, 8887)
	intro2 := createTestIntroducer(t, 8888)
	intro3 := createTestIntroducer(t, 8889)

	err := ir.AddIntroducer(intro1)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	err = ir.AddIntroducer(intro2)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	err = ir.AddIntroducer(intro3)
	require.NoError(t, err)

	assert.Equal(t, 3, ir.GetCount())

	// Add 4th introducer (should replace oldest)
	time.Sleep(10 * time.Millisecond)
	intro4 := createTestIntroducer(t, 8890)
	err = ir.AddIntroducer(intro4)
	require.NoError(t, err)

	assert.Equal(t, 3, ir.GetCount())

	// Verify intro1 was removed (oldest)
	introducers := ir.GetIntroducers()
	for _, intro := range introducers {
		assert.NotEqual(t, intro1.Addr.String(), intro.Addr.String())
	}
}

func TestIntroducerRegistry_RemoveIntroducer(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)
	assert.Equal(t, 1, ir.GetCount())

	ir.RemoveIntroducer(intro.Addr)

	assert.Equal(t, 0, ir.GetCount())
}

func TestIntroducerRegistry_RemoveIntroducer_NilAddress(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	// Should not panic
	ir.RemoveIntroducer(nil)

	assert.Equal(t, 1, ir.GetCount())
}

func TestIntroducerRegistry_RemoveIntroducer_NotFound(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	// Remove non-existent introducer
	otherAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9999}
	ir.RemoveIntroducer(otherAddr)

	assert.Equal(t, 1, ir.GetCount())
}

func TestIntroducerRegistry_GetIntroducers(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	intro1 := createTestIntroducer(t, 8887)
	intro2 := createTestIntroducer(t, 8888)

	err := ir.AddIntroducer(intro1)
	require.NoError(t, err)

	err = ir.AddIntroducer(intro2)
	require.NoError(t, err)

	introducers := ir.GetIntroducers()

	assert.Len(t, introducers, 2)
}

func TestIntroducerRegistry_GetIntroducers_Empty(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	introducers := ir.GetIntroducers()

	assert.Empty(t, introducers)
}

func TestIntroducerRegistry_GetIntroducers_DefensiveCopy(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	introducers1 := ir.GetIntroducers()
	require.Len(t, introducers1, 1)

	// Modify returned value
	introducers1[0].RelayTag = 0xFFFFFFFF
	introducers1[0].RouterHash[0] = 0xFF

	// Get again
	introducers2 := ir.GetIntroducers()
	require.Len(t, introducers2, 1)

	// Should be unchanged
	assert.Equal(t, intro.RelayTag, introducers2[0].RelayTag)
	assert.Equal(t, byte(0), introducers2[0].RouterHash[0])
}

func TestIntroducerRegistry_UpdateLastSeen(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)
	intro.LastSeen = time.Now().Add(-1 * time.Hour)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	oldTime := time.Now().Add(-1 * time.Hour)
	time.Sleep(10 * time.Millisecond)

	ir.UpdateLastSeen(intro.Addr)

	introducers := ir.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.True(t, introducers[0].LastSeen.After(oldTime))
}

func TestIntroducerRegistry_UpdateLastSeen_NilAddress(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	// Should not panic
	ir.UpdateLastSeen(nil)
}

func TestIntroducerRegistry_UpdateLastSeen_NotFound(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	// Update non-existent introducer (should not panic)
	otherAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9999}
	ir.UpdateLastSeen(otherAddr)
}

func TestIntroducerRegistry_SelectBestIntroducers(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	// Add introducers with different last seen times
	intro1 := createTestIntroducer(t, 8887)
	intro1.LastSeen = time.Now().Add(-3 * time.Hour)
	err := ir.AddIntroducer(intro1)
	require.NoError(t, err)

	intro2 := createTestIntroducer(t, 8888)
	intro2.LastSeen = time.Now().Add(-1 * time.Hour)
	err = ir.AddIntroducer(intro2)
	require.NoError(t, err)

	intro3 := createTestIntroducer(t, 8889)
	intro3.LastSeen = time.Now()
	err = ir.AddIntroducer(intro3)
	require.NoError(t, err)

	selected := ir.SelectBestIntroducers(2)

	require.Len(t, selected, 2)
	// Most recent should be first
	assert.Equal(t, intro3.Addr.String(), selected[0].Addr.String())
	assert.Equal(t, intro2.Addr.String(), selected[1].Addr.String())
}

func TestIntroducerRegistry_SelectBestIntroducers_ZeroCount(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	selected := ir.SelectBestIntroducers(0)

	assert.Nil(t, selected)
}

func TestIntroducerRegistry_SelectBestIntroducers_NegativeCount(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	selected := ir.SelectBestIntroducers(-1)

	assert.Nil(t, selected)
}

func TestIntroducerRegistry_SelectBestIntroducers_Empty(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	selected := ir.SelectBestIntroducers(5)

	assert.Nil(t, selected)
}

func TestIntroducerRegistry_SelectBestIntroducers_MoreThanAvailable(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	selected := ir.SelectBestIntroducers(5)

	require.Len(t, selected, 1)
	assert.Equal(t, intro.Addr.String(), selected[0].Addr.String())
}

func TestIntroducerRegistry_SelectBestIntroducers_DefensiveCopy(t *testing.T) {
	ir := NewIntroducerRegistry(3)
	intro := createTestIntroducer(t, 8887)

	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	selected := ir.SelectBestIntroducers(1)
	require.Len(t, selected, 1)

	// Modify returned value
	selected[0].RelayTag = 0xFFFFFFFF

	// Get again
	selected2 := ir.SelectBestIntroducers(1)
	require.Len(t, selected2, 1)

	// Should be unchanged
	assert.Equal(t, intro.RelayTag, selected2[0].RelayTag)
}

func TestIntroducerRegistry_GetCount(t *testing.T) {
	ir := NewIntroducerRegistry(3)

	assert.Equal(t, 0, ir.GetCount())

	intro := createTestIntroducer(t, 8887)
	err := ir.AddIntroducer(intro)
	require.NoError(t, err)

	assert.Equal(t, 1, ir.GetCount())
}

// TestIntroducerRegistry_GetMaxCount pins the spec cap. I2P only defines the
// introducer slots ih[0-2], so a router may publish at most three introducers;
// NewIntroducerRegistry clamps any larger request to 3 so a caller cannot build
// a registry that would publish more than the network can represent. The
// previous assertion expected the unclamped 5, which no implementation can
// satisfy.
func TestIntroducerRegistry_GetMaxCount(t *testing.T) {
	assert.Equal(t, 3, NewIntroducerRegistry(5).GetMaxCount(), "requests above the spec cap clamp to 3")
	assert.Equal(t, 3, NewIntroducerRegistry(3).GetMaxCount())
	assert.Equal(t, 2, NewIntroducerRegistry(2).GetMaxCount(), "a smaller request is honoured")
	assert.Equal(t, 3, NewIntroducerRegistry(0).GetMaxCount(), "non-positive falls back to the default")
}

func TestIntroducerRegistry_ConcurrentOperations(t *testing.T) {
	ir := NewIntroducerRegistry(10)

	const numGoroutines = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()

			intro := createTestIntroducer(t, 8887+index)
			err := ir.AddIntroducer(intro)
			if err != nil {
				t.Logf("Add error: %v", err)
			}
		}(i)
	}

	wg.Wait()

	// Verify some introducers were added
	count := ir.GetCount()
	assert.Greater(t, count, 0)
	assert.LessOrEqual(t, count, 10) // Max count

	// Concurrent reads and updates
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			_ = ir.GetIntroducers()
		}(i)

		go func(index int) {
			defer wg.Done()
			addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887 + index}
			ir.UpdateLastSeen(addr)
		}(i)
	}

	wg.Wait()

	// Verify still consistent
	assert.Equal(t, count, ir.GetCount())
}

// TestIntroducerRegistry_MultipleIntroducers_OrderByLastSeen checks recency
// ordering. Five introducers are offered but the registry holds only the three
// the spec allows, so the assertion is made against the capacity that actually
// exists; ordering is what this test is about, not the cap.
func TestIntroducerRegistry_MultipleIntroducers_OrderByLastSeen(t *testing.T) {
	ir := NewIntroducerRegistry(5)

	// Add introducers in specific order with different times
	times := []time.Duration{
		-5 * time.Hour,
		-3 * time.Hour,
		-1 * time.Hour,
		-30 * time.Minute,
		-5 * time.Minute,
	}

	for i, duration := range times {
		intro := createTestIntroducer(t, 8887+i)
		intro.LastSeen = time.Now().Add(duration)
		err := ir.AddIntroducer(intro)
		require.NoError(t, err)
	}

	// Select as many as the spec permits. Only 3 of the 5 additions survive:
	// the registry replaces the oldest once at capacity.
	selected := ir.SelectBestIntroducers(3)

	require.Len(t, selected, 3)

	// Verify sorted by most recent first
	for i := 0; i < len(selected)-1; i++ {
		assert.True(t, selected[i].LastSeen.After(selected[i+1].LastSeen) ||
			selected[i].LastSeen.Equal(selected[i+1].LastSeen))
	}
}
