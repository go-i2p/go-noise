package config

import (
	"net"
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSSU2Addr(t *testing.T) {
	tests := []struct {
		name         string
		underlying   net.Addr
		routerHash   data.Hash
		connID       uint64
		role         string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid_initiator_addr",
			underlying:  &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:  generateRandomHash(),
			connID:      12345,
			role:        "initiator",
			expectError: false,
		},
		{
			name:        "valid_responder_addr",
			underlying:  &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9091},
			routerHash:  generateRandomHash(),
			connID:      67890,
			role:        "responder",
			expectError: false,
		},
		{
			name:         "nil_underlying_addr",
			underlying:   nil,
			routerHash:   generateRandomHash(),
			connID:       12345,
			role:         "initiator",
			expectError:  true,
			errorMessage: "underlying address cannot be nil",
		},
		{
			name:         "zero_connection_id",
			underlying:   &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   generateRandomHash(),
			connID:       0,
			role:         "initiator",
			expectError:  true,
			errorMessage: "connection ID cannot be zero",
		},
		{
			name:         "invalid_role",
			underlying:   &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   generateRandomHash(),
			connID:       12345,
			role:         "invalid",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
		{
			name:         "empty_role",
			underlying:   &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   generateRandomHash(),
			connID:       12345,
			role:         "",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewSSU2Addr(tt.underlying, tt.routerHash, tt.connID, tt.role)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, addr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, addr)
				assert.Equal(t, tt.underlying, addr.underlying)
				assert.Equal(t, tt.connID, addr.connectionID)
				assert.Equal(t, tt.role, addr.role)
				assert.Equal(t, 32, len(addr.routerHash))
				assert.Nil(t, addr.destHash)
				assert.Nil(t, addr.introducerAddr)
			}
		})
	}
}

func TestSSU2Addr_WithDestinationHash(t *testing.T) {
	// Create base address
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	baseAddr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	t.Run("valid_dest_hash", func(t *testing.T) {
		destHash := generateRandomHash()
		newAddr := baseAddr.WithDestinationHash(destHash)
		require.NotNil(t, newAddr)

		// Verify immutability - original should be unchanged
		assert.Nil(t, baseAddr.destHash)

		returnedDest := newAddr.DestinationHash()
		require.NotNil(t, returnedDest)
		assert.Equal(t, destHash, *returnedDest)
	})

	t.Run("zero_dest_hash", func(t *testing.T) {
		destHash := data.Hash{}
		newAddr := baseAddr.WithDestinationHash(destHash)
		require.NotNil(t, newAddr)

		// Verify immutability - original should be unchanged
		assert.Nil(t, baseAddr.destHash)

		returnedDest := newAddr.DestinationHash()
		require.NotNil(t, returnedDest)
		assert.Equal(t, destHash, *returnedDest)
	})
}

func TestSSU2Addr_WithIntroducer(t *testing.T) {
	// Create base address
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	baseAddr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	tests := []struct {
		name           string
		introducerAddr net.Addr
		expectError    bool
		errorMessage   string
	}{
		{
			name:           "valid_introducer",
			introducerAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9999},
			expectError:    false,
		},
		{
			name:           "nil_introducer",
			introducerAddr: nil,
			expectError:    true,
			errorMessage:   "introducer address cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newAddr, err := baseAddr.WithIntroducer(tt.introducerAddr)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, newAddr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, newAddr)

				// Verify immutability - original should be unchanged
				assert.Nil(t, baseAddr.introducerAddr)
				assert.Equal(t, tt.introducerAddr, newAddr.introducerAddr)
			}
		})
	}
}

func TestSSU2Addr_NetAddrInterface(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	addr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	// Test net.Addr interface compliance
	var netAddr net.Addr = addr
	assert.Equal(t, "ssu2", netAddr.Network())
	assert.Contains(t, netAddr.String(), "ssu2://")
}

// TestSSU2Addr_ConcurrentUpdateRouterHash exercises concurrent
// UpdateRouterHash() writes racing against RouterHash()/String() reads,
// verifying the sync.RWMutex guard added for AUDIT.md Level 9 ssu2/config
// Finding 1 (previously unsynchronized, unlike ntcp2.Addr's identical
// pattern). Run with -race.
func TestSSU2Addr_ConcurrentUpdateRouterHash(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	addr, err := NewSSU2Addr(underlying, generateRandomHash(), 12345, "responder")
	require.NoError(t, err)

	var wg sync.WaitGroup
	const iterations = 200

	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			addr.UpdateRouterHash(generateRandomHash())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = addr.RouterHash()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = addr.String()
		}
	}()
	wg.Wait()
}

func TestSSU2Addr_Network(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	addr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	assert.Equal(t, "ssu2", addr.Network())
}

func TestSSU2Addr_String(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	// Set some recognizable bytes in router hash
	routerHash[0] = 0xAA
	routerHash[31] = 0xBB

	tests := []struct {
		name        string
		setupAddr   func(*SSU2Addr) *SSU2Addr
		contains    []string
		notContains []string
	}{
		{
			name: "basic_address",
			setupAddr: func(addr *SSU2Addr) *SSU2Addr {
				return addr
			},
			contains: []string{
				"ssu2://",
				":12345/initiator/",
				"192.168.1.1:8080",
			},
			notContains: []string{"?dest=", "&introducer="},
		},
		{
			name: "with_destination_hash",
			setupAddr: func(addr *SSU2Addr) *SSU2Addr {
				var destHash data.Hash
				destHash[0] = 0xCC
				newAddr := addr.WithDestinationHash(destHash)
				return newAddr
			},
			contains: []string{
				"ssu2://",
				":12345/initiator/",
				"192.168.1.1:8080",
				"?dest=",
			},
			notContains: []string{"&introducer="},
		},
		{
			name: "with_introducer",
			setupAddr: func(addr *SSU2Addr) *SSU2Addr {
				introducerAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9999}
				newAddr, _ := addr.WithIntroducer(introducerAddr)
				return newAddr
			},
			contains: []string{
				"ssu2://",
				":12345/initiator/",
				"192.168.1.1:8080",
				"?introducer=",
				"10.0.0.2:9999",
			},
			notContains: []string{"dest="},
		},
		{
			name: "with_both_dest_and_introducer",
			setupAddr: func(addr *SSU2Addr) *SSU2Addr {
				var destHash data.Hash
				introducerAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9999}
				newAddr := addr.WithDestinationHash(destHash)
				newAddr, _ = newAddr.WithIntroducer(introducerAddr)
				return newAddr
			},
			contains: []string{
				"ssu2://",
				":12345/initiator/",
				"192.168.1.1:8080",
				"?dest=",
				"&introducer=",
				"10.0.0.2:9999",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseAddr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
			require.NoError(t, err)

			addr := tt.setupAddr(baseAddr)
			str := addr.String()

			for _, substr := range tt.contains {
				assert.Contains(t, str, substr, "String should contain %s", substr)
			}

			for _, substr := range tt.notContains {
				assert.NotContains(t, str, substr, "String should not contain %s", substr)
			}
		})
	}
}

func TestSSU2Addr_AccessorMethods(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	routerHash[0] = 0xAA // Set recognizable byte
	connID := uint64(12345)

	addr, err := NewSSU2Addr(underlying, routerHash, connID, "initiator")
	require.NoError(t, err)

	// Test RouterHash - returns data.Hash value type
	returnedHash := addr.RouterHash()
	assert.Equal(t, 32, len(returnedHash))
	assert.Equal(t, byte(0xAA), returnedHash[0])
	// Modifying the returned value should not affect internal state (value type copy)
	returnedHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.RouterHash()[0]) // Original should be unchanged

	// Test ConnectionID
	assert.Equal(t, connID, addr.ConnectionID())

	// Test Role
	assert.Equal(t, "initiator", addr.Role())

	// Test UnderlyingAddr
	assert.Equal(t, underlying, addr.UnderlyingAddr())

	// Test IsDirectConnection / IsIntroducedConnection
	assert.True(t, addr.IsDirectConnection())
	assert.False(t, addr.IsIntroducedConnection())

	// Test IsRouterToRouter / IsTunnelConnection
	assert.True(t, addr.IsRouterToRouter())
	assert.False(t, addr.IsTunnelConnection())

	// Add destination hash and test again
	var destHash data.Hash
	destHash[0] = 0xBB
	addrWithDest := addr.WithDestinationHash(destHash)

	returnedDest := addrWithDest.DestinationHash()
	require.NotNil(t, returnedDest)
	assert.Equal(t, 32, len(*returnedDest))
	assert.Equal(t, byte(0xBB), returnedDest[0])
	// Modifying the returned value should not affect internal state
	returnedDest[0] = 0xFF
	assert.Equal(t, byte(0xBB), addrWithDest.DestinationHash()[0]) // Original should be unchanged

	assert.False(t, addrWithDest.IsRouterToRouter())
	assert.True(t, addrWithDest.IsTunnelConnection())

	// Add introducer and test
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9999}
	addrWithIntroducer, err := addr.WithIntroducer(introducerAddr)
	require.NoError(t, err)

	assert.Equal(t, introducerAddr, addrWithIntroducer.IntroducerAddr())
	assert.False(t, addrWithIntroducer.IsDirectConnection())
	assert.True(t, addrWithIntroducer.IsIntroducedConnection())
}

func TestSSU2Addr_DefensiveCopying(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	routerHash[0] = 0xAA

	addr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	// data.Hash is a value type [32]byte, so the original variable is independent
	routerHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])

	// Modify returned router hash - should not affect internal state (value copy)
	returned := addr.RouterHash()
	returned[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])
}

func TestSSU2Addr_StringHandlesNilUnderlying(t *testing.T) {
	// Test edge case - this shouldn't happen in normal usage but we handle it gracefully
	addr := &SSU2Addr{
		underlying:   nil,
		routerHash:   data.Hash{},
		connectionID: 12345,
		role:         "initiator",
	}

	str := addr.String()
	assert.Equal(t, "ssu2://invalid", str)
}

func TestSSU2Addr_BuilderPattern(t *testing.T) {
	// Test builder pattern with method chaining
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	var destHash data.Hash
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9999}

	// Set recognizable bytes
	routerHash[0] = 0xAA
	destHash[0] = 0xBB

	// Create base address
	baseAddr, err := NewSSU2Addr(underlying, routerHash, 12345, "initiator")
	require.NoError(t, err)

	// Chain builder methods
	addrWithDest := baseAddr.WithDestinationHash(destHash)

	finalAddr, err := addrWithDest.WithIntroducer(introducerAddr)
	require.NoError(t, err)

	// Verify final address has all components
	assert.Equal(t, byte(0xAA), finalAddr.RouterHash()[0])
	assert.Equal(t, byte(0xBB), finalAddr.DestinationHash()[0])
	assert.Equal(t, introducerAddr, finalAddr.IntroducerAddr())
	assert.True(t, finalAddr.IsTunnelConnection())
	assert.True(t, finalAddr.IsIntroducedConnection())

	// Verify original is unchanged (immutability)
	assert.Nil(t, baseAddr.DestinationHash())
	assert.Nil(t, baseAddr.IntroducerAddr())
	assert.True(t, baseAddr.IsRouterToRouter())
	assert.True(t, baseAddr.IsDirectConnection())
}

func TestGenerateConnectionID(t *testing.T) {
	// Test that generated IDs are non-zero
	for i := 0; i < 100; i++ {
		id, err := GenerateConnectionID()
		require.NoError(t, err)
		assert.NotEqual(t, uint64(0), id, "Generated connection ID should not be zero")
	}

	// Test uniqueness - generate multiple IDs and verify they're different
	ids := make(map[uint64]bool)
	iterations := 1000
	for i := 0; i < iterations; i++ {
		id, err := GenerateConnectionID()
		require.NoError(t, err)
		ids[id] = true
	}

	// With 1000 random 64-bit values, collisions are astronomically unlikely
	assert.Equal(t, iterations, len(ids), "All generated IDs should be unique")
}

func TestSSU2Addr_ConnectionIDInString(t *testing.T) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	connID := uint64(12345)

	addr, err := NewSSU2Addr(underlying, routerHash, connID, "initiator")
	require.NoError(t, err)

	str := addr.String()
	// Connection ID should appear in decimal form in the string
	assert.Contains(t, str, ":12345/")
	assert.Contains(t, str, "initiator")
}

// Benchmark tests to ensure performance is adequate
func BenchmarkSSU2Addr_Creation(b *testing.B) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	connID := uint64(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSSU2Addr(underlying, routerHash, connID, "initiator")
	}
}

func BenchmarkSSU2Addr_String(b *testing.B) {
	underlying := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := generateRandomHash()
	addr, _ := NewSSU2Addr(underlying, routerHash, 12345, "initiator")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.String()
	}
}

func BenchmarkGenerateConnectionID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateConnectionID()
	}
}
