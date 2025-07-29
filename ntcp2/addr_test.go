package ntcp2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNTCP2Addr(t *testing.T) {
	tests := []struct {
		name         string
		underlying   net.Addr
		routerHash   []byte
		role         string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid_initiator_addr",
			underlying:  &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:  make([]byte, 32), // Valid 32-byte hash
			role:        "initiator",
			expectError: false,
		},
		{
			name:        "valid_responder_addr",
			underlying:  &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9091},
			routerHash:  make([]byte, 32),
			role:        "responder",
			expectError: false,
		},
		{
			name:         "nil_underlying_addr",
			underlying:   nil,
			routerHash:   make([]byte, 32),
			role:         "initiator",
			expectError:  true,
			errorMessage: "underlying address cannot be nil",
		},
		{
			name:         "invalid_router_hash_too_short",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   make([]byte, 16), // Too short
			role:         "initiator",
			expectError:  true,
			errorMessage: "router hash must be exactly 32 bytes",
		},
		{
			name:         "invalid_router_hash_too_long",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   make([]byte, 64), // Too long
			role:         "initiator",
			expectError:  true,
			errorMessage: "router hash must be exactly 32 bytes",
		},
		{
			name:         "invalid_role",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   make([]byte, 32),
			role:         "invalid",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
		{
			name:         "empty_role",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   make([]byte, 32),
			role:         "",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewNTCP2Addr(tt.underlying, tt.routerHash, tt.role)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, addr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, addr)
				assert.Equal(t, tt.underlying, addr.underlying)
				assert.Equal(t, tt.role, addr.role)
				assert.Equal(t, 32, len(addr.routerHash))
				assert.Nil(t, addr.destHash)
				assert.Nil(t, addr.sessionTag)
			}
		})
	}
}

func TestNTCP2Addr_WithDestinationHash(t *testing.T) {
	// Create base address
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	baseAddr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	tests := []struct {
		name         string
		destHash     []byte
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid_dest_hash",
			destHash:    make([]byte, 32),
			expectError: false,
		},
		{
			name:        "nil_dest_hash",
			destHash:    nil,
			expectError: false,
		},
		{
			name:         "invalid_dest_hash_too_short",
			destHash:     make([]byte, 16),
			expectError:  true,
			errorMessage: "destination hash must be exactly 32 bytes or nil",
		},
		{
			name:         "invalid_dest_hash_too_long",
			destHash:     make([]byte, 64),
			expectError:  true,
			errorMessage: "destination hash must be exactly 32 bytes or nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newAddr, err := baseAddr.WithDestinationHash(tt.destHash)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, newAddr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, newAddr)

				// Verify immutability - original should be unchanged
				assert.Nil(t, baseAddr.destHash)

				if tt.destHash != nil {
					assert.Equal(t, 32, len(newAddr.destHash))
					// Test defensive copy by modifying original and verifying it doesn't affect the copy
					if len(tt.destHash) > 0 {
						originalByte := tt.destHash[0]
						tt.destHash[0] = 0xFF
						assert.NotEqual(t, byte(0xFF), newAddr.destHash[0])
						tt.destHash[0] = originalByte // Restore
					}
				} else {
					assert.Nil(t, newAddr.destHash)
				}
			}
		})
	}
}

func TestNTCP2Addr_WithSessionTag(t *testing.T) {
	// Create base address
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	baseAddr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	tests := []struct {
		name         string
		sessionTag   []byte
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid_session_tag",
			sessionTag:  make([]byte, 8),
			expectError: false,
		},
		{
			name:        "nil_session_tag",
			sessionTag:  nil,
			expectError: false,
		},
		{
			name:         "invalid_session_tag_too_short",
			sessionTag:   make([]byte, 4),
			expectError:  true,
			errorMessage: "session tag must be exactly 8 bytes or nil",
		},
		{
			name:         "invalid_session_tag_too_long",
			sessionTag:   make([]byte, 16),
			expectError:  true,
			errorMessage: "session tag must be exactly 8 bytes or nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newAddr, err := baseAddr.WithSessionTag(tt.sessionTag)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, newAddr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, newAddr)

				// Verify immutability - original should be unchanged
				assert.Nil(t, baseAddr.sessionTag)

				if tt.sessionTag != nil {
					assert.Equal(t, 8, len(newAddr.sessionTag))
					// Test defensive copy by modifying original and verifying it doesn't affect the copy
					if len(tt.sessionTag) > 0 {
						originalByte := tt.sessionTag[0]
						tt.sessionTag[0] = 0xFF
						assert.NotEqual(t, byte(0xFF), newAddr.sessionTag[0])
						tt.sessionTag[0] = originalByte // Restore
					}
				} else {
					assert.Nil(t, newAddr.sessionTag)
				}
			}
		})
	}
}

func TestNTCP2Addr_NetAddrInterface(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Test net.Addr interface compliance
	var netAddr net.Addr = addr
	assert.Equal(t, "ntcp2", netAddr.Network())
	assert.Contains(t, netAddr.String(), "ntcp2://")
}

func TestNTCP2Addr_Network(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	assert.Equal(t, "ntcp2", addr.Network())
}

func TestNTCP2Addr_String(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	// Set some recognizable bytes in router hash
	routerHash[0] = 0xAA
	routerHash[31] = 0xBB

	tests := []struct {
		name        string
		setupAddr   func(*NTCP2Addr) *NTCP2Addr
		contains    []string
		notContains []string
	}{
		{
			name: "basic_address",
			setupAddr: func(addr *NTCP2Addr) *NTCP2Addr {
				return addr
			},
			contains: []string{
				"ntcp2://",
				"/initiator/",
				"192.168.1.1:8080",
			},
			notContains: []string{"?dest=", "&session="},
		},
		{
			name: "with_destination_hash",
			setupAddr: func(addr *NTCP2Addr) *NTCP2Addr {
				destHash := make([]byte, 32)
				destHash[0] = 0xCC
				newAddr, _ := addr.WithDestinationHash(destHash)
				return newAddr
			},
			contains: []string{
				"ntcp2://",
				"/initiator/",
				"192.168.1.1:8080",
				"?dest=",
			},
			notContains: []string{"&session="},
		},
		{
			name: "with_session_tag",
			setupAddr: func(addr *NTCP2Addr) *NTCP2Addr {
				sessionTag := make([]byte, 8)
				sessionTag[0] = 0xDD
				newAddr, _ := addr.WithSessionTag(sessionTag)
				return newAddr
			},
			contains: []string{
				"ntcp2://",
				"/initiator/",
				"192.168.1.1:8080",
				"?session=",
			},
			notContains: []string{"dest="},
		},
		{
			name: "with_both_dest_and_session",
			setupAddr: func(addr *NTCP2Addr) *NTCP2Addr {
				destHash := make([]byte, 32)
				sessionTag := make([]byte, 8)
				newAddr, _ := addr.WithDestinationHash(destHash)
				newAddr, _ = newAddr.WithSessionTag(sessionTag)
				return newAddr
			},
			contains: []string{
				"ntcp2://",
				"/initiator/",
				"192.168.1.1:8080",
				"?dest=",
				"&session=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseAddr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
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

func TestNTCP2Addr_AccessorMethods(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	routerHash[0] = 0xAA // Set recognizable byte

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Test RouterHash - should return defensive copy
	returnedHash := addr.RouterHash()
	assert.Equal(t, 32, len(returnedHash))
	assert.Equal(t, byte(0xAA), returnedHash[0])
	// Test defensive copy by modifying returned slice
	returnedHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.RouterHash()[0]) // Original should be unchanged

	// Test Role
	assert.Equal(t, "initiator", addr.Role())

	// Test UnderlyingAddr
	assert.Equal(t, underlying, addr.UnderlyingAddr())

	// Test IsRouterToRouter / IsTunnelConnection
	assert.True(t, addr.IsRouterToRouter())
	assert.False(t, addr.IsTunnelConnection())

	// Add destination hash and test again
	destHash := make([]byte, 32)
	destHash[0] = 0xBB
	addrWithDest, err := addr.WithDestinationHash(destHash)
	require.NoError(t, err)

	returnedDest := addrWithDest.DestinationHash()
	assert.Equal(t, 32, len(returnedDest))
	assert.Equal(t, byte(0xBB), returnedDest[0])
	// Test defensive copy by modifying returned slice
	returnedDest[0] = 0xFF
	assert.Equal(t, byte(0xBB), addrWithDest.DestinationHash()[0]) // Original should be unchanged

	assert.False(t, addrWithDest.IsRouterToRouter())
	assert.True(t, addrWithDest.IsTunnelConnection())

	// Test SessionTag
	sessionTag := make([]byte, 8)
	sessionTag[0] = 0xCC
	addrWithSession, err := addr.WithSessionTag(sessionTag)
	require.NoError(t, err)

	returnedSession := addrWithSession.SessionTag()
	assert.Equal(t, 8, len(returnedSession))
	assert.Equal(t, byte(0xCC), returnedSession[0])
	// Test defensive copy by modifying returned slice
	returnedSession[0] = 0xFF
	assert.Equal(t, byte(0xCC), addrWithSession.SessionTag()[0]) // Original should be unchanged
}

func TestNTCP2Addr_DefensiveCopying(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	routerHash[0] = 0xAA

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Modify original router hash - should not affect created address
	routerHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])

	// Modify returned router hash - should not affect internal state
	returned := addr.RouterHash()
	returned[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])
}

func TestNTCP2Addr_StringHandlesNilUnderlying(t *testing.T) {
	// Test edge case - this shouldn't happen in normal usage but we handle it gracefully
	addr := &NTCP2Addr{
		underlying: nil,
		routerHash: make([]byte, 32),
		role:       "initiator",
	}

	str := addr.String()
	assert.Equal(t, "ntcp2://invalid", str)
}

func TestNTCP2Addr_BuilderPattern(t *testing.T) {
	// Test builder pattern with method chaining
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	destHash := make([]byte, 32)
	sessionTag := make([]byte, 8)

	// Set recognizable bytes
	routerHash[0] = 0xAA
	destHash[0] = 0xBB
	sessionTag[0] = 0xCC

	// Create base address
	baseAddr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Chain builder methods
	addrWithDest, err := baseAddr.WithDestinationHash(destHash)
	require.NoError(t, err)

	finalAddr, err := addrWithDest.WithSessionTag(sessionTag)
	require.NoError(t, err)

	// Verify final address has all components
	assert.Equal(t, byte(0xAA), finalAddr.RouterHash()[0])
	assert.Equal(t, byte(0xBB), finalAddr.DestinationHash()[0])
	assert.Equal(t, byte(0xCC), finalAddr.SessionTag()[0])
	assert.True(t, finalAddr.IsTunnelConnection())

	// Verify original is unchanged (immutability)
	assert.Nil(t, baseAddr.DestinationHash())
	assert.Nil(t, baseAddr.SessionTag())
	assert.True(t, baseAddr.IsRouterToRouter())
}

// Benchmark tests to ensure performance is adequate
func BenchmarkNTCP2Addr_Creation(b *testing.B) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewNTCP2Addr(underlying, routerHash, "initiator")
	}
}

func BenchmarkNTCP2Addr_String(b *testing.B) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	routerHash := make([]byte, 32)
	addr, _ := NewNTCP2Addr(underlying, routerHash, "initiator")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.String()
	}
}
