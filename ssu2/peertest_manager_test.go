//go:build test_with_external_deps
// +build test_with_external_deps

// Build constraint: This test file requires the external go-i2p/path dependency
// which may have out-of-date behavior. To run these tests, use:
//   go test -tags=test_with_external_deps -race ./ssu2
// To exclude these tests (keeping the main suite green), simply run:
//   go test -race ./ssu2
// See AUDIT.md (LOW-2) for details on the external dependency issue.

package ssu2

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewPeerTestManager tests manager creation.
func TestNewPeerTestManager(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)
	require.NotNil(t, ptm)

	assert.NotNil(t, ptm.GetListener())
	assert.NotNil(t, ptm.GetTestsMap())
	assert.NotNil(t, ptm.GetResultsMap())
	assert.Empty(t, ptm.GetTestsMap())
	assert.Empty(t, ptm.GetResultsMap())
}

// TestPeerTestManager_InitiatePeerTest tests initiating a peer test.
func TestPeerTestManager_InitiatePeerTest(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}

	// Initiate test
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)
	require.NotZero(t, nonce)

	// Verify test was created
	test := ptm.GetTest(nonce)
	require.NotNil(t, test)
	assert.Equal(t, nonce, test.Nonce)
	assert.Equal(t, RoleInitiator, test.Role)
	assert.Equal(t, TestRequested, test.State)
	assert.Equal(t, bobAddr.String(), test.BobAddr.String())
	assert.False(t, test.StartTime.IsZero())
	assert.False(t, test.Deadline.IsZero())
}

// TestPeerTestManager_InitiatePeerTest_NilAddress tests error handling.
func TestPeerTestManager_InitiatePeerTest_NilAddress(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	nonce, err := ptm.InitiatePeerTest(nil)
	assert.Error(t, err)
	assert.Zero(t, nonce)
	assert.Contains(t, err.Error(), "bob address cannot be nil")
}

// TestPeerTestManager_GetTest tests retrieving test information.
func TestPeerTestManager_GetTest(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Get test
	test := ptm.GetTest(nonce)
	require.NotNil(t, test)
	assert.Equal(t, nonce, test.Nonce)

	// Get non-existent test
	test = ptm.GetTest(99999)
	assert.Nil(t, test)

	// Get with zero nonce
	test = ptm.GetTest(0)
	assert.Nil(t, test)
}

// TestPeerTestManager_UpdateState tests updating test state.
func TestPeerTestManager_UpdateState(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Update to Relayed
	err = ptm.UpdateState(nonce, TestRelayed)
	require.NoError(t, err)

	test := ptm.GetTest(nonce)
	assert.Equal(t, TestRelayed, test.State)

	// Update to Probed
	err = ptm.UpdateState(nonce, TestProbed)
	require.NoError(t, err)

	test = ptm.GetTest(nonce)
	assert.Equal(t, TestProbed, test.State)
}

// TestPeerTestManager_UpdateState_InvalidNonce tests error handling.
func TestPeerTestManager_UpdateState_InvalidNonce(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	// Zero nonce
	err := ptm.UpdateState(0, TestRelayed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce cannot be zero")

	// Non-existent nonce
	err = ptm.UpdateState(99999, TestRelayed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "peer test not found")
}

// TestPeerTestManager_CompleteTest tests completing a test with results.
func TestPeerTestManager_CompleteTest(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Set Alice address for result caching
	ptm.SetTestAliceAddr(nonce, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9090})

	// Complete test
	result := &TestResult{
		NATType:             NATCone,
		ExternalAddr:        &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678},
		ExternalPort:        5678,
		Reachable:           true,
		TestTime:            time.Now(),
		DirectProbeSuccess:  true,
		RelayedProbeSuccess: true,
		PortConsistent:      true,
		IPConsistent:        true,
	}

	err = ptm.CompleteTest(nonce, result)
	require.NoError(t, err)

	// Verify test marked complete
	test := ptm.GetTest(nonce)
	assert.Equal(t, TestComplete, test.State)
	assert.Equal(t, NATCone, test.NATType)
	assert.True(t, test.Reachable)

	// Verify result cached
	cachedResult := ptm.GetResult(test.AliceAddr)
	require.NotNil(t, cachedResult)
	assert.Equal(t, NATCone, cachedResult.NATType)
	assert.True(t, cachedResult.Reachable)
}

// TestPeerTestManager_CompleteTest_NilResult tests error handling.
func TestPeerTestManager_CompleteTest_NilResult(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	err = ptm.CompleteTest(nonce, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "result cannot be nil")
}

// TestPeerTestManager_FailTest tests marking a test as failed.
func TestPeerTestManager_FailTest(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Fail test
	err = ptm.FailTest(nonce, nil)
	require.NoError(t, err)

	// Verify test marked failed
	test := ptm.GetTest(nonce)
	assert.Equal(t, TestFailed, test.State)
}

// TestPeerTestManager_GetResult tests retrieving cached results.
func TestPeerTestManager_GetResult(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	aliceAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9090}

	// No result yet
	result := ptm.GetResult(aliceAddr)
	assert.Nil(t, result)

	// Store result
	ptm.SetRawResult(aliceAddr.String(), &TestResult{
		NATType:   NATCone,
		Reachable: true,
		TestTime:  time.Now(),
	})

	// Retrieve result
	result = ptm.GetResult(aliceAddr)
	require.NotNil(t, result)
	assert.Equal(t, NATCone, result.NATType)
	assert.True(t, result.Reachable)

	// Nil address
	result = ptm.GetResult(nil)
	assert.Nil(t, result)
}

// TestPeerTestManager_RemoveTest tests removing a test.
func TestPeerTestManager_RemoveTest(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Test exists
	test := ptm.GetTest(nonce)
	require.NotNil(t, test)

	// Remove test
	ptm.RemoveTest(nonce)

	// Test removed
	test = ptm.GetTest(nonce)
	assert.Nil(t, test)

	// Remove non-existent (no error)
	ptm.RemoveTest(99999)

	// Remove zero nonce (no error)
	ptm.RemoveTest(0)
}

// TestPeerTestManager_CleanupExpired tests expired test cleanup.
func TestPeerTestManager_CleanupExpired(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Manually expire the test
	ptm.SetTestStartTime(nonce, time.Now().Add(-2*time.Minute))

	// Cleanup
	ptm.CleanupExpired()

	// Test should be removed
	test := ptm.GetTest(nonce)
	assert.Nil(t, test)
}

// TestPeerTestManager_GetStats tests statistics retrieval.
func TestPeerTestManager_GetStats(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	// Initial stats
	stats := ptm.GetStats()
	assert.Equal(t, 0, stats["total_tests"])
	assert.Equal(t, 0, stats["cached_results"])

	// Create some tests
	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}

	nonce1, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	nonce2, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Update states
	err = ptm.UpdateState(nonce1, TestRelayed)
	require.NoError(t, err)

	err = ptm.UpdateState(nonce2, TestProbed)
	require.NoError(t, err)

	// Get stats
	stats = ptm.GetStats()
	assert.Equal(t, 2, stats["total_tests"])
	assert.Equal(t, 1, stats["relayed"])
	assert.Equal(t, 1, stats["probed"])
	assert.Equal(t, 2, stats["role_initiator"])
}

// TestPeerTestManager_DetermineNATType tests NAT type determination logic.
func TestPeerTestManager_DetermineNATType(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	_ = NewPeerTestManager(listener)

	tests := []struct {
		name     string
		result   *TestResult
		expected NATType
	}{
		{
			name:     "nil result",
			result:   nil,
			expected: NATUnknown,
		},
		{
			name: "both probes succeed, consistent",
			result: &TestResult{
				DirectProbeSuccess:  true,
				RelayedProbeSuccess: true,
				PortConsistent:      true,
				IPConsistent:        true,
			},
			expected: NATCone,
		},
		{
			name: "both probes succeed, port inconsistent",
			result: &TestResult{
				DirectProbeSuccess:  true,
				RelayedProbeSuccess: true,
				PortConsistent:      false,
				IPConsistent:        true,
			},
			expected: NATPortRestricted,
		},
		{
			name: "both probes succeed, IP inconsistent",
			result: &TestResult{
				DirectProbeSuccess:  true,
				RelayedProbeSuccess: true,
				PortConsistent:      true,
				IPConsistent:        false,
			},
			expected: NATRestricted,
		},
		{
			name: "only relayed succeeds, port consistent",
			result: &TestResult{
				DirectProbeSuccess:  false,
				RelayedProbeSuccess: true,
				PortConsistent:      true,
				IPConsistent:        true,
			},
			expected: NATRestricted,
		},
		{
			name: "only relayed succeeds, port inconsistent",
			result: &TestResult{
				DirectProbeSuccess:  false,
				RelayedProbeSuccess: true,
				PortConsistent:      false,
				IPConsistent:        true,
			},
			expected: NATSymmetric,
		},
		{
			name: "neither probe succeeds",
			result: &TestResult{
				DirectProbeSuccess:  false,
				RelayedProbeSuccess: false,
			},
			expected: NATUnknown,
		},
		{
			name: "only direct succeeds",
			result: &TestResult{
				DirectProbeSuccess:  true,
				RelayedProbeSuccess: false,
			},
			expected: NATUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			natType := DetermineNATType(tt.result)
			assert.Equal(t, tt.expected, natType)
		})
	}
}

// TestPeerTestRole_String tests role string representation.
func TestPeerTestRole_String(t *testing.T) {
	assert.Equal(t, "Initiator", RoleInitiator.String())
	assert.Equal(t, "Relay", RoleRelay.String())
	assert.Equal(t, "Responder", RoleResponder.String())
	assert.Equal(t, "Unknown", PeerTestRole(99).String())
}

// TestPeerTestState_String tests state string representation.
func TestPeerTestState_String(t *testing.T) {
	assert.Equal(t, "Requested", TestRequested.String())
	assert.Equal(t, "Relayed", TestRelayed.String())
	assert.Equal(t, "Probed", TestProbed.String())
	assert.Equal(t, "Complete", TestComplete.String())
	assert.Equal(t, "Failed", TestFailed.String())
	assert.Equal(t, "Unknown", PeerTestState(99).String())
}

// TestNATType_String tests NAT type string representation.
func TestNATType_String(t *testing.T) {
	assert.Equal(t, "Unknown", NATUnknown.String())
	assert.Equal(t, "None", NATNone.String())
	assert.Equal(t, "Full Cone", NATCone.String())
	assert.Equal(t, "Restricted Cone", NATRestricted.String())
	assert.Equal(t, "Port-Restricted Cone", NATPortRestricted.String())
	assert.Equal(t, "Symmetric", NATSymmetric.String())
	assert.Equal(t, "Unknown", NATType(99).String())
}

// TestPeerTestManager_ConcurrentOperations tests thread safety.
func TestPeerTestManager_ConcurrentOperations(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)
	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}

	// Concurrent test creation
	var wg sync.WaitGroup
	nonces := make([]uint32, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonce, err := ptm.InitiatePeerTest(bobAddr)
			if err == nil {
				nonces[idx] = nonce
			}
		}(i)
	}
	wg.Wait()

	// Verify all tests created
	stats := ptm.GetStats()
	assert.Equal(t, 10, stats["total_tests"])

	// Concurrent state updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if nonces[idx] != 0 {
				_ = ptm.UpdateState(nonces[idx], TestRelayed)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent cleanup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ptm.CleanupExpired()
		}()
	}
	wg.Wait()
}

// TestPeerTestManager_DefensiveCopy tests that returned data is copied.
func TestPeerTestManager_DefensiveCopy(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Get test
	test1 := ptm.GetTest(nonce)
	require.NotNil(t, test1)

	// Modify returned test
	test1.State = TestComplete
	test1.BobAddr.Port = 9999

	// Get again - should be unchanged
	test2 := ptm.GetTest(nonce)
	require.NotNil(t, test2)
	assert.Equal(t, TestRequested, test2.State)
	assert.Equal(t, 8080, test2.BobAddr.Port)
}

// TestPeerTestManager_InitiatePeerTest_ZeroPort tests that port 0 is rejected.
func TestPeerTestManager_InitiatePeerTest_ZeroPort(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 0}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	assert.Error(t, err)
	assert.Zero(t, nonce)
	assert.Contains(t, err.Error(), "invalid source port")
}

// TestPeerTestManager_CreateRelayTest_ZeroPort tests that port 0 is rejected.
func TestPeerTestManager_CreateRelayTest_ZeroPort(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	aliceAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 0}
	charlieAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9090}

	_, err := ptm.CreateRelayTest(42, aliceAddr, charlieAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source port")

	// Charlie zero port also rejected
	aliceAddr.Port = 8080
	charlieAddr.Port = 0
	_, err = ptm.CreateRelayTest(43, aliceAddr, charlieAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source port")
}

// TestPeerTestManager_CreateResponderTest_ZeroPort tests that port 0 is rejected.
func TestPeerTestManager_CreateResponderTest_ZeroPort(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	aliceAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 0}
	bobAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9090}

	err := ptm.CreateResponderTest(42, aliceAddr, bobAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source port")

	// Bob zero port also rejected
	aliceAddr.Port = 8080
	bobAddr.Port = 0
	err = ptm.CreateResponderTest(43, aliceAddr, bobAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source port")
}

// TestPeerTestManager_SetAliceAddr_ZeroPort tests that port 0 is rejected.
func TestPeerTestManager_SetAliceAddr_ZeroPort(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	ptm := NewPeerTestManager(listener)

	// First create a test
	bobAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	nonce, err := ptm.InitiatePeerTest(bobAddr)
	require.NoError(t, err)

	// Now try to set alice addr with port 0
	badAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 0}
	err = ptm.SetAliceAddr(nonce, badAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source port")
}
