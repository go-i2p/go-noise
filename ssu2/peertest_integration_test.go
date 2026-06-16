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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerTest_SevenMessageFlow tests the complete seven-message peer testing protocol.
//
// Flow:
// 1. Alice → Bob: Request (InitiatePeerTest)
// 2. Bob → Charlie: Relay request
// 3. Charlie → Bob: Relay response
// 4. Bob → Alice: Result
// 5. Charlie → Alice: Probe (direct)
// 6. Alice → Charlie: Reply
// 7. Charlie → Alice: Confirmation
func TestPeerTest_SevenMessageFlow(t *testing.T) {
	// Setup three peers for peer testing
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9000")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9001")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9002")
	defer charlie.Close()

	// Message 1: Alice → Bob: Request
	aliceNonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err, "Alice should initiate peer test")
	require.NotZero(t, aliceNonce, "Nonce should be generated")

	// Verify Alice's test state
	aliceTest := alice.ptm.GetTest(aliceNonce)
	require.NotNil(t, aliceTest, "Alice should have active test")
	assert.Equal(t, TestRequested, aliceTest.State, "State should be Requested")
	assert.Equal(t, RoleInitiator, aliceTest.Role, "Alice should be initiator")
	assert.Equal(t, bob.addr.String(), aliceTest.BobAddr.String(), "Bob should be relay")

	// Message 2: Bob creates relay test and forwards to Charlie
	bobNonce, err := bob.ptm.CreateRelayTest(aliceNonce, alice.addr, charlie.addr)
	require.NoError(t, err, "Bob should create relay test")
	require.Equal(t, aliceNonce, bobNonce, "Bob should use same nonce")

	// Verify Bob's test state
	bobTest := bob.ptm.GetTest(bobNonce)
	require.NotNil(t, bobTest, "Bob should have active test")
	assert.Equal(t, TestRelayed, bobTest.State, "State should be Relayed")
	assert.Equal(t, RoleRelay, bobTest.Role, "Bob should be relay")
	assert.Equal(t, alice.addr.String(), bobTest.AliceAddr.String(), "Alice should be initiator")
	assert.Equal(t, charlie.addr.String(), bobTest.CharlieAddr.String(), "Charlie should be responder")

	// Message 3: Charlie receives relay request
	err = charlie.ptm.CreateResponderTest(aliceNonce, alice.addr, bob.addr)
	require.NoError(t, err, "Charlie should create responder test")

	// Verify Charlie's test state
	charlieTest := charlie.ptm.GetTest(aliceNonce)
	require.NotNil(t, charlieTest, "Charlie should have active test")
	assert.Equal(t, TestProbed, charlieTest.State, "State should be Probed")
	assert.Equal(t, RoleResponder, charlieTest.Role, "Charlie should be responder")
	assert.Equal(t, alice.addr.String(), charlieTest.AliceAddr.String(), "Alice should be initiator")
	assert.Equal(t, bob.addr.String(), charlieTest.BobAddr.String(), "Bob should be relay")

	// Message 4: Bob updates Alice with intermediate result
	err = bob.ptm.UpdateState(bobNonce, TestProbed)
	require.NoError(t, err, "Bob should update state to Probed")

	bobTestUpdated := bob.ptm.GetTest(bobNonce)
	assert.Equal(t, TestProbed, bobTestUpdated.State, "Bob state should be Probed")

	// Message 5: Charlie performs probe to Alice (simulate direct probe)
	charlieTest.ExternalAddr = alice.addr // Simulate probe result
	err = charlie.ptm.UpdateState(aliceNonce, TestProbed)
	require.NoError(t, err, "Charlie should update state")

	// Message 6: Alice receives probe from Charlie
	err = alice.ptm.SetAliceAddr(aliceNonce, alice.addr)
	require.NoError(t, err, "Alice should set her own address")

	aliceTestUpdated := alice.ptm.GetTest(aliceNonce)
	assert.Equal(t, alice.addr.String(), aliceTestUpdated.AliceAddr.String(), "Alice address should be set")

	// Message 7: Complete test with results
	testResult := &TestResult{
		NATType:             NATCone,
		ExternalAddr:        alice.addr,
		ExternalPort:        uint16(alice.addr.Port),
		Reachable:           true,
		TestTime:            time.Now(),
		DirectProbeSuccess:  true,
		RelayedProbeSuccess: true,
		PortConsistent:      true,
		IPConsistent:        true,
	}

	// Alice completes test
	err = alice.ptm.CompleteTest(aliceNonce, testResult)
	require.NoError(t, err, "Alice should complete test")

	// Verify final state
	aliceTestFinal := alice.ptm.GetTest(aliceNonce)
	require.NotNil(t, aliceTestFinal, "Test should still exist")
	assert.Equal(t, TestComplete, aliceTestFinal.State, "State should be Complete")
	assert.Equal(t, NATCone, aliceTestFinal.NATType, "NAT type should be Full Cone")
	assert.True(t, aliceTestFinal.Reachable, "Alice should be reachable")

	// Verify cached result
	cachedResult := alice.ptm.GetResult(alice.addr)
	require.NotNil(t, cachedResult, "Result should be cached")
	assert.Equal(t, NATCone, cachedResult.NATType, "Cached NAT type should match")
	assert.Equal(t, alice.addr.String(), cachedResult.ExternalAddr.String(), "Cached address should match")
}

// TestPeerTest_SymmetricNAT tests NAT type detection for symmetric NAT.
func TestPeerTest_SymmetricNAT(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9010")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9011")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9012")
	defer charlie.Close()

	// Initiate test
	nonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Bob creates relay
	_, err = bob.ptm.CreateRelayTest(nonce, alice.addr, charlie.addr)
	require.NoError(t, err)

	// Charlie responds
	err = charlie.ptm.CreateResponderTest(nonce, alice.addr, bob.addr)
	require.NoError(t, err)

	// Simulate symmetric NAT: port changes, direct probe fails
	differentPort := &net.UDPAddr{
		IP:   alice.addr.IP,
		Port: alice.addr.Port + 100, // Different port = symmetric NAT
	}

	testResult := &TestResult{
		NATType:             NATSymmetric,
		ExternalAddr:        differentPort,
		ExternalPort:        uint16(differentPort.Port),
		Reachable:           false, // Direct probe failed
		TestTime:            time.Now(),
		DirectProbeSuccess:  false, // Symmetric NAT blocks direct
		RelayedProbeSuccess: true,  // Relayed works
		PortConsistent:      false, // Port changed
		IPConsistent:        true,  // IP stayed same
	}

	err = alice.ptm.CompleteTest(nonce, testResult)
	require.NoError(t, err)

	// Verify NAT type determination
	aliceTest := alice.ptm.GetTest(nonce)
	assert.Equal(t, NATSymmetric, aliceTest.NATType, "Should detect symmetric NAT")
	assert.False(t, aliceTest.Reachable, "Should not be directly reachable")

	// Verify DetermineNATType function
	detectedType := DetermineNATType(testResult)
	assert.Equal(t, NATSymmetric, detectedType, "DetermineNATType should return Symmetric")
}

// TestPeerTest_FullConeNAT tests NAT type detection for full cone NAT.
func TestPeerTest_FullConeNAT(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9020")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9021")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9022")
	defer charlie.Close()

	// Initiate test
	nonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Setup relay
	_, err = bob.ptm.CreateRelayTest(nonce, alice.addr, charlie.addr)
	require.NoError(t, err)

	err = charlie.ptm.CreateResponderTest(nonce, alice.addr, bob.addr)
	require.NoError(t, err)

	// Simulate full cone NAT: both probes succeed, port/IP consistent
	// Use a public (non-local) IP so DetermineNATType returns NATCone, not NATNone.
	externalAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: alice.addr.Port}
	testResult := &TestResult{
		NATType:             NATCone,
		ExternalAddr:        externalAddr,
		ExternalPort:        uint16(alice.addr.Port),
		Reachable:           true,
		TestTime:            time.Now(),
		DirectProbeSuccess:  true, // Full cone allows direct
		RelayedProbeSuccess: true, // Relayed also works
		PortConsistent:      true, // Same port
		IPConsistent:        true, // Same IP
	}

	err = alice.ptm.CompleteTest(nonce, testResult)
	require.NoError(t, err)

	// Verify NAT type
	aliceTest := alice.ptm.GetTest(nonce)
	assert.Equal(t, NATCone, aliceTest.NATType, "Should detect full cone NAT")
	assert.True(t, aliceTest.Reachable, "Should be directly reachable")

	detectedType := DetermineNATType(testResult)
	assert.Equal(t, NATCone, detectedType, "DetermineNATType should return Full Cone")
}

// TestPeerTest_RestrictedNAT tests NAT type detection for restricted cone NAT.
func TestPeerTest_RestrictedNAT(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9030")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9031")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9032")
	defer charlie.Close()

	// Initiate test
	nonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Setup relay
	_, err = bob.ptm.CreateRelayTest(nonce, alice.addr, charlie.addr)
	require.NoError(t, err)

	err = charlie.ptm.CreateResponderTest(nonce, alice.addr, bob.addr)
	require.NoError(t, err)

	// Simulate restricted NAT: direct fails, relayed succeeds, port consistent
	testResult := &TestResult{
		NATType:             NATRestricted,
		ExternalAddr:        alice.addr,
		ExternalPort:        uint16(alice.addr.Port),
		Reachable:           false,
		TestTime:            time.Now(),
		DirectProbeSuccess:  false, // Restricted blocks unknown sources
		RelayedProbeSuccess: true,  // Relayed works
		PortConsistent:      true,  // Port stays same
		IPConsistent:        true,  // IP stays same
	}

	err = alice.ptm.CompleteTest(nonce, testResult)
	require.NoError(t, err)

	// Verify NAT type
	aliceTest := alice.ptm.GetTest(nonce)
	assert.Equal(t, NATRestricted, aliceTest.NATType, "Should detect restricted cone NAT")
	assert.False(t, aliceTest.Reachable, "Should not be directly reachable")

	detectedType := DetermineNATType(testResult)
	assert.Equal(t, NATRestricted, detectedType, "DetermineNATType should return Restricted")
}

// TestPeerTest_MultipleTests tests concurrent peer tests.
func TestPeerTest_MultipleTests(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9040")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9041")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9042")
	defer charlie.Close()

	// Initiate multiple tests
	nonce1, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	nonce2, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Nonces should be different
	require.NotEqual(t, nonce1, nonce2, "Nonces should be unique")

	// Both tests should exist
	test1 := alice.ptm.GetTest(nonce1)
	test2 := alice.ptm.GetTest(nonce2)
	require.NotNil(t, test1)
	require.NotNil(t, test2)

	// Check stats
	stats := alice.ptm.GetStats()
	assert.GreaterOrEqual(t, stats["total_tests"], 2, "Should have at least 2 tests")
	assert.GreaterOrEqual(t, stats["requested"], 2, "Should have at least 2 requested tests")
	assert.GreaterOrEqual(t, stats["role_initiator"], 2, "Should have at least 2 initiator tests")
}

// TestPeerTest_Timeout tests peer test timeout and cleanup.
func TestPeerTest_Timeout(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9050")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9051")
	defer bob.Close()

	// Initiate test
	nonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Test should exist
	test := alice.ptm.GetTest(nonce)
	require.NotNil(t, test)

	// Manually set start time to past
	alice.ptm.SetTestStartTime(nonce, time.Now().Add(-70*time.Second)) // Beyond 60s timeout

	// Cleanup expired tests
	alice.ptm.CleanupExpired()

	// Test should be removed
	test = alice.ptm.GetTest(nonce)
	assert.Nil(t, test, "Expired test should be removed")
}

// TestPeerTest_FailedTest tests handling of failed peer tests.
func TestPeerTest_FailedTest(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9060")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9061")
	defer bob.Close()

	// Initiate test
	nonce, err := alice.ptm.InitiatePeerTest(bob.addr)
	require.NoError(t, err)

	// Mark test as failed
	err = alice.ptm.FailTest(nonce, nil)
	require.NoError(t, err)

	// Verify failed state
	test := alice.ptm.GetTest(nonce)
	require.NotNil(t, test)
	assert.Equal(t, TestFailed, test.State, "State should be Failed")

	// Check stats
	stats := alice.ptm.GetStats()
	assert.GreaterOrEqual(t, stats["failed"], 1, "Should have at least 1 failed test")
}

// TestPeerTest_BlockEncoding tests PeerTest block encoding/decoding integration.
func TestPeerTest_BlockEncoding(t *testing.T) {
	alice := setupPeerForTest(t, "Alice", "127.0.0.1:9070")
	defer alice.Close()

	bob := setupPeerForTest(t, "Bob", "127.0.0.1:9071")
	defer bob.Close()

	charlie := setupPeerForTest(t, "Charlie", "127.0.0.1:9072")
	defer charlie.Close()

	// Create test blocks for each message type
	nonce := uint32(12345)
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	aliceIP := net.IPv4(192, 168, 1, 1).To4()

	// Message 1: Request
	requestBlock := &PeerTestBlock{
		MessageCode: PeerTestRequest,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   1700000000,
		AlicePort:   9000,
		AliceIP:     aliceIP,
		Signature:   sig,
	}

	ssu2Block, err := EncodePeerTestBlock(requestBlock)
	require.NoError(t, err, "Should encode request block")

	decodedRequest, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err, "Should decode request block")
	assert.Equal(t, PeerTestRequest, decodedRequest.MessageCode)
	assert.Equal(t, nonce, decodedRequest.Nonce)
	assert.Equal(t, sig, decodedRequest.Signature)

	// Message 5: Probe
	probeBlock := &PeerTestBlock{
		MessageCode: PeerTestProbe,
		Nonce:       nonce,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     aliceIP,
		Signature:   sig,
	}

	ssu2Block, err = EncodePeerTestBlock(probeBlock)
	require.NoError(t, err, "Should encode probe block")

	decodedProbe, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err, "Should decode probe block")
	assert.Equal(t, PeerTestProbe, decodedProbe.MessageCode)
	assert.Equal(t, nonce, decodedProbe.Nonce)
	assert.Equal(t, uint32(1234567890), decodedProbe.Timestamp)
	assert.Equal(t, sig, decodedProbe.Signature)
}

// setupPeerForTest creates a test peer with PeerTestManager.
type peerTestNode struct {
	addr    *net.UDPAddr
	ptm     *PeerTestManager
	closeFn func()
}

func (p *peerTestNode) Close() {
	if p.closeFn != nil {
		p.closeFn()
	}
}

func setupPeerForTest(t *testing.T, name, addrStr string) *peerTestNode {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", addrStr)
	require.NoError(t, err, "Should resolve address for %s", name)

	// Create a simple peer test manager without full listener
	ptm := NewPeerTestManagerWithFields(nil, make(map[uint32]*PeerTest), make(map[string]*TestResult))

	return &peerTestNode{
		addr:    addr,
		ptm:     ptm,
		closeFn: nil,
	}
}
