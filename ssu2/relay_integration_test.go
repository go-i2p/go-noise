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

// TestRelay6StepProcess tests the complete SSU2 relay 6-step process:
//
// Per ssu2.rst specification:
//  1. Alice → Bob: RelayRequest
//  2. Bob → Charlie: RelayIntro (with Alice's RI)
//  3. Charlie → Bob: RelayResponse
//  4. Bob → Alice: RelayResponse
//  5. Charlie → Alice: HolePunch
//  6. Alice → Charlie: SessionRequest
//
// This test simulates the message flow at the block encoding/decoding level.
func TestRelay6StepProcess(t *testing.T) {
	// Setup three peers
	alice := setupRelayTestPeer(t, "Alice")
	defer alice.cleanup()

	bob := setupRelayTestPeer(t, "Bob")
	defer bob.cleanup()

	charlie := setupRelayTestPeer(t, "Charlie")
	defer charlie.cleanup()

	// === Step 0: Setup - Bob acts as introducer ===
	// Alice registers Bob as her introducer
	aliceRelayTag, err := bob.relayMgr.AllocateRelayTag(alice.addr)
	require.NoError(t, err)
	require.NotZero(t, aliceRelayTag)

	err = alice.relayMgr.RegisterIntroducer(bob.addr, bob.routerHash, aliceRelayTag)
	require.NoError(t, err)

	t.Logf("Setup complete: Bob allocated relay tag %d for Alice", aliceRelayTag)

	// === Step 1: Alice → Bob: RelayRequest ===
	t.Log("Step 1: Alice creates RelayRequest to reach Charlie via Bob")

	relayRequest := &RelayRequestBlock{
		Nonce:     12345,
		RelayTag:  aliceRelayTag,
		Timestamp: uint32(time.Now().Unix()),
		Version:   2,
		AlicePort: uint16(alice.addr.Port),
		AliceIP:   alice.addr.IP.To4(),
		Signature: makeTestSignature(),
	}

	requestBlock, err := EncodeRelayRequest(relayRequest)
	require.NoError(t, err)
	require.Equal(t, BlockTypeRelayRequest, requestBlock.Type)

	// Simulate sending by verifying encoding/decoding
	decodedRequest, err := DecodeRelayRequest(requestBlock)
	require.NoError(t, err)
	assert.Equal(t, relayRequest.Nonce, decodedRequest.Nonce)
	assert.Equal(t, relayRequest.RelayTag, decodedRequest.RelayTag)
	assert.Equal(t, relayRequest.Signature, decodedRequest.Signature)
	t.Log("Step 1 complete: RelayRequest encoded and decoded successfully")

	// === Step 2: Bob → Charlie: RelayIntro ===
	t.Log("Step 2: Bob creates RelayIntro to forward Alice's info to Charlie")

	relayIntro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: alice.routerHash[:],
		Nonce:           relayRequest.Nonce,
		AliceRelayTag:   aliceRelayTag,
		Timestamp:       uint32(time.Now().Unix()),
		Version:         2,
		AlicePort:       uint16(alice.addr.Port),
		AliceIP:         alice.addr.IP,
		Signature:       make([]byte, 64),
	}

	introBlock, err := EncodeRelayIntro(relayIntro)
	require.NoError(t, err)
	require.Equal(t, BlockTypeRelayIntro, introBlock.Type)

	decodedIntro, err := DecodeRelayIntro(introBlock)
	require.NoError(t, err)
	assert.Equal(t, relayIntro.AliceRouterHash, decodedIntro.AliceRouterHash)
	assert.Equal(t, relayIntro.AliceRelayTag, decodedIntro.AliceRelayTag)
	assert.Equal(t, relayIntro.Nonce, decodedIntro.Nonce)
	t.Log("Step 2 complete: RelayIntro encoded and decoded successfully")

	// === Step 3: Charlie → Bob: RelayResponse ===
	t.Log("Step 3: Charlie creates RelayResponse acknowledging intro")

	charlieResponse := &RelayResponseBlock{
		Flag:        0,
		Code:        0,
		Nonce:       relayRequest.Nonce, // Echo original nonce
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   make([]byte, 64),
		Token:       make([]byte, 8),
	}

	responseBlock, err := EncodeRelayResponse(charlieResponse)
	require.NoError(t, err)
	require.Equal(t, BlockTypeRelayResponse, responseBlock.Type)

	decodedResponse, err := DecodeRelayResponse(responseBlock)
	require.NoError(t, err)
	assert.Equal(t, charlieResponse.Nonce, decodedResponse.Nonce)
	assert.Equal(t, uint8(0), decodedResponse.Code) // Success
	assert.NotNil(t, decodedResponse.Token)
	t.Log("Step 3 complete: Charlie's RelayResponse encoded and decoded successfully")

	// === Step 4: Bob → Alice: RelayResponse ===
	t.Log("Step 4: Bob forwards RelayResponse to Alice")

	bobToAliceResponse := &RelayResponseBlock{
		Flag:        0,
		Code:        0,
		Nonce:       relayRequest.Nonce,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   make([]byte, 64),
		Token:       make([]byte, 8),
	}

	forwardBlock, err := EncodeRelayResponse(bobToAliceResponse)
	require.NoError(t, err)

	decodedForward, err := DecodeRelayResponse(forwardBlock)
	require.NoError(t, err)
	assert.Equal(t, bobToAliceResponse.Nonce, decodedForward.Nonce)
	assert.Equal(t, bobToAliceResponse.Token, decodedForward.Token)
	t.Log("Step 4 complete: Bob forwarded RelayResponse to Alice")

	// === Step 5: Charlie → Alice: HolePunch ===
	t.Log("Step 5: Charlie sends HolePunch to Alice")

	// Alice initiates hole punch coordination
	sessionID, err := alice.holePunchCoord.InitiateHolePunch(charlie.addr, bob.addr, aliceRelayTag)
	require.NoError(t, err)

	// BUG-M03: block must be non-nil; sign it with the resolver's keypair so
	// the coordinator's real signature verification succeeds.
	hpTimestamp := uint32(time.Now().Unix())
	hpSignature, err := SignRelayRequest(alice.hpSignPriv, relayTestBobHash, relayTestCharlieHash,
		relayIntro.Nonce, aliceRelayTag, hpTimestamp, ssu2ProtocolVersion,
		uint16(alice.addr.Port), alice.addr.IP)
	require.NoError(t, err)
	dummyBlock := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: alice.routerHash[:],
		Nonce:           relayIntro.Nonce,
		AliceRelayTag:   aliceRelayTag,
		Timestamp:       hpTimestamp,
		Version:         2,
		AlicePort:       uint16(alice.addr.Port),
		AliceIP:         alice.addr.IP,
		Signature:       hpSignature,
	}
	// Charlie's hole punch message (simulated through state updates)
	err = alice.holePunchCoord.HandleHolePunch(sessionID, charlie.addr, dummyBlock)
	require.NoError(t, err)

	attempt := alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchWaiting, attempt.State)
	t.Log("Step 5 complete: HolePunch received and processed")

	// === Step 6: Alice → Charlie: SessionRequest ===
	t.Log("Step 6: Alice sends SessionRequest to Charlie")

	// Alice processes the hole punch response
	err = alice.holePunchCoord.ProcessHolePunchResponse(sessionID, charlie.addr, dummyBlock)
	require.NoError(t, err)

	attempt = alice.holePunchCoord.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchSuccess, attempt.State)
	t.Log("Step 6 complete: Session establishment initiated")

	// Verify final state
	t.Log("=== Relay 6-step process completed successfully ===")
}

// TestRelayRequestEncoding tests RelayRequest block encoding and decoding.
func TestRelayRequestEncoding(t *testing.T) {
	testCases := []struct {
		name    string
		request *RelayRequestBlock
		wantErr bool
	}{
		{
			name: "valid_ipv4",
			request: &RelayRequestBlock{
				Nonce:     0xDEADBEEF,
				RelayTag:  55555,
				Timestamp: 1700000000,
				Version:   2,
				AlicePort: 9000,
				AliceIP:   net.IPv4(10, 0, 0, 1).To4(),
				Signature: makeTestSignature(),
			},
			wantErr: false,
		},
		{
			name: "valid_ipv6",
			request: &RelayRequestBlock{
				Nonce:     1,
				RelayTag:  77777,
				Timestamp: 1700000000,
				Version:   2,
				AlicePort: 12345,
				AliceIP:   net.ParseIP("2001:db8::1"),
				Signature: makeTestSignature(),
			},
			wantErr: false,
		},
		{
			name:    "nil_request",
			request: nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := EncodeRelayRequest(tc.request)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, block)

			decoded, err := DecodeRelayRequest(block)
			require.NoError(t, err)

			assert.Equal(t, tc.request.Nonce, decoded.Nonce)
			assert.Equal(t, tc.request.RelayTag, decoded.RelayTag)
			assert.Equal(t, tc.request.Timestamp, decoded.Timestamp)
			assert.Equal(t, tc.request.Version, decoded.Version)
			assert.Equal(t, tc.request.AlicePort, decoded.AlicePort)
			assert.True(t, tc.request.AliceIP.Equal(decoded.AliceIP))
			assert.Equal(t, tc.request.Signature, decoded.Signature)
		})
	}
}

// TestRelayResponseEncoding tests RelayResponse block encoding and decoding.
func TestRelayResponseEncoding(t *testing.T) {
	testCases := []struct {
		name     string
		response *RelayResponseBlock
		wantErr  bool
	}{
		{
			name: "accepted_ipv4",
			response: &RelayResponseBlock{
				Flag:        0,
				Code:        0,
				Nonce:       12345,
				Timestamp:   1700000000,
				Version:     2,
				CharliePort: 9000,
				CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
				Signature:   makeSignedData(),
				Token:       make([]byte, 8),
			},
			wantErr: false,
		},
		{
			name: "accepted_ipv6",
			response: &RelayResponseBlock{
				Flag:        0,
				Code:        0,
				Nonce:       12345,
				Timestamp:   1700000000,
				Version:     2,
				CharliePort: 9000,
				CharlieIP:   net.ParseIP("2001:db8::1"),
				Signature:   make([]byte, 64),
				Token:       make([]byte, 8),
			},
			wantErr: false,
		},
		{
			name: "bob_rejection",
			response: &RelayResponseBlock{
				Flag:  0,
				Code:  1, // Bob rejection
				Nonce: 12345,
			},
			wantErr: false,
		},
		{
			name:     "nil_response",
			response: nil,
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := EncodeRelayResponse(tc.response)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, block)

			decoded, err := DecodeRelayResponse(block)
			require.NoError(t, err)

			assert.Equal(t, tc.response.Nonce, decoded.Nonce)
			assert.Equal(t, tc.response.Code, decoded.Code)
			if tc.response.Code == 0 {
				assert.Equal(t, tc.response.Token, decoded.Token)
				assert.Equal(t, tc.response.Signature, decoded.Signature)
			}
		})
	}
}

// TestRelayIntroEncoding tests RelayIntro block encoding and decoding.
func TestRelayIntroEncoding(t *testing.T) {
	testCases := []struct {
		name    string
		intro   *RelayIntroBlock
		wantErr bool
	}{
		{
			name: "valid_ipv4",
			intro: &RelayIntroBlock{
				AliceRouterHash: make([]byte, 32),
				AliceRelayTag:   99999,
				AlicePort:       12345,
				AliceIP:         net.IPv4(10, 0, 0, 1),
				Version:         2,
				Timestamp:       uint32(time.Now().Unix()),
				Signature:       make([]byte, 64),
			},
			wantErr: false,
		},
		{
			name: "valid_ipv6",
			intro: &RelayIntroBlock{
				AliceRouterHash: make([]byte, 32),
				AliceRelayTag:   88888,
				AlicePort:       54321,
				AliceIP:         net.ParseIP("::1"),
				Version:         2,
				Timestamp:       uint32(time.Now().Unix()),
				Signature:       make([]byte, 64),
			},
			wantErr: false,
		},
		{
			name:    "nil_intro",
			intro:   nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, err := EncodeRelayIntro(tc.intro)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, block)

			decoded, err := DecodeRelayIntro(block)
			require.NoError(t, err)

			assert.Equal(t, tc.intro.AliceRouterHash, decoded.AliceRouterHash)
			assert.Equal(t, tc.intro.AliceRelayTag, decoded.AliceRelayTag)
			assert.Equal(t, tc.intro.AlicePort, decoded.AlicePort)
			assert.Equal(t, tc.intro.Timestamp, decoded.Timestamp)
		})
	}
}

// TestRelayTagBlockEncoding tests RelayTagRequest and RelayTag block encoding.
func TestRelayTagBlockEncoding(t *testing.T) {
	t.Run("RelayTagRequest", func(t *testing.T) {
		// Per spec §Relay Tag Request Block: size=0 (empty data).
		// Encode produces empty data; decode returns zero nonce.
		request := &RelayTagRequestBlock{}

		block, err := EncodeRelayTagRequest(request)
		require.NoError(t, err)
		require.Equal(t, BlockTypeRelayTagRequest, block.Type)

		decoded, err := DecodeRelayTagRequest(block)
		require.NoError(t, err)
		assert.NotNil(t, decoded)
	})

	t.Run("RelayTag", func(t *testing.T) {
		tagBlock := &RelayTagBlock{
			RelayTag: 0x12345678,
		}

		block, err := EncodeRelayTag(tagBlock)
		require.NoError(t, err)
		require.Equal(t, BlockTypeRelayTag, block.Type)

		decoded, err := DecodeRelayTag(block)
		require.NoError(t, err)
		assert.Equal(t, tagBlock.RelayTag, decoded.RelayTag)
	})
}

// TestRelayFlowWithErrors tests error handling in the relay flow.
func TestRelayFlowWithErrors(t *testing.T) {
	t.Run("invalid_relay_tag", func(t *testing.T) {
		alice := setupRelayTestPeer(t, "Alice")
		defer alice.cleanup()

		bob := setupRelayTestPeer(t, "Bob")
		defer bob.cleanup()

		// Try to use an invalid (unallocated) relay tag
		isValid := bob.relayMgr.ValidateRelayTag(0, alice.addr)
		assert.False(t, isValid)

		isValid = bob.relayMgr.ValidateRelayTag(99999, alice.addr)
		assert.False(t, isValid)
	})

	t.Run("expired_relay_tag", func(t *testing.T) {
		bob := setupRelayTestPeer(t, "Bob")
		defer bob.cleanup()

		alice := setupRelayTestPeer(t, "Alice")
		defer alice.cleanup()

		// Allocate tag
		tag, err := bob.relayMgr.AllocateRelayTag(alice.addr)
		require.NoError(t, err)

		// Verify valid initially
		assert.True(t, bob.relayMgr.ValidateRelayTag(tag, alice.addr))

		// Manually expire the tag
		bob.relayMgr.SetRelayTagExpiry(tag, time.Now().Add(-1*time.Hour))
		// Tag should now be invalid
		assert.False(t, bob.relayMgr.ValidateRelayTag(tag, alice.addr))
	})

	t.Run("relay_response_failure_codes", func(t *testing.T) {
		// Test various failure status codes
		failureCodes := []uint8{
			1,  // Generic failure
			64, // Bob does not know Charlie
			65, // Bob is firewalled
			66, // Charlie is firewalled
			69, // Charlie signature verification failed
			70, // Charlie is already connected to Alice
		}

		for _, code := range failureCodes {
			response := &RelayResponseBlock{
				Flag:  0,
				Code:  code,
				Nonce: 12345,
			}

			block, err := EncodeRelayResponse(response)
			require.NoError(t, err)

			decoded, err := DecodeRelayResponse(block)
			require.NoError(t, err)

			assert.Equal(t, code, decoded.Code)
			assert.Nil(t, decoded.Token)
		}
	})
}

// TestConcurrentRelayOperations tests thread safety of relay operations.
func TestConcurrentRelayOperations(t *testing.T) {
	bob := setupRelayTestPeer(t, "Bob")
	defer bob.cleanup()

	numClients := 20
	clients := make([]*relayTestPeer, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = setupRelayTestPeer(t, "Client")
	}
	defer func() {
		for _, c := range clients {
			c.cleanup()
		}
	}()

	var wg sync.WaitGroup
	tags := make([]uint32, numClients)
	errors := make([]error, numClients)

	// Concurrently allocate tags
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tag, err := bob.relayMgr.AllocateRelayTag(clients[idx].addr)
			tags[idx] = tag
			errors[idx] = err
		}(i)
	}
	wg.Wait()

	// Verify all allocations succeeded
	for i := 0; i < numClients; i++ {
		assert.NoError(t, errors[i], "client %d allocation failed", i)
		assert.NotZero(t, tags[i], "client %d got zero tag", i)
	}

	// Verify all tags are unique
	tagSet := make(map[uint32]bool)
	for i, tag := range tags {
		assert.False(t, tagSet[tag], "tag collision at index %d", i)
		tagSet[tag] = true
	}

	// Verify all tags validate correctly
	for i, tag := range tags {
		assert.True(t, bob.relayMgr.ValidateRelayTag(tag, clients[i].addr))
	}

	stats := bob.relayMgr.GetStats()
	assert.Equal(t, numClients, stats["relay_tags"])
}

// TestRelayMessageRoundTrip tests full message serialization round trips.
func TestRelayMessageRoundTrip(t *testing.T) {
	alice := setupRelayTestPeer(t, "Alice")
	defer alice.cleanup()

	charlie := setupRelayTestPeer(t, "Charlie")
	defer charlie.cleanup()

	// Create a complete relay request with all fields
	originalRequest := &RelayRequestBlock{
		Nonce:     0xFEDCBA98,
		RelayTag:  44444,
		Timestamp: 1700000000,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.IPv4(192, 168, 1, 1).To4(),
		Signature: makeTestSignature(),
	}

	// Encode → Serialize → Deserialize → Decode
	block, err := EncodeRelayRequest(originalRequest)
	require.NoError(t, err)

	serialized, err := block.Serialize()
	require.NoError(t, err)

	// Create new block from serialized data
	newBlock := &SSU2Block{}
	_, err = newBlock.Deserialize(serialized)
	require.NoError(t, err)

	decoded, err := DecodeRelayRequest(newBlock)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, originalRequest.Nonce, decoded.Nonce)
	assert.Equal(t, originalRequest.RelayTag, decoded.RelayTag)
	assert.Equal(t, originalRequest.Timestamp, decoded.Timestamp)
	assert.Equal(t, originalRequest.Version, decoded.Version)
	assert.Equal(t, originalRequest.AlicePort, decoded.AlicePort)
	assert.True(t, originalRequest.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, originalRequest.Signature, decoded.Signature)
}

// relayTestPeer represents a peer for relay integration testing.
type relayTestPeer struct {
	addr           *net.UDPAddr
	routerHash     data.Hash
	packetConn     net.PacketConn
	listener       *SSU2Listener
	relayMgr       *RelayManager
	holePunchCoord *HolePunchCoordinator
	// hpSignPriv/hpSignPub are the keypair the hole-punch resolver returns as
	// the signer identity; tests sign RelayIntro blocks with hpSignPriv.
	hpSignPriv ed25519.PrivateKey
	hpSignPub  ed25519.PublicKey
}

// relayTestBobHash and relayTestCharlieHash are the fixed peer identities the
// test hole-punch resolver returns.
var (
	relayTestBobHash     = data.Hash{0xB0}
	relayTestCharlieHash = data.Hash{0xC0}
)

// setupRelayTestPeer creates a test peer with relay components.
func setupRelayTestPeer(t *testing.T, name string) *relayTestPeer {
	t.Helper()

	// Create unique router hash
	var routerHash data.Hash
	for i := range routerHash {
		routerHash[i] = byte(i) ^ byte(name[0])
	}

	// Create configuration
	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	config.DestroyTimeout = 0 // Skip destroy wait in tests
	config.RouterInfoValidator = DefaultRouterInfoValidator

	staticKey := make([]byte, 32)
	config = config.WithStaticKey(staticKey)

	// Create UDP connection
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	// Create SSU2 listener
	listener, err := NewSSU2Listener(packetConn, config)
	require.NoError(t, err)

	// Create relay components
	relayMgr := NewRelayManager(listener)
	hpPub, hpPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	holePunchCoord, err := NewHolePunchCoordinator(relayMgr, func(_ HolePunchVerifyInfo) (HolePunchVerifyContext, ed25519.PublicKey, bool) {
		return HolePunchVerifyContext{BobHash: relayTestBobHash, CharlieHash: relayTestCharlieHash}, hpPub, true
	})
	require.NoError(t, err)

	return &relayTestPeer{
		addr:           packetConn.LocalAddr().(*net.UDPAddr),
		routerHash:     routerHash,
		packetConn:     packetConn,
		listener:       listener,
		relayMgr:       relayMgr,
		holePunchCoord: holePunchCoord,
		hpSignPriv:     hpPriv,
		hpSignPub:      hpPub,
	}
}

// cleanup releases resources for the test peer.
func (p *relayTestPeer) cleanup() {
	if p.relayMgr != nil {
		p.relayMgr.Stop()
	}
	if p.listener != nil {
		p.listener.Close()
	}
}
