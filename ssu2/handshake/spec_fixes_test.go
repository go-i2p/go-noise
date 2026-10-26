package handshake

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// completeToSessionConfirmed drives the XK handshake up to (but not including)
// the Session Confirmed, returning both handlers.
func completeToSessionConfirmed(t *testing.T) (*HandshakeHandler, *HandshakeHandler, []byte) {
	t.Helper()
	initiator, responder, initiatorPub, _ := setupHandshakePair(t)

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(22222, 11111)
	require.NoError(t, err)
	require.NoError(t, initiator.ProcessSessionCreated(created))
	return initiator, responder, initiatorPub
}

// TestProcessSessionCreated_WrongSourceAddressIsDropped covers ssu2.md
// §"Session Created" -> §"Notes": "Alice must drop the message if the source IP
// and port do not match the destination IP and port of the Session Request."
// Reference: Java relies on the same pinned endpoint
// (SSU2Util §"Header Encryption Keys": "This design relies on endpoints
// retaining a stable address for the duration of the handshake").
func TestProcessSessionCreated_WrongSourceAddressIsDropped(t *testing.T) {
	sentTo := &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 40001}

	tests := []struct {
		name    string
		src     *net.UDPAddr
		wantErr bool
	}{
		{"matching ip and port", sentTo, false},
		{"different port", &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 40002}, true},
		{"different ip", &net.UDPAddr{IP: net.ParseIP("203.0.113.21"), Port: 40001}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, responder, _, _ := setupHandshakePair(t)
			initiator.SetExpectedPeerAddr(sentTo)

			req, err := initiator.CreateSessionRequest(11111, 22222)
			require.NoError(t, err)
			_, err = responder.ProcessSessionRequest(req)
			require.NoError(t, err)

			created, err := responder.CreateSessionCreated(22222, 11111)
			require.NoError(t, err)
			created.Source = tt.src

			err = initiator.ProcessSessionCreated(created)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "Session Created arrived from")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestProcessSessionCreated_WrongNetworkIDIsDropped covers ssu2.md §"Header
// Binding": "If the version is != 2, or the netid is != the expected value
// (generally 2, except in test networks), the receiver should drop the message",
// and §"Session Request" -> §"Notes" (proposal 147): a mismatched network ID
// means "disconnect and block future connections".
func TestProcessSessionCreated_WrongNetworkIDIsDropped(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)
	// Both ends on the same test network so the handshake itself proceeds; the
	// Session Created is then tampered with to declare a foreign netid.
	initiator.SetNetworkID(7) // a test network
	responder.SetNetworkID(7)

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err)
	created, err := responder.CreateSessionCreated(22222, 11111)
	require.NoError(t, err)
	created.Header[14] = 9 // neither our 7 nor the main-network 2
	created.NetworkID = created.Header[14]

	err = initiator.ProcessSessionCreated(created)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network ID")
}

// TestProcessSessionRequest_ZeroNetworkIDIsDropped covers ssu2.md
// §"Header Validation": "If the version is != 2, or the netid is != the
// expected value (generally 2, except in test networks), the receiver should
// drop the message." A long header declaring netid 0 declares a network no
// deployment uses, so it must be dropped rather than excused as "field not
// populated".
func TestProcessSessionRequest_ZeroNetworkIDIsDropped(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	require.Equal(t, uint8(MainNetworkID), req.Header[14])
	req.Header[14] = 0
	req.NetworkID = 0

	_, err = responder.ProcessSessionRequest(req)
	require.Error(t, err, "a long header declaring netid 0 must be dropped")
	assert.Contains(t, err.Error(), "network ID")
}

// TestNetworkID_DefaultsToMainNetwork covers ssu2.md §"Header": "id :: 1 byte,
// the network ID (currently 2, except for test networks)". An unset config must
// still emit the main-network value.
func TestNetworkID_DefaultsToMainNetwork(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)
	assert.Equal(t, uint8(MainNetworkID), initiator.NetworkID())

	initiator.SetNetworkID(0)
	assert.Equal(t, uint8(MainNetworkID), initiator.NetworkID(), "zero must mean the main network, not no network")

	initiator.SetNetworkID(5)
	assert.Equal(t, uint8(5), initiator.NetworkID())

	req, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	assert.Equal(t, uint8(5), req.Header[14], "configured netid must reach the wire")
}

// TestValidateSessionConfirmedBlocks covers ssu2.md §"SessionConfirmed (Type 2)"
// -> §"Payload": "RouterInfo block (must be the first block) / Options block
// (optional) / New Token block (optional) / Relay Request block (optional) /
// Peer Test block (optional) / First Packet Number block (optional) / I2NP,
// First Fragment, or Follow-on Fragment blocks (optional…) / Padding block
// (optional)". Blocks outside that set must not be accepted in the handshake.
func TestValidateSessionConfirmedBlocks(t *testing.T) {
	ri := func() *SSU2Block {
		b, err := EncodeRouterInfoBlock([]byte("router-info-bytes"), false, false)
		require.NoError(t, err)
		return b
	}

	tests := []struct {
		name    string
		blocks  []*SSU2Block
		wantErr bool
		errText string
	}{
		{"RI then Options", []*SSU2Block{ri(), NewSSU2Block(BlockTypeOptions, make([]byte, 12))}, false, ""},
		{"RI then Padding last", []*SSU2Block{ri(), NewSSU2Block(BlockTypePadding, make([]byte, 8))}, false, ""},
		{"RI then Termination", []*SSU2Block{ri(), NewSSU2Block(BlockTypeTermination, make([]byte, 9))}, true, "not one of the payload types"},
		{"RI then Address", []*SSU2Block{ri(), NewSSU2Block(BlockTypeAddress, make([]byte, 18))}, true, "not one of the payload types"},
		{"RI then ACK", []*SSU2Block{ri(), NewSSU2Block(BlockTypeACK, make([]byte, 5))}, true, "not one of the payload types"},
		{"Padding before RI", []*SSU2Block{NewSSU2Block(BlockTypePadding, make([]byte, 8)), ri()}, true, "must be first"},
		{"Options before RI", []*SSU2Block{NewSSU2Block(BlockTypeOptions, make([]byte, 12)), ri()}, true, "must be first"},
		{"Padding not last", []*SSU2Block{ri(), NewSSU2Block(BlockTypePadding, make([]byte, 8)), ri()}, true, "must be the last block"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the frame by hand rather than through SerializeBlocks, which
			// normalises ordering: the validator guards INBOUND bytes, and a
			// remote peer's framing is exactly what we must not trust.
			payload := rawBlockFrame(t, tt.blocks)

			err := validateSessionConfirmedBlocks(payload)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errText)
				return
			}
			require.NoError(t, err)
		})
	}

	// A payload with no blocks at all.
	err := validateSessionConfirmedBlocks(rawBlockFrame(t, nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no blocks")
}

// rawBlockFrame serialises blocks in the given order with no reordering, so a
// test can present the validator with bytes a non-conformant peer would send.
func rawBlockFrame(t *testing.T, blocks []*SSU2Block) []byte {
	t.Helper()
	var out []byte
	for _, b := range blocks {
		data, err := b.Serialize()
		require.NoError(t, err)
		out = append(out, data...)
	}
	return out
}

// TestCreateSessionConfirmed_RequiresRouterInfo covers ssu2.md §"Session
// Confirmed Fragmentation": "The Session Confirmed message must contain the full
// signed Router Info from Alice so that Bob may perform several required checks"
// (static key "s", introduction key "i", RI signature). Reference: Java
// InboundEstablishState2.java:977 throws "No RI in Session Confirmed".
//
// A bare RouterHash is not a substitute: it carries neither "s" nor "i", so a
// conformant responder cannot validate the session and the handshake dies.
func TestCreateSessionConfirmed_RequiresRouterInfo(t *testing.T) {
	initiator, _, _ := completeToSessionConfirmed(t)

	_, err := initiator.CreateSessionConfirmed(55555, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must carry the full signed local RouterInfo")

	_, err = initiator.CreateSessionConfirmedFragments(55555, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must carry the full signed local RouterInfo")
}

// TestCreateSessionConfirmed_CarriesOptionsBlock covers ssu2.md §"Session
// Confirmed" -> §"Notes": "Options should be included, to specify padding
// parameters."
func TestCreateSessionConfirmed_CarriesOptionsBlock(t *testing.T) {
	initiator, _, initiatorPub := completeToSessionConfirmed(t)
	initiator.SetLocalOptions(&OptionsParams{TMaxRatio: 0.5, RMaxRatio: 0.5})

	pkt, err := initiator.CreateSessionConfirmed(55555, 0, testRouterInfoFor(t, initiatorPub))
	require.NoError(t, err)

	// The payload is AEAD-sealed by Noise, so assert on the builder instead:
	// serializeConfirmedPayload must emit RI then Options.
	payload, err := initiator.serializeConfirmedPayload(testRouterInfoFor(t, initiatorPub))
	require.NoError(t, err)
	blocks, err := DeserializeBlocks(payload)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	assert.Equal(t, BlockTypeRouterInfo, blocks[0].Type, "RouterInfo must be first")
	assert.Equal(t, BlockTypeOptions, blocks[1].Type, "Options must follow")
	assert.NotNil(t, pkt)
}

// TestFragmentSizes_LastFragmentKeeps24ByteTail covers ssu2.md §"Session
// Confirmed Fragmentation": "Calculate the size of the data in the last packet.
// It must be greater than or equal to 24 bytes, so that header encryption will
// work. If it is too small, either add a padding block, OR increase the size of
// the padding block if already present, OR reduce the size of one of the other
// packets so that the last packet will be big enough."
//
// 24 is the header-protection IV: §"KDF for Session Confirmed" derives it from
// "the last 24 bytes of the packet".
func TestFragmentSizes_LastFragmentKeeps24ByteTail(t *testing.T) {
	// The conservative default: spec-minimum MTU over IPv6.
	const cap = sessionConfirmedMinMTU - sessionConfirmedOverheadIPv6

	for n := 1; n <= 4*cap+64; n++ {
		sizes := fragmentSizes(n, cap)
		sum := 0
		for i, s := range sizes {
			assert.LessOrEqual(t, s, cap, "fragment %d over capacity for n=%d", i, n)
			assert.GreaterOrEqual(t, s, 0, "negative fragment size for n=%d", n)
			sum += s
		}
		assert.Equal(t, n, sum, "fragments must not lose or duplicate bytes (n=%d)", n)
		if len(sizes) > 1 {
			assert.GreaterOrEqual(t, sizes[len(sizes)-1], minFragmentTail, "tail too short for n=%d: %v", n, sizes)
		}
	}

	// The band that used to break: remainder 1..23 after a greedy split.
	assert.Equal(t, []int{1193, 24}, fragmentSizes(cap+1, cap))
	assert.Equal(t, []int{cap, 24}, fragmentSizes(cap+24, cap))
	assert.Equal(t, []int{cap, cap}, fragmentSizes(2*cap, cap))
}

// TestFragmentCapacity_FollowsMTUAndFamily covers ssu2.md §"Session Confirmed
// Fragmentation": "Calculate the space available in each packet, which is the
// MTU minus the IP header (20 or 40), minus the UDP header (8), minus the SSU2
// short header (16). Total per-packet overhead is 44 (IPv4) or 64 (IPv6)."
//
// The capacity must therefore track both the session MTU and the peer's address
// family; hard-coding the 1280/IPv6 figure made an IPv4 or large-MTU session
// emit more fragments than a compliant peer expects.
func TestFragmentCapacity_FollowsMTUAndFamily(t *testing.T) {
	initiator, _, _, _ := setupHandshakePair(t)
	handler := initiator

	// Unset defaults to the spec minimum over IPv6.
	assert.Equal(t, 1280-64, handler.fragmentCapacity(), "unset MTU must use the 1280 IPv6 minimum")

	handler.SetFragmentMTU(1500, true)
	assert.Equal(t, 1500-44, handler.fragmentCapacity(), "IPv4 overhead is 44")

	handler.SetFragmentMTU(1500, false)
	assert.Equal(t, 1500-64, handler.fragmentCapacity(), "IPv6 overhead is 64")

	// A sub-minimum MTU is clamped to the floor (§"MTU": "The minimum SSU2 MTU
	// is 1280"), never trusted as-is.
	handler.SetFragmentMTU(576, true)
	assert.Equal(t, 1280-44, handler.fragmentCapacity(), "MTU below the minimum must be clamped")

	// A larger capacity must not ask for more fragments than the bytes require.
	handler.SetFragmentMTU(1500, true)
	count, err := computeFragmentCount(1500-44, handler.fragmentCapacity())
	require.NoError(t, err)
	assert.Equal(t, 1, count, "a full-MTU jumbo must fit one IPv4 fragment")
}
