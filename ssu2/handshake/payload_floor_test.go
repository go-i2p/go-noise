// Tests for the SSU2 minimum payload size on handshake messages.
//
// ssu2.md §"SessionRequest (Type 0)" -> §"Payload": "The minimum payload size is
// 8 bytes. Since the DateTime block is only 7 bytes, at least one other block
// must be present." §"SessionCreated (Type 1)" -> §"Payload" and
// §"SessionConfirmed (Type 2)" -> §"Payload" repeat the 8-byte floor.

package handshake

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidatePayloadFloor covers the receive-side boundary directly.
func TestValidatePayloadFloor(t *testing.T) {
	require.NoError(t, validatePayloadFloor(make([]byte, MinPayloadSize), MessageTypeSessionRequest))
	require.NoError(t, validatePayloadFloor(make([]byte, MinPayloadSize+1), MessageTypeSessionRequest))

	err := validatePayloadFloor(make([]byte, MinPayloadSize-1), MessageTypeSessionRequest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below the 8-byte SSU2 minimum")

	require.Error(t, validatePayloadFloor(nil, MessageTypeSessionCreated))
}

// TestBuildHandshakePacket_PadsSubFloorPayload proves the sender honors the
// floor: a lone DateTime block (7 bytes serialized, below the 8-byte minimum)
// is padded up so the message is accepted by a conformant receiver.
func TestBuildHandshakePacket_PadsSubFloorPayload(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	var ts [4]byte
	binaryPutNow(&ts)
	small := []*SSU2Block{{Type: BlockTypeDateTime, Data: ts[:]}}
	raw, err := SerializeBlocks(small)
	require.NoError(t, err)
	require.Less(t, len(raw), MinPayloadSize, "fixture must start below the floor")

	// buildHandshakePacket pads to the floor, so the paired responder accepts it.
	packet, err := initiator.buildHandshakePacket(small, MessageTypeSessionRequest,
		0x3333333333333333, 0, nil)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(packet)
	require.NoError(t, err, "a padded sub-floor block list must be accepted")
}

// TestProcessSessionRequest_AcceptsCompliantPayload proves the guard does not
// reject the normal builder output (DateTime + Options).
func TestProcessSessionRequest_AcceptsCompliantPayload(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	req, err := initiator.CreateSessionRequest(0x2222222222222222, 0)
	require.NoError(t, err)

	_, err = responder.ProcessSessionRequest(req)
	require.NoError(t, err, "a spec-compliant SessionRequest must still process")
}

// binaryPutNow writes the current unix seconds (big endian) into a 4-byte array.
func binaryPutNow(b *[4]byte) {
	now := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(b[:], now)
}
