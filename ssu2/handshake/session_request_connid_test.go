package handshake

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessSessionRequest_RejectsIdenticalConnIDs verifies Bob drops a
// SessionRequest whose source and destination connection IDs are equal.
//
// ssu2.md §"Session Request" -> §"Notes": "Bob must drop the message if the
// Source Connection ID equals the Destination Connection ID." §"Connection ID
// Numbering" explains why: an identical pair lets "an on-path attacker ...
// capture and send a packet back to the originator that looks valid."
func TestProcessSessionRequest_RejectsIdenticalConnIDs(t *testing.T) {
	initiator, responder, _, _ := setupHandshakePair(t)

	const shared = uint64(0x1122334455667788)
	req, err := initiator.CreateSessionRequest(shared, 0)
	require.NoError(t, err)
	// Force both header halves to the same value regardless of how the builder
	// lays out the (normally distinct) pair.
	binary.BigEndian.PutUint64(req.Header[0:8], shared)
	binary.BigEndian.PutUint64(req.Header[16:24], shared)

	_, err = responder.ProcessSessionRequest(req)
	require.Error(t, err, "identical source/destination connection IDs must be rejected")
	assert.Contains(t, err.Error(), "identical")

	// A well-formed request from a separate initiator still processes normally,
	// showing the guard rejects only the malformed case.
	initiator2, responder2, _, _ := setupHandshakePair(t)
	goodReq, err := initiator2.CreateSessionRequest(0x1111111111111111, 0)
	require.NoError(t, err)
	_, err = responder2.ProcessSessionRequest(goodReq)
	require.NoError(t, err, "a valid request must still process")
}
