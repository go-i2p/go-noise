package server

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/samber/oops"
)

// errNoTokenPresent is a sentinel error returned by validateSessionRequestToken
// when the SessionRequest does not contain a NewToken block. This is used by
// handleNewSession to decide whether to send a Retry message.
var errNoTokenPresent = errors.New("no token present in SessionRequest")

// sendRetry constructs and transmits a Retry message to the remote address.
// This is called when config.RequireRetry is enabled and the SessionRequest
// does not carry a valid token. The Retry message contains a fresh token that
// the initiator can include in its next SessionRequest.
//
// Per SSU2 spec, the Retry message includes:
//   - Long header (32 bytes) with the server's connection ID and the token
//   - Payload containing a DateTime block and a NewToken block
//   - MAC (16 bytes, but not authenticated in Retry)
//
// Anti-amplification: The outbound Retry message size is capped at 3x the
// incoming SessionRequest size to prevent reflection amplification attacks.
//
// Parameters:
//   - remoteAddr: Destination address for the Retry packet
//   - token: 8-byte token value for the NewToken block
//   - originalHeader: Header from the SessionRequest (for connection ID extraction)
//   - incomingSize: Size of the incoming message (for amplification limit)
func (l *SSU2Listener) sendRetry(remoteAddr *net.UDPAddr, token, originalHeader []byte, incomingSize int) error {
	if len(token) != TokenSize {
		return oops.Errorf("token must be exactly %d bytes, got %d", TokenSize, len(token))
	}

	payload, err := l.buildRetryPayload(token)
	if err != nil {
		return err
	}

	header, err := l.buildRetryHeader(originalHeader, token)
	if err != nil {
		return err
	}

	retryPacket := NewSSU2Packet(MessageTypeRetry, 0)
	retryPacket.Header = header
	retryPacket.Payload = payload
	retryPacket.MAC = make([]byte, MACSize)

	packetData, err := retryPacket.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize Retry packet")
	}

	if incomingSize > 0 && len(packetData) > 3*incomingSize {
		return oops.Errorf("Retry message (%d bytes) exceeds 3x amplification limit of incoming message (%d bytes)", len(packetData), incomingSize)
	}

	_, err = l.underlying.WriteTo(packetData, remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to send Retry packet")
	}
	return nil
}

// buildRetryPayload creates the DateTime + NewToken payload for a Retry message.
func (l *SSU2Listener) buildRetryPayload(token []byte) ([]byte, error) {
	now := time.Now()

	dtData := make([]byte, 4)
	binary.BigEndian.PutUint32(dtData, uint32(now.Unix()))
	dateTimeBlock := NewSSU2Block(BlockTypeDateTime, dtData)

	expiration := now.Add(l.tokenCache.GetTTL())
	tokenBlock, err := NewNewTokenBlock(expiration, token)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create NewToken block")
	}

	payload, err := SerializeBlocks([]*SSU2Block{dateTimeBlock, tokenBlock})
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize Retry payload blocks")
	}
	return payload, nil
}

// buildRetryHeader constructs the 32-byte long header for a Retry message.
// AUDIT 5.4: Now a method on SSU2Listener to use the stable retry source connection ID
// instead of generating a fresh random value each time. This ensures that all
// Retries from the same listener use the same source ConnID, as required by the
// SSU2 spec for spec-compliant initiators that cache the responder ConnID.
func (l *SSU2Listener) buildRetryHeader(originalHeader, token []byte) ([]byte, error) {
	header := make([]byte, LongHeaderSize)

	if len(originalHeader) >= 24 {
		copy(header[0:8], originalHeader[16:24])
	} else if len(originalHeader) >= 8 {
		copy(header[0:8], originalHeader[0:8])
	}

	header[12] = MessageTypeRetry
	header[13] = SSU2ProtocolVersion
	header[14] = SSU2NetworkID

	// AUDIT 5.4: Use stable retrySourceConnID instead of generating a fresh random value
	copy(header[16:24], l.retrySourceConnID[:])
	copy(header[24:32], token)

	return header, nil
}
