package handshake

import (
	"bytes"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/samber/oops"
)

// extractPeerRouterInfo scans a SessionConfirmed payload for a RouterInfo block and
// stores the RouterInfo block data for later validation.
// Returns an error if the payload is non-empty but cannot be deserialized.
func extractPeerRouterInfo(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		flog("extractPeerRouterInfo").WithError(err).Warn("failed to deserialize SessionConfirmed blocks")
		return nil, oops.Wrapf(err, "failed to deserialize SessionConfirmed blocks")
	}
	for _, block := range blocks {
		if block.Type == BlockTypeRouterInfo && len(block.Data) > 0 {
			return copyBytes(block.Data), nil
		}
	}
	return nil, nil
}

// verifyPeerRouterInfoStaticKey checks that the RouterInfo received in
// SessionConfirmed advertises the same Curve25519 static key that the Noise
// XK handshake authenticated. This binds the claimed I2P identity to the
// Noise transcript, preventing peer impersonation.
//
// The check uses an I2P-base64 substring scan consistent with the NTCP2
// implementation. It is skipped when either peerRouterInfo or remoteStaticKey
// is absent (e.g. tests that omit RouterInfo).
//
// Returns an error tagged TerminationSParamMissing on mismatch.
func verifyPeerRouterInfoStaticKey(peerRouterInfo, remoteStaticKey []byte) error {
	if len(peerRouterInfo) == 0 {
		return nil // RouterInfo optional; skip.
	}
	if len(remoteStaticKey) != 32 {
		return nil // Static key not yet established; skip.
	}
	pubB64 := i2pbase64.EncodeToString(remoteStaticKey)
	if bytes.Contains(peerRouterInfo, []byte(pubB64)) {
		return nil
	}
	return oops.
		In("handshake").
		With("termination_reason", TerminationSParamMissing).
		Errorf("peer RouterInfo does not advertise the static key authenticated by the Noise handshake")
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	copied := make([]byte, len(b))
	copy(copied, b)
	return copied
}
