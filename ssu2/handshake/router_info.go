package handshake

import (
	"crypto/subtle"

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
		if block.Type != BlockTypeRouterInfo || len(block.Data) == 0 {
			continue
		}
		// The block carries a mandatory flag+frag prefix; hand the caller the
		// RouterInfo bytes themselves so downstream consumers (static-key
		// binding, netdb storage) do not have to know about the prefix.
		decoded, err := DecodeRouterInfoBlock(block)
		if err != nil {
			return nil, oops.Wrapf(err, "malformed RouterInfo block in SessionConfirmed")
		}

		riBytes := decoded.Data
		// ssu2.md §"RouterInfo" block: "flag :: 1 byte ... bit 1 = gzip". A
		// compressed RouterInfo must be inflated before it can be parsed,
		// signature-verified, or used to extract the data-phase introduction
		// key; handing downstream consumers the compressed bytes would fail
		// every one of those checks.
		if decoded.Compressed {
			decompressed, err := Gunzip(riBytes)
			if err != nil {
				return nil, oops.Wrapf(err, "failed to gunzip RouterInfo block in SessionConfirmed")
			}
			riBytes = decompressed
		}
		return copyBytes(riBytes), nil
	}
	return nil, nil
}

// verifyPeerRouterInfoStaticKey binds the claimed I2P identity to the Noise
// transcript: the RouterInfo received in Session Confirmed must advertise, in
// the "s" option of an address whose "v" option matches, the same Curve25519
// static key the Noise XK handshake authenticated.
//
// ssu2.md §"Session Confirmed" -> §"Notes": "Bob must verify that Alice's
// static key received in the first frame matches the static key in the Router
// Info. Bob must first search the Router Info for a NTCP or SSU2 Router Address
// with a matching version (v) option." §"Published Addresses" additionally
// makes "i" mandatory: "The introduction key \"i\" in the RI must be extracted
// and valid, to be used in the data phase."
//
// The RouterInfo is parsed and its SSU2 options extracted through the shared
// wire helpers rather than scanned as text: a substring match on the base64 of
// the key would accept a RouterInfo that merely *mentions* the key, and would
// reject a valid one whose signature block hides the options inside a gzip
// stream.
//
// Skipped when either value is absent (initiator side, or a handshake built
// without a RouterInfo). Returns an error tagged TerminationSParamMissing on
// mismatch, which §"Session Confirmed" -> §"Notes" requires Bob to treat as
// "halt further message processing and close the connection without
// responding".
func verifyPeerRouterInfoStaticKey(peerRouterInfo, remoteStaticKey []byte) error {
	if len(peerRouterInfo) == 0 {
		return nil // RouterInfo optional; skip.
	}
	if len(remoteStaticKey) != 32 {
		return nil // Static key not yet established; skip.
	}

	ri, err := ReadRouterInfo(peerRouterInfo)
	if err != nil {
		return oops.
			In("handshake").
			With("termination_reason", TerminationSParamMissing).
			Wrapf(err, "peer RouterInfo in Session Confirmed could not be parsed")
	}

	params, err := ExtractSSU2AddressParams(ri)
	if err != nil {
		return oops.
			In("handshake").
			With("termination_reason", TerminationSParamMissing).
			Wrapf(err, "peer RouterInfo in Session Confirmed has no valid SSU2 address")
	}

	if subtle.ConstantTimeCompare(params.StaticKey, remoteStaticKey) != 1 {
		return oops.
			In("handshake").
			With("termination_reason", TerminationSParamMissing).
			Errorf("peer RouterInfo does not advertise the static key authenticated by the Noise handshake")
	}
	return nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	copied := make([]byte, len(b))
	copy(copied, b)
	return copied
}
