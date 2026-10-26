package ntcp2

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-noise/internal/routerinfo"
	"github.com/samber/oops"
)

// ntcp2ProtocolVersion is the only NTCP2 version this implementation speaks.
// ntcp2.md §"Published Addresses": "v=2 The current version (2)."
const ntcp2ProtocolVersion = 2

// Transport style strings from ntcp2.md §"Published Addresses": "The published
// RouterAddress (part of the RouterInfo) will have a protocol identifier of
// either "NTCP" or "NTCP2"."
const (
	transportStyleNTCP  = "NTCP"
	transportStyleNTCP2 = "NTCP2"
)

// StaticKeySize is the binary length of the "s" option; ntcp2.md §"Published
// Addresses": "32 bytes in binary, 44 bytes as Base 64 encoded, little-endian
// X25519 public key".
const staticKeyOptionSize = 32

// peerRouterInfoAddress is the parsed, signature-verified view of a peer's
// RouterInfo that NTCP2 requires before trusting it.
type peerRouterInfoAddress struct {
	// StaticKey is the "s" option of a version-matching NTCP/NTCP2 address.
	StaticKey []byte
}

// validatePeerRouterInfo performs the responder's RouterInfo checks on the block
// received in message 3 part 2.
//
// ntcp2.md §"3) SessionConfirmed" -> §"Notes":
//
//   - "Bob must perform the usual Router Info validation. Ensure the signature
//     type is supported, verify the signature, verify the timestamp is within
//     bounds, and any other checks necessary."
//   - "Bob must verify that Alice's static key received in the first frame
//     matches the static key in the Router Info. Bob must first search the
//     Router Info for a NTCP or NTCP2 Router Address with a matching version (v)
//     option."
//
// A mismatch means the RouterInfo does not belong to the router that completed
// the Noise handshake, so it must be rejected rather than handed to the netdb:
// accepting a mismatched pair would let a peer register a router identity it
// cannot prove possession of.
//
// NTCP2 never compresses the RouterInfo (§"RouterInfo" in ssu2.md notes this
// explicitly: "This is different from NTCP2, where it is never compressed"), so
// no inflation step is needed here.
func validatePeerRouterInfo(riBytes, peerStatic []byte) error {
	if len(riBytes) == 0 {
		return nil // no RouterInfo block; the caller handles its absence
	}
	if len(peerStatic) != staticKeyOptionSize {
		return nil // static key not established; not this check's business
	}

	ri, err := routerinfo.Read(riBytes)
	if err != nil {
		return oops.
			Code("PEER_ROUTER_INFO_INVALID").
			In("ntcp2").
			Wrapf(err, "peer RouterInfo in message 3 could not be parsed")
	}

	if err := routerinfo.VerifySignature(ri); err != nil {
		return oops.
			Code("PEER_ROUTER_INFO_INVALID").
			In("ntcp2").
			Wrapf(err, "peer RouterInfo failed validation")
	}

	addr, err := findNTCP2Address(ri)
	if err != nil {
		return oops.
			Code("PEER_ROUTER_INFO_INVALID").
			In("ntcp2").
			Wrapf(err, "peer RouterInfo has no usable NTCP2 address")
	}

	if !routerinfo.ConstantTimeEqualKey(addr.StaticKey, peerStatic) {
		return oops.
			Code("PEER_ROUTER_INFO_KEY_MISMATCH").
			In("ntcp2").
			Errorf("message 3 RouterInfo does not advertise the static key received in the handshake")
	}
	return nil
}

// findNTCP2Address returns the "s" option of the first NTCP/NTCP2 address whose
// "v" option matches this implementation's version.
//
// ntcp2.md §"Unpublished NTCP2 Address": a hidden initiator "must publish a
// "NTCP2" router address containing only her static key and NTCP2 version, so
// that Bob may validate the key after receiving Alice's RouterInfo in message 3
// part 2" — that address carries no "i", "host" or "port", which is why only "s"
// and "v" are required here.
func findNTCP2Address(ri *router_info.RouterInfo) (*peerRouterInfoAddress, error) {
	for _, addr := range ri.RouterAddresses() {
		if addr == nil || !routerinfo.MatchesStyle(addr, transportStyleNTCP, transportStyleNTCP2) {
			continue
		}
		if !routerinfo.AdvertisesVersion(addr, ntcp2ProtocolVersion) {
			continue
		}
		options, err := routerinfo.Options(addr)
		if err != nil {
			continue
		}
		staticKey, err := routerinfo.KeyOption(options, "s", staticKeyOptionSize)
		if err != nil {
			continue
		}
		return &peerRouterInfoAddress{StaticKey: staticKey}, nil
	}
	return nil, oops.
		Code("ROUTER_INFO_NO_NTCP2_ADDRESS").
		Errorf("RouterInfo contains no NTCP/NTCP2 RouterAddress advertising version %d", ntcp2ProtocolVersion)
}

// verifyLocalRouterInfoMatchesStaticKey checks that the RouterInfo this router is
// about to send advertises the same public key its live NTCP2 static private key
// derives to.
//
// This is the sender-side mirror of validatePeerRouterInfo: ntcp2.md
// §"Published Addresses" makes "s" mandatory ("The current Noise static public
// key (s) for this RouterAddress"), so a local RouterInfo that does not carry our
// handshake key would fail every peer that applies §"3) SessionConfirmed" to it.
// Failing here turns a peer-side disconnect into a clear local error.
//
// It parses the RouterInfo and scopes the comparison to NTCP/NTCP2 addresses with
// a matching version option, rather than substring-scanning the serialized bytes:
// a substring match would accept a RouterInfo that merely mentions the key
// anywhere (including in another transport's options or a signature blob) and
// would reject a valid one whose key appears in a different encoding.
//
// A no-op when either input is absent or the wrong length — the callers validate
// those separately, and this helper exists only to catch the mismatch failure
// mode.
func verifyLocalRouterInfoMatchesStaticKey(staticPriv, riBytes []byte) error {
	if len(staticPriv) != StaticKeySize {
		return nil
	}
	if len(riBytes) == 0 {
		return nil
	}

	priv, err := curve25519.NewCurve25519PrivateKey(staticPriv)
	if err != nil {
		return oops.Wrapf(err, "failed to create Curve25519 private key")
	}
	pubKey, err := priv.Public()
	if err != nil {
		return oops.Wrapf(err, "failed to derive public key from the NTCP2 static private key")
	}
	pub := pubKey.Bytes()

	ri, err := routerinfo.Read(riBytes)
	if err != nil {
		return oops.
			Code("LOCAL_ROUTER_INFO_INVALID").
			In("ntcp2").
			Wrapf(err, "LocalRouterInfo could not be parsed")
	}

	addr, err := findNTCP2Address(ri)
	if err != nil {
		return oops.
			Code("LOCAL_ROUTER_INFO_INVALID").
			In("ntcp2").
			Wrapf(err, "LocalRouterInfo has no NTCP2 address to advertise the handshake static key")
	}

	if !routerinfo.ConstantTimeEqualKey(addr.StaticKey, pub) {
		return oops.
			Code("ROUTER_INFO_KEY_MISMATCH").
			In("ntcp2").
			Errorf("LocalRouterInfo's NTCP2 address advertises a static key that is not the one derived from the configured NTCP2 static private key")
	}
	return nil
}
