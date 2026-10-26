package wire

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/samber/oops"
)

// Transport style strings from ssu2.md §"Published Addresses": the published
// RouterAddress carries a protocol identifier of either "SSU" or "SSU2".
const (
	transportStyleSSU  = "SSU"
	transportStyleSSU2 = "SSU2"

	// ssu2ProtocolVersion is the only SSU2 version this implementation speaks.
	ssu2ProtocolVersion = 2

	// mtuOptionKey is the published MTU RouterAddress option. ssu2.md §"MTU":
	// "Routers must publish a non-default MTU in each SSU or SSU2 router
	// address."
	mtuOptionKey = "mtu"

	// maxPublishedRIAge bounds how old a peer RouterInfo may be before it is
	// rejected. The spec requires "verify the timestamp is within bounds"
	// (§"Session Confirmed" → §"Notes") without naming a bound; this matches
	// the RI publication lifetime used by the reference implementations.
	maxPublishedRIAge = 90 * 24 * time.Hour
)

// SSU2AddressParams holds the options that ssu2.md §"Published Addresses"
// makes mandatory on an SSU/SSU2 RouterAddress, plus the optional published
// MTU:
//
//   - s=(Base64 key) — the Noise static public key
//   - i=(Base64 key) — the introduction key for header encryption
//   - v=2            — the protocol version
//   - mtu=N          — optional, see §"MTU"
type SSU2AddressParams struct {
	// StaticKey is the 32-byte "s" option.
	StaticKey []byte
	// IntroKey is the 32-byte "i" option. Per §"Header Encryption KDF" it is
	// the data-phase k_header_1 for every packet whose receiver is this peer.
	IntroKey []byte
	// MTU is the published "mtu" option. Valid only when HasMTU is set.
	MTU    int
	HasMTU bool
}

// ReadRouterInfo parses RouterInfo bytes, tolerating trailing data.
func ReadRouterInfo(riBytes []byte) (*router_info.RouterInfo, error) {
	if len(riBytes) == 0 {
		return nil, oops.Code("EMPTY_ROUTER_INFO").In("ssu2").Errorf("RouterInfo is empty")
	}
	ri, _, err := router_info.ReadRouterInfo(riBytes)
	if err != nil {
		return nil, oops.Code("ROUTER_INFO_PARSE_FAILED").In("ssu2").
			Wrapf(err, "failed to parse RouterInfo")
	}
	return &ri, nil
}

// ExtractSSU2AddressParams returns the SSU2 options of the first RouterAddress
// that advertises protocol version 2.
//
// ssu2.md §"Session Confirmed" → §"Notes" requires the responder to "first
// search the Router Info for a NTCP or SSU2 Router Address with a matching
// version (v) option", and §"Published Addresses" makes all three of s, i and
// v mandatory: "Alice must verify that all three options are present and valid
// before connecting using the SSU2 protocol."
func ExtractSSU2AddressParams(ri *router_info.RouterInfo) (*SSU2AddressParams, error) {
	if ri == nil {
		return nil, oops.Code("EMPTY_ROUTER_INFO").In("ssu2").Errorf("RouterInfo is nil")
	}

	for _, addr := range ri.RouterAddresses() {
		if addr == nil || !isSSUFamilyTransport(addr) {
			continue
		}
		if !addressAdvertisesVersion(addr, ssu2ProtocolVersion) {
			continue
		}

		options, err := routerAddressOptions(addr)
		if err != nil {
			continue
		}

		staticKey, err := StaticKeyFromRouterAddress(options)
		if err != nil {
			continue
		}

		introKey, err := IntroKeyFromRouterAddress(options)
		if err != nil {
			// §"Session Confirmed" → §"Notes": "The introduction key "i" in the
			// RI must be extracted and valid, to be used in the data phase."
			return nil, oops.Code("ROUTER_INFO_MISSING_INTRO_KEY").In("ssu2").
				Wrapf(err, "SSU2 RouterAddress advertises v=2 but carries no valid introduction key")
		}

		params := &SSU2AddressParams{StaticKey: staticKey, IntroKey: introKey}
		if mtu, ok := publishedMTU(options); ok {
			params.MTU, params.HasMTU = mtu, true
		}
		return params, nil
	}

	return nil, oops.Code("ROUTER_INFO_NO_SSU2_ADDRESS").In("ssu2").
		Errorf("RouterInfo contains no SSU/SSU2 RouterAddress advertising version %d", ssu2ProtocolVersion)
}

// VerifyRouterInfoSignature verifies the RouterInfo signature and checks that
// its publication timestamp is within bounds.
//
// ssu2.md §"Session Confirmed" → §"Notes": "Bob must perform the usual Router
// Info validation. Ensure the signature type is supported, verify the
// signature, verify the timestamp is within bounds, and any other checks
// necessary."
func VerifyRouterInfoSignature(ri *router_info.RouterInfo) error {
	if ri == nil {
		return oops.Code("EMPTY_ROUTER_INFO").In("ssu2").Errorf("RouterInfo is nil")
	}

	// Signature type support and structural validation (identity, timestamp
	// bound, size, addresses) are delegated upstream.
	if err := ri.Validate(); err != nil {
		return oops.Code("ROUTER_INFO_INVALID").In("ssu2").
			Wrapf(err, "RouterInfo failed structural validation")
	}

	ok, err := ri.VerifySignature()
	if err != nil {
		return oops.Code("ROUTER_INFO_SIGNATURE_ERROR").In("ssu2").
			Wrapf(err, "failed to verify RouterInfo signature")
	}
	if !ok {
		return oops.Code("ROUTER_INFO_SIGNATURE_INVALID").In("ssu2").
			Errorf("RouterInfo signature verification failed")
	}

	if published := ri.Published(); published != nil {
		age := time.Since(published.Time())
		if age > maxPublishedRIAge {
			return oops.Code("ROUTER_INFO_STALE").In("ssu2").
				With("age", age.String()).
				Errorf("RouterInfo publication timestamp is out of bounds")
		}
	}

	return nil
}

// Gunzip inflates a gzip-compressed payload. SSU2 RouterInfo blocks may
// optionally be gzip compressed (ssu2.md §"RouterInfo" block, flag bit 1).
// The output is capped to keep a hostile "zip bomb" from exhausting memory.
func Gunzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create gzip reader")
	}
	defer reader.Close()

	const maxInflated = 1 << 20 // 1 MiB, well above any real RouterInfo
	limited := io.LimitReader(reader, maxInflated+1)

	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to gunzip payload")
	}
	if len(out) > maxInflated {
		return nil, oops.Errorf("gunzipped payload exceeds %d bytes", maxInflated)
	}
	return out, nil
}

// isSSUFamilyTransport reports whether the address is published as "SSU" or
// "SSU2". Both styles may carry SSU2 options; §"Published Addresses": "When
// published as "SSU" with "s", "i", and "v" options ... the router must accept
// incoming connections on that host and port for both SSU and SSU2 protocols".
func isSSUFamilyTransport(addr *router_address.RouterAddress) bool {
	if addr.TransportType == nil {
		return false
	}
	style, err := addr.TransportType.Data()
	if err != nil {
		return false
	}
	s := string(style)
	return s == transportStyleSSU || s == transportStyleSSU2
}

// addressAdvertisesVersion checks the "v" option. §"Published Addresses":
// "Support for future versions will be with comma-separated values, e.g. v=2,3
// ... Implementation should verify compatibility, including multiple versions
// if a comma is present."
func addressAdvertisesVersion(addr *router_address.RouterAddress, version int) bool {
	v := addr.ProtocolVersionString()
	if v == nil {
		return false
	}
	raw, err := v.Data()
	if err != nil {
		return false
	}
	for _, part := range strings.Split(string(raw), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n == version {
			return true
		}
	}
	return false
}

// routerAddressOptions returns the address options as a Go map, for use with
// the *FromRouterAddress helpers in introkey.go.
func routerAddressOptions(addr *router_address.RouterAddress) (map[string]string, error) {
	if addr.TransportOptions == nil {
		return nil, oops.Errorf("RouterAddress has no transport options")
	}
	options := addr.Options()
	return options.ToGoMap()
}

// publishedMTU reads the optional "mtu" RouterAddress option (§"MTU").
func publishedMTU(options map[string]string) (int, bool) {
	raw, ok := options[mtuOptionKey]
	if !ok || raw == "" {
		return 0, false
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || mtu <= 0 {
		return 0, false
	}
	return mtu, true
}
