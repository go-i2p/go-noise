// Package routerinfo provides the transport-layer RouterInfo checks that both
// NTCP2 and SSU2 require, and that neither spec lets an implementation skip.
//
// Both dev specs put the same three obligations on the responder when it
// receives the initiator's RouterInfo in the third handshake message:
//
//   - ntcp2.md §"3) SessionConfirmed" -> §"Notes" and ssu2.md §"Session
//     Confirmed" -> §"Notes": "Bob must perform the usual Router Info
//     validation. Ensure the signature type is supported, verify the signature,
//     verify the timestamp is within bounds, and any other checks necessary."
//   - both: "Bob must verify that Alice's static key received in the first
//     frame matches the static key in the Router Info. Bob must first search the
//     Router Info for a … Router Address with a matching version (v) option."
//
// It lives under internal/ because the two transports share it and neither may
// depend on the other. All of the heavy lifting — parsing, signature type
// support, signature verification, address and option structure — is delegated
// to github.com/go-i2p/common; this package only adds the pieces the specs
// require that upstream does not provide (the freshness bound and the
// version-scoped address search).
package routerinfo

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"io"
	"strconv"
	"strings"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/samber/oops"
)

// MaxPublishedAge bounds how old a peer RouterInfo may be before it is
// rejected. Both specs require "verify the timestamp is within bounds" without
// naming a bound; this matches the RouterInfo publication lifetime the
// reference implementations use, and github.com/go-i2p/common's
// RouterInfo.Validate() checks only that a timestamp is present, not that it is
// recent.
const MaxPublishedAge = 90 * 24 * time.Hour

// Read parses RouterInfo bytes, tolerating trailing data.
func Read(riBytes []byte) (*router_info.RouterInfo, error) {
	if len(riBytes) == 0 {
		return nil, oops.Code("EMPTY_ROUTER_INFO").Errorf("RouterInfo is empty")
	}
	ri, _, err := router_info.ReadRouterInfo(riBytes)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse RouterInfo")
	}
	return &ri, nil
}

// VerifySignature checks the signature type, the signature itself, and that the
// publication timestamp is within bounds.
func VerifySignature(ri *router_info.RouterInfo) error {
	if ri == nil {
		return oops.Code("EMPTY_ROUTER_INFO").Errorf("RouterInfo is nil")
	}

	// Signature type support and structural validation (identity, timestamp
	// presence, size, addresses, options) are delegated upstream.
	if err := ri.Validate(); err != nil {
		return oops.Code("ROUTER_INFO_INVALID").Wrapf(err, "RouterInfo failed structural validation")
	}

	ok, err := ri.VerifySignature()
	if err != nil {
		return oops.Code("ROUTER_INFO_SIGNATURE_ERROR").Wrapf(err, "failed to verify RouterInfo signature")
	}
	if !ok {
		return oops.Code("ROUTER_INFO_SIGNATURE_INVALID").Errorf("RouterInfo signature verification failed")
	}

	if published := ri.Published(); published != nil {
		if age := time.Since(published.Time()); age > MaxPublishedAge {
			return oops.Code("ROUTER_INFO_STALE").
				With("age", age.String()).
				Errorf("RouterInfo publication timestamp is out of bounds")
		}
	}

	return nil
}

// Gunzip inflates a gzip-compressed payload. SSU2 RouterInfo blocks may
// optionally be gzip compressed (ssu2.md §"RouterInfo" block, flag bit 1). The
// output is capped so a hostile "zip bomb" cannot exhaust memory.
func Gunzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create gzip reader")
	}
	defer reader.Close()

	const maxInflated = 1 << 20 // 1 MiB, well above any real RouterInfo
	out, err := io.ReadAll(io.LimitReader(reader, maxInflated+1))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to gunzip payload")
	}
	if len(out) > maxInflated {
		return nil, oops.Errorf("gunzipped payload exceeds %d bytes", maxInflated)
	}
	return out, nil
}

// Options returns a RouterAddress's transport options as a Go map.
func Options(addr *router_address.RouterAddress) (map[string]string, error) {
	if addr == nil || addr.TransportOptions == nil {
		return nil, oops.Errorf("RouterAddress has no transport options")
	}
	options := addr.Options()
	return options.ToGoMap()
}

// Style returns the address's protocol identifier ("NTCP", "NTCP2", "SSU",
// "SSU2", …) or an empty string when it is unavailable.
func Style(addr *router_address.RouterAddress) string {
	if addr == nil || addr.TransportType == nil {
		return ""
	}
	raw, err := addr.TransportType.Data()
	if err != nil {
		return ""
	}
	return string(raw)
}

// MatchesStyle reports whether the address is published under one of styles.
//
// Both specs publish the same options under either the legacy or the versioned
// name — ssu2.md §"Published Addresses": a router "published as "SSU" with "s",
// "i", and "v" options … must accept incoming connections … for both SSU and
// SSU2 protocols" — so an exact style match alone misses valid peers.
// github.com/go-i2p/common's IsSSU2()/IsNTCP2() helpers do exactly that, hence
// this helper taking the accepted styles from the caller.
func MatchesStyle(addr *router_address.RouterAddress, styles ...string) bool {
	style := Style(addr)
	if style == "" {
		return false
	}
	for _, want := range styles {
		if style == want {
			return true
		}
	}
	return false
}

// AdvertisesVersion reports whether the address's "v" option lists version.
//
// ssu2.md / ntcp2.md §"Published Addresses": "Support for future versions will
// be with comma-separated values, e.g. v=2,3 Implementation should verify
// compatibility, including multiple versions if a comma is present."
func AdvertisesVersion(addr *router_address.RouterAddress, version int) bool {
	if addr == nil {
		return false
	}
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

// KeyOption decodes a fixed-size I2P-base64 option, e.g. the 32-byte "s" static
// key or the 32-byte SSU2 "i" introduction key.
func KeyOption(options map[string]string, name string, size int) ([]byte, error) {
	raw, ok := options[name]
	if !ok || raw == "" {
		return nil, oops.
			Code("ROUTER_INFO_MISSING_OPTION").
			With("option", name).
			Errorf("RouterAddress missing required '%s' option", name)
	}
	key, err := i2pbase64.I2PEncoding.DecodeString(raw)
	if err != nil {
		return nil, oops.
			Code("ROUTER_INFO_BAD_OPTION").
			With("option", name).
			Wrapf(err, "invalid I2P Base64 in '%s' option", name)
	}
	if len(key) != size {
		return nil, oops.
			Code("ROUTER_INFO_BAD_OPTION").
			With("option", name).
			Errorf("'%s' option must decode to %d bytes, got %d", name, size, len(key))
	}
	return key, nil
}

// MTUOption reads the optional "mtu" RouterAddress option. ssu2.md §"MTU":
// "Routers must publish a non-default MTU in each SSU or SSU2 router address."
func MTUOption(options map[string]string) (int, bool) {
	raw, ok := options["mtu"]
	if !ok || raw == "" {
		return 0, false
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || mtu <= 0 {
		return 0, false
	}
	return mtu, true
}

// ConstantTimeEqualKey compares two key blobs without leaking their contents
// through timing.
func ConstantTimeEqualKey(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
