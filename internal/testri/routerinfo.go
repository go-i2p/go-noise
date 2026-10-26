// Package testri builds spec-compliant RouterInfo fixtures for tests.
//
// ssu2.md §"Session Confirmed" → §"Notes" requires the responder to verify the
// peer RouterInfo's signature, timestamp and SSU2 options, and §"Session
// Confirmed Fragmentation" requires Session Confirmed to carry "the full signed
// Router Info". Ad-hoc byte blobs cannot satisfy those checks, so tests that
// exercise the handshake end to end must send a real, signed RouterInfo.
package testri

import (
	"strconv"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/require"
)

// SignedRouterInfo is a RouterInfo fixture plus the keys it was built with.
type SignedRouterInfo struct {
	Info *router_info.RouterInfo
	// NoiseStaticPub is the X25519 public key advertised in the SSU2 "s"
	// option — the key the peer's Noise handshake must authenticate.
	NoiseStaticPub []byte
	// IntroKey is the 32-byte value advertised in the SSU2 "i" option.
	IntroKey []byte
	// Bytes is the serialized RouterInfo, ready for a RouterInfo block.
	Bytes []byte
}

// NewLarge returns a signed RouterInfo whose serialized length exceeds
// targetBytes. Session Confirmed fragmentation (ssu2.md §"Session Confirmed
// Fragmentation") is only exercised by a RouterInfo larger than one packet.
func NewLarge(t testing.TB, staticKey []byte) []byte {
	t.Helper()
	const targetBytes = 1500
	for n := 1; n <= 40; n++ {
		ri := New(t, &Options{StaticKey: staticKey, ExtraAddresses: n})
		if len(ri.Bytes) >= targetBytes {
			return ri.Bytes
		}
	}
	t.Fatalf("unable to build a RouterInfo of at least %d bytes", targetBytes)
	return nil
}

// Options lets a caller pin the fixture's SSU2 address parameters instead of
// using fresh random keys.
type Options struct {
	// StaticKey overrides the advertised "s" (32 bytes). Nil generates one.
	StaticKey []byte
	// IntroKey overrides the advertised "i" (32 bytes). Nil generates one.
	IntroKey []byte
	// MTU, when > 0, is published in the "mtu" option.
	MTU int
	// Host and Port for the SSU2 address.
	Host string
	Port string
	// Transport overrides the address style; defaults to "SSU2".
	Transport string
	// Version overrides the "v" option; defaults to "2".
	Version string
	// SkipOptions omits s/i/v entirely, for negative tests.
	SkipOptions bool
	// ExtraAddresses publishes additional SSU2 addresses (different ports,
	// identical s/i per ssu2.md §"Published Addresses": "all addresses
	// specifying the same port must contain the identical SSU2 options") to
	// grow the serialized RouterInfo.
	ExtraAddresses int
}

// New builds a signed RouterInfo carrying a single SSU2 address with the
// mandatory s/i/v options (ssu2.md §"Published Addresses").
func New(t testing.TB, opts *Options) *SignedRouterInfo {
	t.Helper()

	if opts == nil {
		opts = &Options{}
	}

	transport := opts.Transport
	if transport == "" {
		transport = "SSU2"
	}
	host := opts.Host
	if host == "" {
		host = "203.0.113.10"
	}
	port := opts.Port
	if port == "" {
		port = "8888"
	}
	version := opts.Version
	if version == "" {
		version = "2"
	}

	var staticPub []byte
	if len(opts.StaticKey) == 32 {
		staticPub = append([]byte(nil), opts.StaticKey...)
	} else {
		pub, _, err := curve25519.GenerateKeyPair()
		require.NoError(t, err)
		staticPub = pub.Bytes()
	}

	introKey := make([]byte, 32)
	if len(opts.IntroKey) == 32 {
		copy(introKey, opts.IntroKey)
	} else {
		_, err := rand.Read(introKey)
		require.NoError(t, err)
	}

	addressOptions := map[string]string{"host": host, "port": port}
	if !opts.SkipOptions {
		addressOptions["s"] = i2pbase64.EncodeToString(staticPub)
		// The "i" option differs by transport: ntcp2.md §"Published Addresses"
		// defines it as a 16-byte IV, ssu2.md as a 32-byte ChaCha20 key. Emit the
		// right width so a parser scoped to that transport accepts the fixture.
		iKey := introKey
		if transport == "NTCP2" || transport == "NTCP" {
			iKey = introKey[:16]
		}
		addressOptions["i"] = i2pbase64.EncodeToString(iKey)
		addressOptions["v"] = version
	}
	if opts.MTU > 0 {
		addressOptions["mtu"] = strconv.Itoa(opts.MTU)
	}

	addr, err := router_address.NewRouterAddress(7, time.Time{}, transport, addressOptions)
	require.NoError(t, err)

	addresses := []*router_address.RouterAddress{addr}
	for i := 0; i < opts.ExtraAddresses; i++ {
		extraOpts := map[string]string{}
		for k, v := range addressOptions {
			extraOpts[k] = v
		}
		// ssu2.md §"Published Addresses": addresses on a different port may
		// repeat the same s/i; use a distinct port per extra address.
		extraOpts["port"] = strconv.Itoa(9000 + i)
		extra, err := router_address.NewRouterAddress(14, time.Time{}, transport, extraOpts)
		require.NoError(t, err)
		addresses = append(addresses, extra)
	}

	signingPriv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	typedPriv, ok := signingPriv.(ed25519.Ed25519PrivateKey)
	require.True(t, ok)
	signingPub, err := typedPriv.Public()
	require.NoError(t, err)

	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	require.NoError(t, err)
	cert := &keyCert.Certificate

	receivingPub, err := curve25519.NewCurve25519PublicKey(staticPub)
	require.NoError(t, err)
	var receiving types.ReceivingPublicKey = receivingPub

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	padding := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE-pubKeySize-sigKeySize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	identity, err := router_identity.NewRouterIdentity(receiving, signingPub, cert, padding)
	require.NoError(t, err)

	ri, err := router_info.NewRouterInfo(
		identity,
		time.Now(),
		addresses,
		map[string]string{"router.version": "0.9.64", "netId": "2"},
		&typedPriv,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	raw, err := ri.Bytes()
	require.NoError(t, err)

	valid, err := ri.VerifySignature()
	require.NoError(t, err)
	require.True(t, valid, "test RouterInfo fixture must be validly signed")

	return &SignedRouterInfo{Info: ri, NoiseStaticPub: staticPub, IntroKey: introKey, Bytes: raw}
}
