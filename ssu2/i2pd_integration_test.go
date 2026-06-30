//go:build i2pd_integration

// Package ssu2 i2pd integration tests.
//
// These tests exercise SSU2 peer-test and introducer (relay) flows against a
// live i2pd instance, validating wire compatibility that in-process Go tests
// cannot: symmetric-NAT traversal and introducer relay end to end.
//
// They are excluded from the default build via the `i2pd_integration` tag and
// additionally skip at runtime unless the operator points them at a reachable
// i2pd. Run with:
//
//	I2PD_SSU2_ADDR=127.0.0.1:port \
//	I2PD_ROUTER_HASH=<base64 router hash> \
//	go test -tags i2pd_integration ./ssu2/ -run TestI2pd
//
// When the required environment is not present the tests SKIP (never fail), so
// CI without an i2pd sidecar stays green.
package ssu2

import (
	"os"
	"testing"
	"time"
)

// i2pdEnv holds the operator-supplied connection parameters for a live i2pd.
type i2pdEnv struct {
	addr       string // SSU2 UDP endpoint, e.g. 127.0.0.1:23456
	routerHash string // base64 of the i2pd router identity hash
}

// requireI2pd loads i2pd connection parameters from the environment, skipping
// the test when they are absent or incomplete.
func requireI2pd(t *testing.T) i2pdEnv {
	t.Helper()
	addr := os.Getenv("I2PD_SSU2_ADDR")
	hash := os.Getenv("I2PD_ROUTER_HASH")
	if addr == "" || hash == "" {
		t.Skip("i2pd integration: set I2PD_SSU2_ADDR and I2PD_ROUTER_HASH to run")
	}
	return i2pdEnv{addr: addr, routerHash: hash}
}

// TestI2pdIntroducerRelay validates that go-noise can request an introduction
// through a live i2pd acting as Bob and reach an introduced peer (Charlie),
// confirming the RelayRequest -> RelayResponse -> RelayIntro sequence and the
// `introducers` RouterAddress publication parse correctly against i2pd.
func TestI2pdIntroducerRelay(t *testing.T) {
	env := requireI2pd(t)
	_ = env

	// TODO(i2pd): Establish an SSU2 session to env.addr, register the relay
	// Coordinator's BuildCallbacks on the session, issue StartRelay toward a
	// Charlie advertised in i2pd's netDB, and assert a signed RelayResponse with
	// a session token is received within the deadline.
	t.Skip("i2pd introducer relay scaffold: live-i2pd assertions not yet implemented")
}

// TestI2pdSymmetricNATPeerTest validates the four-message peer-test exchange
// against a live i2pd, including address-result signaling under simulated
// symmetric-NAT conditions (source-port rewriting), to confirm NAT type
// detection matches i2pd's determination.
func TestI2pdSymmetricNATPeerTest(t *testing.T) {
	env := requireI2pd(t)
	_ = env

	deadline := time.Now().Add(60 * time.Second)
	_ = deadline

	// TODO(i2pd): Drive StartPeerTest toward env.addr (Bob), let i2pd select
	// Charlie, and assert the returned PeerTest Result (msg 4) carries a valid
	// Charlie signature and the expected NAT classification.
	t.Skip("i2pd symmetric-NAT peer-test scaffold: live-i2pd assertions not yet implemented")
}
