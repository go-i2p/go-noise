package server

import (
	"net"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
)

// generateRandomHash creates a random data.Hash for testing.
func generateRandomHash() data.Hash {
	var h data.Hash
	_, _ = rand.Read(h[:])
	return h
}

// hashPtr returns a pointer to the given data.Hash, useful for struct literals.
func hashPtr(h data.Hash) *data.Hash {
	return &h
}

// testStaticKey returns a valid, non-zero 32-byte Curve25519 private key for
// testing. go-i2p's NewCurve25519PrivateKey rejects all-zero keys, so tests
// must not pass make([]byte, 32) as a local static key.
func testStaticKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

// testPeerAddr returns a fixed UDP source address for tests that drive the
// listener's parse path directly instead of through a socket. parseInboundPacket
// stamps the datagram's origin onto the packet (ssu2.md §"Session Created"
// requires the Session Created source to match the Session Request destination),
// so direct-call tests must supply one.
func testPeerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9012}
}
