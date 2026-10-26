package exampleutil

import (
	"context"
	"time"

	"github.com/go-i2p/go-noise"
	"github.com/go-i2p/pool"
)

// NewExampleTransport builds a dedicated noise.Transport with its own connection
// pool and shutdown manager.
//
// Each example owns its Transport instead of sharing package-level state, so
// runs do not leak pools or shutdown managers into one another. Callers should
// arrange for transport.GracefulShutdown() to run when they are done.
//
// Examples that need to inspect pool statistics build the pool themselves and
// pass it to noise.NewTransport, as pool/main.go shows.
func NewExampleTransport() *noise.Transport {
	cp := pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 10,
		MaxAge:  30 * time.Minute,
		MaxIdle: 5 * time.Minute,
	})
	return noise.NewTransport(cp, noise.NewShutdownManager(30*time.Second))
}

// Dial opens a TCP connection wrapped in a NoiseConn without performing the
// handshake. The caller runs Handshake itself. This is the Transport-based
// replacement for the removed package-level DialNoise.
func Dial(t *noise.Transport, addr string, config *noise.ConnConfig) (*noise.NoiseConn, error) {
	return t.Dial("tcp", addr, config)
}

// DialWithHandshake opens a TCP connection and performs the Noise handshake
// with the Transport's retry policy. It replaces the removed
// DialNoiseWithHandshake.
func DialWithHandshake(t *noise.Transport, addr string, config *noise.ConnConfig) (*noise.NoiseConn, error) {
	return t.DialWithHandshake("tcp", addr, config)
}

// DialWithHandshakeContext is DialWithHandshake with a context for
// cancellation. It replaces the removed DialNoiseWithHandshakeContext.
func DialWithHandshakeContext(ctx context.Context, t *noise.Transport, addr string, config *noise.ConnConfig) (*noise.NoiseConn, error) {
	return t.DialWithHandshakeContext(ctx, "tcp", addr, config)
}

// DialWithPool opens a connection reusing an idle pooled TCP connection when
// one exists, without performing the handshake. It replaces the removed
// DialNoiseWithPool.
func DialWithPool(t *noise.Transport, addr string, config *noise.ConnConfig) (*noise.NoiseConn, error) {
	return t.DialWithPool("tcp", addr, config)
}

// Listen starts a TCP listener wrapped by the given Transport. It replaces the
// removed package-level ListenNoise.
func Listen(t *noise.Transport, addr string, config *noise.ListenerConfig) (*noise.NoiseListener, error) {
	return t.Listen("tcp", addr, config)
}
