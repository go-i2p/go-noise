package ntcp2

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAltResponderConfig(t *testing.T) *Config {
	t.Helper()
	var routerHash data.Hash
	copy(routerHash[:], "updated-responder-hash-32-bytes!!!")
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	return config.WithAESObfuscation(false, nil)
}

func TestNTCP2UpdateIdentity_RejectsInvalidInput(t *testing.T) {
	config := newTestResponderConfigNoAES(t)
	ntcp2Ln, _ := startTestNTCP2Listener(t, config)

	assert.Error(t, ntcp2Ln.UpdateIdentity(nil), "nil config must be rejected")

	bad := newAltResponderConfig(t)
	bad.Pattern = ""
	assert.Error(t, ntcp2Ln.UpdateIdentity(bad), "invalid config must be rejected")

	// A rejected update leaves the live config and address unchanged.
	assert.Equal(t, config.BobRouterHash, ntcp2Ln.Config().BobRouterHash)
	assert.Equal(t, config.BobRouterHash, ntcp2Ln.Addr().(*Addr).RouterHash())
}

func TestNTCP2UpdateIdentity_PublishesNewIdentity(t *testing.T) {
	config := newTestResponderConfigNoAES(t)
	ntcp2Ln, _ := startTestNTCP2Listener(t, config)

	updated := newAltResponderConfig(t)
	require.NoError(t, ntcp2Ln.UpdateIdentity(updated))

	assert.Equal(t, updated.BobRouterHash, ntcp2Ln.Config().BobRouterHash,
		"new handshakes must read the updated config")

	// The listener address carries the responder hash used for peer identity.
	assert.Equal(t, updated.BobRouterHash, ntcp2Ln.Addr().(*Addr).RouterHash(),
		"listener address must report the updated router hash")
}

// TestNTCP2UpdateIdentity_DoesNotRebindSocket pins the invariant the design
// rests on. Rebinding cannot work: the old listener must stay open for the swap
// to be atomic, and a second bind on the same port fails with EADDRINUSE.
func TestNTCP2UpdateIdentity_DoesNotRebindSocket(t *testing.T) {
	config := newTestResponderConfigNoAES(t)
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, config)

	before := ntcp2Ln.Underlying()
	require.NoError(t, ntcp2Ln.UpdateIdentity(newAltResponderConfig(t)))

	assert.Same(t, before, ntcp2Ln.Underlying(), "the socket must not be replaced")
	assert.Equal(t, tcpAddr.String(), ntcp2Ln.Underlying().Addr().String(),
		"the listening port must be preserved")

	// The listener is still usable after the update.
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	require.NoError(t, err, "the listener must still accept connections")
	_ = conn.Close()
}

// TestNTCP2UpdateIdentity_ConcurrentWithAccept is the regression test for the
// data race that made identity updates unsafe: createResponderConnConfig clones
// the config on every Accept while an update publishes a new one. Under -race
// this fails if config is a plain field.
//
// Nothing here calls require.* from a worker goroutine: t.FailNow is only
// valid on the test goroutine, and calling it elsewhere aborts the goroutine
// nondeterministically. Workers report through t.Errorf and the assertions run
// on the test goroutine.
func TestNTCP2UpdateIdentity_ConcurrentWithAccept(t *testing.T) {
	config := newTestResponderConfigNoAES(t)
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpLn.Close()

	ntcp2Ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)

	// Pre-build the update configs on the test goroutine so the worker only
	// publishes them.
	const rounds = 200
	nextConfigs := make([]*Config, rounds)
	for i := range nextConfigs {
		next := newAltResponderConfig(t)
		// Validate on the test goroutine so a rejected config fails clearly
		// rather than surfacing from a worker.
		require.NoError(t, next.Validate())
		nextConfigs[i] = next
	}

	stopDial := make(chan struct{})
	var wg sync.WaitGroup

	// Accept until the listener is closed. Accept() blocks, so it cannot poll
	// stopDial; closing the listener is what ends it.
	acceptErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, aerr := ntcp2Ln.Accept()
			if aerr != nil {
				acceptErr <- aerr
				return
			}
			_ = conn.Close()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopDial:
				return
			default:
			}
			conn, derr := net.DialTimeout("tcp", tcpLn.Addr().String(), 500*time.Millisecond)
			if derr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if uerr := ntcp2Ln.UpdateIdentity(nextConfigs[i]); uerr != nil {
				t.Errorf("UpdateIdentity round %d: %v", i, uerr)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopDial:
				return
			default:
			}
			if c := ntcp2Ln.Config(); c == nil {
				t.Error("Config() returned nil during updates")
				return
			}
			_ = ntcp2Ln.Addr().(*Addr).RouterHash()
		}
	}()

	time.Sleep(250 * time.Millisecond)
	close(stopDial)

	// Closing the listener is what unblocks Accept.
	closeErr := ntcp2Ln.Close()
	wg.Wait()

	require.NoError(t, closeErr, "closing the listener must succeed")
	select {
	case aerr := <-acceptErr:
		// Accept must fail because the listener was closed, never because a
		// race corrupted the responder config.
		assert.Error(t, aerr)
	default:
		t.Error("accept goroutine did not report completion")
	}

	assert.NotNil(t, ntcp2Ln.Config(), "config must remain readable after updates")
}

// spyDetector records whether Close was called. It is deliberately not a
// ReplayCache: closing a ReplayCache only stops a background cleanup
// goroutine, so CheckAndAdd keeps working and the ownership violation is not
// observable through it. Asserting on Close() is the only honest test.
type spyDetector struct {
	mu     sync.Mutex
	closed bool
}

func (d *spyDetector) CheckAndAdd(_ [32]byte) bool { return false }
func (d *spyDetector) Size() int                   { return 0 }
func (d *spyDetector) Close() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
}

func (d *spyDetector) wasClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// TestNTCP2Listener_CloseDoesNotCloseSharedDetector pins the ownership fix:
// config.ReplayDetector is shared across clones (see ntcp2/config.go), so a
// listener must not close it. Closing one listener would otherwise stop the
// cleanup goroutine of every other holder of the same detector.
func TestNTCP2Listener_CloseDoesNotCloseSharedDetector(t *testing.T) {
	detector := &spyDetector{}

	config := newTestResponderConfigNoAES(t)
	config.ReplayDetector = detector

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpLn.Close()

	ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	assert.False(t, detector.wasClosed(),
		"a listener must not close a detector it does not own")
}
