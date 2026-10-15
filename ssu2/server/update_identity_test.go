package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateIdentity_RejectsInvalidInput(t *testing.T) {
	pc := createMockPacketConn(t)
	cfg := createValidConfig(t)
	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	defer listener.Close()

	assert.Error(t, listener.UpdateIdentity(nil), "nil config must be rejected")

	bad := createValidConfig(t)
	bad.Pattern = ""
	assert.Error(t, listener.UpdateIdentity(bad), "invalid config must be rejected")

	// A rejected update must leave the live config untouched.
	assert.Equal(t, cfg.RouterHash, listener.Config().RouterHash)
}

func TestUpdateIdentity_PublishesNewIdentity(t *testing.T) {
	pc := createMockPacketConn(t)
	cfg := createValidConfig(t)
	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	defer listener.Close()

	oldHash := cfg.RouterHash
	oldStatic := append([]byte(nil), cfg.StaticKey...)

	updated := createValidConfig(t)
	newStatic := make([]byte, 32)
	for i := range newStatic {
		newStatic[i] = byte(0xF0 - i)
	}
	updated.StaticKey = newStatic
	newHash := updated.RouterHash
	require.NotEqual(t, oldHash, newHash, "test must use a different router hash")

	require.NoError(t, listener.UpdateIdentity(updated))

	// Config visible to new sessions.
	assert.Equal(t, newHash, listener.Config().RouterHash)
	assert.Equal(t, newStatic, listener.Config().StaticKey)

	// The listener address advertises the responder hash, so it must follow.
	assert.Equal(t, newHash, listener.Addr().(*SSU2Addr).RouterHash(),
		"listener address must report the updated router hash")

	// The session table is untouched by an identity update.
	assert.NotEqual(t, oldStatic, listener.Config().StaticKey)
	assert.Equal(t, 0, listener.SessionCount())
}

// TestUpdateIdentity_RebuildsIntroKeyProtector guards the derived state: the
// inbound header protector is built from IntroKey at construction, so an update
// that changes or clears IntroKey must rebuild or clear it. Without this, the
// listener would keep decrypting SessionRequests under a retired intro key.
func TestUpdateIdentity_RebuildsIntroKeyProtector(t *testing.T) {
	pc := createMockPacketConn(t)
	cfg := createValidConfig(t)
	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	defer listener.Close()

	// Construction with no IntroKey leaves protection disabled.
	require.Nil(t, listener.introHeaderProtector.Load())

	withKey := createValidConfig(t)
	introKey := make([]byte, 32)
	for i := range introKey {
		introKey[i] = byte(i + 0x20)
	}
	withKey.IntroKey = introKey
	require.NoError(t, listener.UpdateIdentity(withKey))
	require.NotNil(t, listener.introHeaderProtector.Load(),
		"a new IntroKey must build an inbound header protector")

	// Clearing the intro key must clear the protector rather than leave it
	// decrypting with a retired key.
	cleared := createValidConfig(t)
	require.NoError(t, listener.UpdateIdentity(cleared))
	assert.Nil(t, listener.introHeaderProtector.Load(),
		"clearing IntroKey must clear the protector")
}

// TestUpdateIdentity_ConcurrentWithPacketProcessing is the regression test for
// the data race that made identity updates unsafe: receiveLoop and the packet
// workers read the listener config while an update publishes a new one. Under
// -race this fails if config or introHeaderProtector is a plain field.
//
// Worker goroutines never call require.*: t.FailNow is only valid on the test
// goroutine, so assertions from a worker would abort it nondeterministically.
// Configs are pre-built on the test goroutine because createValidConfig itself
// uses require.
func TestUpdateIdentity_ConcurrentWithPacketProcessing(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)

	cfg := createValidConfig(t)
	cfg.AllowLoopback = true
	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	require.NoError(t, listener.Start())
	defer listener.Close()

	peer, err := net.Dial("udp", pc.LocalAddr().String())
	require.NoError(t, err)
	defer peer.Close()

	const rounds = 200
	nextConfigs := make([]*SSU2Config, rounds)
	for i := range nextConfigs {
		next := createValidConfig(t)
		if i%2 == 0 {
			// Alternate intro key on/off so both the protector rebuild and the
			// protector clear paths race with readers.
			ik := make([]byte, 32)
			for j := range ik {
				ik[j] = byte(j + i)
			}
			next.IntroKey = ik
		}
		// Validate here so a rejected config fails the test with a clear
		// message instead of surfacing from inside a worker goroutine.
		require.NoError(t, next.Validate())
		nextConfigs[i] = next
	}

	payloads := [][]byte{make([]byte, 4), {}, make([]byte, 79), make([]byte, 200)}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Drive the receive path into parseInboundPacket and the SessionRequest
	// handler, which are the read side of the race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, werr := peer.Write(payloads[i%len(payloads)]); werr != nil {
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if uerr := listener.UpdateIdentity(nextConfigs[i]); uerr != nil {
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
			case <-stop:
				return
			default:
			}
			// Read the same fields the handshake path reads (handleNewSession
			// takes StaticKey, buildConnConfig copies the whole struct), so a
			// non-atomic publisher races here exactly as it would there.
			c := listener.Config()
			if c == nil {
				t.Error("Config() returned nil during updates")
				return
			}
			_ = c.MaxSessions
			_ = len(c.StaticKey)
			_ = listener.Addr().(*SSU2Addr).RouterHash()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	require.NotNil(t, listener.Config(), "config must remain readable after updates")
}

// TestUpdateIdentity_DoesNotRebindSocket is the invariant the whole design
// rests on: an identity update must not replace the socket, because a second
// bind to the same port fails with EADDRINUSE while the old one is open.
func TestUpdateIdentity_DoesNotRebindSocket(t *testing.T) {
	pc := createMockPacketConn(t)
	cfg := createValidConfig(t)
	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	defer listener.Close()

	before := listener.Underlying()
	beforeAddr := listener.Addr()

	require.NoError(t, listener.UpdateIdentity(createValidConfig(t)))

	assert.Same(t, before, listener.Underlying(), "the socket must not be replaced")
	assert.Equal(t, beforeAddr.(*SSU2Addr).ConnectionID(),
		listener.Addr().(*SSU2Addr).ConnectionID(),
		"the listener conn ID must be stable across identity updates")
}

// TestNewSSU2Listener_KeepsCallerConfigAliased documents deliberate behaviour
// that a defensive Clone() would break: go-i2p populates IntroKey and
// ObfuscationIV on the config AFTER the listener is constructed and started,
// and buildConnConfig must observe them through the shared pointer.
func TestNewSSU2Listener_KeepsCallerConfigAliased(t *testing.T) {
	pc := createMockPacketConn(t)
	cfg := createValidConfig(t)
	cfg.IntroKey = nil

	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)
	defer listener.Close()

	iv := make([]byte, 8)
	cfg.ObfuscationIV = iv
	cfg.IntroKey = make([]byte, 32)

	assert.Equal(t, iv, listener.Config().ObfuscationIV,
		"post-construction caller mutation must be visible to the listener")

	// The per-session copy path reads through the same pointer.
	assert.Len(t, listener.Config().IntroKey, 32)
}
