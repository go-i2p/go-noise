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
// workers read the listener config while an update publishes a new one. Run
// under -race, this fails if config or introHeaderProtector is a plain field.
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

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Drive the receive path: oversized, truncated and empty datagrams all
	// reach the config/protector reads in parseInboundPacket and the
	// SessionRequest path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		payloads := [][]byte{
			make([]byte, 4),
			{},
			make([]byte, 79),
			make([]byte, 200),
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = peer.Write(payloads[i%len(payloads)])
		}
	}()

	// Update identity concurrently, alternating intro key on and off so both
	// the protector rebuild and the protector clear paths race with readers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := 0; round < 200; round++ {
			next := createValidConfig(t)
			if round%2 == 0 {
				ik := make([]byte, 32)
				for i := range ik {
					ik[i] = byte(i + round)
				}
				next.IntroKey = ik
			}
			if err := listener.UpdateIdentity(next); err != nil {
				t.Errorf("UpdateIdentity round %d: %v", round, err)
				return
			}
		}
	}()

	// Reader that observes the same state the handshake path uses.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c := listener.Config()
			require.NotNil(t, c)
			_ = c.MaxSessions
			_ = listener.Addr().(*SSU2Addr).RouterHash()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	assert.NotNil(t, listener.Config(), "config must remain readable after updates")
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
