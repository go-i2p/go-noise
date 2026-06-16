package listener

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/conn"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/shutdown"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestNoiseListenerFromTCP creates a NoiseListener backed by a real TCP listener
// with a random static key and the given pattern. Caller must close the returned listener.
func newTestNoiseListenerFromTCP(t *testing.T, pattern string) *Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)
	config := NewListenerConfig(pattern).WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)
	return noiseListener
}

// newTestNoiseListenerFromMock creates a NoiseListener backed by a mockListener
// with a random static key and the given pattern.
func newTestNoiseListenerFromMock(t *testing.T, pattern string, ml *mockListener) *Listener {
	t.Helper()
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)
	config := NewListenerConfig(pattern).WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	return noiseListener
}

// pipedMockListener creates a net.Pipe, builds a mockListener whose Accept
// returns the server end, and returns (clientConn, mockListener). Both pipe
// ends are registered with t.Cleanup.
func pipedMockListener(t *testing.T, addr net.Addr) (net.Conn, *mockListener) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	ml := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return serverConn, nil
		},
	}
	return clientConn, ml
}

// acceptAsNoiseConn calls Accept on the listener, asserts success, registers
// cleanup, and returns the underlying *conn.NoiseConn.
func acceptAsNoiseConn(t *testing.T, nl *Listener) *conn.Conn {
	t.Helper()
	c, err := nl.Accept()
	require.NoError(t, err)
	require.NotNil(t, c)
	noiseConn, ok := c.(*conn.Conn)
	require.True(t, ok)
	t.Cleanup(func() { noiseConn.Close() })
	return noiseConn
}

func TestNewListenerConfig(t *testing.T) {
	config := NewListenerConfig("XX")

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
}

func TestListenerConfigBuilder(t *testing.T) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.WriteTimeout)
}

func TestListenerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *ListenerConfig
		expectError bool
		errorCode   string
	}{
		{
			name: "valid config",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "valid config without static key",
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("NN") // No static key - should be valid
			},
			expectError: false,
		},
		{
			name: "empty pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "noise pattern is required",
		},
		{
			name: "invalid pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("INVALID").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "invalid noise pattern",
		},
		{
			name: "invalid key length",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 16) // Wrong length
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "static key must be 32 bytes",
		},
		{
			name: "invalid timeout",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").
					WithStaticKey(staticKey).
					WithHandshakeTimeout(-1 * time.Second)
			},
			expectError: true,
			errorCode:   "handshake timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewNoiseListener(t *testing.T) {
	tests := []struct {
		name            string
		setupUnderlying func() net.Listener
		setupConfig     func() *ListenerConfig
		expectError     bool
		errorType       string
	}{
		{
			name: "valid listener creation",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				_, err := rand.Read(staticKey)
				require.NoError(t, err)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "nil underlying listener",
			setupUnderlying: func() net.Listener {
				return nil
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorType:   "underlying listener cannot be nil",
		},
		{
			name: "nil config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return nil
			},
			expectError: true,
			errorType:   "listener config cannot be nil",
		},
		{
			name: "invalid config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("") // Invalid pattern
			},
			expectError: true,
			errorType:   "invalid listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := tt.setupUnderlying()
			if underlying != nil {
				defer underlying.Close()
			}
			config := tt.setupConfig()

			listener, err := NewNoiseListener(underlying, config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, listener)
				if tt.errorType != "" {
					assert.Contains(t, err.Error(), tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				assert.Equal(t, underlying.Addr().Network(), listener.Addr().(*conn.Addr).Underlying().Network())
				listener.Close()
			}
		})
	}
}

func TestNoiseListenerAddr(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	addr := noiseListener.Addr()
	noiseAddr, ok := addr.(*conn.Addr)
	require.True(t, ok)

	assert.Equal(t, "noise+tcp", noiseAddr.Network())
	assert.Contains(t, noiseAddr.String(), "XX")
	assert.Contains(t, noiseAddr.String(), "responder")
	assert.Contains(t, noiseAddr.String(), "127.0.0.1")
}

func TestNoiseListenerClose(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Close should succeed
	err := noiseListener.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = noiseListener.Close()
	assert.NoError(t, err)

	// Accept should fail after close
	_, err = noiseListener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listener is closed")
}

func TestNoiseListenerAcceptAfterClose(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Close the listener
	err := noiseListener.Close()
	require.NoError(t, err)

	// Accept should return error
	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "listener is closed")
}

// mockListener implements net.Listener for testing
type mockListener struct {
	addr       net.Addr
	acceptFunc func() (net.Conn, error)
	closeFunc  func() error
	closed     bool
	mu         sync.Mutex
}

func (ml *mockListener) Accept() (net.Conn, error) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	if ml.closed {
		return nil, net.ErrClosed
	}
	if ml.acceptFunc != nil {
		return ml.acceptFunc()
	}
	return nil, assert.AnError
}

func (ml *mockListener) Close() error {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.closed = true
	if ml.closeFunc != nil {
		return ml.closeFunc()
	}
	return nil
}

func (ml *mockListener) Addr() net.Addr {
	return ml.addr
}

func TestNoiseListenerAcceptError(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	ml := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return nil, assert.AnError
		},
	}
	noiseListener := newTestNoiseListenerFromMock(t, "XX", ml)
	defer noiseListener.Close()

	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to accept underlying connection")
}

func TestNoiseListenerConcurrentOperations(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Test concurrent close operations
	var wg sync.WaitGroup
	closeErrors := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			closeErrors[index] = noiseListener.Close()
		}(i)
	}

	wg.Wait()

	// All close operations should succeed (idempotent)
	for i, err := range closeErrors {
		assert.NoError(t, err, "Close operation %d should succeed", i)
	}
}

func TestNoiseListenerNetworkInterface(t *testing.T) {
	// Verify NoiseListener implements net.Listener interface
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	// Verify it implements net.Listener
	var _ net.Listener = noiseListener

	// Test interface methods
	addr := noiseListener.Addr()
	assert.NotNil(t, addr)

	// Accept should work (but we won't wait for connections)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go func() {
		<-ctx.Done()
		noiseListener.Close()
	}()

	_, err := noiseListener.Accept()
	// Should get an error due to timeout/close, but that's expected
	assert.Error(t, err)
}

func TestListenerConfigAllPatterns(t *testing.T) {
	patterns := []string{
		"NN", "NK", "NX", "XN", "XK", "XX",
		"KN", "KK", "KX", "IN", "IK", "IX",
		"N", "K", "X",
		"Noise_NN_25519_AESGCM_SHA256",
		"Noise_XX_25519_AESGCM_SHA256",
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			config := NewListenerConfig(pattern).WithStaticKey(staticKey)
			err := config.Validate()
			assert.NoError(t, err, "Pattern %s should be valid", pattern)
		})
	}
}

// Benchmark the listener creation and basic operations
func BenchmarkNoiseListenerCreation(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)
	defer listener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		noiseListener, err := NewNoiseListener(listener, config)
		if err != nil {
			b.Fatal(err)
		}
		noiseListener.Close()
	}
}

func BenchmarkListenerConfigValidation(b *testing.B) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- Tests for ListenerConfig Modifiers, PostHandshakeHook, AdditionalSymmetricKeyLabels ---

// testModifier is a minimal HandshakeModifier for testing.
type testModifier struct {
	name string
}

func (m *testModifier) ModifyOutbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}

func (m *testModifier) ModifyInbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}
func (m *testModifier) Name() string { return m.name }
func (m *testModifier) Close() error { return nil }

func TestListenerConfigWithModifiers(t *testing.T) {
	mod1 := &testModifier{name: "mod1"}
	mod2 := &testModifier{name: "mod2"}

	config := NewListenerConfig("XX").
		WithModifiers(mod1, mod2)

	require.Len(t, config.Modifiers, 2)
	assert.Equal(t, "mod1", config.Modifiers[0].Name())
	assert.Equal(t, "mod2", config.Modifiers[1].Name())
}

func TestListenerConfigWithModifiers_DefensiveCopy(t *testing.T) {
	mod1 := &testModifier{name: "mod1"}
	mods := []handshake.HandshakeModifier{mod1}

	config := NewListenerConfig("XX").WithModifiers(mods...)

	// Mutating the original slice should not affect the config
	mods[0] = &testModifier{name: "replaced"}
	assert.Equal(t, "mod1", config.Modifiers[0].Name())
}

func TestListenerConfigWithPostHandshakeHook(t *testing.T) {
	hookCalled := false
	hook := func(nc *conn.Conn) error {
		hookCalled = true
		return nil
	}

	config := NewListenerConfig("XX").
		WithPostHandshakeHook(hook)

	require.NotNil(t, config.PostHandshakeHook)

	// Verify hook is callable
	err := config.PostHandshakeHook(nil)
	assert.NoError(t, err)
	assert.True(t, hookCalled)
}

func TestListenerConfigWithAdditionalSymmetricKeyLabels(t *testing.T) {
	labels := [][]byte{[]byte("ask"), []byte("extra")}

	config := NewListenerConfig("XX").
		WithAdditionalSymmetricKeyLabels(labels)

	require.Len(t, config.AdditionalSymmetricKeyLabels, 2)
	assert.Equal(t, []byte("ask"), config.AdditionalSymmetricKeyLabels[0])
	assert.Equal(t, []byte("extra"), config.AdditionalSymmetricKeyLabels[1])
}

func TestListenerConfigBuilderChain_AllFields(t *testing.T) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	mod := &testModifier{name: "test-mod"}
	hookCalled := false
	hook := func(nc *conn.Conn) error {
		hookCalled = true
		return nil
	}
	labels := [][]byte{[]byte("ask")}

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second).
		WithModifiers(mod).
		WithPostHandshakeHook(hook).
		WithAdditionalSymmetricKeyLabels(labels)

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Len(t, config.Modifiers, 1)
	assert.Equal(t, "test-mod", config.Modifiers[0].Name())
	assert.NotNil(t, config.PostHandshakeHook)
	assert.Len(t, config.AdditionalSymmetricKeyLabels, 1)

	// Verify hook works
	_ = config.PostHandshakeHook(nil)
	assert.True(t, hookCalled)
}

// --- Test that Accept() propagates Modifiers/Hook/ASKLabels to ConnConfig ---

func TestNoiseListenerAcceptPropagatesModifiers(t *testing.T) {
	// Use a mock listener that returns a mock conn on Accept
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
	_, ml := pipedMockListener(t, addr)

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	mod := &testModifier{name: "propagated-mod"}
	hookCalled := false
	hook := func(nc *conn.Conn) error {
		hookCalled = true
		return nil
	}
	labels := [][]byte{[]byte("ask")}

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithModifiers(mod).
		WithPostHandshakeHook(hook).
		WithAdditionalSymmetricKeyLabels(labels)

	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	noiseConn := acceptAsNoiseConn(t, noiseListener)

	// Verify modifiers were propagated
	require.Len(t, noiseConn.Config().Modifiers, 1)
	assert.Equal(t, "propagated-mod", noiseConn.Config().Modifiers[0].Name())

	// Verify PostHandshakeHook was propagated
	require.NotNil(t, noiseConn.Config().PostHandshakeHook)

	// Verify ASK labels were propagated
	require.Len(t, noiseConn.Config().AdditionalSymmetricKeyLabels, 1)
	assert.Equal(t, []byte("ask"), noiseConn.Config().AdditionalSymmetricKeyLabels[0])

	// Verify hook is functional
	_ = noiseConn.Config().PostHandshakeHook(nil)
	assert.True(t, hookCalled)
}

func TestNoiseListenerAcceptNoModifiers(t *testing.T) {
	// Verify Accept works correctly when no modifiers are configured (no regression)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9091}
	_, ml := pipedMockListener(t, addr)

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	noiseConn := acceptAsNoiseConn(t, noiseListener)

	assert.Empty(t, noiseConn.Config().Modifiers)
	assert.Nil(t, noiseConn.Config().PostHandshakeHook)
	assert.Empty(t, noiseConn.Config().AdditionalSymmetricKeyLabels)
}

// --- Test isClosed() is thread-safe ---

func TestNoiseListenerIsClosedThreadSafe(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Concurrent readers calling isClosed() while a writer calls Close()
	// should not deadlock or panic.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Call isClosed() repeatedly — this is the method that previously
			// had a misleading doc comment saying it was NOT thread-safe.
			for j := 0; j < 100; j++ {
				_ = noiseListener.isClosed()
			}
		}()
	}

	// Close from another goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		noiseListener.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success — no deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: isClosed() is not thread-safe")
	}
}

// --- Test concurrent Accept without acceptMutex serialization ---

func TestNoiseListenerConcurrentAccepts(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	const numAcceptors = 3
	const numConnections = 3

	// Spawn multiple concurrent acceptors
	accepted := make(chan net.Conn, numConnections)
	acceptErrs := make(chan error, numAcceptors)

	for i := 0; i < numAcceptors; i++ {
		go func() {
			conn, err := noiseListener.Accept()
			if err != nil {
				acceptErrs <- err
				return
			}
			accepted <- conn
		}()
	}

	// Give acceptors time to all block on Accept()
	time.Sleep(50 * time.Millisecond)

	// Connect clients
	listenAddr := noiseListener.Addr().(*conn.Addr).Underlying().String()
	for i := 0; i < numConnections; i++ {
		go func() {
			conn, err := net.Dial("tcp", listenAddr)
			if err == nil {
				defer conn.Close()
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}

	// Collect accepted connections
	var conns []net.Conn
	timeout := time.After(5 * time.Second)
	for i := 0; i < numConnections; i++ {
		select {
		case conn := <-accepted:
			conns = append(conns, conn)
		case <-timeout:
			// Some may not be accepted due to timing; that's fine
			break
		}
	}

	// Clean up
	noiseListener.Close()
	for _, c := range conns {
		c.Close()
	}

	// At least one concurrent accept should have succeeded
	assert.GreaterOrEqual(t, len(conns), 1,
		"at least one concurrent accept should succeed without acceptMutex serialization")
}

// mockShutdownManager is a minimal implementation of shutdown.Shutdowner for testing.
type mockShutdownManager struct {
	mu        sync.Mutex
	listeners map[*Listener]bool
	conns     map[interface{}]bool
}

func newMockShutdownManager() *mockShutdownManager {
	return &mockShutdownManager{
		listeners: make(map[*Listener]bool),
		conns:     make(map[interface{}]bool),
	}
}

func (m *mockShutdownManager) RegisterListener(l shutdown.ShutdownListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if nl, ok := l.(*Listener); ok {
		m.listeners[nl] = true
	}
}

func (m *mockShutdownManager) UnregisterListener(l shutdown.ShutdownListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if nl, ok := l.(*Listener); ok {
		delete(m.listeners, nl)
	}
}

func (m *mockShutdownManager) RegisterConnection(c shutdown.ShutdownConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conns[c] = true
}

func (m *mockShutdownManager) UnregisterConnection(c shutdown.ShutdownConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns, c)
}

func (m *mockShutdownManager) Shutdown() error {
	return nil
}

func (m *mockShutdownManager) isRegistered(l *Listener) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listeners[l]
}

// TestListenerSetShutdownManagerRace verifies that SetShutdownManager
// properly synchronizes with Close to prevent data races and avoid
// registering an already-closed listener in the shutdown manager.
// This test addresses the MEDIUM-severity finding.
func TestListenerSetShutdownManagerRace(t *testing.T) {
	// Test case 1: SetShutdownManager called after Close should not register
	t.Run("SetAfterClose", func(t *testing.T) {
		nl := newTestNoiseListenerFromTCP(t, "XX")
		sm := newMockShutdownManager()

		// Close the listener
		err := nl.Close()
		require.NoError(t, err)

		// Now attempt to set the shutdown manager
		nl.SetShutdownManager(sm)

		// Listener should NOT be registered since it was already closed
		assert.False(t, sm.isRegistered(nl), "closed listener should not be registered")
	})

	// Test case 2: Concurrent SetShutdownManager and Close should not race
	t.Run("ConcurrentSetAndClose", func(t *testing.T) {
		const iterations = 100
		for i := 0; i < iterations; i++ {
			nl := newTestNoiseListenerFromTCP(t, "XX")
			sm := newMockShutdownManager()

			var wg sync.WaitGroup
			wg.Add(2)

			// Goroutine 1: SetShutdownManager
			go func() {
				defer wg.Done()
				nl.SetShutdownManager(sm)
			}()

			// Goroutine 2: Close
			go func() {
				defer wg.Done()
				nl.Close()
			}()

			wg.Wait()

			// If the listener is registered, it should not be closed yet,
			// or if it is closed, it should have been unregistered.
			// The key is no data race (checked by -race flag).
		}
	})
}

// TestAccept_MaxConnections_ExposesHandshake verifies that when MaxConnections is
// configured, the semaphoreReleaseWrapper still exposes the Handshake() method and
// other Noise-specific methods through method promotion (HIGH-1 regression test).
func TestAccept_MaxConnections_ExposesHandshake(t *testing.T) {
	nl := newTestNoiseListenerFromTCP(t, "XX")
	// Enable connection limiting with a small limit to force wrapper usage
	nl.config.MaxConnections = 4
	t.Cleanup(func() { nl.Close() })

	// Create a client connection
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	// Mock the underlying listener to return our server end
	mockUnderlyingListener := &mockListener{
		addr: nl.underlying.Addr(),
		acceptFunc: func() (net.Conn, error) {
			return serverConn, nil
		},
	}

	// Replace the underlying listener temporarily
	oldUnderlying := nl.underlying
	nl.underlying = mockUnderlyingListener
	defer func() { nl.underlying = oldUnderlying }()

	// Accept a connection (should return semaphoreReleaseWrapper)
	acceptedConn, err := nl.Accept()
	require.NoError(t, err)
	require.NotNil(t, acceptedConn)
	t.Cleanup(func() { acceptedConn.Close() })

	// Verify that the returned connection exposes Handshake() method
	// through interface assertion (the method should be promoted by embedding *conn.Conn)
	handshaker, ok := acceptedConn.(interface{ Handshake(context.Context) error })
	require.True(t, ok, "accepted conn must expose Handshake() when MaxConnections>0")

	// Verify it also exposes GetConnectionState() for completeness
	stateGetter, ok := acceptedConn.(interface{ GetConnectionState() conn.ConnState })
	require.True(t, ok, "accepted conn must expose GetConnectionState() when MaxConnections>0")

	// Verify we can call the methods (they may fail due to mock setup, but should be callable)
	_ = handshaker
	_ = stateGetter
}
