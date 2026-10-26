package noise

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockShutdownListener is a minimal net.Listener for shutdown_test.go.
type mockShutdownListener struct {
	addr net.Addr
}

func (m *mockShutdownListener) Accept() (net.Conn, error) {
	// Block until closed; unused in shutdown tests.
	select {}
}
func (m *mockShutdownListener) Close() error   { return nil }
func (m *mockShutdownListener) Addr() net.Addr { return m.addr }

func TestNewShutdownManager(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "with custom timeout",
			timeout:         10 * time.Second,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "with zero timeout uses default",
			timeout:         0,
			expectedTimeout: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewShutdownManager(tt.timeout)

			assert.NotNil(t, sm)
			assert.Equal(t, tt.expectedTimeout, sm.Timeout())
			assert.NotNil(t, sm.Context())
		})
	}
}

func TestShutdownManagerContext(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	ctx := sm.Context()
	assert.NotNil(t, ctx)

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled initially")
	default:
		// expected
	}

	// Start shutdown
	go func() {
		sm.Shutdown()
	}()

	// Context should be cancelled after shutdown
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("context should be cancelled after shutdown")
	}
}

// TestTransportGracefulShutdown verifies that shutting a Transport down shuts
// down its own shutdown manager and closes its own pool. Each Transport owns
// these components; there is no package-level shutdown state.
func TestTransportGracefulShutdown(t *testing.T) {
	sm := NewShutdownManager(10 * time.Second)
	cp := pool.NewConnPool(&pool.PoolConfig{MaxSize: 4})

	transport := NewTransport(cp, sm)

	require.NoError(t, transport.GracefulShutdown())

	// The pool must be closed by the transport shutdown.
	assert.Nil(t, cp.Get("127.0.0.1:1"), "pool should be closed after GracefulShutdown")

	// A second shutdown must not panic on the already-closed components.
	assert.NoError(t, transport.GracefulShutdown())
}

// shutdownRegistrationTest verifies the shutdown registration lifecycle:
// SetShutdownManager → assert registered → Close → assert deregistered.
func shutdownRegistrationTest(t *testing.T, sm *ShutdownManager, resource interface {
	SetShutdownManager(Shutdowner)
	Close() error
},
) {
	t.Helper()
	resource.SetShutdownManager(sm)
	assertShutdownRegistered(t, sm, resource, true)

	err := resource.Close()
	assert.NoError(t, err)
	assertShutdownRegistered(t, sm, resource, false)
}

func TestNoiseConnShutdownManagerIntegration(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	mockConn, peerConn := net.Pipe()
	defer peerConn.Close()
	config := NewConnConfig("NN", true)
	noiseConn, err := NewNoiseConn(mockConn, config)
	require.NoError(t, err)

	shutdownRegistrationTest(t, sm, noiseConn)
}

func TestNoiseListenerShutdownManagerIntegration(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	ml := &mockShutdownListener{
		addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}
	config := NewListenerConfig("NN")
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)

	shutdownRegistrationTest(t, sm, noiseListener)
}

// assertShutdownRegistered checks whether a resource (conn or listener) is
// present in (or absent from) the shutdown manager's tracked set.
// Direct map lookup is used because the tracked sets use interface key types
// (ShutdownConn / ShutdownListener), which allows assert.Contains to behave
// unpredictably when the element is a concrete pointer type.
func assertShutdownRegistered(t *testing.T, sm *ShutdownManager, resource interface{}, expected bool) {
	t.Helper()
	switch v := resource.(type) {
	case *NoiseConn:
		found := sm.ConnectionRegistered(v)
		if expected {
			assert.True(t, found, "expected connection to be registered in ShutdownManager")
		} else {
			assert.False(t, found, "expected connection to not be registered in ShutdownManager")
		}
	case *NoiseListener:
		found := sm.ListenerRegistered(v)
		if expected {
			assert.True(t, found, "expected listener to be registered in ShutdownManager")
		} else {
			assert.False(t, found, "expected listener to not be registered in ShutdownManager")
		}
	default:
		t.Fatalf("unsupported resource type: %T", resource)
	}
}
