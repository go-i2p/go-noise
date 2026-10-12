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

// Config-related tests (TestNewNTCP2Config, TestNewNTCP2ConfigInvalidRouterHash,
// TestNTCP2ConfigBuilder, TestNTCP2ConfigBuilderInvalidStaticKey,
// TestNTCP2ConfigValidation) live in config_test.go which covers all these
// scenarios comprehensively. See TestNewNTCP2ConfigWithInitiator,
// TestNTCP2ConfigBuilderMethods, TestNTCP2ConfigComprehensiveValidation, etc.

func TestNewNTCP2Listener(t *testing.T) {
	tl := newTestNTCP2Listener(t)

	assert.NotNil(t, tl.listener)
	assert.NotNil(t, tl.listener.Addr())
	assert.Equal(t, "ntcp2", tl.listener.Addr().Network())
}

func TestNewNTCP2ListenerErrors(t *testing.T) {
	routerHash := generateRandomHash()

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	tests := []struct {
		name          string
		listener      net.Listener
		config        *Config
		expectedError string
	}{
		{
			name:          "nil underlying listener",
			listener:      nil,
			config:        config,
			expectedError: "underlying listener cannot be nil",
		},
		{
			name: "nil config",
			listener: func() net.Listener {
				l, _ := net.Listen("tcp", "127.0.0.1:0")
				return l
			}(),
			config:        nil,
			expectedError: "ntcp2 config cannot be nil",
		},
		{
			name: "invalid config",
			listener: func() net.Listener {
				l, _ := net.Listen("tcp", "127.0.0.1:0")
				return l
			}(),
			config: func() *Config {
				c, _ := NewNTCP2Config(routerHash, false)
				// With data.Hash, BobRouterHash is always 32 bytes,
				// so we invalidate by clearing the pattern instead
				c.Pattern = ""
				return c
			}(),
			expectedError: "invalid ntcp2 listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := NewNTCP2Listener(tt.listener, tt.config)
			assert.Error(t, err)
			assert.Nil(t, listener)
			assert.Contains(t, err.Error(), tt.expectedError)

			// Clean up valid listeners
			if tt.listener != nil {
				tt.listener.Close()
			}
		})
	}
}

func TestNTCP2ListenerAddr(t *testing.T) {
	tl := newTestNTCP2Listener(t)

	addr := tl.listener.Addr()
	assert.NotNil(t, addr)
	assert.Equal(t, "ntcp2", addr.Network())

	// Should be NTCP2Addr
	ntcp2Addr, ok := addr.(*Addr)
	assert.True(t, ok)
	assert.Equal(t, tl.routerHash, ntcp2Addr.routerHash)
	assert.Equal(t, "responder", ntcp2Addr.role)
}

func TestNTCP2ListenerClose(t *testing.T) {
	tl := newTestNTCP2Listener(t)

	// Close should work
	err := tl.listener.Close()
	assert.NoError(t, err)

	// Second close should also work (idempotent)
	err = tl.listener.Close()
	assert.NoError(t, err)
}

func TestNTCP2ListenerAcceptAfterClose(t *testing.T) {
	tl := newTestNTCP2Listener(t)

	// Close the listener
	err := tl.listener.Close()
	require.NoError(t, err)

	// Accept should return error
	conn, err := tl.listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "ntcp2 listener is closed")
}

func TestNTCP2ListenerConcurrentClose(t *testing.T) {
	tl := newTestNTCP2Listener(t)

	// Test concurrent close operations
	var wg sync.WaitGroup
	closeCount := 10

	for i := 0; i < closeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tl.listener.Close()
		}()
	}

	wg.Wait()

	// Listener should be closed
	conn, err := tl.listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestFormatRouterHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     data.Hash
		expected string
	}{
		{
			name:     "valid hash",
			hash:     data.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			expected: "0102030405060708...",
		},
		{
			name:     "zero hash",
			hash:     data.Hash{},
			expected: "0000000000000000...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRouterHash(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Listener accept error-path tests
// ============================================================================

// errorListener is a net.Listener whose Accept always returns an error,
// simulating transient errors (e.g., EMFILE, network reset).
type errorListener struct {
	addr net.Addr
	err  error
}

func (e *errorListener) Accept() (net.Conn, error) { return nil, e.err }
func (e *errorListener) Close() error              { return nil }
func (e *errorListener) Addr() net.Addr            { return e.addr }

// TestNTCP2Listener_AcceptUnderlyingError verifies that a transient error
// from the underlying TCP listener is correctly propagated by Accept().
func TestNTCP2Listener_AcceptUnderlyingError(t *testing.T) {
	config := newTestResponderConfigNoAES(t)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := tcpLn.Addr()
	tcpLn.Close() // close the real one

	fakeErr := net.UnknownNetworkError("simulated EMFILE")
	el := &errorListener{addr: addr, err: fakeErr}

	ntcp2Ln, err := NewNTCP2Listener(el, config)
	require.NoError(t, err)
	defer ntcp2Ln.Close()

	conn, err := ntcp2Ln.Accept()
	assert.Nil(t, conn, "conn should be nil on underlying accept error")
	assert.Error(t, err, "accept should propagate underlying error")
	assert.Contains(t, err.Error(), "simulated EMFILE")
}

// TestNTCP2Listener_AcceptToConnConfigError verifies that if ToConnConfig()
// fails mid-accept (e.g., due to an invalid config mutation), the raw
// connection is closed and the error is propagated.
func TestNTCP2Listener_AcceptToConnConfigError(t *testing.T) {
	config := newTestResponderConfigNoAES(t)

	// Create a real listener so Accept() succeeds
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, config)

	// Corrupt the config's pattern so ToConnConfig() will fail during Accept.
	// The listener clones config on each accept, so we corrupt the source.
	ntcp2Ln.config.Pattern = "" // empty pattern → invalid

	// Dial to unblock Accept
	go func() {
		conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
		if err == nil {
			conn.Close()
		}
	}()

	conn, err := ntcp2Ln.Accept()
	assert.Nil(t, conn, "conn should be nil when ToConnConfig fails")
	assert.Error(t, err, "Accept should return error from createResponderConnConfig")
}
