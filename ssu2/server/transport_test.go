package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDialSSU2_ValidParams tests successful dial with valid parameters.
func TestDialSSU2_ValidParams(t *testing.T) {
	config := createValidInitiatorConfig(t)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	conn, err := DialSSU2(localAddr, remoteAddr, config)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Verify connection properties
	assert.NotNil(t, conn.LocalAddr())
	assert.NotNil(t, conn.RemoteAddr())
}

// TestDialSSU2_NilRemoteAddr tests dial fails with nil remote address.
func TestDialSSU2_NilRemoteAddr(t *testing.T) {
	config := createValidInitiatorConfig(t)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	conn, err := DialSSU2(localAddr, nil, config)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "remote address cannot be nil")
}

// TestDialSSU2_NilConfig tests dial fails with nil configuration.
func TestDialSSU2_NilConfig(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	conn, err := DialSSU2(localAddr, remoteAddr, nil)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestDialSSU2_InvalidInitiatorFlag tests dial fails when initiator flag is false.
func TestDialSSU2_InvalidInitiatorFlag(t *testing.T) {
	config := createValidResponderConfig(t)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	conn, err := DialSSU2(localAddr, remoteAddr, config)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "dial operations require initiator=true")
}

// TestDialSSU2_NilLocalAddr tests dial succeeds with nil local address (automatic binding).
func TestDialSSU2_NilLocalAddr(t *testing.T) {
	config := createValidInitiatorConfig(t)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	conn, err := DialSSU2(nil, remoteAddr, config)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Should have automatically assigned local address
	assert.NotNil(t, conn.LocalAddr())
}

// TestDialSSU2WithHandshake_ValidParams tests successful dial with handshake.
// Note: This test creates the connection but handshake will fail without a real server,
// which is expected behavior.
func TestDialSSU2WithHandshake_ValidParams(t *testing.T) {
	config := createValidInitiatorConfig(t)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// This will timeout or fail handshake since no server is listening
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn, err := DialSSU2WithHandshakeContext(ctx, localAddr, remoteAddr, config)

	// Expect error (no server listening)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "handshake")
}

// TestDialSSU2WithHandshake_ContextCancellation tests context cancellation during handshake.
func TestDialSSU2WithHandshake_ContextCancellation(t *testing.T) {
	config := createValidInitiatorConfig(t)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := DialSSU2WithHandshakeContext(ctx, localAddr, remoteAddr, config)

	// Expect error due to cancelled context
	assert.Error(t, err)
	assert.Nil(t, conn)
}

// TestDialSSU2WithHandshake_WithoutContext tests handshake without explicit context.
func TestDialSSU2WithHandshake_WithoutContext(t *testing.T) {
	config := createValidInitiatorConfig(t)
	// Use a short handshake timeout so the test completes quickly.
	// The default (15s) exceeds the test's wait window.
	config.WithHandshakeTimeout(2 * time.Second)
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Should use background context internally
	// Will timeout since no server is listening
	done := make(chan struct{})
	go func() {
		conn, err := DialSSU2WithHandshake(localAddr, remoteAddr, config)
		assert.Error(t, err)
		assert.Nil(t, conn)
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		// Expected to complete (with error)
	case <-time.After(10 * time.Second):
		t.Fatal("DialSSU2WithHandshake did not complete within timeout")
	}
}

// TestListenSSU2_ValidParams tests successful listener creation.
func TestListenSSU2_ValidParams(t *testing.T) {
	config := createValidResponderConfig(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	listener, err := ListenSSU2(addr, config)
	require.NoError(t, err)
	require.NotNil(t, listener)
	defer listener.Close()

	// Verify listener properties
	assert.NotNil(t, listener.Addr())
}

// TestListenSSU2_NilAddr tests listener creation fails with nil address.
func TestListenSSU2_NilAddr(t *testing.T) {
	config := createValidResponderConfig(t)

	listener, err := ListenSSU2(nil, config)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "listen address cannot be nil")
}

// TestListenSSU2_NilConfig tests listener creation fails with nil configuration.
func TestListenSSU2_NilConfig(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	listener, err := ListenSSU2(addr, nil)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestListenSSU2_InvalidInitiatorFlag tests listener creation fails when initiator flag is true.
func TestListenSSU2_InvalidInitiatorFlag(t *testing.T) {
	config := createValidInitiatorConfig(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	listener, err := ListenSSU2(addr, config)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "listen operations require initiator=false")
}

// TestListenSSU2_AddressInUse tests listener creation fails when address is already bound.
func TestListenSSU2_AddressInUse(t *testing.T) {
	config1 := createValidResponderConfig(t)
	config2 := createValidResponderConfig(t)

	// Create first listener
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener1, err := ListenSSU2(addr, config1)
	require.NoError(t, err)
	require.NotNil(t, listener1)
	defer listener1.Close()

	// Get the bound address
	listener1Addr := listener1.Addr().(*SSU2Addr).UnderlyingAddr()
	boundAddr, ok := listener1Addr.(*net.UDPAddr)
	require.True(t, ok, "Expected underlying addr to be *net.UDPAddr")

	// Try to create second listener on same address
	listener2, err := ListenSSU2(boundAddr, config2)
	assert.Error(t, err)
	assert.Nil(t, listener2)
	assert.Contains(t, err.Error(), "address already in use")
}

// TestWrapSSU2Conn_ValidParams tests successful connection wrapping.
func TestWrapSSU2Conn_ValidParams(t *testing.T) {
	config := createValidInitiatorConfig(t)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	// Wrap it
	conn, err := WrapSSU2Conn(underlying, remoteAddr, config)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Verify connection properties
	assert.NotNil(t, conn.LocalAddr())
	assert.NotNil(t, conn.RemoteAddr())
}

// TestWrapSSU2Conn_NilUnderlying tests wrapping fails with nil underlying connection.
func TestWrapSSU2Conn_NilUnderlying(t *testing.T) {
	config := createValidInitiatorConfig(t)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	conn, err := WrapSSU2Conn(nil, remoteAddr, config)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "underlying packet connection cannot be nil")
}

// TestWrapSSU2Conn_NilRemoteAddr tests wrapping fails with nil remote address.
func TestWrapSSU2Conn_NilRemoteAddr(t *testing.T) {
	config := createValidInitiatorConfig(t)

	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	conn, err := WrapSSU2Conn(underlying, nil, config)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "remote address cannot be nil")
}

// TestWrapSSU2Conn_NilConfig tests wrapping fails with nil configuration.
func TestWrapSSU2Conn_NilConfig(t *testing.T) {
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	conn, err := WrapSSU2Conn(underlying, remoteAddr, nil)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestWrapSSU2Listener_ValidParams tests successful listener wrapping.
func TestWrapSSU2Listener_ValidParams(t *testing.T) {
	config := createValidResponderConfig(t)

	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	// Wrap it
	listener, err := WrapSSU2Listener(underlying, config)
	require.NoError(t, err)
	require.NotNil(t, listener)
	defer listener.Close()

	// Verify listener properties
	assert.NotNil(t, listener.Addr())
}

// TestWrapSSU2Listener_NilUnderlying tests wrapping fails with nil underlying connection.
func TestWrapSSU2Listener_NilUnderlying(t *testing.T) {
	config := createValidResponderConfig(t)

	listener, err := WrapSSU2Listener(nil, config)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "underlying packet connection cannot be nil")
}

// TestWrapSSU2Listener_NilConfig tests wrapping fails with nil configuration.
func TestWrapSSU2Listener_NilConfig(t *testing.T) {
	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	listener, err := WrapSSU2Listener(underlying, nil)
	assert.Error(t, err)
	assert.Nil(t, listener)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestWrapSSU2Listener_StartManually tests that wrapped listener doesn't auto-start.
func TestWrapSSU2Listener_StartManually(t *testing.T) {
	config := createValidResponderConfig(t)

	// Create underlying PacketConn
	underlying, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer underlying.Close()

	// Wrap it (does not auto-start)
	listener, err := WrapSSU2Listener(underlying, config)
	require.NoError(t, err)
	require.NotNil(t, listener)
	defer listener.Close()

	// Start manually
	err = listener.Start()
	assert.NoError(t, err)
}

// TestValidateDialParams tests parameter validation for dial operations.
func TestValidateDialParams(t *testing.T) {
	tests := []struct {
		name        string
		localAddr   *net.UDPAddr
		remoteAddr  *net.UDPAddr
		config      *SSU2Config
		expectError string
	}{
		{
			name:        "nil remote address",
			localAddr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:  nil,
			config:      createValidInitiatorConfig(t),
			expectError: "remote address cannot be nil",
		},
		{
			name:        "nil config",
			localAddr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			config:      nil,
			expectError: "config cannot be nil",
		},
		{
			name:        "responder config for dial",
			localAddr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			config:      createValidResponderConfig(t),
			expectError: "dial operations require initiator=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDialParams(tt.localAddr, tt.remoteAddr, tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateListenParams tests parameter validation for listen operations.
func TestValidateListenParams(t *testing.T) {
	tests := []struct {
		name        string
		addr        *net.UDPAddr
		config      *SSU2Config
		expectError string
	}{
		{
			name:        "nil address",
			addr:        nil,
			config:      createValidResponderConfig(t),
			expectError: "listen address cannot be nil",
		},
		{
			name:        "nil config",
			addr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			config:      nil,
			expectError: "config cannot be nil",
		},
		{
			name:        "initiator config for listen",
			addr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			config:      createValidInitiatorConfig(t),
			expectError: "listen operations require initiator=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListenParams(tt.addr, tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConcurrentDial tests concurrent dial operations don't interfere.
func TestConcurrentDial(t *testing.T) {
	const numDials = 10
	done := make(chan struct{}, numDials)
	errors := make(chan error, numDials)

	for i := 0; i < numDials; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()

			config := createValidInitiatorConfig(t)
			localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
			remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345 + id}

			conn, err := DialSSU2(localAddr, remoteAddr, config)
			if err != nil {
				errors <- err
				return
			}
			conn.Close()
		}(i)
	}

	// Wait for all dials to complete
	for i := 0; i < numDials; i++ {
		<-done
	}
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent dial failed: %v", err)
	}
}

// Helper function to create a valid initiator configuration.
func createValidInitiatorConfig(t *testing.T) *SSU2Config {
	staticKey := make([]byte, 32)
	remoteStaticKey := make([]byte, 32)
	remoteRouterHash := generateRandomHash()
	routerHash := generateRandomHash()

	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)
	config.DestroyTimeout = 0 // Skip destroy wait in tests
	config.WithStaticKey(staticKey).WithRemoteRouterHash(remoteRouterHash).WithRemoteStaticKey(remoteStaticKey)
	return config
}

func createValidResponderConfig(t *testing.T) *SSU2Config {
	staticKey := make([]byte, 32)
	routerHash := generateRandomHash()

	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	config.DestroyTimeout = 0 // Skip destroy wait in tests
	config.RouterInfoValidator = DefaultRouterInfoValidator
	config.WithStaticKey(staticKey)
	return config
}

// TestAddressValidation_BoundaryConditions tests edge cases in address validation.
// AUDIT 7.2 — Address validation for dial/listen.
func TestAddressValidation_BoundaryConditions(t *testing.T) {
	remoteRouterHash := generateRandomHash()

	tests := []struct {
		name            string
		localAddr       *net.UDPAddr
		remoteAddr      *net.UDPAddr
		allowLoopback   bool
		expectDialErr   bool
		expectListenErr bool
		description     string
	}{
		// Port 0 — ephemeral port semantics
		{
			name:          "dial_remote_port_0_rejected",
			localAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			allowLoopback: true,
			expectDialErr: true,
			description:   "dial remote with port 0 must be rejected (not an ephemeral source)",
		},
		{
			name:            "listen_port_0_allowed",
			localAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:      nil,
			allowLoopback:   true,
			expectListenErr: false,
			description:     "listen with port 0 allowed (OS-selected ephemeral port)",
		},

		// Reserved ports 1-1023
		{
			name:          "dial_reserved_port_rejected",
			localAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, // SSH port
			allowLoopback: true,
			expectDialErr: true,
			description:   "dial remote with reserved port 22 must be rejected",
		},
		{
			name:            "listen_reserved_port_rejected",
			localAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}, // SMTP port
			remoteAddr:      nil,
			allowLoopback:   true,
			expectListenErr: true,
			description:     "listen on reserved port 25 must be rejected",
		},

		// Loopback with AllowLoopback=false
		{
			name:          "dial_loopback_without_allowloopback",
			localAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			allowLoopback: false,
			expectDialErr: true,
			description:   "dial to loopback without AllowLoopback must be rejected",
		},
		{
			name:            "listen_loopback_without_allowloopback",
			localAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			remoteAddr:      nil,
			allowLoopback:   false,
			expectListenErr: true,
			description:     "listen on loopback without AllowLoopback must be rejected",
		},

		// IPv6 loopback
		{
			name:          "dial_ipv6_loopback_without_allowloopback",
			localAddr:     &net.UDPAddr{IP: net.IPv6loopback, Port: 0},
			remoteAddr:    &net.UDPAddr{IP: net.IPv6loopback, Port: 12345},
			allowLoopback: false,
			expectDialErr: true,
			description:   "dial to IPv6 loopback without AllowLoopback must be rejected",
		},
		{
			name:            "listen_ipv6_loopback_without_allowloopback",
			localAddr:       &net.UDPAddr{IP: net.IPv6loopback, Port: 0},
			remoteAddr:      nil,
			allowLoopback:   false,
			expectListenErr: true,
			description:     "listen on IPv6 loopback without AllowLoopback must be rejected",
		},

		// Valid non-loopback addresses
		{
			name:          "dial_valid_nonloopback",
			localAddr:     &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0},
			remoteAddr:    &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}, // TEST-NET-1
			allowLoopback: false,
			expectDialErr: false,
			description:   "dial to valid non-loopback address should succeed",
		},
		{
			name:            "listen_valid_nonloopback",
			localAddr:       &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0},
			remoteAddr:      nil,
			allowLoopback:   false,
			expectListenErr: false,
			description:     "listen on valid non-loopback address should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a config with the appropriate AllowLoopback setting
			testConfig := createValidInitiatorConfig(t)
			testConfig.AllowLoopback = tt.allowLoopback
			testConfig.WithRemoteRouterHash(remoteRouterHash)

			if tt.expectDialErr {
				// Test dial validation
				err := validateDialParams(tt.localAddr, tt.remoteAddr, testConfig)
				assert.Error(t, err, "Expected dial validation to fail: %s", tt.description)
				t.Logf("✓ %s: %v", tt.description, err)
			} else if tt.remoteAddr != nil {
				// Test dial validation succeeds
				err := validateDialParams(tt.localAddr, tt.remoteAddr, testConfig)
				assert.NoError(t, err, "Expected dial validation to succeed: %s", tt.description)
				t.Logf("✓ %s: dial validation passed", tt.description)
			}

			if tt.expectListenErr {
				// Test listen validation
				responderConfig := createValidResponderConfig(t)
				responderConfig.AllowLoopback = tt.allowLoopback
				err := validateListenParams(tt.localAddr, responderConfig)
				assert.Error(t, err, "Expected listen validation to fail: %s", tt.description)
				t.Logf("✓ %s: %v", tt.description, err)
			} else if tt.remoteAddr == nil {
				// Test listen validation succeeds
				responderConfig := createValidResponderConfig(t)
				responderConfig.AllowLoopback = tt.allowLoopback
				err := validateListenParams(tt.localAddr, responderConfig)
				assert.NoError(t, err, "Expected listen validation to succeed: %s", tt.description)
				t.Logf("✓ %s: listen validation passed", tt.description)
			}
		})
	}
}
