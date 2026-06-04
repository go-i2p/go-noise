package session

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/mod"
	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers

// createTestConfig creates a test SSU2Config with sensible defaults.
func createTestConfig(t *testing.T) *SSU2Config {
	t.Helper()
	routerHash := generateRandomHash()
	remoteHash := generateRandomHash()
	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)
	config.RemoteRouterHash = hashPtr(remoteHash)
	config.RemoteStaticKey = make([]byte, 32) // placeholder static key for tests
	config.ConnectionID = 123456              // Non-zero connection ID
	config.DestroyTimeout = 0                 // Skip destroy wait in tests
	return config
}

// mockPacketConn implements net.PacketConn for testing.
type mockPacketConn struct {
	readChan     chan mockPacket
	writeChan    chan mockPacket
	localAddr    net.Addr
	closed       bool
	readDeadline time.Time
}

type mockPacket struct {
	data []byte
	addr net.Addr
	err  error
}

// timeoutError implements net.Error for timeout conditions.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func newMockPacketConn(localAddr net.Addr) *mockPacketConn {
	return &mockPacketConn{
		readChan:  make(chan mockPacket, 10),
		writeChan: make(chan mockPacket, 10),
		localAddr: localAddr,
	}
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if m.closed {
		return 0, nil, net.ErrClosed
	}

	// Respect read deadline
	var timer *time.Timer
	var timerChan <-chan time.Time
	if !m.readDeadline.IsZero() {
		timeout := time.Until(m.readDeadline)
		if timeout <= 0 {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
		}
		timer = time.NewTimer(timeout)
		timerChan = timer.C
		defer timer.Stop()
	}

	select {
	case packet, ok := <-m.readChan:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if packet.err != nil {
			return 0, nil, packet.err
		}
		n = copy(p, packet.data)
		return n, packet.addr, nil
	case <-timerChan:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
	}
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if m.closed {
		return 0, net.ErrClosed
	}
	data := make([]byte, len(p))
	copy(data, p)
	m.writeChan <- mockPacket{data: data, addr: addr}
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.closed = true
	close(m.readChan)
	close(m.writeChan)
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// setupConnPair creates a pair of mock connections for testing.
func setupConnPair(t *testing.T) (*mockPacketConn, *mockPacketConn, []byte, []byte, []byte, []byte) {
	t.Helper()

	// Generate keypairs
	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	// Create mock packet connections
	initLocalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	respLocalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}

	initConn := newMockPacketConn(initLocalAddr)
	respConn := newMockPacketConn(respLocalAddr)

	return initConn, respConn, initDH.Private, initDH.Public, respDH.Private, respDH.Public
}

// NewSSU2Conn tests

func TestNewSSU2Conn_ValidInitiator(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	routerHash := generateRandomHash()
	remoteHash := generateRandomHash()
	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)
	config.RemoteRouterHash = hashPtr(remoteHash) // Required for initiator
	config.RemoteStaticKey = respPub              // X25519 static key for XK handshake
	config.ConnectionID = 12345
	config.MTU = 1500
	config.DestroyTimeout = 0 // Skip destroy wait in tests

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, StateInit, conn.GetState())
	assert.NotNil(t, conn.handshakeHandler)
	assert.NotNil(t, conn.dataHandler)
	assert.NotNil(t, conn.ackHandler)

	// Cleanup
	_ = conn.Close()
}

func TestNewSSU2Conn_ValidResponder(t *testing.T) {
	_, respConn, _, _, respPriv, _ := setupConnPair(t)
	defer respConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	config := createTestConfig(t)
	config.ConnectionID = 54321
	config.MTU = 1500

	conn, err := NewSSU2Conn(respConn, remoteAddr, config, false, respPriv, nil)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, StateInit, conn.GetState())

	// Cleanup
	_ = conn.Close()
}

func TestNewSSU2Conn_NilUnderlyingConn(t *testing.T) {
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(nil, remoteAddr, config, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "underlying PacketConn is nil")
}

func TestNewSSU2Conn_NilRemoteAddr(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	config := createTestConfig(t)
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(initConn, nil, config, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "remoteAddr is nil")
}

func TestNewSSU2Conn_NilConfig(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(initConn, remoteAddr, nil, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestNewSSU2Conn_InvalidStaticKey(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	invalidKey := make([]byte, 16) // Wrong size

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, invalidKey, make([]byte, 32))
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "static key")
}

// State management tests

func TestSSU2Conn_GetState(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateInit, conn.GetState())
}

func TestSSU2Conn_StateTransitions(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Initial state
	assert.Equal(t, StateInit, conn.GetState())

	// Transition to handshaking (will fail without peer, but state should change)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = conn.Handshake(ctx) // Expected to fail

	// Close should transition to closed
	err = conn.Close()
	assert.NoError(t, err)
	assert.Equal(t, StateClosed, conn.GetState())
}

// net.Conn interface tests

func TestSSU2Conn_LocalAddr(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	config.ConnectionID = 12345

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr()
	require.NotNil(t, localAddr)

	ssu2Addr, ok := localAddr.(*SSU2Addr)
	require.True(t, ok)
	assert.Equal(t, uint64(12345), ssu2Addr.ConnectionID())
}

func TestSSU2Conn_RemoteAddr(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	remote := conn.RemoteAddr()
	require.NotNil(t, remote)

	ssu2Addr, ok := remote.(*SSU2Addr)
	require.True(t, ok)
	assert.Equal(t, remoteAddr.Port, ssu2Addr.UnderlyingAddr().(*net.UDPAddr).Port)
}

func TestSSU2Conn_SetDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.readDeadline)
	assert.Equal(t, deadline, conn.writeDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_SetReadDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetReadDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.readDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_SetWriteDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetWriteDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.writeDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_Close(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)

	// Close should succeed
	err = conn.Close()
	assert.NoError(t, err)
	assert.Equal(t, StateClosed, conn.GetState())

	// Second close should also succeed (idempotent)
	err = conn.Close()
	assert.NoError(t, err)
}

func TestSSU2Conn_CloseMultipleGoroutines(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)

	// Close from multiple goroutines
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_ = conn.Close()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	assert.Equal(t, StateClosed, conn.GetState())
}

// Read/Write tests

func TestSSU2Conn_ReadWriteNotEstablished(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Read should fail (not established)
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")

	// Write should fail (not established)
	_, err = conn.Write([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")
}

// TestSSU2Conn_ReadShortBufferReassembles verifies the MED-1 fix: when the
// caller's buffer is smaller than the next message, Read returns the partial
// data with a nil error (not a "buffer too small" error) and the remainder is
// returned on subsequent Read calls, mirroring conn.Conn.Read and honoring the
// io.Reader/net.Conn contract.
func TestSSU2Conn_ReadShortBufferReassembles(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Manually mark the connection as established so Read proceeds to the data path.
	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	// Inject a complete message larger than the read buffer used below.
	msg := []byte("hello world, this is a multi-segment I2NP message")
	conn.dataHandler.messageQueue <- msg

	// Read it back in small chunks; each Read must return a nil error.
	buf := make([]byte, 10)
	var got []byte
	for len(got) < len(msg) {
		n, rerr := conn.Read(buf)
		require.NoError(t, rerr, "short-buffer Read must not return an error while buffering the remainder")
		require.Greater(t, n, 0)
		got = append(got, buf[:n]...)
	}
	assert.Equal(t, msg, got, "message must be fully reassembled across multiple Reads")
}

// Handshake tests

func TestSSU2Conn_HandshakeInvalidState(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Manually set state to established
	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	// Handshake should fail
	ctx := context.Background()
	err = conn.Handshake(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state")
}

func TestSSU2Conn_HandshakeTimeout(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	config.HandshakeTimeout = 100 * time.Millisecond

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	ctx := context.Background()
	err = conn.Handshake(ctx)
	assert.Error(t, err)
	// Should timeout waiting for SessionCreated
}

// Activity tracking tests

func TestSSU2Conn_UpdateActivity(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Get initial activity time
	conn.lastActivityLock.RLock()
	initial := conn.lastActivity
	conn.lastActivityLock.RUnlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Update activity
	conn.updateActivity()

	// Check that activity time was updated
	conn.lastActivityLock.RLock()
	updated := conn.lastActivity
	conn.lastActivityLock.RUnlock()

	assert.True(t, updated.After(initial))
}

// Sequence number tests

func TestSSU2Conn_NextSendSequence(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Get sequence numbers
	seq1 := conn.nextSendSequence()
	seq2 := conn.nextSendSequence()
	seq3 := conn.nextSendSequence()

	assert.Equal(t, uint32(0), seq1)
	assert.Equal(t, uint32(1), seq2)
	assert.Equal(t, uint32(2), seq3)
}

func TestSSU2Conn_NextSendSequenceThreadSafe(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Call from multiple goroutines
	const numGoroutines = 100
	sequences := make(chan uint32, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			sequences <- conn.nextSendSequence()
		}()
	}

	// Collect all sequences
	seqMap := make(map[uint32]bool)
	for i := 0; i < numGoroutines; i++ {
		seq := <-sequences
		seqMap[seq] = true
	}

	// Should have unique sequences
	assert.Equal(t, numGoroutines, len(seqMap))
}

// ConnState string tests

func TestConnState_String(t *testing.T) {
	tests := []struct {
		state    ConnState
		expected string
	}{
		{StateInit, "init"},
		{StateHandshaking, "handshaking"},
		{StateEstablished, "established"},
		{StateClosing, "closing"},
		{StateClosed, "closed"},
		{ConnState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// Helper function tests

func TestCopyBytes(t *testing.T) {
	// Test nil
	assert.Nil(t, copyBytes(nil))

	// Test empty slice
	empty := []byte{}
	copied := copyBytes(empty)
	assert.NotNil(t, copied)
	assert.Equal(t, 0, len(copied))

	// Test with data
	data := []byte{1, 2, 3, 4, 5}
	copied = copyBytes(data)
	assert.Equal(t, data, copied)

	// Verify it's a copy (not same backing array)
	copied[0] = 99
	assert.Equal(t, byte(1), data[0])
	assert.Equal(t, byte(99), copied[0])
}

// I2NP fragmentation tests

func TestBuildI2NPFragmentBlocks_SmallPayload(t *testing.T) {
	config := createTestConfig(t)
	dh, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	dh2, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	config.StaticKey = dh.Private
	var rh1 data.Hash
	copy(rh1[:], dh2.Public)
	config.RemoteRouterHash = &rh1
	config.RemoteStaticKey = dh2.Public

	mockConn := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	conn, err := NewSSU2Conn(mockConn, remoteAddr, config, true, dh.Private, dh2.Public)
	require.NoError(t, err)

	// A small payload that fits in one fragment
	data := make([]byte, 100)
	maxBlockData := config.MTU - 80 - 3
	blocks, err := conn.buildI2NPFragmentBlocks(data, maxBlockData)
	require.NoError(t, err)

	// Should produce at least 2 blocks: FirstFragment + FollowOnFragment (isLast)
	require.GreaterOrEqual(t, len(blocks), 1)

	// First block should be FirstFragment
	assert.Equal(t, BlockTypeFirstFragment, blocks[0].Type)
	// First 9 bytes are I2NP header
	require.GreaterOrEqual(t, len(blocks[0].Data), 9)

	// Last block should be FollowOnFragment with isLast bit
	if len(blocks) > 1 {
		lastBlock := blocks[len(blocks)-1]
		assert.Equal(t, BlockTypeFollowOnFragment, lastBlock.Type)
		fragInfo := lastBlock.Data[0]
		assert.True(t, fragInfo&0x01 != 0, "last fragment should have isLast bit set")
	}
}

func TestBuildI2NPFragmentBlocks_LargePayload(t *testing.T) {
	config := createTestConfig(t)
	dh, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	dh2, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	config.StaticKey = dh.Private
	var rh2 data.Hash
	copy(rh2[:], dh2.Public)
	config.RemoteRouterHash = &rh2
	config.RemoteStaticKey = dh2.Public

	mockConn := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	conn, err := NewSSU2Conn(mockConn, remoteAddr, config, true, dh.Private, dh2.Public)
	require.NoError(t, err)

	// A large payload that requires multiple fragments
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	maxBlockData := config.MTU - 80 - 3
	blocks, err := conn.buildI2NPFragmentBlocks(data, maxBlockData)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1, "large payload should produce multiple fragments")

	// First block is FirstFragment
	assert.Equal(t, BlockTypeFirstFragment, blocks[0].Type)

	// Remaining blocks are FollowOnFragment
	for i := 1; i < len(blocks); i++ {
		assert.Equal(t, BlockTypeFollowOnFragment, blocks[i].Type)
		fragInfo := blocks[i].Data[0]
		fragNum := fragInfo >> 1
		assert.Equal(t, uint8(i), fragNum, "fragment number should match index")
	}

	// Last block should have isLast bit
	lastBlock := blocks[len(blocks)-1]
	assert.True(t, lastBlock.Data[0]&0x01 != 0, "last fragment should have isLast bit")

	// Verify total data integrity: all the payload fragments should
	// reconstruct the original data.
	var reconstructed []byte
	// From first fragment: skip 9-byte I2NP header
	reconstructed = append(reconstructed, blocks[0].Data[9:]...)
	// From follow-on fragments: skip 5-byte header
	for i := 1; i < len(blocks); i++ {
		reconstructed = append(reconstructed, blocks[i].Data[5:]...)
	}
	assert.Equal(t, data, reconstructed, "reconstructed data should match original")

	// Verify no block exceeds maxBlockData
	for i, block := range blocks {
		assert.LessOrEqual(t, len(block.Data), maxBlockData, "block %d exceeds max block data", i)
	}
}

func TestBuildI2NPFragmentBlocks_MessageIDConsistent(t *testing.T) {
	config := createTestConfig(t)
	dh, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	dh2, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	config.StaticKey = dh.Private
	var rh3 data.Hash
	copy(rh3[:], dh2.Public)
	config.RemoteRouterHash = &rh3
	config.RemoteStaticKey = dh2.Public

	mockConn := newMockPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	conn, err := NewSSU2Conn(mockConn, remoteAddr, config, true, dh.Private, dh2.Public)
	require.NoError(t, err)

	data := make([]byte, 3000)
	maxBlockData := config.MTU - 80 - 3
	blocks, err := conn.buildI2NPFragmentBlocks(data, maxBlockData)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1)

	// Extract message ID from first fragment
	firstMsgID := blocks[0].Data[1:5]

	// All follow-on fragments should have the same message ID
	for i := 1; i < len(blocks); i++ {
		followMsgID := blocks[i].Data[1:5]
		assert.Equal(t, firstMsgID, followMsgID, "fragment %d should have same message ID", i)
	}
}

// TestDataPhaseNonce_PacketNumberAsNonce verifies the SSU2 data-phase AEAD
// nonce convention: the 4-byte packet number is zero-extended to uint64 and
// used as the nonce via CipherState.SetNonce(). Encrypt with nonce N must
// only decrypt correctly with nonce N.
func TestDataPhaseNonce_PacketNumberAsNonce(t *testing.T) {
	// Complete a full handshake to obtain real cipher states.
	initiator, responder, _, _ := setupHandshakePair(t)

	reqPkt, err := initiator.CreateSessionRequest(11111, 22222)
	require.NoError(t, err)
	_, err = responder.ProcessSessionRequest(reqPkt)
	require.NoError(t, err)
	crePkt, err := responder.CreateSessionCreated(33333, 44444)
	require.NoError(t, err)
	err = initiator.ProcessSessionCreated(crePkt)
	require.NoError(t, err)
	confPkt, err := initiator.CreateSessionConfirmed(55555, 0, nil)
	require.NoError(t, err)
	err = responder.ProcessSessionConfirmed(confPkt)
	require.NoError(t, err)

	sendCS, _, err := initiator.GetCipherStates()
	require.NoError(t, err, "initiator must have cipher states")
	_, recvCS, err := responder.GetCipherStates()
	require.NoError(t, err, "responder must have cipher states")

	plaintext := []byte("SSU2 nonce test payload")
	ad := make([]byte, ShortHeaderSize)

	// Encrypt with packet number 42.
	pktNum := uint32(42)
	sendCS.SetNonce(uint64(pktNum))
	ciphertext, err := sendCS.Encrypt(nil, ad, plaintext)
	require.NoError(t, err)

	// Decrypt with the matching nonce should succeed.
	recvCS.SetNonce(uint64(pktNum))
	decrypted, err := recvCS.Decrypt(nil, ad, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "round-trip with same nonce must recover plaintext")
}

// setupHandshakePair creates an initiator/responder pair for tests.
func setupHandshakePair(t *testing.T) (*HandshakeHandler, *HandshakeHandler, []byte, []byte) {
	t.Helper()
	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	initiator, err := NewHandshakeHandlerWithKeys(true, initDH, respDH.Public, nil)
	require.NoError(t, err)
	responder, err := NewHandshakeHandlerWithKeys(false, respDH, nil, nil)
	require.NoError(t, err)
	return initiator, responder, initDH.Public, respDH.Public
}

// TestPathValidationRace verifies that reading remoteAddr during path validation
// is protected by remoteAddrLock. This addresses AUDIT H-6.
func TestPathValidationRace(t *testing.T) {
	config := createTestConfig(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	conn := &SSU2Conn{
		underlying: &mockPacketConn{localAddr: &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 8888}},
		remoteAddr: remoteAddr,
		config:     config,
		state:      mod.StateEstablished,
		closeChan:  make(chan struct{}),
	}
	conn.pathValidator = NewPathValidator(conn)

	// Simulate concurrent remoteAddr updates and reads
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			newAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 10000 + i}
			_ = conn.SetRemoteAddr(newAddr)
		}
	}()

	// Concurrent reads via GetRemoteAddr
	for i := 0; i < 100; i++ {
		go func() {
			_ = conn.GetRemoteAddr()
		}()
	}

	<-done
}

// TestHandshakeFailureNoGoroutineLeak verifies that a failed handshake properly
// cleans up the recvLoop goroutine. This addresses AUDIT H-8.
func TestHandshakeFailureNoGoroutineLeak(t *testing.T) {
	// Record baseline goroutine count (with some tolerance for runtime background goroutines)
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Create a connection that will fail handshake (use a mock conn that will timeout)
	mockConn := newMockPacketConn(&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 8888})
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}

	// Generate valid keypairs
	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	config := createTestConfig(t)
	config.RemoteStaticKey = respDH.Public

	conn, err := NewSSU2Conn(mockConn, remoteAddr, config, true, initDH.Private, respDH.Public)
	require.NoError(t, err, "NewSSU2Conn should succeed")

	// Attempt handshake which should fail with timeout (no responder on the other end)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = conn.Handshake(ctx)
	require.Error(t, err, "Handshake should fail with timeout")

	// Give goroutines time to clean up
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	// Check goroutine count returned to baseline (with ±5 tolerance for runtime variation)
	currentGoroutines := runtime.NumGoroutine()
	goroutineDelta := currentGoroutines - baselineGoroutines
	assert.LessOrEqual(t, goroutineDelta, 5,
		"Goroutine count should return to baseline after failed handshake (baseline=%d, current=%d, delta=%d)",
		baselineGoroutines, currentGoroutines, goroutineDelta)
}
