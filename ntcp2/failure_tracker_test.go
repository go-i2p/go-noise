package ntcp2

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock drives the tracker's window deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestTracker(threshold int, window time.Duration) (*inMemoryFailureTracker, *fakeClock) {
	clock := &fakeClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	tracker := NewFailureTracker(FailureTrackerConfig{
		Threshold: threshold,
		Window:    window,
		Now:       clock.Now,
	})
	return tracker, clock
}

func addr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// TestFailureTracker_ThresholdIsPerSource covers ntcp2.md §"AEAD Error Handling":
// "Bob should maintain a blacklist of IPs with repeated failures".
func TestFailureTracker_ThresholdIsPerSource(t *testing.T) {
	tracker, _ := newTestTracker(3, time.Minute)
	good := addr("2001:db8::1", 1234)
	bad := addr("2001:db8::2", 4321)

	for i := 0; i < 2; i++ {
		tracker.RecordFailure(bad)
		require.False(t, tracker.IsBlacklisted(bad),
			"the source is not refused until it reaches the threshold")
	}
	tracker.RecordFailure(bad)
	assert.True(t, tracker.IsBlacklisted(bad), "the threshold must be reached")

	assert.False(t, tracker.IsBlacklisted(good),
		"one source's failures must not blacklist another")
}

// TestFailureTracker_KeysOnIPNotPort: a peer retrying from a new ephemeral port is
// still the same source, so port-keyed tracking would let a flood outrun the
// blacklist by incrementing its port.
func TestFailureTracker_KeysOnIPNotPort(t *testing.T) {
	tracker, _ := newTestTracker(3, time.Minute)

	tracker.RecordFailure(addr("203.0.113.7", 50001))
	tracker.RecordFailure(addr("203.0.113.7", 50002))
	require.False(t, tracker.IsBlacklisted(addr("203.0.113.7", 50003)))
	tracker.RecordFailure(addr("203.0.113.7", 50003))

	assert.True(t, tracker.IsBlacklisted(addr("203.0.113.7", 60000)),
		"failures from the same IP at different ports must accumulate together")
}

// TestFailureTracker_WindowExpiry: a temporary glitch must not follow a peer around
// forever, which is why the built-in policy is a sliding window rather than a
// permanent ban.
func TestFailureTracker_WindowExpiry(t *testing.T) {
	tracker, clock := newTestTracker(3, 5*time.Minute)
	source := addr("198.51.100.9", 443)

	for i := 0; i < 3; i++ {
		tracker.RecordFailure(source)
	}
	require.True(t, tracker.IsBlacklisted(source))

	clock.Advance(6 * time.Minute)
	assert.False(t, tracker.IsBlacklisted(source),
		"failures older than the window must stop counting")
}

func TestFailureTracker_Defaults(t *testing.T) {
	tracker := NewFailureTracker(FailureTrackerConfig{})

	assert.Equal(t, DefaultFailureThreshold, tracker.threshold)
	assert.Equal(t, DefaultFailureWindow, tracker.window)
	assert.Equal(t, DefaultFailureTrackerCap, tracker.max)

	source := addr("192.0.2.1", 1)
	for i := 0; i < DefaultFailureThreshold-1; i++ {
		tracker.RecordFailure(source)
	}
	assert.False(t, tracker.IsBlacklisted(source))
	tracker.RecordFailure(source)
	assert.True(t, tracker.IsBlacklisted(source))
}

// TestFailureTracker_CapIsBounded: the tracker must not itself become an exhaustion
// vector when flooded from many sources.
func TestFailureTracker_CapIsBounded(t *testing.T) {
	tracker, _ := newTestTracker(3, time.Minute)
	tracker.max = 10

	for i := 0; i < 500; i++ {
		tracker.RecordFailure(addr("192.0.2.1", i))
		tracker.RecordFailure(addr("198.51.100.1", i))
	}

	tracker.mutex.Lock()
	size := len(tracker.failures)
	tracker.mutex.Unlock()
	assert.LessOrEqual(t, size, 10, "tracked sources must stay within the cap")
}

func TestFailureTracker_IgnoresUnusableAddresses(t *testing.T) {
	tracker, _ := newTestTracker(1, time.Minute)

	tracker.RecordFailure(nil)
	assert.False(t, tracker.IsBlacklisted(nil))

	// A pipe-backed connection has no IP; the address string is used instead.
	pipeAddr := &net.UnixAddr{Name: "/dev/null", Net: "unix"}
	tracker.RecordFailure(pipeAddr)
	assert.True(t, tracker.IsBlacklisted(pipeAddr),
		"an address without an IP is still attributed to something stable")
}

func TestSourceKey(t *testing.T) {
	assert.Equal(t, "192.0.2.1", sourceKey(addr("192.0.2.1", 5555)))
	assert.Equal(t, "2001:db8::1", sourceKey(addr("2001:db8::1", 5555)))
	assert.Equal(t, "192.0.2.9", sourceKey(&net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 9}))
	assert.Equal(t, "", sourceKey(nil))
}

// TestAccept_RefusesBlacklistedSource proves the listener enforces the tracker at
// accept time, before spending a socket and a detection window on the source.
func TestAccept_RefusesBlacklistedSource(t *testing.T) {
	tracker, _ := newTestTracker(1, time.Minute)

	config := newTestResponderConfigNoAES(t).WithFailureTracker(tracker)
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, config)

	accepted := make(chan error, 1)
	go func() {
		conn, err := ntcp2Ln.Accept()
		if conn != nil {
			conn.Close()
		}
		accepted <- err
	}()

	dial := func() *net.TCPConn {
		conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
		require.NoError(t, err)
		return conn.(*net.TCPConn)
	}

	// Blacklist the loopback source BEFORE dialing. sourceKey reduces an address to
	// its IP, so this covers any port the dialer happens to use, and it makes the
	// ordering deterministic: the listener's check runs after underlying.Accept()
	// returns, which is necessarily after the dial.
	tracker.RecordFailure(addr("127.0.0.1", 0))

	client := dial()
	_, err := client.Write([]byte("junk from a refused source"))
	require.NoError(t, err)

	select {
	case err := <-accepted:
		t.Fatalf("a blacklisted connection must not be returned by Accept; got err=%v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// The refused socket is closed by the listener.
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := client.Read(buf)
	assert.Error(t, readErr, "the refused connection must be closed")
	client.Close()

	require.NoError(t, ntcp2Ln.Close())
	<-accepted
}

// TestAccept_NoTrackerByDefault: refusing traffic is a policy the spec gives no
// numbers for, so it is opt-in and cannot break an existing deployment.
func TestAccept_NoTrackerByDefault(t *testing.T) {
	config := newTestResponderConfigNoAES(t)
	require.Nil(t, config.FailureTracker)
	ntcp2Ln, tcpAddr := startTestNTCP2Listener(t, config)

	client, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ntcp2Ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("without a tracker the listener must not refuse connections")
	}
}

// addrConn is a net.Conn whose only interesting behaviour is a fixed RemoteAddr, so
// a test can attribute a failure to a chosen source.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (a *addrConn) RemoteAddr() net.Addr { return a.remote }
func (a *addrConn) Read(b []byte) (int, error) {
	// Block until closed: applyProbingResistance reads junk bytes with a deadline.
	time.Sleep(50 * time.Millisecond)
	return 0, net.ErrClosed
}
func (a *addrConn) Write(b []byte) (int, error)     { return len(b), nil }
func (a *addrConn) Close() error                    { return nil }
func (a *addrConn) SetReadDeadline(time.Time) error { return nil }
func (a *addrConn) SetDeadline(time.Time) error     { return nil }

// TestApplyProbingResistance_RecordsFailure proves the failure is attributed to the
// source, which is the input the blacklist is built from.
func TestApplyProbingResistance_RecordsFailure(t *testing.T) {
	tracker, _ := newTestTracker(1, time.Minute)

	source := addr("203.0.113.42", 51000)
	conn := &addrConn{remote: source}

	config := newTestResponderConfigNoAES(t).WithFailureTracker(tracker)
	piped := newPipedNTCP2Conn(t)
	nc := piped.conn
	nc.SetNTCP2Config(config)

	require.False(t, tracker.IsBlacklisted(source))
	nc.applyProbingResistance(conn, false)
	assert.True(t, tracker.IsBlacklisted(source),
		"the failure must be attributed to the connection's source address")
}

// TestApplyProbingResistance_NoTracker: blacklisting is opt-in, so a conn without a
// tracker must still perform the required probing-resistance close.
func TestApplyProbingResistance_NoTracker(t *testing.T) {
	piped := newPipedNTCP2Conn(t)
	nc := piped.conn
	config := newTestResponderConfigNoAES(t)
	require.Nil(t, config.FailureTracker)
	nc.SetNTCP2Config(config)

	conn := &addrConn{remote: addr("203.0.113.43", 51001)}
	nc.applyProbingResistance(conn, false)
	assert.True(t, nc.broken.Load(), "the connection is still marked broken")
}
