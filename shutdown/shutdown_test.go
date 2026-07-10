package shutdown

import (
	"io"
	"net"
	"testing"
)

// typedNilConn is a concrete *typedNilConn used to construct a typed-nil
// ShutdownConn interface value (var c *typedNilConn = nil; var i ShutdownConn = c).
// Its methods are never actually invoked by RegisterConnection/UnregisterConnection
// when the typed-nil guard works correctly, but they must exist to satisfy
// the ShutdownConn interface, and must not panic if a future regression
// causes them to be called on a nil receiver.
type typedNilConn struct{}

var dummyAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

func (c *typedNilConn) Close() error         { return nil }
func (c *typedNilConn) LocalAddr() net.Addr  { return dummyAddr }
func (c *typedNilConn) RemoteAddr() net.Addr { return dummyAddr }

var _ ShutdownConn = (*typedNilConn)(nil)
var _ io.Closer = (*typedNilConn)(nil)

type typedNilListener struct{}

func (l *typedNilListener) Close() error   { return nil }
func (l *typedNilListener) Addr() net.Addr { return nil }

var _ ShutdownListener = (*typedNilListener)(nil)

// TestRegisterConnection_TypedNilPointer verifies that a typed-nil pointer
// satisfying ShutdownConn (the classic Go "nil interface" pitfall: the
// interface value itself is not == nil, since it carries a concrete type)
// is rejected the same way a bare nil interface is, rather than being
// registered and later causing a nil-pointer-dereference panic when
// LocalAddr()/RemoteAddr() are called during shutdown logging.
func TestRegisterConnection_TypedNilPointer(t *testing.T) {
	sm := NewShutdownManager(0)

	var typedNil *typedNilConn // nil pointer
	sm.RegisterConnection(typedNil)

	sm.mu.RLock()
	count := len(sm.connections)
	sm.mu.RUnlock()

	if count != 0 {
		t.Fatalf("expected typed-nil connection to be rejected, but %d connection(s) were registered", count)
	}
}

// TestRegisterListener_TypedNilPointer is the listener-side equivalent of
// TestRegisterConnection_TypedNilPointer.
func TestRegisterListener_TypedNilPointer(t *testing.T) {
	sm := NewShutdownManager(0)

	var typedNil *typedNilListener // nil pointer
	sm.RegisterListener(typedNil)

	sm.mu.RLock()
	count := len(sm.listeners)
	sm.mu.RUnlock()

	if count != 0 {
		t.Fatalf("expected typed-nil listener to be rejected, but %d listener(s) were registered", count)
	}
}

// TestRegisterConnection_BareNil verifies the pre-existing bare-nil-interface
// case (var c ShutdownConn = nil) still works, since isNilInterface must
// handle both the bare-nil and typed-nil cases correctly.
func TestRegisterConnection_BareNil(t *testing.T) {
	sm := NewShutdownManager(0)
	sm.RegisterConnection(nil)

	sm.mu.RLock()
	count := len(sm.connections)
	sm.mu.RUnlock()

	if count != 0 {
		t.Fatalf("expected bare-nil connection to be rejected, but %d connection(s) were registered", count)
	}
}

// TestRegisterConnection_ValidConnection verifies isNilInterface does not
// reject a genuinely non-nil connection.
func TestRegisterConnection_ValidConnection(t *testing.T) {
	sm := NewShutdownManager(0)
	sm.RegisterConnection(&typedNilConn{})

	sm.mu.RLock()
	count := len(sm.connections)
	sm.mu.RUnlock()

	if count != 1 {
		t.Fatalf("expected 1 registered connection, got %d", count)
	}
}
