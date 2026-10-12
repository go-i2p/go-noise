package ntcp2

import (
	"context"
	"net"
)

// ConnIface is the minimal interface satisfied by *Conn.
//
// Dialer.DialContext and Acceptor.AcceptWithHandshake return ConnIface
// instead of the concrete *Conn type, so tests can substitute a fake
// connection without importing the real one.
//
// Where NTCP2-specific methods (e.g. PropagateSipHash, RouterHash) are
// needed, use a type assertion: conn.(*Conn).PropagateSipHash().
type ConnIface interface {
	net.Conn
	// Handshake performs the NTCP2 handshake. It must be called before
	// Read or Write.
	Handshake(ctx context.Context) error
}

// Dialer establishes outbound NTCP2 connections, including the handshake.
//
// The package-level DialNTCP2WithHandshakeContext function provides this
// behavior; NewDialer wraps it in a Dialer value, which is convenient for
// dependency injection and test substitution.
type Dialer interface {
	// DialContext opens an outbound NTCP2 connection to network/addr using
	// config, performs the NTCP2 handshake, and returns the established
	// connection. The context governs handshake cancellation.
	DialContext(ctx context.Context, network, addr string, config *Config) (ConnIface, error)
}

// Acceptor accepts inbound NTCP2 connections on a listener.
//
// It extends net.Listener with AcceptWithHandshake, which performs the
// NTCP2 handshake as part of the accept loop. *Listener satisfies this
// interface.
type Acceptor interface {
	net.Listener
	// AcceptWithHandshake accepts the next inbound connection and performs
	// the NTCP2 handshake before returning. The context governs handshake
	// cancellation for each accepted connection.
	AcceptWithHandshake(ctx context.Context) (ConnIface, error)
}

// dialerImpl wraps DialNTCP2WithHandshakeContext as a Dialer.
type dialerImpl struct{}

// NewDialer returns a Dialer backed by DialNTCP2WithHandshakeContext.
//
// The returned value may be stored in a Dialer field and replaced by a
// test double without changing call sites.
func NewDialer() Dialer { return &dialerImpl{} }

func (d *dialerImpl) DialContext(ctx context.Context, network, addr string, config *Config) (ConnIface, error) {
	return DialNTCP2WithHandshakeContext(ctx, network, addr, config)
}

// Compile-time interface satisfaction checks.
var (
	_ Acceptor  = (*Listener)(nil)
	_ Dialer    = (*dialerImpl)(nil)
	_ ConnIface = (*Conn)(nil)
)
