package ssu2

import (
	"context"
	"net"

	"github.com/go-i2p/go-noise/ssu2/session"
)

// ConnIface is the minimal interface satisfied by *SSU2Conn.
// Dialer.DialContext returns ConnIface so that callers can substitute test
// doubles without importing the concrete *session.SSU2Conn type.
// Where SSU2-specific methods are needed, use a type assertion:
//
//	conn.(*session.SSU2Conn).CloseWithReason(...)
type ConnIface interface {
	net.Conn
	// Handshake performs the SSU2 XK handshake. It must be called before
	// Read/Write.
	Handshake(ctx context.Context) error

	// WriteBlocksWithNumbers sends blocks as individual Data packets and
	// returns the packet number assigned to each block, in order. Callers can
	// use these numbers to match explicit ACK blocks from the peer to the
	// exact outbound packets, giving spec-correct delivery confirmation
	// without guessing which packet an ACK refers to.
	WriteBlocksWithNumbers(blocks []*session.SSU2Block) ([]uint32, error)
}

// Dialer establishes outbound SSU2 connections, including the handshake.
// Use NewDialer to obtain the default implementation.
type Dialer interface {
	// DialContext establishes a new SSU2 session from localAddr to remoteAddr.
	// The context controls connection and handshake timeouts.
	DialContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (ConnIface, error)
}

// dialerImpl wraps DialSSU2WithHandshakeContext as a Dialer.
type dialerImpl struct{}

// NewDialer returns a Dialer backed by DialSSU2WithHandshakeContext.
func NewDialer() Dialer { return &dialerImpl{} }

func (d *dialerImpl) DialContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (ConnIface, error) {
	return DialSSU2WithHandshakeContext(ctx, localAddr, remoteAddr, config)
}

// Compile-time interface satisfaction checks.
var (
	_ Acceptor  = (*SSU2Listener)(nil)
	_ Router    = (*PacketRouter)(nil)
	_ Dialer    = (*dialerImpl)(nil)
	_ ConnIface = (*session.SSU2Conn)(nil)
)
