package session

import (
	"net"
	"time"
)

// Compile-time interface checks to verify SSU2Conn satisfies expected contracts.
// These will fail at build time if the interface contract is broken.

// SSU2Conn implements the full net.Conn interface. In addition to the shared
// net.Addr / deadline methods it provides Read (returning one I2NP message at a
// time, buffering any remainder that does not fit the supplied buffer) and
// Write (with automatic I2NP fragmentation). See ssu2/session/conn_read.go and
// conn_write.go.
var _ net.Conn = (*SSU2Conn)(nil)

// SSU2Conn does implement the methods it shares with net.Conn:
var _ interface {
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
} = (*SSU2Conn)(nil)
