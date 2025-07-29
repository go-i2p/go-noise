package ntcp2

import (
	"net"
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Conn implements net.Conn for NTCP2 transport connections.
// It wraps a NoiseConn with NTCP2-specific addressing and protocol handling.
// Moved from: ntcp2/conn.go
type NTCP2Conn struct {
	// noiseConn is the underlying encrypted connection
	noiseConn *noise.NoiseConn

	// localAddr is the NTCP2-specific local address
	localAddr *NTCP2Addr

	// remoteAddr is the NTCP2-specific remote address
	remoteAddr *NTCP2Addr

	// logger for connection events
	logger logger.Logger
}

// NewNTCP2Conn creates a new NTCP2Conn wrapping the provided NoiseConn.
// The NoiseConn must already be configured with appropriate NTCP2 modifiers.
func NewNTCP2Conn(noiseConn *noise.NoiseConn, localAddr, remoteAddr *NTCP2Addr) (*NTCP2Conn, error) {
	if noiseConn == nil {
		return nil, oops.
			Code("INVALID_NOISE_CONN").
			In("ntcp2").
			Errorf("noise connection cannot be nil")
	}

	if localAddr == nil {
		return nil, oops.
			Code("INVALID_LOCAL_ADDR").
			In("ntcp2").
			Errorf("local address cannot be nil")
	}

	if remoteAddr == nil {
		return nil, oops.
			Code("INVALID_REMOTE_ADDR").
			In("ntcp2").
			Errorf("remote address cannot be nil")
	}
	conn := &NTCP2Conn{
		noiseConn:  noiseConn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		logger:     *log,
	}

	conn.logger.Debug("NTCP2 connection created",
		"local_addr", localAddr.String(),
		"remote_addr", remoteAddr.String())

	return conn, nil
}

// Read implements net.Conn.Read.
// Reads data from the underlying encrypted Noise connection.
func (nc *NTCP2Conn) Read(b []byte) (int, error) {
	n, err := nc.noiseConn.Read(b)
	if err != nil {
		return 0, oops.
			Code("READ_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			With("bytes_requested", len(b)).
			Wrapf(err, "ntcp2 read failed")
	}

	nc.logger.Trace("NTCP2 data read",
		"bytes_read", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// Write implements net.Conn.Write.
// Writes data to the underlying encrypted Noise connection.
func (nc *NTCP2Conn) Write(b []byte) (int, error) {
	n, err := nc.noiseConn.Write(b)
	if err != nil {
		return 0, oops.
			Code("WRITE_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			With("bytes_to_write", len(b)).
			Wrapf(err, "ntcp2 write failed")
	}

	nc.logger.Trace("NTCP2 data written",
		"bytes_written", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// Close implements net.Conn.Close.
// Closes the underlying Noise connection and cleans up resources.
func (nc *NTCP2Conn) Close() error {
	nc.logger.Debug("NTCP2 connection closing",
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	err := nc.noiseConn.Close()
	if err != nil {
		return oops.
			Code("CLOSE_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 close failed")
	}

	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
// Returns the NTCP2-specific local address.
func (nc *NTCP2Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr implements net.Conn.RemoteAddr.
// Returns the NTCP2-specific remote address.
func (nc *NTCP2Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline implements net.Conn.SetDeadline.
// Sets read and write deadlines on the underlying connection.
func (nc *NTCP2Conn) SetDeadline(t time.Time) error {
	err := nc.noiseConn.SetDeadline(t)
	if err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set deadline failed")
	}

	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
// Sets the read deadline on the underlying connection.
func (nc *NTCP2Conn) SetReadDeadline(t time.Time) error {
	err := nc.noiseConn.SetReadDeadline(t)
	if err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set read deadline failed")
	}

	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
// Sets the write deadline on the underlying connection.
func (nc *NTCP2Conn) SetWriteDeadline(t time.Time) error {
	err := nc.noiseConn.SetWriteDeadline(t)
	if err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set write deadline failed")
	}

	return nil
}

// RouterHash returns the router hash from the remote address.
// This is I2P-specific functionality for NTCP2 connections.
func (nc *NTCP2Conn) RouterHash() []byte {
	return nc.remoteAddr.RouterHash()
}

// DestinationHash returns the destination hash from the remote address.
// Returns nil for router-to-router connections.
func (nc *NTCP2Conn) DestinationHash() []byte {
	return nc.remoteAddr.DestinationHash()
}

// SessionTag returns the session tag from the remote address.
// Returns nil if no session tag is set.
func (nc *NTCP2Conn) SessionTag() []byte {
	return nc.remoteAddr.SessionTag()
}

// Role returns the connection role (initiator or responder).
func (nc *NTCP2Conn) Role() string {
	return nc.localAddr.Role()
}

// UnderlyingConn returns the underlying NoiseConn for advanced operations.
// This allows access to Noise-specific functionality when needed.
func (nc *NTCP2Conn) UnderlyingConn() *noise.NoiseConn {
	return nc.noiseConn
}
