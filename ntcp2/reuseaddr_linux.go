//go:build linux

package ntcp2

import (
	"syscall"

	"github.com/samber/oops"
)

// reuseAddrControl is the platform-specific implementation of SO_REUSEADDR
// for Linux. On Linux, SO_REUSEADDR (value 2) allows a socket in TIME_WAIT
// state to be reused, enabling fast restart of servers.
//
// AUDIT 7.1: Linux-specific implementation allows fast socket reuse.
var reuseAddrControl = func(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		// SO_REUSEADDR on Linux
		setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return oops.Wrapf(err, "failed to control socket")
	}
	if setErr != nil {
		return oops.Wrapf(setErr, "SO_REUSEADDR setsockopt failed on Linux")
	}
	return nil
}
