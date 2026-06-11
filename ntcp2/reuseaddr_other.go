//go:build !linux

package ntcp2

import (
	"syscall"

	"github.com/go-i2p/logger"
)

// reuseAddrControl is the platform-specific implementation of SO_REUSEADDR
// for non-Linux platforms.
//
// AUDIT 7.1: On non-Linux platforms (macOS, Windows, BSD, etc.), SO_REUSEADDR
// has different semantics or behavior. On macOS, SO_REUSEADDR does not provide
// the same TIME_WAIT bypass that Linux offers. On Windows, it has yet different
// behavior. Rather than risk applying incorrect socket options, we log a warning
// and skip SO_REUSEADDR on these platforms.
//
// Users of go-noise on non-Linux platforms who need fast restart semantics
// should use platform-specific approaches or wait for the OS kernel's TIME_WAIT
// to expire (typically 30-120 seconds).
var reuseAddrControl = func(network, address string, c syscall.RawConn) error {
	// AUDIT 7.1: Log that SO_REUSEADDR is not applied on this platform
	log.WithFields(logger.Fields{
		"pkg":      "ntcp2",
		"func":     "reuseAddrControl",
		"platform": "non-linux",
		"address":  address,
	}).Warn("SO_REUSEADDR not applied on this platform; use platform-specific approaches for fast restart")

	// On non-Linux platforms, we do not attempt to set SO_REUSEADDR to avoid
	// applying platform-specific semantics that may differ from Linux.
	// The connection will follow the OS kernel's natural TIME_WAIT behavior.
	return nil
}
