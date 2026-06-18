// Package securemem provides helpers for safely erasing sensitive key material
// from memory. It is intentionally internal so that only packages within this
// module can import it.
package securemem

import (
	"runtime"

	"github.com/go-i2p/logger"
)

// SecureZero zeroes out the given byte slice. Uses runtime.KeepAlive to
// prevent the compiler from eliding the zeroing as a dead store.
func SecureZero(b []byte) {
	flog("SecureZero", logger.Fields{"len": len(b)}).Debug("Zeroing key material")
	clear(b)
	runtime.KeepAlive(b)
}
