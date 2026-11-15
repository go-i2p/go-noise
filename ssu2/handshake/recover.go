package handshake

import (
	"runtime/debug"

	"github.com/go-i2p/logger"
)

// recoverTick runs a periodic maintenance function (a rotation-check tick) and
// recovers from any panic it raises. I2P-004: the background key-rotation
// checker runs on its own goroutine with no upstream recover seam, so a panic
// in a tick would otherwise kill the router process. The panic is logged with
// the tick's name; the goroutine survives to the next tick, so a bad tick costs
// one skipped rotation check, not the process.
func recoverTick(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			flog("recoverTick", logger.Fields{
				"tick":  name,
				"panic": r,
				"stack": string(debug.Stack()),
			}).Error("recovered from panic in cleanup tick; skipping this interval")
		}
	}()
	fn()
}
