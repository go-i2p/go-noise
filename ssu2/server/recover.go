package server

import (
	"runtime/debug"

	"github.com/go-i2p/logger"
)

// recoverTick runs a periodic maintenance function (a cleanup tick) and
// recovers from any panic it raises. I2P-004: background cleanup goroutines
// run with no upstream recover seam, and the state they walk is built from
// remote input, so a panic there is remotely triggerable process death. The
// panic is logged with the tick's name; the goroutine survives to the next
// tick, so a bad tick costs one skipped cleanup interval, not the process.
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
