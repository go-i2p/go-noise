package server

import (
	"runtime/debug"

	"github.com/go-i2p/logger"
)

// safeGo starts fn on a new goroutine guarded by panic recovery. I2P-004:
// fire-and-forget spawns (the per-session force-destroy trigger during
// listener shutdown) run with no upstream recover seam, so an unrecovered
// panic in one of them is process death. The panic is logged with the spawn's
// name and the goroutine exits; the surrounding operation is best-effort, so a
// bad spawn costs one lost side effect, not the router.
//
// This is the spawn-level counterpart to recoverTick (a per-tick seam for
// long-running loops).
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				flog("safeGo", logger.Fields{
					"spawn": name,
					"panic": r,
					"stack": string(debug.Stack()),
				}).Error("recovered from panic in spawned goroutine; goroutine exited")
			}
		}()
		fn()
	}()
}
