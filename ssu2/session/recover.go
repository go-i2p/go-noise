package session

import (
	"runtime/debug"

	"github.com/go-i2p/logger"
)

// safeGo starts fn on a new goroutine guarded by panic recovery. I2P-004:
// fire-and-forget spawns (a deferred Close, a NextNonce rekey, the dial-path
// recvLoop) run with no upstream recover seam, and the work they do touches
// state derived from remote input, so an unrecovered panic in one of them is
// process death. The panic is logged with the spawn's name and the goroutine
// exits; the connection's own lifecycle (closeChan, wg, rekeyInFlight re-arm)
// then drives teardown, so a bad spawn costs one lost operation, not the
// router.
//
// This is the spawn-level counterpart to recoverTick (a per-tick seam for
// long-running loops). Use safeGo where the goroutine is started once and is
// expected to run to completion; use recoverTick where a loop must survive a
// single bad iteration and keep ticking.
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
