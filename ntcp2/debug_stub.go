//go:build !ntcp2_debug

package ntcp2

// debug_stub.go — no-op stubs for NTCP2 wire-dump helpers.
//
// When the ntcp2_debug build tag is absent (the default), these stubs replace
// the real implementations in debug.go so that production binaries carry zero
// diagnostic I/O surface and no file-system or env-var reads.

import "sync/atomic"

// msg1WireDumpRemaining is the zero-value no-op counterpart to the atomic
// counter declared in debug.go. It always reads as zero, so the Load() > 0
// guard in the production write path is never taken. Only the msg1 counter is
// read outside debug.go; the msg3 counter lives entirely inside the tagged
// implementation, so the stub does not declare it.
var msg1WireDumpRemaining atomic.Int32

func dumpMsg1IfEnabled(_ *Config, _ interface{}, _, _ []byte)                 {}
func dumpInboundMsg1IfEnabled(_ *Config, _ interface{}, _, _ []byte, _ error) {}
func classifyMsg2ReadFailure(_ *Config, _ interface{}, _ int, _ error)        {}
func dumpMsg3IfEnabled(_ *Config, _ interface{}, _, _ []byte, _ uint16)       {}
