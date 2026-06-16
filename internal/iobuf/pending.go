package iobuf

import (
	"github.com/go-i2p/go-noise/internal/securemem"
)

// DrainPendingBuffer drains a pending buffer into the caller's buffer.
// It copies up to len(b) bytes from pending into b, updates the pending
// buffer slice to reflect consumed bytes, and zeroes the backing array
// if the buffer is fully drained (to prevent plaintext lingering).
//
// Parameters:
//   - pending: Pointer to the pending buffer slice. Will be modified in-place.
//   - b: Destination buffer to copy into.
//   - zero: Whether to zero the backing array on full drain (security-sensitive
//     buffers should set this to true).
//
// Returns:
//   - n: Number of bytes copied to b.
//   - drained: Whether the pending buffer was fully drained (pending is now nil).
//
// Thread Safety: The caller is responsible for synchronization (e.g., readMutex).
// This function assumes the pending slice and its backing array are not accessed
// concurrently.
func DrainPendingBuffer(pending *[]byte, b []byte, zero bool) (n int, drained bool) {
	if len(*pending) == 0 {
		return 0, false
	}

	// Copy as many bytes as the destination buffer can hold
	n = copy(b, *pending)

	// If zeroing is enabled, immediately zero the delivered bytes to minimize
	// plaintext lifetime in memory. This ensures already-delivered plaintext
	// doesn't linger in the backing array even if the buffer isn't fully drained yet.
	if zero && n > 0 {
		securemem.SecureZero((*pending)[:n])
	}

	*pending = (*pending)[n:]

	// If fully drained, ensure the entire backing array is zeroed
	if len(*pending) == 0 {
		if zero && cap(*pending) > 0 {
			// Reslice to the original backing array capacity and zero any remainder
			tail := (*pending)[:cap(*pending)]
			securemem.SecureZero(tail)
		}
		*pending = nil
		return n, true
	}

	return n, false
}
