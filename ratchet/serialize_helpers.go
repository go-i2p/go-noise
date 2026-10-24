package ratchet

// writeArray32 serializes a fixed 32-byte value into dst.
// Caller must ensure len(dst) >= 32.
func writeArray32(dst []byte, src [32]byte) {
	copy(dst[:32], src[:])
}

// readArray32 deserializes a fixed 32-byte value from src into dst.
// Caller must ensure len(src) >= 32.
func readArray32(dst *[32]byte, src []byte) {
	copy(dst[:], src[:32])
}
