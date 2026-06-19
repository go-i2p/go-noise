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

// writeArray495 serializes a fixed 495-byte value into dst.
// Caller must ensure len(dst) >= 495.
func writeArray495(dst []byte, src [495]byte) {
	copy(dst[:495], src[:])
}

// writePrefix16FromArray32 serializes the first 16 bytes of a 32-byte value.
// Caller must ensure len(dst) >= 16.
func writePrefix16FromArray32(dst []byte, src [32]byte) {
	copy(dst[:16], src[:16])
}

// readPrefix16ToArray32 deserializes a 16-byte prefix into a 32-byte value.
// Bytes 16..31 in dst are left unchanged (zero-value for a new dst).
// Caller must ensure len(src) >= 16.
func readPrefix16ToArray32(dst *[32]byte, src []byte) {
	copy(dst[:16], src[:16])
}
