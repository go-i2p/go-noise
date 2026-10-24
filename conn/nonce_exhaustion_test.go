package conn

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/go-i2p/noise"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNonceExhaustedTerminatesSession covers Noise spec §11: "If
// EncryptWithAd() or DecryptWithAd() signal an error due to nonce exhaustion,
// then the application must delete the CipherState and terminate the session."
//
// A nonce may not wrap back to zero (§5: "Nonces are not allowed to wrap back to
// zero due to integer overflow, and the maximum nonce value is reserved"), so
// the only conforming action past the ceiling is to tear the session down.
func TestNonceExhaustedTerminatesSession(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	// 2^64-1 is the value reserved for rekeying; the cipher state refuses to
	// use it and reports ErrMaxNonce.
	client.sendCipherState.SetNonce(math.MaxUint64)

	_, err := client.Write([]byte("past the ceiling"))
	require.Error(t, err, "Write must fail once the send nonce is exhausted")

	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "NONCE_EXHAUSTED", oopsErr.Code(),
		"nonce exhaustion must be distinguishable from an ordinary encrypt failure")

	// The session must be terminated, not merely errored.
	assertClosed(t, client)

	// And the key material must be deleted.
	assertKeyZeroed(t, client.sendCipherState)
}

// TestReceiveNonceExhaustedTerminatesSession covers the read half of the same
// Noise §11 requirement.
//
// It drives Decrypt() rather than Read() because net.Pipe is fully synchronous:
// Read() would need a concurrent writer, and the socket round-trip adds nothing
// to what is under test — the nonce guard lives in the decrypt step itself.
func TestReceiveNonceExhaustedTerminatesSession(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	frame, err := client.Encrypt([]byte("frame for an exhausted receiver"))
	require.NoError(t, err)

	server.recvCipherState.SetNonce(math.MaxUint64)

	_, err = server.Decrypt(frame)
	require.Error(t, err, "Decrypt must fail once the receive nonce is exhausted")

	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "NONCE_EXHAUSTED", oopsErr.Code())

	assertClosed(t, server)
	assertKeyZeroed(t, server.recvCipherState)
}

// TestDecryptFailureDoesNotTerminateSession pins the other half of Noise §11:
// an authentication failure (as opposed to nonce exhaustion) is left to the
// application, which "may choose to delete the CipherState and terminate the
// session on such an error, or may continue to attempt communications."
// NTCP2 relies on being able to inspect and act on that error itself.
func TestDecryptFailureDoesNotTerminateSession(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	frame, err := client.Encrypt([]byte("bad tag"))
	require.NoError(t, err)
	frame[len(frame)-1] ^= 0xFF

	_, err = server.Decrypt(frame)
	require.Error(t, err, "a bad AEAD tag must be reported as a decrypt failure")

	var oopsErr oops.OopsError
	require.ErrorAs(t, err, &oopsErr)
	assert.Equal(t, "DECRYPT_FAILED", oopsErr.Code(),
		"an authentication failure must not be relabelled as nonce exhaustion")
	assert.False(t, errors.Is(err, noise.ErrMaxNonce))

	// The session stays usable: the spec makes termination optional here.
	assert.False(t, server.isClosed(), "a decrypt failure must not terminate the session by itself")
}

func assertClosed(t *testing.T, c *Conn) {
	t.Helper()
	// Close() runs in a goroutine on the exhaustion path, so allow a moment for
	// it to land rather than asserting on a racy instant.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.isClosed() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expected the connection to be terminated after nonce exhaustion")
}

func assertKeyZeroed(t *testing.T, cs *noise.CipherState) {
	t.Helper()
	var zero [32]byte
	assert.Equal(t, zero, cs.UnsafeKey(), "the exhausted CipherState key must be deleted")
}
