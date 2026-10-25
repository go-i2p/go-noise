// Package conn provides a high-level wrapper around the go-i2p/noise package
// that implements the net.Conn and net.Addr interfaces for the Noise Protocol
// Framework. It is the core building block for I2P's modern transport
// protocols, NTCP2 and SSU2.
//
// # How it works
//
// At its heart, this package puts the Noise Protocol on top of an ordinary
// net.Conn. A net.Conn is Go's standard interface for a network connection
// (for example, a TCP socket). The Noise Protocol is a set of rules for two
// parties to agree on shared encryption keys and then exchange encrypted
// messages. By combining the two, a Conn in this package behaves like a
// normal network connection, but everything that passes over it is encrypted.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// # The protocols it supports
//
// I2P uses two modern transport protocols, and both are built on the same
// Noise foundation:
//
//   - NTCP2 is I2P's TCP-based transport. It uses the Noise pattern
//     Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256.
//   - SSU2 is I2P's UDP-based transport. It uses the Noise pattern
//     Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256.
//
// Both patterns start from the same base pattern, XK, and use the same
// building blocks: X25519 for key exchange, ChaCha20-Poly1305 for encryption,
// and SHA-256 for hashing. The only real difference is how each protocol
// shapes the handshake messages and adds its own obfuscation and padding.
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for details.
//
// # Handshake modifiers
//
// Because NTCP2 and SSU2 share the same Noise core, this package does not
// hard-code either protocol. Instead, it exposes a small extension point
// called a handshake modifier. A modifier is a function that can inspect or
// change a single step of the handshake, or the data flowing through the
// connection, without touching the core Noise cryptography.
//
// Think of modifiers as a chain of filters. Each protocol plugs in the
// filters it needs. For example, NTCP2 and SSU2 each add their own
// obfuscation and padding filters, while the shared Noise socket, key
// exchange, and encryption logic stays exactly the same. This is what lets
// one implementation serve both protocols.
//
// # Typical use
//
// A caller creates a ConnConfig to describe the connection (which pattern to
// use, which side it is on, and any modifiers to apply), wraps an existing
// net.Conn with NewNoiseConn, runs the handshake with Handshake, and then
// reads and writes encrypted data with the usual Read and Write methods.
package conn

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/internal/iobuf"
	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/go-noise/mod"
	shutdown "github.com/go-i2p/go-noise/shutdown"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// aeadTagSize is the AEAD authentication tag length for the Noise cipher
// suites in use (ChaCha20-Poly1305 and AES-256-GCM both produce a 16-byte tag).
// noise.html §5.4 CipherState: "The output ... is plaintext plus a 16-byte
// authentication tag."
const aeadTagSize = 16

// maxNoiseMessageSize is the maximum Noise message size per the Noise spec
// §3 "Message format" ("All Noise messages are less than or equal to 65535 bytes
// in length"). Each message on the wire is preceded by a 2-byte big-endian
// length prefix, per §13 "Application responsibilities".
// This limit applies to the ciphertext frame (encrypted data plus the 16-byte
// AEAD tag), so the largest single Write of plaintext is
// maxNoiseMessageSize - AEAD tag (16) = 65519 bytes.
const maxNoiseMessageSize = 65535

// Connection state constants for public API
const (
	// StateInit represents a newly created connection
	StateInit = mod.StateInit
	// StateHandshaking represents a connection performing handshake
	StateHandshaking = mod.StateHandshaking
	// StateEstablished represents a connection with completed handshake
	StateEstablished = mod.StateEstablished
	// StateClosed represents a closed connection
	StateClosed = mod.StateClosed
)

// ConnState represents the state of a NoiseConn
type ConnState = mod.ConnState

// Conn is an encrypted network connection that implements the net.Conn
// interface. It wraps an ordinary net.Conn and encrypts everything that
// passes over it using the Noise Protocol.
//
// A Conn moves through a few states over its lifetime: it starts in
// StateInit, moves to StateHandshaking while the two sides agree on keys,
// reaches StateEstablished once the handshake is done, and ends in
// StateClosed. You can read and write data only after the handshake has
// completed.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
//
// Thread Safety:
// Conn is safe for concurrent use by multiple goroutines with the following guarantees:
//   - Read() and Write() can be called concurrently from different goroutines
//   - Close() can be called concurrently with other operations and will be idempotent
//   - GetConnectionState() and GetConnectionMetrics() are safe for concurrent access
//   - Handshake() operations are serialized - only one handshake can occur at a time
//   - All operations that check connection state are atomic and consistent
//
// Synchronization is achieved through multiple mutexes:
//   - stateMutex: Protects connection state transitions (RWMutex for read-heavy access)
//   - handshakeMutex: Serializes handshake operations
//   - closeMutex: Protects close operations from concurrent execution
//   - Internal metrics mutex: Protects connection metrics updates
type Conn struct {
	// underlying is the wrapped network connection
	underlying net.Conn

	// config contains the Noise protocol configuration
	config *ConnConfig

	// privateStaticKey is a per-connection copy of the static key, isolated from
	// the caller-owned config. It is zeroed on Close() to prevent the caller's
	// config from being corrupted.
	privateStaticKey []byte

	// sendCipherState handles encryption for outgoing data after handshake.
	// For interactive patterns: initiator uses cs1, responder uses cs2.
	sendCipherState *noise.CipherState

	// recvCipherState handles decryption for incoming data after handshake.
	// For interactive patterns: initiator uses cs2, responder uses cs1.
	recvCipherState *noise.CipherState

	// handshakeState handles the handshake process
	handshakeState *noise.HandshakeState

	// localAddr is the local Noise address
	localAddr *Addr

	// remoteAddr is the remote Noise address
	remoteAddr *Addr

	// state tracks the connection lifecycle and metrics
	state mod.ConnState

	// metrics tracks connection performance data
	metrics *mod.ConnectionMetrics

	// stateMutex protects state transitions
	stateMutex sync.RWMutex

	// handshakeMutex protects handshake operations
	handshakeMutex sync.Mutex

	// logger for connection events
	logger *i2plogger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager shutdown.Shutdowner

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// readMutex serializes Read calls to protect recvCipherState nonce
	readMutex sync.Mutex

	// writeMutex serializes Write calls to protect sendCipherState nonce
	writeMutex sync.Mutex

	// pendingPlaintext holds overflow plaintext from a previous Read when the
	// user buffer was too small. Protected by readMutex.
	pendingPlaintext []byte
}

// NewNoiseConn creates a new encrypted connection that wraps the given
// underlying network connection. The handshake must be completed (via
// Handshake) before Read and Write can be used.
//
// The config is stored by reference, not copied. Because of this, once you
// pass a *ConnConfig to NewNoiseConn you should treat it as read-only for as
// long as the returned *Conn exists. Most of its fields are read directly by
// Read, Write, and Handshake without any locking of their own (the Modifiers
// field is the one exception, which is synchronized internally). Changing a
// *ConnConfig after passing it here — including sharing the same config
// between two concurrent NewNoiseConn calls — is a data race. If you need
// different settings per connection, build a fresh ConnConfig for each one.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*Conn, error) {
	if err := validateNewConnParams(underlying, config); err != nil {
		return nil, err
	}

	// Make a per-connection copy of the static key to isolate from the caller's
	// config. This prevents Close() from corrupting the caller's key material.
	var privateStaticKey []byte
	if len(config.StaticKey) > 0 {
		privateStaticKey = make([]byte, len(config.StaticKey))
		copy(privateStaticKey, config.StaticKey)
	}

	hs, err := createHandshakeState(config, privateStaticKey)
	if err != nil {
		// Ensure the private key is zeroed on error
		if len(privateStaticKey) > 0 {
			securemem.SecureZero(privateStaticKey)
		}
		return nil, err
	}

	localAddr, remoteAddr := createNoiseAddresses(underlying, config)

	nc := &Conn{
		underlying:       underlying,
		config:           config,
		privateStaticKey: privateStaticKey,
		handshakeState:   hs,
		localAddr:        localAddr,
		remoteAddr:       remoteAddr,
		logger:           log,
		metrics:          mod.NewConnectionMetrics(),
		state:            mod.StateInit,
	}

	nc.logger.WithFields(i2plogger.Fields{
		"pkg":         "noise",
		"func":        "NewNoiseConn",
		"pattern":     nc.config.Pattern,
		"role":        baseconfig.RoleString(nc.config.Initiator),
		"local_addr":  nc.localAddr.String(),
		"remote_addr": nc.remoteAddr.String(),
	}).Debug("noise connection created")
	return nc, nil
}

// Read reads data from the connection.
// If the handshake is not complete, it will return an error.
//
// Thread Safety: This method is safe for concurrent use. Multiple goroutines
// can call Read simultaneously; calls are serialized via readMutex to protect
// the receive cipher state nonce counter.
func (nc *Conn) Read(b []byte) (int, error) {
	if err := nc.validateReadState(); err != nil {
		return 0, err
	}

	nc.readMutex.Lock()
	defer nc.readMutex.Unlock()

	// First, drain any pending plaintext from a previous Read call
	if n, drained := iobuf.DrainPendingBuffer(&nc.pendingPlaintext, b, true); drained || n > 0 {
		nc.metrics.AddBytesRead(int64(n))
		nc.logger.Trace("Data read from pending", i2plogger.Fields{
			"copied_len": n,
			"remaining":  len(nc.pendingPlaintext),
		})
		return n, nil
	}

	// Configure timeout only after acquiring the lock and draining pending data,
	// so the timeout applies only to the socket operation, not to lock acquisition time.
	if err := nc.configureReadTimeout(); err != nil {
		return 0, err
	}

	encrypted, n, err := nc.readEncryptedData(b)
	if err != nil {
		return 0, err
	}

	decrypted, err := nc.decryptData(encrypted[:n], n)
	if err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain on decrypted plaintext (e.g., strip padding).
	decrypted, err = nc.applyInboundModifier(decrypted)
	if err != nil {
		return 0, err
	}

	return nc.copyDecryptedData(b, decrypted, n, len(decrypted))
}

// Write writes data to the connection.
// If the handshake is not complete, it will return an error.
// The maximum plaintext size for a single Write call is 65519 bytes, not
// 65535. The Noise per-message limit of 65535 applies to the ciphertext
// frame (the 2-byte length prefix counts the encrypted data plus the
// 16-byte AEAD tag), so the plaintext ceiling is 65535 - 16 = 65519.
// Attempts to write more than 65519 bytes in one call will return an error.
// For automatic fragmentation of large payloads, use the transport-layer
// implementations (NTCP2, SSU2) which add application-level framing.
//
// Thread Safety: This method is safe for concurrent use. Multiple goroutines
// can call Write simultaneously; calls are serialized via writeMutex to protect
// the send cipher state nonce counter.
func (nc *Conn) Write(b []byte) (int, error) {
	if err := nc.validateWriteState(); err != nil {
		return 0, err
	}

	nc.writeMutex.Lock()
	defer nc.writeMutex.Unlock()

	if err := nc.configureWriteTimeout(); err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain before encryption (e.g., add padding).
	// toEncrypt may be larger than b if a modifier adds padding; we still report
	// len(b) as the number of caller bytes consumed.
	toEncrypt, err := nc.applyOutboundModifier(b)
	if err != nil {
		return 0, err
	}

	// Size check BEFORE encrypting, not after.
	//
	// noise.html §3 "Message Format": "All Noise messages are less than or equal
	// to 65535 bytes", and ntcp2.md §"ChaCha20/Poly1305" gives the ciphertext
	// "encrypted data :: Same size as plaintext data, 0 - 65519 bytes". Checking
	// only in writeFramedMessage means a message that a padding modifier pushed
	// over the limit is encrypted first and then refused, which consumes the send
	// nonce for a frame that never goes out and permanently desynchronises the
	// nonce counter from the peer's receive counter.
	if len(toEncrypt)+aeadTagSize > maxNoiseMessageSize {
		return 0, oops.
			Code("MESSAGE_TOO_LARGE").
			In("noise").
			With("plaintext_len", len(b)).
			With("modified_len", len(toEncrypt)).
			With("max_plaintext_len", maxNoiseMessageSize-aeadTagSize).
			Errorf("message too large: %d bytes of data plus the %d-byte AEAD tag exceeds the maximum Noise message size of %d bytes",
				len(toEncrypt), aeadTagSize, maxNoiseMessageSize)
	}

	encrypted, err := nc.encryptData(toEncrypt)
	if err != nil {
		return 0, err
	}

	return nc.writeEncryptedData(b, encrypted)
}

// Close closes the connection and releases its resources. It is safe to call
// more than once; only the first call does the real work.
//
// Thread Safety: This method is safe for concurrent use and is idempotent.
// Multiple goroutines can call Close simultaneously - only the first call
// will perform the actual close operation, subsequent calls will return nil.
// The close mutex ensures atomic close operations.
//
// Liveness: the underlying connection is closed BEFORE the read and write
// mutexes are acquired, not after. Read() and Write() hold their respective
// mutex for the entire duration of a blocking underlying I/O call (including
// when no ReadTimeout/WriteTimeout is configured, which is the default). If
// Close() acquired those mutexes first, a concurrently blocked Read() or
// Write() with no configured timeout would never release the mutex, and
// Close() would hang indefinitely. Closing the underlying connection first
// forces any blocked syscall to return an error immediately, releasing the
// mutex promptly, so Close() can then safely zero the key material.
func (nc *Conn) Close() error {
	nc.closeMutex.Lock()
	defer nc.closeMutex.Unlock()

	// Check and set state atomically to prevent race conditions
	nc.stateMutex.Lock()
	if nc.state == mod.StateClosed {
		nc.stateMutex.Unlock()
		return nil // Already closed
	}

	oldState := nc.state
	nc.state = mod.StateClosed
	nc.stateMutex.Unlock()

	nc.logger.WithFields(i2plogger.Fields{
		"pkg":       "noise",
		"func":      "NoiseConn.Close",
		"old_state": oldState.String(),
		"new_state": mod.StateClosed.String(),
	}).Debug("Connection state changed")

	// Close the underlying connection FIRST, to unblock any concurrently
	// in-flight Read()/Write() call before attempting to acquire the
	// mutexes those methods hold across a blocking underlying I/O call.
	// The close error is captured now and returned at the end, after key
	// material has still been zeroed on every code path.
	closeErr := nc.underlying.Close()

	// Acquire both read and write mutexes to ensure no in-flight operations are
	// using the cipher states before we zero them (defense-in-depth).
	// Lock order: readMutex first, then writeMutex, to match potential caller order.
	nc.readMutex.Lock()
	nc.writeMutex.Lock()

	// Zero cipher state key material before closing
	nc.ZeroKeys()

	nc.writeMutex.Unlock()
	nc.readMutex.Unlock()

	// Close modifier chain to release any resources held by modifiers
	if chain := nc.config.GetModifierChain(); chain != nil {
		chain.Close()
	}

	// Zero the per-connection static key copy instead of the caller's config.
	// This prevents corrupting a reused ConnConfig.
	if len(nc.privateStaticKey) > 0 {
		securemem.SecureZero(nc.privateStaticKey)
	}

	// Zero any undelivered decrypted plaintext so it does not linger on the
	// heap after close. Guarded by readMutex to avoid racing a concurrent Read.
	nc.readMutex.Lock()
	if len(nc.pendingPlaintext) > 0 {
		securemem.SecureZero(nc.pendingPlaintext)
		nc.pendingPlaintext = nil
	}
	nc.readMutex.Unlock()

	// Unregister from shutdown manager if set
	if nc.shutdownManager != nil {
		nc.shutdownManager.UnregisterConnection(nc)
	}

	if closeErr != nil {
		return oops.
			Code("UNDERLYING_CLOSE_FAILED").
			In("noise").
			With("state", nc.getState().String()).
			Wrapf(closeErr, "failed to close underlying connection")
	}

	return nil
}

// LocalAddr returns the local network address.
func (nc *Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr returns the remote network address.
func (nc *Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (nc *Conn) SetDeadline(t time.Time) error {
	if err := nc.underlying.SetDeadline(t); err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set deadline on underlying connection")
	}
	return nil
}

// SetReadDeadline sets the read deadline.
func (nc *Conn) SetReadDeadline(t time.Time) error {
	if err := nc.underlying.SetReadDeadline(t); err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set read deadline on underlying connection")
	}
	return nil
}

// SetWriteDeadline sets the write deadline.
func (nc *Conn) SetWriteDeadline(t time.Time) error {
	if err := nc.underlying.SetWriteDeadline(t); err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set write deadline on underlying connection")
	}
	return nil
}
