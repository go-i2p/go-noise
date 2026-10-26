package ntcp2

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Conn is an NTCP2 connection. It works like a net.Conn: after the
// handshake completes, use Read and Write to send and receive I2P
// messages.
//
// Under the hood, a Conn wraps a Noise connection and adds the NTCP2
// extensions: AES obfuscation of the handshake keys, random padding, and
// SipHash-obfuscated frame lengths. In the data phase, every frame is
// sent as a two-byte scrambled length followed by an encrypted payload.
//
// This type only handles the transport. Higher-level I2P concerns —
// parsing I2NP messages, termination blocks, options negotiation, and
// replay protection — live in the router transport layer
// (github.com/go-i2p/go-i2p/lib/transport/ntcp).
type Conn struct {
	// noiseConn is the underlying encrypted connection
	noiseConn *noise.NoiseConn

	// localAddr is the NTCP2-specific local address
	localAddr *Addr

	// remoteAddr is the NTCP2-specific remote address
	remoteAddr *Addr

	// lengthObfuscator applies SipHash-2-4 frame length obfuscation
	// in the data phase. When non-nil, Read/Write use framed I/O:
	//   Write: [2-byte SipHash-obfuscated length][ChaChaPoly ciphertext]
	//   Read:  deobfuscate 2-byte length, read exact frame, decrypt
	// When nil, Read/Write delegate directly to NoiseConn (no framing).
	// Access is via atomic.Pointer to avoid data races between
	// SetLengthObfuscator (PostHandshakeHook) and Read/Write.
	lengthObfuscator atomic.Pointer[SipHashLengthModifier]

	// readBuffer holds surplus plaintext from readFramed when the
	// decrypted frame is larger than the caller's Read buffer.
	readBuffer []byte

	// readMu serialises readFramed calls so that SipHash inbound mask
	// generation and the subsequent TCP read are atomic with respect to
	// each other. This mirrors writeMu for the write path.
	readMu sync.Mutex

	// writeMu serialises writeFramed calls so that SipHash mask generation
	// and the subsequent TCP write are atomic with respect to each other.
	writeMu sync.Mutex

	// ntcp2Config is the per-connection NTCP2Config used to create this conn.
	// Retained so that after Handshake() fires the PostHandshakeHook (which
	// stores derived SipHash keys on the config), the caller can call
	// PropagateSipHash() to copy them to lengthObfuscator.
	// Access is via atomic.Pointer for thread safety.
	ntcp2Config atomic.Pointer[Config]

	// peerMsg3Payload stores the decrypted plaintext from the responder's
	// view of NTCP2 message 3 part 2. This is the I2NP block frame
	// containing Alice's RouterInfo (block type 2) plus any optional
	// padding/options blocks. nil for initiator connections (Alice already
	// has her own RouterInfo) and prior to a successful inbound handshake.
	// Access is via atomic.Pointer for thread safety.
	peerMsg3Payload atomic.Pointer[[]byte]

	// closeOnce ensures Close is idempotent and key material is zeroed exactly once.
	closeOnce sync.Once

	// broken is set when a framing I/O error occurs after the SipHash mask has
	// been consumed. Once set, the connection's SipHash state is irrecoverably
	// desynchronized and all future Read/Write calls will fail immediately.
	broken atomic.Bool

	// established is set to true at the very end of a successful Handshake().
	// Read() and Write() MUST check this before performing any data-phase I/O
	// to prevent sending or receiving data before the cipher states are ready.
	// Without this gate, callers could read/write plaintext or use
	// uninitialised SipHash keys before the handshake has completed.
	established atomic.Bool

	// underlyingClosed is set when sendTCPRST has already closed the TCP socket
	// via SetLinger(0)+Close(). Close() checks this flag and skips the second
	// noiseConn.Close() call to prevent an fd-reuse double-close race.
	underlyingClosed atomic.Bool

	// writeNonce tracks the number of frames written (data-phase encrypt operations).
	// The connection MUST be terminated after this reaches MaxNonce (2^64-2);
	// the message sent AT MaxNonce is still legal. Only accessed under writeMu.
	writeNonce uint64

	// readNonce tracks the number of frames read (data-phase decrypt operations).
	// The connection MUST be terminated after this reaches MaxNonce (2^64-2).
	// Only accessed under readMu.
	readNonce uint64

	// OnAEADError is an optional callback invoked during data-phase AEAD
	// failure handling, after the probing-resistance junk-read phase but
	// before the connection is killed. It lets the transport layer override
	// the spec's default teardown.
	//
	// The transport layer uses it to emit a spec-compliant Termination frame
	// (block type 4) by calling SendTerminationFrame on the supplied Conn —
	// which seals a real data-phase frame (SipHash-masked length + AEAD) even
	// though the connection is marked broken. A receive-side AEAD failure only
	// desynchronises the inbound state; the outbound cipher, nonce, and SipHash
	// mask are still in sync, so exactly one more outbound frame is valid and
	// meaningful to the peer.
	//
	// validFramesReceived is the count of successfully-decrypted data-phase
	// frames so far (the current receive nonce), which the spec requires the
	// termination block to carry.
	//
	// Returning nil tells applyProbingResistance the frame was sent, so the
	// socket is closed gracefully (FIN) to let it flush; returning an error
	// falls back to the abnormal TCP RST. When the callback is nil,
	// applyProbingResistance sends the spec's default termination block
	// (reason 4 = "data phase AEAD failure") itself — ntcp2.md §"AEAD Error
	// Handling": "the recipient should send a payload with a termination block
	// containing an 'AEAD failure' reason code, and close the connection."
	//
	// The callback runs while the read lock is held; it must not call Read.
	OnAEADError func(conn *Conn, validFramesReceived uint64) error

	// logger for connection events (pointer so runtime log-level changes are visible)
	logger *logger.Logger

	// handshakeDeadline is the absolute deadline set by Accept() for the full
	// handshake window. When non-zero, Handshake() will not extend the deadline
	// beyond this value, ensuring the total window (accept→handshake) is bounded
	// to a single HandshakeTimeout.
	handshakeDeadline time.Time
}

// NewNTCP2Conn creates a Conn around an existing Noise connection. The
// Noise connection must already be configured with the NTCP2 modifiers
// (AES obfuscation, padding, SipHash length). localAddr and remoteAddr
// describe the two ends of the connection.
func NewNTCP2Conn(noiseConn *noise.NoiseConn, localAddr, remoteAddr *Addr) (*Conn, error) {
	if noiseConn == nil {
		return nil, oops.
			Code("INVALID_NOISE_CONN").
			In("ntcp2").
			Errorf("noise connection cannot be nil")
	}

	if localAddr == nil {
		return nil, oops.
			Code("INVALID_LOCAL_ADDR").
			In("ntcp2").
			Errorf("local address cannot be nil")
	}

	if remoteAddr == nil {
		return nil, oops.
			Code("INVALID_REMOTE_ADDR").
			In("ntcp2").
			Errorf("remote address cannot be nil")
	}
	conn := &Conn{
		noiseConn:  noiseConn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		logger:     log,
	}

	conn.logger.Debug("NTCP2 connection created",
		"local_addr", localAddr.String(),
		"remote_addr", remoteAddr.String())

	return conn, nil
}

// SetLengthObfuscator installs the SipHash length obfuscator used for
// data-phase framing. Once set, Read and Write send and receive framed
// data: a two-byte scrambled length followed by the encrypted payload.
// It is safe to call while Read or Write is running.
func (nc *Conn) SetLengthObfuscator(slm *SipHashLengthModifier) {
	flog("NTCP2Conn.SetLengthObfuscator").Debug("Storing SipHash length obfuscator")
	nc.lengthObfuscator.Store(slm)
}

// SetNTCP2Config remembers the Config used to create this connection.
// The handshake derives the SipHash keys from that config, and
// PropagateSipHash copies them onto the connection afterwards. It is
// safe to call while PropagateSipHash is running.
func (nc *Conn) SetNTCP2Config(cfg *Config) {
	flog("NTCP2Conn.SetNTCP2Config").Debug("Storing NTCP2 config reference")
	nc.ntcp2Config.Store(cfg)
}

// PropagateSipHash copies the SipHash modifier derived during the
// handshake onto this connection, enabling framed I/O. Call it right
// after a successful Handshake().
//
// It returns an error if no config was stored (SetNTCP2Config was not
// called) or if the SipHash modifier is not available yet (the handshake
// has not finished, or SipHash is disabled).
func (nc *Conn) PropagateSipHash() error {
	cfg := nc.ntcp2Config.Load()
	if cfg == nil {
		return oops.
			Code("NO_NTCP2_CONFIG").
			In("ntcp2").
			Errorf("PropagateSipHash called but no NTCP2 config is stored")
	}
	slm := cfg.SipHashModifier()
	if slm == nil {
		return oops.
			Code("NO_SIPHASH_MODIFIER").
			In("ntcp2").
			Errorf("PropagateSipHash called but SipHash modifier is nil (handshake not complete or SipHash disabled)")
	}
	flog("NTCP2Conn.PropagateSipHash").Debug("Copying SipHash modifier from config to connection")
	nc.lengthObfuscator.Store(slm)
	return nil
}

// shouldCloseUnderlyingConn reports whether noiseConn.Close() should be called.
// Returns false when sendTCPRST already closed the socket via SetLinger+Close,
// preventing a double-close race on the file descriptor.
func (nc *Conn) shouldCloseUnderlyingConn() bool {
	return !nc.underlyingClosed.Load()
}

// Close closes the connection: it zeroes the key material and closes the
// underlying Noise connection. Close is idempotent — calling it more than
// once is safe.
func (nc *Conn) Close() error {
	var closeErr error
	nc.closeOnce.Do(func() {
		nc.logger.Debug("NTCP2 connection closing",
			"local_addr", nc.localAddr.String(),
			"remote_addr", nc.remoteAddr.String())

		nc.zeroKeyMaterial()

		// If sendTCPRST already closed the underlying TCP socket (via SetLinger
		// + Close), skip calling noiseConn.Close() to prevent a double-close.
		// A double-close is safe in Go (returns an error, no panic), but between
		// the two closes the OS could reassign the fd to a new socket; the second
		// Close() would then erroneously close that new socket.
		if !nc.shouldCloseUnderlyingConn() {
			nc.logger.Debug("skipping noiseConn.Close(): underlying socket already RST'd",
				"local_addr", nc.localAddr.String(),
				"remote_addr", nc.remoteAddr.String())
			return
		}

		err := nc.noiseConn.Close()
		if err != nil {
			// If the connection was already RST'd (broken due to AEAD error
			// or nonce exhaustion), suppress "use of closed network connection"
			// errors since the socket was intentionally closed by sendTCPRST.
			if nc.broken.Load() {
				nc.logger.Debug("suppressing close error on broken connection",
					"error", err.Error())
				return
			}
			closeErr = oops.
				Code("CLOSE_FAILED").
				In("ntcp2").
				With("local_addr", nc.localAddr.String()).
				With("remote_addr", nc.remoteAddr.String()).
				Wrapf(err, "ntcp2 close failed")
		}
	})
	return closeErr
}

// zeroKeyMaterial zeroes SipHash keys and any buffered plaintext to prevent
// sensitive data from lingering in memory after connection close. Per the
// NTCP2 spec: "routers should zero-out any in-memory ephemeral data".
func (nc *Conn) zeroKeyMaterial() {
	flog("NTCP2Conn.zeroKeyMaterial").Debug("Zeroing SipHash keys and buffered plaintext")
	if slm := nc.lengthObfuscator.Load(); slm != nil {
		slm.ZeroKeys()
	}

	// Zero the Noise cipher state key material (send and receive CipherStates).
	if nc.noiseConn != nil {
		nc.noiseConn.ZeroKeys()
	}

	// Wipe any buffered plaintext (under readMu to avoid racing with Read).
	nc.readMu.Lock()
	for i := range nc.readBuffer {
		nc.readBuffer[i] = 0
	}
	nc.readBuffer = nil
	nc.readMu.Unlock()
}

// LocalAddr returns the NTCP2 address of this end of the connection.
func (nc *Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr returns the NTCP2 address of the other end of the
// connection.
func (nc *Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline sets a single deadline that applies to both future Read and
// Write calls. A Read or Write that takes longer than the deadline returns
// an error.
func (nc *Conn) SetDeadline(t time.Time) error {
	err := nc.noiseConn.SetDeadline(t)
	if err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set deadline failed")
	}

	return nil
}

// SetReadDeadline sets a deadline for future Read calls. A Read that takes
// longer than the deadline returns an error.
func (nc *Conn) SetReadDeadline(t time.Time) error {
	err := nc.noiseConn.SetReadDeadline(t)
	if err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set read deadline failed")
	}

	return nil
}

// SetWriteDeadline sets a deadline for future Write calls. A Write that
// takes longer than the deadline returns an error.
func (nc *Conn) SetWriteDeadline(t time.Time) error {
	err := nc.noiseConn.SetWriteDeadline(t)
	if err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set write deadline failed")
	}

	return nil
}

// RouterHash returns the router hash of the peer on the other end of the
// connection. See [Addr.RouterHash] for the placeholder caveat: until
// [Conn.PropagatePeerStaticKey] has run, the value is SHA-256 of the peer's
// static key rather than a real I2P router hash.
func (nc *Conn) RouterHash() data.Hash {
	return nc.remoteAddr.RouterHash()
}

// Role returns "initiator" if this side started the connection, or
// "responder" if this side accepted it.
func (nc *Conn) Role() string {
	return nc.localAddr.Role()
}

// UnderlyingConn returns the Noise connection wrapped by this Conn. Use it
// only when you need Noise-specific features that Conn does not expose.
func (nc *Conn) UnderlyingConn() *noise.NoiseConn {
	return nc.noiseConn
}

// Rekey rotates the encryption keys of the underlying Noise connection,
// per the Noise Protocol Framework. Note that rekeying does not reset the
// nonce counters, so a connection near its nonce limit should be replaced
// with a new one instead.
//
// See [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for details.
func (nc *Conn) Rekey() error {
	return nc.noiseConn.Rekey()
}

// PropagatePeerStaticKey records the remote router's identity on the
// connection's remote address. Call it after a successful Handshake().
//
// Before the handshake, the remote address holds a placeholder zero hash.
// This method replaces it with the SHA-256 hash of the peer's static key,
// so the router transport layer can identify the peer. It is a no-op if
// the address already has a real hash. It returns an error if the peer's
// key is not available yet (the handshake has not completed).
func (nc *Conn) PropagatePeerStaticKey() error {
	peerKey := nc.noiseConn.PeerStatic()
	if len(peerKey) != RouterHashSize {
		return oops.
			Code("PEER_STATIC_KEY_UNAVAILABLE").
			In("ntcp2").
			With("got_length", len(peerKey)).
			With("want_length", RouterHashSize).
			Errorf("peer static key not yet available or has unexpected length")
	}

	// Only update if the current hash is all zeros (placeholder).
	currentHash := nc.remoteAddr.RouterHash()
	if !currentHash.IsZero() {
		return nil
	}

	// Hash the peer static key with SHA-256 rather than copying the raw
	// bytes into the Hash field. data.NewHashFromSlice stores the 32-byte
	// key verbatim, which is not SHA-256(RouterIdentity). Using
	// SHA-256(static_key) as the placeholder is consistent with how the
	// SSU2 listener builds its placeholder hash and is a closer analogue
	// to the I2P router-hash definition.
	//
	// It is still a placeholder, not RH_A: store it via
	// SetPlaceholderRouterHash so RouterHashResolved() keeps reporting false
	// until the transport layer supplies the real RouterIdentity hash.
	hash := data.HashData(peerKey)
	nc.remoteAddr.SetPlaceholderRouterHash(hash)
	return nil
}

// PeerStaticKey returns the remote router's long-term public key (32
// bytes). It is available after the handshake completes. The router
// transport layer uses it to compute the full router hash.
func (nc *Conn) PeerStaticKey() []byte {
	return nc.noiseConn.PeerStatic()
}

// HandshakeHash returns the Noise handshake hash from the completed
// session. The router transport layer uses it to derive the SipHash keys
// that scramble data-phase frame lengths (see DeriveSipHashKeys). It
// returns nil if the handshake has not started.
func (nc *Conn) HandshakeHash() []byte {
	return nc.noiseConn.ChannelBinding()
}

// snapshotNonces returns a consistent copy of the current write/read nonces.
// Callers use this for threshold checks without duplicating lock-read-unlock
// blocks across methods.
func (nc *Conn) snapshotNonces() (writeNonce, readNonce uint64) {
	nc.writeMu.Lock()
	writeNonce = nc.writeNonce
	nc.writeMu.Unlock()

	nc.readMu.Lock()
	readNonce = nc.readNonce
	nc.readMu.Unlock()

	return writeNonce, readNonce
}

// NonceExhaustionImminent reports whether the connection is close to
// running out of nonces. A nonce is a number that must never repeat for a
// given key, and the Noise Protocol's Rekey() does not reset the counter.
// When this returns true, the right response is to open a new connection
// rather than keep using this one.
func (nc *Conn) NonceExhaustionImminent() bool {
	wn, rn := nc.snapshotNonces()
	return wn >= NonceRekeyThreshold || rn >= NonceRekeyThreshold
}

// PeerMessage3Payload returns the decrypted content of message 3, part 2,
// as sent by the remote router. It is only meaningful on the responder
// side of a completed handshake; it returns nil for initiator connections
// and before the handshake succeeds.
//
// The payload is an I2P block frame. Per the NTCP2 spec it contains a
// RouterInfo block (type 2) and may also contain padding (type 254) and
// options (type 1) blocks. The router transport layer parses it and stores
// the RouterInfo so replies can be routed back to the peer.
//
// The returned slice is a copy; you may modify it freely.
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Conn) PeerMessage3Payload() []byte {
	p := nc.peerMsg3Payload.Load()
	if p == nil {
		return nil
	}
	out := make([]byte, len(*p))
	copy(out, *p)
	return out
}

// PeerRouterInfoBytes finds the RouterInfo block inside the message-3
// part-2 payload and returns just the RouterInfo bytes, with the leading
// flag byte removed. It returns nil if no payload was captured, the
// payload is malformed, or no RouterInfo block is present.
//
// Each block in the frame has this layout:
//
//	byte 0    : block type
//	bytes 1-2 : block size (two bytes, big-endian) — number of bytes that follow
//	bytes 3+  : block data (size bytes)
//
// See [I2P Spec: NTCP2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst) for details.
func (nc *Conn) PeerRouterInfoBytes() []byte {
	payload := nc.PeerMessage3Payload()
	if payload == nil {
		return nil
	}
	const blockHeader = 3 // type (1) + size (2)
	const riFlag = 1
	for off := 0; off+blockHeader <= len(payload); {
		blockType := payload[off]
		blockSize := int(payload[off+1])<<8 | int(payload[off+2])
		dataStart := off + blockHeader
		dataEnd := dataStart + blockSize
		if dataEnd > len(payload) {
			return nil // malformed: declared size overruns payload
		}
		if blockType == RouterInfoBlockType {
			if blockSize < riFlag {
				return nil
			}
			out := make([]byte, blockSize-riFlag)
			copy(out, payload[dataStart+riFlag:dataEnd])
			return out
		}
		off = dataEnd
	}
	return nil
}
