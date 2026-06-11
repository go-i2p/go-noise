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

// Conn implements net.Conn for NTCP2 transport connections.
// It wraps a NoiseConn with NTCP2-specific addressing and protocol handling.
//
// This package implements the Noise XK handshake with NTCP2 extensions
// (AES ephemeral key obfuscation, SipHash frame length obfuscation, and
// cleartext padding). It provides framed I/O (SipHash-obfuscated length
// prefix + ChaChaPoly AEAD) and probing resistance on AEAD failures.
//
// Higher-level concerns — I2NP message parsing, block framing (types 0–9),
// termination blocks, options negotiation, timestamp validation, replay
// caches, and version detection — belong in the router transport layer
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

	// underlyingClosed is set when sendTCPRST has already closed the TCP socket
	// via SetLinger(0)+Close(). Close() checks this flag and skips the second
	// noiseConn.Close() call to prevent an fd-reuse double-close race.
	underlyingClosed atomic.Bool

	// writeNonce tracks the number of frames written (data-phase encrypt operations).
	// The connection MUST be terminated before this reaches MaxNonce (2^64-2).
	// Only accessed under writeMu.
	writeNonce uint64

	// readNonce tracks the number of frames read (data-phase decrypt operations).
	// The connection MUST be terminated before this reaches MaxNonce (2^64-2).
	// Only accessed under readMu.
	readNonce uint64

	// OnAEADError is an optional callback invoked during AEAD failure handling,
	// after the probing-resistance junk-read phase but before the TCP RST.
	// The router transport layer can use this to send a termination block
	// (type 4, reason 4 = "AEAD failure") before the connection is killed.
	// The callback receives the underlying net.Conn for direct writing;
	// the NTCP2Conn's broken flag is already set, so normal Write() is blocked.
	// If nil, no termination block is sent (current behaviour).
	OnAEADError func(conn net.Conn)

	// logger for connection events (pointer so runtime log-level changes are visible)
	logger *logger.Logger

	// handshakeDeadline is the absolute deadline set by Accept() for the full
	// handshake window. When non-zero, Handshake() will not extend the deadline
	// beyond this value, ensuring the total window (accept→handshake) is bounded
	// to a single HandshakeTimeout. BUG-RC-2 / BUG-SM-2.
	handshakeDeadline time.Time
}

// NewNTCP2Conn creates a new NTCP2Conn wrapping the provided NoiseConn.
// The NoiseConn must already be configured with appropriate NTCP2 modifiers.
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

// SetLengthObfuscator sets the SipHash length obfuscator for data-phase framing.
// When set, Read/Write will use framed I/O with SipHash-obfuscated length prefixes.
// This is safe to call concurrently with Read/Write (uses atomic.Pointer).
func (nc *Conn) SetLengthObfuscator(slm *SipHashLengthModifier) {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Conn.SetLengthObfuscator"}).Debug("Storing SipHash length obfuscator")
	nc.lengthObfuscator.Store(slm)
}

// SetNTCP2Config stores a reference to the originating NTCP2Config so that
// PropagateSipHash can copy PostHandshakeHook-derived keys after handshake.
// This is safe to call concurrently with PropagateSipHash (uses atomic.Pointer).
func (nc *Conn) SetNTCP2Config(cfg *Config) {
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Conn.SetNTCP2Config"}).Debug("Storing NTCP2 config reference")
	nc.ntcp2Config.Store(cfg)
}

// PropagateSipHash copies the SipHash modifier from the stored NTCP2Config
// (populated by the PostHandshakeHook during Handshake) into this connection's
// lengthObfuscator. Call this immediately after a successful Handshake().
//
// Returns an error if:
// - No NTCP2 config is stored (SetNTCP2Config was not called)
// - The SipHash modifier is nil (PostHandshakeHook has not yet executed or SipHash is disabled)
//
// This prevents silent no-op behavior when PropagateSipHash is called before the handshake completes.
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
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Conn.PropagateSipHash"}).Debug("Copying SipHash modifier from config to connection")
	nc.lengthObfuscator.Store(slm)
	return nil
}

// Close implements net.Conn.Close.
// Closes the underlying Noise connection, zeroes key material, and cleans up
// resources. Close is idempotent — calling it multiple times is safe.
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
		if nc.underlyingClosed.Load() {
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
	log.WithFields(logger.Fields{"pkg": "ntcp2", "func": "NTCP2Conn.zeroKeyMaterial"}).Debug("Zeroing SipHash keys and buffered plaintext")
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

// LocalAddr implements net.Conn.LocalAddr.
// Returns the NTCP2-specific local address.
func (nc *Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr implements net.Conn.RemoteAddr.
// Returns the NTCP2-specific remote address.
func (nc *Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline implements net.Conn.SetDeadline.
// Sets read and write deadlines on the underlying connection.
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

// SetReadDeadline implements net.Conn.SetReadDeadline.
// Sets the read deadline on the underlying connection.
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

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
// Sets the write deadline on the underlying connection.
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

// RouterHash returns the router hash from the remote address.
// This is I2P-specific functionality for NTCP2 connections.
func (nc *Conn) RouterHash() data.Hash {
	return nc.remoteAddr.RouterHash()
}

// Role returns the connection role (initiator or responder).
func (nc *Conn) Role() string {
	return nc.localAddr.Role()
}

// UnderlyingConn returns the underlying NoiseConn for advanced operations.
// This allows access to Noise-specific functionality when needed.
func (nc *Conn) UnderlyingConn() *noise.NoiseConn {
	return nc.noiseConn
}

// Rekey triggers a rekey operation on the underlying Noise connection.
// This delegates to NoiseConn.Rekey(), which advances the encryption key
// material per the Noise Protocol specification.
//
// This method allows NTCP2Conn to satisfy a Rekeyer interface:
//
//	type Rekeyer interface { Rekey() error }
func (nc *Conn) Rekey() error {
	return nc.noiseConn.Rekey()
}

// PropagatePeerStaticKey extracts the remote peer's Noise static public key
// from the completed handshake and updates the remote NTCP2 address's router
// hash. This must be called after a successful Handshake() to replace the
// placeholder zero hash that was used before the peer's identity was known
// (e.g., on inbound/responder connections).
//
// If the peer static key is not available (handshake not completed) or the
// remote address already has a non-zero router hash, this is a no-op.
// PropagatePeerStaticKey stores the peer's Noise static public key in the
// remote address's router-hash field so the router transport layer can use
// it for session deduplication. Returns an error when the key is not yet
// available (handshake not complete) or the key length is unexpected.
//
// BUG-EH-4: previously returned nothing, making a no-op (key not yet
// available) indistinguishable from success.
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

	// AUDIT 5.3: Hash the peer static key with SHA-256 rather than copying
	// the raw bytes into the Hash field.  data.NewHashFromSlice stores the
	// 32-byte key verbatim, which is not SHA-256(RouterIdentity).  Using
	// SHA-256(static_key) as the placeholder is consistent with how the
	// SSU2 listener builds its placeholder hash and is a closer analogue
	// to the I2P router-hash definition.
	hash := data.HashData(peerKey)
	nc.remoteAddr.SetRouterHash(hash)
	return nil
}

// PeerStaticKey returns the remote peer's Noise static public key (32 bytes).
// This is available after the handshake completes and can be used by the
// router transport layer (github.com/go-i2p/go-i2p/lib/transport/ntcp) to
// compute the full router hash via SHA-256(RouterIdentity) using
// github.com/go-i2p/common/router_identity.
func (nc *Conn) PeerStaticKey() []byte {
	return nc.noiseConn.PeerStatic()
}

// HandshakeHash returns the Noise handshake hash (h) from the completed session.
// This is needed by the router transport layer to derive data-phase keys via
// DeriveSipHashKeys(ask_master, h) for SipHash frame length obfuscation.
// Returns nil if the handshake has not been initiated.
func (nc *Conn) HandshakeHash() []byte {
	return nc.noiseConn.ChannelBinding()
}

// NonceExhaustionImminent returns true if either the read or write nonce
// counter has reached NonceRekeyThreshold, indicating that the connection
// is approaching the maximum nonce limit and should be replaced.
//
// The Noise Protocol's Rekey() operation does NOT reset nonce counters,
// so the correct response to imminent exhaustion is to establish a new
// connection rather than attempt a rekey.
func (nc *Conn) NonceExhaustionImminent() bool {
	nc.writeMu.Lock()
	wn := nc.writeNonce
	nc.writeMu.Unlock()

	nc.readMu.Lock()
	rn := nc.readNonce
	nc.readMu.Unlock()

	return wn >= NonceRekeyThreshold || rn >= NonceRekeyThreshold
}

// PeerMessage3Payload returns the decrypted plaintext of NTCP2 message 3
// part 2 received from the remote peer. This is meaningful only on the
// responder side of a completed inbound handshake; it returns nil for
// initiator connections and before Handshake() succeeds.
//
// The payload is the I2NP block frame as transmitted by Alice. Per the
// NTCP2 spec it contains a RouterInfo block (type 2) and may contain
// optional padding (type 254) and options (type 1) blocks. The router
// transport layer is responsible for parsing this and storing Alice's
// RouterInfo in the local NetDB / peer cache so that direct replies
// (e.g. ShortTunnelBuildReply for 1-hop outbound tunnels) can be routed
// back to her NTCP2 address.
//
// The returned slice is a defensive copy and may be modified freely.
func (nc *Conn) PeerMessage3Payload() []byte {
	p := nc.peerMsg3Payload.Load()
	if p == nil {
		return nil
	}
	out := make([]byte, len(*p))
	copy(out, *p)
	return out
}

// PeerRouterInfoBytes is a convenience wrapper around PeerMessage3Payload
// that locates the RouterInfo block (type 2) inside the message-3 part-2
// frame and returns just the inner RouterInfo bytes (with the 1-byte
// flag field stripped). Returns nil if no payload was captured, the
// payload is malformed, or no RouterInfo block is present.
//
// Block frame layout (per NTCP2 spec §5):
//
//	byte 0    : block type
//	bytes 1-2 : block size (uint16, big-endian) — number of bytes that follow
//	bytes 3+  : block data (size bytes)
//
// For the RouterInfo block (type 2) the first data byte is a flag field;
// the remaining bytes are the serialized RouterInfo.
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
		if blockType == routerInfoBlockType {
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
