# go-noise

A wrapper library around the [go-i2p/noise](https://github.com/go-i2p/noise) package that provides `net.Conn`, `net.Listener`, and `net.Addr` interfaces for the Noise Protocol Framework. Designed for implementing I2P's NTCP2 and SSU2 transport protocols with extensible handshake modification capabilities.

## Notes on scope

go-i2p theoretically has strictly scoped packages for low-level operations.
This package is intended to be the package where specific modifications are applied to Noise protocol handshakes.
It is currently slightly jumbled with `go-i2p/crypto` on the lower levels, and `go-i2p/go-i2p` on the upper levels.

- [go-i2p/go-noise](https://github.com/go-i2p/go-noise): Noise handshake modifications and router interface

This package MAY use any of the following libraries, and SHOULD use them where possible.

- [go-i2p/noise](https://github.com/go-i2p/noise): Noise handshake implementations
- [go-i2p/crypto](https://github.com/go-i2p/crypto): Cryptographic primitives only
- [go-i2p/common](https://github.com/go-i2p/common): I2P Common datastructures

This package MUST NOT use any of the following libraries.

- [go-i2p/go-i2p](https://github.com/go-i2p/go-i2p): I2P router implementation
- I2P Common datastructures are not allowed in the root, unmodified noise directory.

## Features

- **Configurable Noise Patterns**: Support for all standard Noise Protocol patterns  
- **net.Conn Interface**: 
  - The core Noise connection wrapper (`conn/conn.go`) implements `net.Conn` fully but is subject to the Noise Protocol specification limit of 65535 bytes per message (from the 2-byte length prefix). That limit applies to the ciphertext frame including the 16-byte AEAD tag, so the largest single `Write` is 65519 bytes of plaintext. For automatic transparent fragmentation of larger payloads, use the transport-layer implementations below.
  - NTCP2 connections (`ntcp2/conn.go`) implement `net.Conn` with `Write` auto-fragmentation for payloads larger than the frame size.
  - SSU2 connections (`ssu2/session/conn.go`) implement `net.Conn` with `Write` auto-fragmentation. 
  - Message boundaries differ per implementation: SSU2 `Read` returns one reassembled I2NP message at a time; the core Noise `conn.Conn` and NTCP2 `Read` each return one decrypted Noise/NTCP2 frame (which may contain part of, exactly one, or several I2NP blocks). All implementations buffer any remainder that does not fit the supplied buffer and return it on the next `Read`. A callback-based message path is additionally available via `DataHandler.MessageChan()` — see [SSU2 README](ssu2/README.md) for details.
- **Error Handling**: Contextual error information using samber/oops  
- **Thread-Safe**: Concurrent connection handling with synchronization - Read/Write operations can be called concurrently, Close() is idempotent, and state access is atomic  
- **Memory Management**: Structured buffer management  

## Supported Noise Patterns

The library supports all standard Noise Protocol patterns with both short names and full specification:

- **One-way patterns**: `N`, `K`, `X`
- **Interactive patterns**: `NN`, `NK`, `NX`, `XN`, `XK`, `XX`, `KN`, `KK`, `KX`, `IN`, `IK`, `IX`
- **Full pattern names**: `Noise_XX_25519_AESGCM_SHA256`, etc.

## Quick Start

```go
package main

import (
    "context"
    "crypto/ecdh"
    "crypto/rand"
    "fmt"
    "net"
    "time"
    
    noise "github.com/go-i2p/go-noise"
)

// generateKey returns a 32-byte X25519 private key.
func generateKey() ([]byte, error) {
    key, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    return key.Bytes(), nil
}

func main() {
    // XX requires a long-term (static) private key on BOTH sides. Generate or
    // load a 32-byte Curve25519 key; the handshake fails without it.
    staticKey, err := generateKey()
    if err != nil {
        panic(err)
    }

    // Create configuration for XX pattern
    config := noise.NewConnConfig("XX", true).
        WithStaticKey(staticKey).
        WithHandshakeTimeout(10 * time.Second).
        WithReadTimeout(5 * time.Second)
    
    // Wrap an existing connection
    tcpConn, err := net.Dial("tcp", "localhost:8080")
    if err != nil {
        panic(err)
    }
    defer tcpConn.Close()
    
    // Create Noise connection
    noiseConn, err := noise.NewNoiseConn(tcpConn, config)
    if err != nil {
        panic(err)
    }
    defer noiseConn.Close()
    
    // Perform handshake
    ctx := context.Background()
    if err := noiseConn.Handshake(ctx); err != nil {
        panic(err)
    }
    
    // Use as regular net.Conn
    _, err = noiseConn.Write([]byte("Hello, Noise!"))
    if err != nil {
        panic(err)
    }
    
    buffer := make([]byte, 1024)
    n, err := noiseConn.Read(buffer)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Received: %s\n", buffer[:n])
}
```

> **Note:** The `XX` pattern authenticates both peers with static keys, so each
> side must call `WithStaticKey(...)` with its own 32-byte Curve25519 private
> key before `Handshake`. If you want a no-authentication example, use the `NN`
> pattern instead (which needs no keys but provides no identity — not for
> production).

## Configuration

### ConnConfig Options

```go
config := noise.NewConnConfig("XX", true).
    WithStaticKey(staticKey).              // 32-byte Curve25519 private key
    WithHandshakeTimeout(30*time.Second).  // Handshake timeout
    WithReadTimeout(5*time.Second).        // Read operation timeout
    WithWriteTimeout(5*time.Second)        // Write operation timeout
```

### Pattern Selection

Choose the appropriate pattern based on your security requirements:

- **XX**: Mutual authentication with ephemeral keys
- **IK**: Initiator knows responder's static key
- **XK**: Initiator knows responder's static key, responder authenticates
- **NK**: Responder has known static key, one-way authentication
- **NN**: No authentication, only encryption (not recommended for production)

## Connection State Management

The library provides connection state tracking and metrics:

```go
// Check connection state
state := noiseConn.GetConnectionState()
switch state {
case noise.StateInit:
    fmt.Println("Connection created, handshake not started")
case noise.StateHandshaking:
    fmt.Println("Handshake in progress")
case noise.StateEstablished:
    fmt.Println("Handshake complete, ready for secure communication")
case noise.StateClosed:
    fmt.Println("Connection closed")
}

// Get connection metrics
bytesRead, bytesWritten, handshakeDuration := noiseConn.GetConnectionMetrics()
fmt.Printf("Transferred %d bytes read, %d bytes written\n", bytesRead, bytesWritten)
fmt.Printf("Handshake completed in %v\n", handshakeDuration)
```

### State Transitions

Connections follow this lifecycle:

1. **Init** → Created with `NewNoiseConn()`
2. **Handshaking** → `Handshake()` called
3. **Established** → Handshake completed successfully
4. **Closed** → `Close()` called or connection failed

### Monitoring

The library tracks:

- **Handshake Duration**: Time taken to complete the Noise handshake
- **Bytes Read/Written**: Total data transferred (plaintext, not encrypted)
- **Connection Lifecycle**: Creation time and state transitions

## Implementation Status

Core Noise and NTCP2 implementations completed. SSU2 implementation in beta.

## Packages

### Core: Noise Protocol Transport

The root package provides `net.Conn`, `net.Listener`, and `net.Addr` wrappers
for the Noise Protocol Framework, used by I2P's NTCP2 transport.

`Transport` is the entry point for dialing and listening. Each `Transport`
owns its connection pool and shutdown manager, so separate parts of a program
do not share (or race over) package-level state:

```go
transport := noise.NewTransport(pool.NewConnPool(cfg), noise.NewShutdownManager(30*time.Second))
defer transport.GracefulShutdown()

conn, err := transport.DialWithHandshake("tcp", "127.0.0.1:8080", config)
```

`WrapConn` / `WrapListener` remain for wrapping an already-established
`net.Conn` / `net.Listener`. The former package-level `DialNoise*` /
`ListenNoise*` functions and the shared `Default` transport have been removed;
use a `Transport` method instead (the `examples/exampleutil` helpers show the
pattern used by the example programs).

#### NTCP2 note: `BobRouterHash` is the responder's hash

`ntcp2.NewNTCP2Config(bobRouterHash, initiator)` takes **RH_B**, the
*responder's* router hash. It is the AES key for the obfuscated ephemeral keys
in handshake messages 1 and 2 (ntcp2.md §"1) SessionRequest": "AES encryption
uses Bob's router hash as the key"; §"2) Created": same). For an initiator that
is the **peer's** identity, not your own. Set `WithLocalRouterHash` to this
side's own hash so `LocalAddr()` on a dialed connection reports your identity
rather than the peer's.

Configuration validation now rejects an initiator whose `BobRouterHash` is zero
(`MISSING_BOB_ROUTER_HASH`, when AES obfuscation is enabled) or disagrees with
`WithRemoteRouterHash` (`BOB_ROUTER_HASH_MISMATCH`) — both would otherwise
obfuscate with a key no conformant peer can decrypt.

### `ratchet/` — ECIES-X25519-AEAD-Ratchet

The [`ratchet`](ratchet/) package provides the ECIES-X25519-AEAD-Ratchet
cryptographic engine for I2P's end-to-end garlic encryption:

- **Garlic sessions**: Double-ratchet encrypt/decrypt with DH ratchet rotation
- **Build record crypto**: ChaCha20-Poly1305 and ECIES for tunnel build records
- **Interface-based**: All APIs defined via interfaces for testability

See [`ratchet/README.md`](ratchet/README.md) for detailed API documentation.

### `ntcp2/` — NTCP2 Transport Helpers

The `ntcp2` package provides NTCP2-specific connection handling, replay
detection (`ReplayCache`), and KDF utilities.

## Architecture

```
NoiseConn (net.Conn)
├── Config (pattern, keys, timeouts)
├── HandshakeState (go-i2p/noise)
├── CipherState (post-handshake encryption)
├── NoiseAddr (net.Addr with pattern info)
└── Underlying net.Conn (TCP, UDP, etc.)
```

## Dependencies

Direct requirements, as declared in `go.mod`:

- **go-i2p/noise**: Core Noise Protocol implementation
- **go-i2p/crypto**: Cryptographic primitives — `curve25519`, `chacha20`,
  `chacha20poly1305`, `aes`, `siphash`, `hkdf`, `hmac`, `kdf`, `ecies`,
  `elligator2`, `ed25519`, `ratchet`, `rand`
- **go-i2p/common**: I2P common data structures — `data`, `router_info`,
  `router_identity`, `router_address`, `signature`, `keys_and_cert`,
  `key_certificate`, `base64`
- **go-i2p/path**: SSU2 relay, hole-punch and path-validation logic, re-exported
  through `ssu2` and `ssu2/session` and used by `ssu2/server`
- **go-i2p/pool**: Connection pooling used by the root `transport.go` and
  `pool_wrapper.go`
- **go-i2p/logger**: Structured logging support
- **samber/oops**: Rich error context
- **stretchr/testify**: Assertions, declared as a direct requirement because the
  `internal/testri` fixture helper is a regular (non-`_test`) source file

`go-i2p/path` and `go-i2p/go-noise` reference each other at the module level
(`path` imports `go-noise/ssu2/wire`), but there is no package cycle:
`go-noise/ssu2/wire` imports nothing from `path`. The pins do form a
release-ordering constraint — see the upstream report
`go-i2p/bugs/path-ssu2-path-validation-and-build.md`.

## Logging

This library uses [`go-i2p/logger`](https://github.com/go-i2p/logger) for structured logging across all packages. Logging is controlled via environment variables:

| Variable | Values | Description |
|---|---|---|
| `DEBUG_I2P` | `debug`, `warn`, `error` | Sets log level. Unset = no output. |
| `WARNFAIL_I2P` | any non-empty value | Promotes warnings to fatal errors (useful for CI). Only read when `DEBUG_I2P` is also set, so `WARNFAIL_I2P` has no effect on its own; the value is not compared to `true` — any non-empty string arms it. |

Most packages have a dedicated `log.go` file that initializes a package-level logger:

```go
var log = logger.GetGoI2PLogger()
```

Every log call includes structured `pkg` and `func` fields for filtering and tracing:

```go
log.WithFields(logger.Fields{
    "pkg":     "noise",
    "func":    "NewConnConfig",
    "pattern": config.Pattern,
}).Debug("Creating new connection config")

log.WithFields(logger.Fields{
    "pkg":  "ntcp2",
    "func": "Handshake",
}).WithError(err).Error("Handshake failed")
```

Values used in the `pkg` field include: `noise`, `conn`, `handshake`, `handshake/siphash`, `ntcp2`, `ratchet`, `replaycache`, `mod`, `mod/validation`, `validation`, `ssu2`, `config`, `session`, `server`, `wire`, `reliability`, `internal/cryptorand`, and `internal/securemem`.

### Running Tests with Logging

```bash
# Default (no log output)
go test ./...

# With debug logging
DEBUG_I2P=debug go test ./...

# With warn-fail mode (warnings become fatal)
# Note: WARNFAIL_I2P=true exercises warn-level paths in production code,
# but many intentional warn-path tests will fail because they deliberately
# trigger warnings. For the full test suite, use DEBUG_I2P=debug without
# WARNFAIL_I2P. For CI validation of production warnings, run WARNFAIL_I2P
# only on the production-path subset below.
WARNFAIL_I2P=true DEBUG_I2P=debug go test ./...

# Production-path test subset for CI (WARNFAIL_I2P compatible):
# These packages contain only production-path tests that should not trigger warnings.
# DEBUG_I2P must be set: go-i2p/logger only reads WARNFAIL_I2P when DEBUG_I2P is
# non-empty, so WARNFAIL_I2P on its own is a no-op.
WARNFAIL_I2P=true DEBUG_I2P=debug go test -count=1 \
  ./conn \
  ./internal/securemem \
  ./mod/... \
  ./ssu2/config \
  ./ssu2/handshake \
  ./ssu2/reliability \
  ./ssu2/server \
  ./tests/...
```

## Testing

```bash
go test -v ./...
```

Current test coverage includes unit and integration tests for core functionality across all components:

- Handshake pattern parsing and validation
- Configuration validation  
- NoiseAddr interface compliance
- NoiseConn read/write operations and error handling
- NTCP2Addr I2P-specific addressing functionality
- NTCP2Conn net.Conn interface compliance and error wrapping
- Handshake modifier chaining and transformations
- Error handling scenarios across all components

### Test Organization

The test suite is organized into two levels:

- **Per-package tests** (`*_test.go` files): Unit and integration tests live alongside their source code. Each package includes focused tests for its own functionality.
  - `conn/conn_test.go`, `conn/config_test.go`, `transport_test.go`, etc. test their respective packages in isolation
  - Some packages include integration tests (e.g., `conn/integration_test.go`, `ntcp2/e2e_integration_test.go`) for testing cross-package interaction

- **`tests/` directory**: Cross-package and performance tests that depend on multiple modules:
  - `tests/integration/`: Integration tests exercising the pool, config, and connection layers together
  - `tests/benchmarks/`: Performance benchmarks for measuring throughput and memory usage of pooling and connection operations

The `tests/` directory layout keeps cross-cutting concerns separate from individual package tests, improving test organization when a test depends on multiple components that don't belong in any single package.

## Contributing

This library follows Go best practices:

- Functions under 30 lines with single responsibility
- Explicit error handling (no ignored returns)
- Self-documenting code with clear naming
- Unit and integration testing with coverage monitoring

## License

MIT License

## Status

**Development Status**: Core functionality, handshake modification system, connection pooling, and listener features implemented. SSU2 transport in beta.
