# go-noise

A wrapper library around the flynn/noise package that provides `net.Conn`, `net.Listener`, and `net.Addr` interfaces for the Noise Protocol Framework. Designed for implementing I2P's NTCP2 and SSU2 transport protocols with extensible handshake modification capabilities.

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
- **net.Conn Interface**: The core Noise connection wrapper (`conn/conn.go`) implements `net.Conn` fully. NTCP2 connections (`ntcp2/conn.go`) implement `net.Conn`. SSU2 connections (`ssu2/session/conn.go`) also implement the full `net.Conn` interface: `Read` returns one I2NP message at a time (buffering any remainder that does not fit the supplied buffer) and `Write` auto-fragments. A callback-based message path is additionally available via `DataHandler.MessageChan()` — see [SSU2 README](ssu2/README.md) for details.  
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
    "fmt"
    "net"
    "time"
    
    "github.com/go-i2p/go-noise"
)

func main() {
    // Create configuration for XX pattern
    config := noise.NewConnConfig("XX", true).
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
├── HandshakeState (flynn/noise)
├── CipherState (post-handshake encryption)
├── NoiseAddr (net.Addr with pattern info)
└── Underlying net.Conn (TCP, UDP, etc.)
```

## Dependencies

- **flynn/noise** v1.1.0: Core Noise Protocol implementation
- **go-i2p/logger**: Structured logging support
- **samber/oops** v1.19.0: Rich error context

## Logging

This library uses [`go-i2p/logger`](https://github.com/go-i2p/logger) for structured logging across all packages. Logging is controlled via environment variables:

| Variable | Values | Description |
|---|---|---|
| `DEBUG_I2P` | `debug`, `warn`, `error` | Sets log level. Unset = no output. |
| `WARNFAIL_I2P` | `true` | Promotes warnings to fatal errors (useful for CI). |

Each package has a dedicated `log.go` file that initializes a package-level logger:

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

Available `pkg` values: `noise`, `handshake`, `internal`, `replaycache`, `ntcp2`, `pool`, `ratchet`, `ssu2`.

### Running Tests with Logging

```bash
# Default (no log output)
go test ./...

# With debug logging
DEBUG_I2P=debug go test ./...

# With warn-fail mode (warnings become fatal)
WARNFAIL_I2P=true DEBUG_I2P=debug go test ./...
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
