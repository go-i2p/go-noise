# go-noise

A wrapper library around the flynn/noise package that provides `net.Conn`, `net.Listener`, and `net.Addr` interfaces for the Noise Protocol Framework. Designed for implementing I2P's NTCP2 and SSU2 transport protocols with extensible handshake modification capabilities.

## Features

- **Configurable Noise Patterns**: Support for all standard Noise Protocol patterns  
- **net.Conn Interface**: Compatible with Go's standard network interfaces  
- **Error Handling**: Contextual error information using samber/oops  
- **Thread-Safe**: Concurrent connection handling with synchronization  
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
- **NK**: Responder has known static key, one-way authentication
- **NN**: No authentication, only encryption (not recommended for production)

## Connection State Management

The library provides connection state tracking and metrics:

```go
// Check connection state
state := noiseConn.GetConnectionState()
switch state {
case internal.StateInit:
    fmt.Println("Connection created, handshake not started")
case internal.StateHandshaking:
    fmt.Println("Handshake in progress")
case internal.StateEstablished:
    fmt.Println("Handshake complete, ready for secure communication")
case internal.StateClosed:
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

Core Noise and NTCP2 implementations completed. SSU2 implementation planned.

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

**Development Status**: Core functionality and handshake modification system implemented. Connection pooling and listener features in development.
