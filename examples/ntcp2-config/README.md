# NTCP2Config - Builder Pattern Configuration Example

This example demonstrates the `NTCP2Config` builder pattern implementation from Phase 3 of the go-noise project. The `NTCP2Config` provides a fluent interface for configuring NTCP2 connections with all the necessary I2P-specific parameters.

## Overview

The `NTCP2Config` is a configuration system that:

1. **Follows Established Patterns**: Uses the same builder pattern as the main `ConnConfig`
2. **NTCP2-Specific**: Includes I2P NTCP2-specific configuration options
3. **Extensible**: Supports custom handshake modifiers and obfuscation settings
4. **Validated**: Configuration validation with clear error messages
5. **Convertible**: Can be converted to standard `ConnConfig` for use with `NoiseConn`

## Key Features

### 1. Builder Pattern Configuration

```go
config, err := ntcp2.NewNTCP2Config(routerHash, true) // true = initiator
if err != nil {
    log.Fatal(err)
}

config = config.
    WithStaticKey(staticKey).
    WithRemoteRouterHash(remoteHash).
    WithHandshakeTimeout(45 * time.Second).
    WithHandshakeRetries(5).
    WithRetryBackoff(2 * time.Second)
```

### 2. NTCP2-Specific Features

- **AES Obfuscation**: Configurable AES-based ephemeral key obfuscation
- **SipHash Length**: Frame length obfuscation using SipHash-2-4
- **Frame Settings**: Configurable frame sizes and padding parameters
- **Router Identity**: Support for I2P router hash addressing

### 3. Security Options

```go
config = config.
    WithAESObfuscation(true, customIV).              // Custom IV for AES
    WithSipHashLength(true, k1, k2).                 // Custom SipHash keys
    WithFrameSettings(32768, true, 16, 128).         // 32KB frames, 16-128 byte padding
    WithModifiers(xorMod, paddingMod)                // Additional custom modifiers
```

### 4. Validation and Error Handling

The configuration includes comprehensive validation:

- Router hash must be exactly 32 bytes
- Static keys must be 32 bytes for Curve25519
- Initiator connections require remote router hash
- Timeout values must be positive
- Frame and padding settings must be reasonable

### 5. Integration with NoiseConn

```go
connConfig, err := ntcp2Config.ToConnConfig()
if err != nil {
    return err
}

// connConfig now includes NTCP2-specific modifiers and can be used with NoiseConn
```

## Configuration Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `Pattern` | Noise protocol pattern | "XK" | Yes |
| `Initiator` | Handshake initiator flag | - | Yes |
| `RouterHash` | Local router identity | - | Yes |
| `StaticKey` | Long-term static key | nil | No |
| `RemoteRouterHash` | Remote router identity | nil | Yes (initiator) |
| `HandshakeTimeout` | Handshake completion timeout | 30s | No |
| `ReadTimeout` | Post-handshake read timeout | 0 (none) | No |
| `WriteTimeout` | Post-handshake write timeout | 0 (none) | No |
| `HandshakeRetries` | Retry attempts | 3 | No |
| `RetryBackoff` | Base retry delay | 1s | No |
| `EnableAESObfuscation` | AES ephemeral key obfuscation | true | No |
| `ObfuscationIV` | Custom AES IV | derived | No |
| `EnableSipHashLength` | Frame length obfuscation | true | No |
| `SipHashKeys` | Custom SipHash keys | derived | No |
| `MaxFrameSize` | Maximum frame size | 16384 | No |
| `FramePaddingEnabled` | Frame padding | true | No |
| `MinPaddingSize` | Minimum padding | 0 | No |
| `MaxPaddingSize` | Maximum padding | 64 | No |
| `Modifiers` | Custom handshake modifiers | empty | No |

## Usage Examples

### Basic Responder (Listener)

```go
routerHash := getLocalRouterHash() // 32 bytes

config, err := ntcp2.NewNTCP2Config(routerHash, false)
if err != nil {
    return err
}

config = config.
    WithStaticKey(staticKey).
    WithHandshakeTimeout(45 * time.Second)

listener, err := ntcp2.NewNTCP2Listener(tcpListener, config)
```

### Advanced Initiator (Client)

```go
config, err := ntcp2.NewNTCP2Config(localRouterHash, true)
if err != nil {
    return err
}

config = config.
    WithStaticKey(staticKey).
    WithRemoteRouterHash(remoteRouterHash).
    WithHandshakeRetries(5).
    WithFrameSettings(32768, true, 32, 256)

connConfig, err := config.ToConnConfig()
if err != nil {
    return err
}

conn, err := noise.NewNoiseConn(tcpConn, connConfig)
```

### Development/Testing Configuration

```go
// Minimal configuration for testing (no obfuscation)
config, err := ntcp2.NewNTCP2Config(routerHash, false)
if err != nil {
    return err
}

config = config.
    WithAESObfuscation(false, nil).
    WithSipHashLength(false, 0, 0).
    WithFrameSettings(16384, false, 0, 0)
```

## Configuration Considerations

### Frame Size Selection

- **Small frames (16KB)**: Suitable for interactive applications
- **Large frames (64KB)**: Suitable for bulk data transfer
- **Padding**: Improves security but increases bandwidth usage

### Retry Configuration

- **Conservative**: 3 retries with 1s backoff (default)
- **Aggressive**: 5-10 retries with 500ms backoff (low-latency networks)
- **Persistent**: -1 retries (infinite) for critical connections

### Obfuscation Options

- **Full obfuscation**: Traffic analysis resistance
- **Selective obfuscation**: Balance security and functionality
- **No obfuscation**: Testing only, not recommended for production

## Error Handling

The configuration uses rich error context with `samber/oops`:

```go
err := config.Validate()
if err != nil {
    // Error includes operation context, parameter values, and error codes
    fmt.Printf("Configuration error: %v\n", err)
    // Example: "router hash must be exactly 32 bytes [hash_length=16]"
}
```

## Integration with I2P Ecosystem

The `NTCP2Config` is designed to integrate with the I2P ecosystem:

- **Router Identity**: Uses standard I2P router hash format
- **Cryptography**: Compatible with `go-i2p/crypto` for key derivation
- **Logging**: Integrates with `go-i2p/logger` for structured logging
- **Error Handling**: Uses project-standard `samber/oops` error wrapping

## Running the Example

```bash
cd examples/ntcp2-config
go run main.go
```

The example demonstrates all major configuration patterns and validates that the implementation follows the established builder pattern conventions.

## Implementation Status

✅ **Completed Features:**
- Builder pattern configuration following established conventions
- NTCP2-specific parameter support
- Comprehensive validation with clear error messages
- Integration with existing handshake modifier system
- Conversion to standard `ConnConfig` for `NoiseConn` integration
- Extensive test coverage with both success and failure scenarios

This implementation satisfies the Phase 3 acceptance criteria:
- ✅ NTCP2 configuration follows established builder pattern conventions
- ✅ All configuration parameters properly validated
- ✅ Thread-safe operations with defensive copying
- ✅ Integration with existing modifier and error handling systems
