# Handshake Modifier System Example

This example demonstrates the handshake modifier system implemented in Phase 3 of the go-noise project. The modifier system provides extensible, chainable transformations for Noise protocol handshake data, enabling obfuscation and padding capabilities required for I2P transport protocols.

## Overview

The handshake modifier system consists of:

1. **HandshakeModifier Interface**: Core interface for all modifiers
2. **ModifierChain**: Chains multiple modifiers with proper ordering
3. **Built-in Modifiers**: XOR obfuscation and padding implementations
4. **ConnConfig Integration**: Builder pattern support for modifiers

## Features Demonstrated

### 1. Individual Modifiers

- **XOR Modifier**: Simple XOR-based obfuscation with configurable key patterns
- **Padding Modifier**: Adds deterministic padding with length prefix for message size obfuscation

### 2. Modifier Chaining

- **Sequential Application**: Modifiers applied in order for outbound data
- **Reverse Processing**: Modifiers applied in reverse order for inbound data  
- **Error Propagation**: Rich error context with modifier names and chain information

### 3. Phase Awareness

- **Handshake Phases**: Support for Initial, Exchange, and Final phases
- **Phase-Specific Processing**: Modifiers can behave differently per phase

### 4. Data Analysis

- **Overhead Measurement**: Shows padding overhead characteristics
- **Data Size Analysis**: Demonstrates operation with various data sizes

## Running the Example

```bash
cd examples/modifiers
go run main.go
```

## Expected Output

The example will show:
- Original handshake data (83 bytes)
- XOR transformation and recovery  
- Padding transformation and recovery
- Chain application (XOR + Padding)
- Data processing characteristics across different data sizes

## Key Design Principles

### 1. Security Preservation
- Modifiers maintain Noise protocol security guarantees
- XOR patterns don't weaken cryptographic properties
- Padding uses deterministic patterns for testing; **production implementations must use cryptographically secure random padding** to avoid weakening security.

### 2. Composability  
- Modifiers can be chained without conflicts
- Order matters: outbound applies sequentially, inbound applies in reverse
- Each modifier is independent and reusable

### 3. Resource Management
- Memory allocation tracking for transformations
- Padding overhead analysis
- Memory management without leaks

### 4. Error Handling
- Error context using samber/oops
- Modifier names and chain information in error messages
- Graceful failure with clear debugging information

## Integration with ConnConfig

```go
// Create modifiers
xorMod := handshake.NewXORModifier("obfuscation", []byte{0xAA, 0xBB})
paddingMod, _ := handshake.NewPaddingModifier("padding", 4, 8)

// Configure in connection
The second parameter to NewConnConfig, named isInitiator (bool), specifies whether this side is the initiator (true) or responder (false).
config := noise.NewConnConfig("XX", true).
    WithModifiers(xorMod, paddingMod).
    WithHandshakeTimeout(30 * time.Second)

// Modifiers are automatically applied during handshake
conn, err := noise.NewNoiseConn(underlying, config)
```

## Use Cases for I2P

### NTCP2 Transport (TCP-based) `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`

> **Pattern Explanation:**  
> The pattern string `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256` follows the [Noise Protocol naming conventions](https://noiseprotocol.org/noise.html#naming-conventions), where:
> - `Noise_` is the prefix,
> - `XKaesobfse+hs2+hs3` specifies the handshake pattern and any modifier extensions (e.g., `aesobfse` for obfuscation, `hs2`, `hs3` for handshake steps),
> - `25519` is the DH function,
> - `ChaChaPoly` is the cipher,
> - `SHA256` is the hash function.
>  
> Custom modifier names (like `aesobfse`, `hs2`, `hs3`) are appended to indicate protocol-specific extensions for I2P NTCP2.

- **Handshake obfuscation**: XOR patterns to prevent DPI fingerprinting of Noise protocol handshakes
- **Message padding**: Randomized padding to obscure actual payload sizes and timing patterns
- **Frame-level transformations**: Modifier chains applied to individual NTCP2 frames before encryption
- **Session establishment**: Phase-specific modifiers for RouterInfo exchange and session key derivation

### SSU2 Transport (UDP-based) `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`
- **Packet size normalization**: Padding to create uniform UDP packet sizes (typically 1280 bytes for IPv6 compatibility)
- **Header obfuscation**: XOR transformations on packet headers to avoid protocol detection
- **Anti-replay protection**: Modifier integration with SSU2's session tags and acknowledgment systems
- **Peer introduction**: Specialized modifiers for SSU2's hole-punching and peer introduction mechanisms

### Cross-Protocol Benefits
- **Traffic analysis resistance**: Consistent modifier patterns across both transports
- **Pluggable obfuscation**: Runtime selection of modifier chains based on network conditions
- **Bandwidth optimization**: Adaptive padding based on connection type and available bandwidth

## Implementation Notes

### Thread Safety
- All modifiers are safe for concurrent use
- ModifierChain uses defensive copying to protect against external slice modification, preventing data races and unintended side effects
- ConnConfig methods use defensive copying

### Memory Management
- Modifiers create new byte slices to avoid data corruption
- No shared mutable state between modifier instances
- Copying with minimal allocations

### Extensibility
- New modifiers implement the HandshakeModifier interface
- Existing code works with new modifier types
- Plugin-style architecture for custom transformations

This example validates the [Phase 3 acceptance criteria](../../PLAN.md#phase-3-handshake-modifier-system):
- Modifiers can be chained without conflicts
- Processing overhead varies by message size  
- Error handling provides clear debugging information
- Interface supports different handshake phases
- Integration with existing configuration system
