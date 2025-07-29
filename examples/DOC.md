# go-noise Examples Documentation

## Overview

The examples directory contains comprehensive demonstrations of the go-noise library functionality, organized by use case and following established architecture patterns. All examples have been refactored to ensure consistent argument handling and comprehensive Noise Protocol pattern support.

## Refactored Examples

The following examples have been updated to follow the established go-noise architecture patterns:

### ✅ Completed Refactoring

1. **ntcp2-config** - NTCP2Config builder pattern demonstration
   - ✅ Uses `ntcp2shared.ParseNTCP2Args()` for argument parsing
   - ✅ Supports `-demo`, `-generate`, `-server`, `-client` modes
   - ✅ Demonstrates builder pattern configuration with proper NTCP2 features
   - ✅ Includes comprehensive argument validation and error handling

### ✅ Already Well-Refactored

These examples were already following the established patterns:

1. **basic** - General Noise Protocol demonstration with all 15 patterns
2. **echoclient** - Echo client supporting all Noise patterns
3. **echoserver** - Echo server supporting all Noise patterns  
4. **listener** - NoiseListener demonstration with pattern support
5. **pool** - Connection pooling with Noise handshakes
6. **retry** - Handshake retry mechanisms
7. **shutdown** - Graceful shutdown demonstration
8. **state** - Connection state management
9. **transport** - Transport wrapping functionality
10. **ntcp2** - NTCP2 addressing demonstration
11. **ntcp2-listener** - NTCP2Listener with I2P router identity management

### ✅ Specialized Examples (No Refactoring Needed)

1. **modifiers** - Pure handshake modifier system demo (no network patterns needed)

## Architecture Compliance

All refactored examples now follow these patterns:

### Argument Parsing
- **General examples**: Use `shared.ParseCommonArgs()` for standard Noise patterns
- **NTCP2 examples**: Use `ntcp2shared.ParseNTCP2Args()` for NTCP2-specific functionality
- **Validation**: All use `args.ValidateArgs()` for comprehensive validation

### Pattern Support
- **General examples**: Support all 15 standard Noise patterns (N, K, X, NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX)
- **NTCP2 examples**: Use IK pattern exclusively as per I2P specification
- **Short/Full names**: Support both "XX" and "Noise_XX_25519_AESGCM_SHA256" formats

### Key Requirements
Automatic handling based on pattern requirements:
- **No keys required**: N, NN, NK, NX, XN, IN, IX
- **Local static key**: X, XX, KN, KK, KX, IK, IX
- **Remote static key**: K, NK, XK, KN, KK, KX, IK, IN
- **Both keys**: K, XK, KK, IK

### Configuration Pattern
All examples use the ConnConfig builder pattern:
```go
config := noise.NewConnConfig(pattern, initiator).
    WithHandshakeTimeout(timeout).
    WithReadTimeout(readTimeout).
    WithWriteTimeout(writeTimeout).
    WithStaticKey(staticKey)
```

### Operation Modes
Consistent support for:
- `-demo`: Demonstration mode with pattern explanations
- `-generate`: Generate cryptographic keys for testing
- `-server addr`: Run as server/responder
- `-client addr`: Run as client/initiator

## Usage Examples

### General Noise Protocol Examples

```bash
# Run demo showing all patterns
go run examples/basic/main.go -demo

# Generate keys for testing
go run examples/basic/main.go -generate

# Run server with XX pattern
go run examples/basic/main.go -server localhost:8080 -pattern XX -static-key <key>

# Run client with NN pattern (no keys required)
go run examples/echoclient/main.go -client localhost:8080 -pattern NN
```

### NTCP2-Specific Examples

```bash
# NTCP2 configuration demo
go run examples/ntcp2-config/main.go -demo

# Generate NTCP2 material
go run examples/ntcp2-config/main.go -generate

# NTCP2 listener
go run examples/ntcp2-listener/main.go -server localhost:7654 -router-hash <hash>

# NTCP2 with custom features
go run examples/ntcp2-config/main.go -demo -aes-obfuscation=false -max-frame-size=32768
```

## Pattern Testing

All examples can be tested with different patterns:

```bash
# Test with different patterns
for pattern in NN NK XX IK; do
    echo "Testing pattern: $pattern"
    go run examples/basic/main.go -demo -pattern $pattern
done
```

## Key Generation

Examples automatically generate required keys when missing, or you can pre-generate:

```bash
# Generate keys for manual use
go run examples/basic/main.go -generate
# Copy the generated keys for use in server/client commands

# NTCP2 key generation
go run examples/ntcp2-config/main.go -generate
```

## Error Handling

All examples include:
- Comprehensive argument validation
- Pattern requirement checking
- Key format validation (64-character hex strings for 32-byte keys)
- Mutual exclusion of operation modes
- Graceful error messages with usage information

## Testing the Refactoring

To verify all examples work correctly:

```bash
cd /home/idk/go/src/github.com/go-i2p/go-noise

# Test general examples
for example in basic echoclient echoserver listener pool retry shutdown state transport; do
    echo "Testing $example demo mode..."
    go run examples/$example/main.go -demo > /dev/null && echo "✅ $example" || echo "❌ $example"
done

# Test NTCP2 examples  
for example in ntcp2 ntcp2-config ntcp2-listener; do
    echo "Testing $example demo mode..."
    go run examples/$example/main.go -demo > /dev/null && echo "✅ $example" || echo "❌ $example"
done

# Test modifier system
echo "Testing modifiers..."
go run examples/modifiers/main.go > /dev/null && echo "✅ modifiers" || echo "❌ modifiers"
```

This refactoring ensures all examples follow consistent patterns, provide comprehensive argument handling, and demonstrate the full capabilities of the go-noise library across all supported Noise Protocol variants.
