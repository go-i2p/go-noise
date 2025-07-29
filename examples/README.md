# go-noise Examples

This directory contains examples demonstrating the usage of the go-noise library with proper command-line argument handling and support for all Noise Protocol patterns.

## Example Categories

### General Noise Protocol Examples
Examples supporting all standard Noise patterns with proper key management:

- **[basic/](basic/)** - Basic Noise Protocol usage with configurable patterns
- **[echoserver/](echoserver/)** - Echo server supporting all Noise patterns  
- **[echoclient/](echoclient/)** - Echo client supporting all Noise patterns
- **[listener/](listener/)** - Noise listener examples with pattern support
- **[transport/](transport/)** - Transport layer examples

### NTCP2-Specific Examples
Examples exclusively for I2P's NTCP2 transport (Noise_XK_25519_AESGCM_SHA256):

- **[ntcp2/](ntcp2/)** - NTCP2 addressing demonstration
- **[ntcp2-config/](ntcp2-config/)** - NTCP2 configuration builder patterns
- **[ntcp2-listener/](ntcp2-listener/)** - NTCP2 listener implementation

### Specialized Examples
Advanced features and utilities:

- **[modifiers/](modifiers/)** - Handshake modification examples
- **[pool/](pool/)** - Connection pooling examples
- **[retry/](retry/)** - Retry logic demonstrations
- **[shutdown/](shutdown/)** - Graceful shutdown examples
- **[state/](state/)** - Connection state management

## Common Usage Patterns

### Key Generation
All examples support key generation for testing:

```bash
# Generate random keys for any example
go run main.go -generate

# Example output:
# Cryptographic Material:
#   Local Static Key:  a1b2c3d4e5f6...
#   Remote Static Key: f6e5d4c3b2a1...
```

### Demo Mode
All examples include demonstration modes:

```bash
# Show supported patterns and configurations
go run main.go -demo
```

### General Noise Examples

#### Pattern Support
All general examples support these Noise patterns:

**One-way patterns**: N, K, X  
**Interactive patterns**: NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX

#### Basic Usage

```bash
# Simple NN pattern (no keys required)
go run main.go -server localhost:8080 -pattern NN

# XX pattern (mutual authentication - keys required)  
go run main.go -server localhost:8080 -pattern XX -static-key <64-char-hex>

# IK pattern (client knows server's key)
go run main.go -server localhost:8080 -pattern IK -static-key <server-key>
```

#### Key Requirements by Pattern

| Pattern | Local Key | Remote Key | Use Case |
|---------|-----------|------------|----------|
| NN      | ❌         | ❌          | Testing/development only |
| NK      | ❌         | ✅          | Anonymous client to known server |
| XX      | ✅         | ❌          | Mutual authentication (recommended) |
| IK      | ✅         | ✅          | Client knows server, both authenticate |

### NTCP2 Examples

NTCP2 examples exclusively use the `Noise_IK_25519_AESGCM_SHA256` pattern as per I2P specification.

#### NTCP2-Specific Arguments

```bash
# Required for NTCP2
-router-hash <64-char-hex>           # Local router hash
-remote-router-hash <64-char-hex>    # Remote router hash (for clients)
-static-key <64-char-hex>            # Static private key

# Optional NTCP2 features
-destination-hash <64-char-hex>      # For tunnel connections
-aes-obfuscation=true               # Enable AES obfuscation
-siphash-length=true                # Enable SipHash length obfuscation
-max-frame-size=16384               # Frame size limit
```

#### NTCP2 Usage Examples

```bash
# Generate NTCP2 material
go run main.go -generate

# NTCP2 server
go run main.go -server localhost:7654 \
  -router-hash <64-char-hex> \
  -static-key <64-char-hex>

# NTCP2 client  
go run main.go -client localhost:7654 \
  -router-hash <local-router-hash> \
  -remote-router-hash <server-router-hash> \
  -static-key <64-char-hex>
```

## Shared Utilities

### `examples/shared/`
Common utilities for general Noise examples:

- **crypto.go** - Key generation and parsing utilities
- **patterns.go** - Pattern validation and requirements
- **args.go** - Common command-line argument parsing
- **demo.go** - Demonstration and help functions

### `examples/ntcp2-shared/`  
NTCP2-specific utilities:

- **args.go** - NTCP2 command-line parsing and material handling

## Command-Line Reference

### Common Arguments (General Examples)

```
Network Configuration:
  -server <addr>           Run as server on address
  -client <addr>           Run as client to address
  -pattern <pattern>       Noise pattern (default: NN)

Cryptographic Material:
  -static-key <hex>        64-character hex static key
  -remote-key <hex>        64-character hex remote key

Timeouts:
  -handshake-timeout <dur> Handshake timeout (default: 30s)
  -read-timeout <dur>      Read timeout (default: 60s)
  -write-timeout <dur>     Write timeout (default: 60s)

Modes:
  -demo                    Show patterns and configurations
  -generate                Generate test keys
  -verbose                 Enable verbose logging
```

### NTCP2 Arguments (NTCP2 Examples)

```
Network Configuration:
  -server <addr>           Run NTCP2 server on address  
  -client <addr>           Connect NTCP2 client to address

NTCP2 Material:
  -router-hash <hex>       Local router hash (required)
  -remote-router-hash <hex> Remote router hash (client only)
  -destination-hash <hex>  Destination hash (optional)
  -static-key <hex>        Static private key

NTCP2 Features:
  -aes-obfuscation         Enable AES obfuscation (default: true)
  -siphash-length          Enable SipHash length (default: true)
  -max-frame-size <int>    Maximum frame size (default: 16384)

Timeouts:
  -handshake-timeout <dur> Handshake timeout (default: 45s)
  -read-timeout <dur>      Read timeout (default: 60s) 
  -write-timeout <dur>     Write timeout (default: 60s)
```

## Example Workflow

### 1. Learn the Patterns
```bash
cd examples/basic
go run main.go -demo
```

### 2. Generate Keys
```bash
go run main.go -generate
# Copy the generated keys for use in server/client
```

### 3. Test Communication
```bash
# Terminal 1 (Server)
go run main.go -server localhost:8080 -pattern XX -static-key <key1>

# Terminal 2 (Client)  
go run main.go -client localhost:8080 -pattern XX -static-key <key2>
```

### 4. Try NTCP2
```bash
cd ../ntcp2
go run main.go -generate
# Use generated NTCP2 material in other NTCP2 examples
```

## Security Notes

**Test Keys Only**: All key generation in these examples creates test keys. Never use generated keys in production.

**Pattern Selection**: Choose patterns based on your security requirements:
- **NN**: Development/testing only (no security)
- **XX**: Production use with mutual authentication  
- **IK**: When client knows server's static key
- **NTCP2**: I2P network integration

## Building and Running

All examples use Go modules and require no external dependencies beyond the go-noise library:

```bash
cd examples/<example-name>
go run main.go [arguments]
```

For development and testing:
```bash
go mod tidy
go test ./...
```
