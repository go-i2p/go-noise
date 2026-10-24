# SSU2 Transport Implementation

I2P SSU2 (Secure Semi-reliable UDP version 2) transport protocol implementation using the Noise Protocol Framework.

## Overview

This package provides handshake modifiers and utilities for implementing the SSU2 transport protocol, which is I2P's UDP-based encrypted transport. SSU2 uses the Noise Protocol Framework with ChaCha20-Poly1305 for encryption and ChaCha20 stream cipher for ephemeral key obfuscation.

## Features

### Completed Components ✅

- **ChaCha20 Obfuscation Modifier** - Ephemeral key obfuscation for handshake messages (91.1% coverage)
- **SSU2 Padding Modifier** - MTU-aware padding with I2P ratios 0.0-15.9375 (82.7% coverage)
- **Header Protection** - Per-packet header obfuscation with ChaCha20 (ssu2.rst §"Header Encryption"); SSU2 has **no** length obfuscation, since §"Messages" makes the datagram length the message length
- **SSU2 Address (`SSU2Addr`)** - Complete `net.Addr` implementation with connection ID and NAT traversal support (100% coverage)
- **SSU2 Configuration (`SSU2Config`)** - Builder pattern configuration with comprehensive validation (88.4% coverage)
- **SSU2 Connection (`SSU2Conn`)** - Full `net.Conn` implementation (Close, LocalAddr, RemoteAddr, deadlines, Read, Write) with XK handshake. `Read` returns one I2NP message at a time, buffering any remainder that does not fit the caller's buffer; `Write` auto-fragments large messages. Because `Read`/`Write` are message-oriented rather than a raw byte stream, a callback-based path via `DataHandler.MessageChan()` is also offered for consumers that prefer explicit per-message handling.
- **SSU2 Listener (`SSU2Listener`)** - `net.Listener` implementation for accepting inbound SSU2 connections
- **SSU2 Transport** - Transport-level Dial/Listen functions for SSU2

> **Note:** SessionConfirmed (3rd XK message) processing routes through the Noise state machine but has not been tested against a live I2P router.

> **Security Limitation (M-2):** NextNonce (block type 11) key rotation is disabled by default (`EnableNextNonce: false`) because the SSU2 spec marks this area as "TODO" with size "TBD". **Forward-secrecy implications for operators:** Without mid-session key rotation, long-lived sessions (held for hours or days) retain the same send/receive cipher keys for their entire lifetime. An adversary who later compromises the static key can retroactively decrypt the entire session. Nonce-exhaustion guards prevent nonce reuse, but forward secrecy is not refreshed until the session closes and a new one is established. Operators running routers with sustained SSU2 sessions should be aware of this trade-off. Enabling `EnableNextNonce` before the spec is finalized risks breaking interoperability with peers.

## Protocol Compliance

- **Pattern**: `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`
- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305 AEAD
- **Hash**: SHA-256
- **Obfuscation**: ChaCha20 stream cipher

## Quick Start

### ChaCha20 Obfuscation Modifier

```go
package main

import (
    "crypto/rand"
    "github.com/go-i2p/go-noise/ssu2"
    "github.com/go-i2p/go-noise/handshake"
)

func main() {
    // Generate 32-byte router hash and 8-byte IV
    routerHash := make([]byte, 32)
    iv := make([]byte, 8)
    rand.Read(routerHash)
    rand.Read(iv)
    
    // Create ChaCha20 obfuscation modifier
    modifier, err := ssu2.NewChaChaObfuscationModifier(
        "ssu2-chacha-obfs",
        routerHash,
        iv,
    )
    if err != nil {
        panic(err)
    }
    
    // Use in handshake (initiator)
    ephemeralKey := make([]byte, 32) // X or Y ephemeral key
    rand.Read(ephemeralKey)
    
    // Encrypt outbound message 1
    encrypted, err := modifier.ModifyOutbound(handshake.PhaseInitial, ephemeralKey)
    if err != nil {
        panic(err)
    }
    
    // ... send encrypted data over network ...
    
    // Decrypt inbound message 2 (responder's ephemeral key)
    // Note: Receiver must create their own modifier with same routerHash and IV
    decrypted, err := modifier.ModifyInbound(handshake.PhaseExchange, encrypted)
    if err != nil {
        panic(err)
    }
}
```

## Architecture

### ChaCha20 Obfuscation

The ChaCha20 obfuscation modifier implements SSU2's ephemeral key obfuscation:

- **Message 1 (Initial)**: XOR X ephemeral key with ChaCha20(routerHash, IV)
  - Derives state from last 8 bytes of encrypted output for message 2
- **Message 2 (Exchange)**: XOR Y ephemeral key with ChaCha20(routerHash, derived_IV)
- **Message 3+ (Final)**: No obfuscation (Noise protocol handles encryption)

Key differences from NTCP2's AES obfuscation:
- **IV Size**: 8 bytes (SSU2) vs 16 bytes (NTCP2)
- **Cipher Type**: Stream cipher (ChaCha20) vs block cipher (AES-CBC)
- **Operation**: XOR-based vs block encryption
- **State Derivation**: From encrypted data (sender and receiver must coordinate)

### No Length Obfuscation (unlike NTCP2)

SSU2 does **not** obfuscate message lengths. ssu2.rst §"Messages": "Each UDP
datagram contains exactly one message. The length of the datagram (after the IP
and UDP headers) is the length of the message." Padding is therefore carried
inside the message as a Padding block rather than applied to a length field:

- **No length field**: the UDP datagram length is the message length
- **Padding block only**: type 254 inside the encrypted payload
- **Traffic analysis**: mitigated by padding blocks, not by masking a length

SipHash appears in SSU2 only for the optional stateless-token construction that
§"Session Request" discusses (and explicitly cautions against for replay
rejection). The SipHash-2-4 length-obfuscation chain is NTCP2-only
(ntcp2.rst §"Data Phase"); its implementation lives in
`github.com/go-i2p/go-noise/handshake/siphash` and is used by the `ntcp2`
package.

## Security Properties

### Obfuscation

ChaCha20 obfuscation provides:
- **DPI Resistance**: Encrypted ephemeral keys prevent deep packet inspection fingerprinting
- **Pattern Hiding**: Noise handshake pattern is obscured from network observers
- **Performance**: ChaCha20 is faster than AES on non-AES-NI hardware

### Key Management

- **Router Hash**: 32-byte I2P router identity (must match peer's public router info)
- **IV**: 8-byte initialization vector from network database (public, non-secret)
- **Derived State**: Automatically derived for message 2 from message 1 output

### Thread Safety

All modifiers are thread-safe for concurrent use:
- Defensive copying of input parameters
- Safe for use in concurrent handshakes
- State management is modifier-instance-specific

## Performance

Based on benchmarks on Intel Core i7-10710U @ 1.10GHz:

```text
BenchmarkChaChaObfuscation-12            1396284    855.2 ns/op     40 B/op     2 allocs/op
BenchmarkSSU2Padding-12                  1000000   1170 ns/op      140 B/op     0 allocs/op
BenchmarkSSU2PaddingRemoval-12          13712234     73.52 ns/op     0 B/op     0 allocs/op
```

- **ChaCha20 Throughput**: ~1.4 million operations/second
- **Padding Overhead**: ~1.2 microseconds per operation
- **Padding Removal**: ~73 nanoseconds (extremely fast)
- **Memory**: Minimal allocations (0-140 bytes per operation)

## Testing

```bash
# Run all SSU2 tests
go test -v ./ssu2/...

# Run with coverage
go test -cover ./ssu2/...

# Run benchmarks
go test -bench=. -benchmem ./ssu2/...
```

Current test coverage: **88.4%**

### Test Scenarios

- ✅ Constructor validation (router hash, IV sizes)
- ✅ Defensive copying of parameters
- ✅ Roundtrip encryption/decryption
- ✅ Phase-specific behavior (Initial, Exchange, Final)
- ✅ State management across messages
- ✅ Non-32-byte data pass-through
- ✅ Different keys/IVs produce different output
- ✅ Symmetric XOR operation
- ✅ Builder pattern and fluent API
- ✅ Comprehensive validation coverage
- ✅ SSU2Addr interface compliance
- ✅ Connection ID generation

## Dependencies

- **golang.org/x/crypto/chacha20**: ChaCha20 stream cipher implementation
- **github.com/samber/oops**: Rich error context and wrapping
- **github.com/go-i2p/go-noise/handshake**: Handshake modifier interface

## Contributing

This library follows Go best practices:

- Functions under 30 lines with single responsibility
- Explicit error handling (no ignored returns)
- Self-documenting code with clear naming
- Comprehensive testing (>80% coverage requirement)
- GoDoc comments for all exported types/functions

## License

MIT License

## Status

**Development Status**: The transport is feature-complete for the parts of ssu2.rst
that are finalized: handshake modifiers, addressing, configuration, the connection and
listener layers, and the tunnel/relay block handling.

**What's Available**:
- Handshake modifiers (ChaCha20 obfuscation, Padding) with comprehensive testing
- `SSU2Addr` implementing `net.Addr` for UDP connections with NAT traversal support
- `SSU2Config` builder for fluent configuration with automatic modifier setup
- `SSU2Conn` implementing `net.Conn`, and `SSU2Listener` implementing `net.Listener`

**Next Steps**: interoperability testing against a live I2P router. SessionConfirmed
(message 3 of the XK exchange) is routed through the Noise state machine but has not
yet been validated against another implementation, and NextNonce key rotation remains
disabled by default because the spec marks that area "TODO"/"TBD".
