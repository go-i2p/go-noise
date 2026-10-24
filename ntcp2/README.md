# NTCP2 Modifier Implementation

This package implements NTCP2-specific handshake modifications for the I2P transport protocol. NTCP2 is a TCP-based transport that uses the Noise Protocol Framework with specific obfuscation and padding techniques to resist traffic analysis and Deep Packet Inspection (DPI).

## Features

### 1. AES Obfuscation Modifier

Implements AES-256-CBC obfuscation of ephemeral keys (X and Y values) in handshake messages 1 and 2.

- **AESObfuscationModifier**: Encrypts/decrypts 32-byte ephemeral keys using router hash as AES key
- **Message 1**: Uses published IV from network database
- **Message 2**: Uses AES state from message 1 encryption
- **Message 3+**: No AES obfuscation applied

```go
// Create AES obfuscation modifier
routerHash := make([]byte, 32) // 32-byte router hash (RH_B)
iv := make([]byte, 16)         // 16-byte IV from network database
modifier, err := ntcp2.NewAESObfuscationModifier("aes_obfuscation", routerHash, iv)
```

### 2. SipHash Length Modifier

Implements SipHash-2-4 obfuscation of frame lengths in the data phase to prevent length analysis.

- **SipHashLengthModifier**: Obfuscates 2-byte frame lengths using SipHash-2-4
- **Data Phase Only**: Only applies to final phase (after handshake completion)
- **Symmetric XOR**: Uses XOR with SipHash output for reversible obfuscation

```go
// Create SipHash length modifier
sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210} // k1, k2
initialIV := uint64(0x1122334455667788)                      // 8-byte IV
modifier := ntcp2.NewSipHashLengthModifier("siphash_length", sipKeys, initialIV)
```

### 3. NTCP2 Padding Modifier

Implements NTCP2-specific padding strategies aligned with I2P specifications for different message phases.

- **Cleartext Padding**: For messages 1 and 2 (outside AEAD frames) with cryptographically secure random padding
- **AEAD Padding**: For message 3 and data phase (inside AEAD frames with type 254) using I2P block format
- **Configurable Padding Ratios**: Supports I2P NTCP2 spec padding ratios (0.0 to 15.9375) for traffic analysis resistance
- **Dynamic Parameter Updates**: Runtime adjustment of padding limits and ratios during connection
- **Block Parsing**: I2P block format parsing with security validation

```go
// Create padding modifiers for different phases
cleartextPadding, err := ntcp2.NewNTCP2PaddingModifier("cleartext_padding", 4, 16, false)
aeadPadding, err := ntcp2.NewNTCP2PaddingModifier("aead_padding", 0, 32, true)

// Create with specific padding ratio for traffic analysis resistance
ratioPadding, err := ntcp2.NewNTCP2PaddingModifierWithRatio("ratio_padding", 4, 64, true, 1.0) // 100% padding

// For testing only (deterministic padding - INSECURE for production).
// There is no separate testing constructor; enable deterministic mode on a
// normal modifier via WithTestMode().
testPadding, err := ntcp2.NewNTCP2PaddingModifier("test_padding", 4, 16, false)
testPadding = testPadding.WithTestMode()
```

## Package Responsibilities

The NTCP2 protocol implementation is split between this package (`go-i2p/go-noise/ntcp2`) and the router transport layer (`go-i2p/go-i2p/lib/transport/ntcp`). Each layer has clearly defined responsibilities:

### This package (`go-noise/ntcp2`) — Noise Protocol Layer

| Responsibility | Implementation |
|---|---|
| Noise XK handshake execution | `NTCP2Conn` via `NoiseConn` |
| AES-256-CBC ephemeral key obfuscation (messages 1 & 2) | `AESObfuscationModifier` |
| SipHash-2-4 frame length obfuscation (data phase) | `SipHashLengthModifier` |
| SipHash key derivation from `ask_master` + handshake hash | `DeriveSipHashKeys()` in `kdf.go` |
| ChaChaPoly AEAD frame encryption/decryption | `NTCP2Conn.Read()` / `Write()` |
| Data-phase AEAD error handling (probing resistance) | `handleAEADError()` |
| Frame padding (type 254 padding blocks) | `NTCP2PaddingModifier` |
| Nonce management and exhaustion detection | `NonceExhaustionImminent()` advisory (upstream `CipherState` enforces hard limit) |
| Replay cache | Per-router ephemeral key (X value) cache with TTL eviction; mandatory per ntcp2.rst, so a shared default cache is installed when the operator configures none |
| KDF intermediate material zeroing | `securemem.SecureZero()` calls in `kdf.go` |
| Connection configuration and validation | `NTCP2Config` |

### Router transport layer (`go-i2p/go-i2p/lib/transport/ntcp`)

| Responsibility | Notes |
|---|---|
| Handshake-phase probing resistance | Random delay + junk read on message 1/2 AEAD failure |
| Encrypted termination blocks | All 18 reason codes, AEAD-encrypted for graceful close |
| I2NP block framing | Block types 0–4, 254: demuxing, parsing, serialization |
| Options negotiation | Type 1 block: padding limits, dummy traffic, delay |
| Clock skew validation | ±60s tolerance on messages 1 & 2 timestamps |
| `RemoteStaticKey` lookup | Network database → `RouterInfo` → `s=` static key |
| RouterIdentity parsing | Full `RouterIdentity` from message 3 part 2 |
| Router hash computation | `SHA-256(RouterIdentity)` via `common/data.HashData()` |
| Version detection | NTCP2 version negotiation |

### Integration Points

The router transport layer integrates with this package through:

- **`NTCP2Config`** — Connection configuration with handshake parameters, modifier toggles, and keys
- **`NTCP2Conn`** — Exposes `PeerStaticKey()`, `HandshakeHash()`, `SetLengthObfuscator()`, and standard `net.Conn` interface
- **`DeriveSipHashKeys()`** — Called by `PostHandshakeHook` to derive per-direction SipHash keys
- **`PostHandshakeHook`** — Callback mechanism for post-handshake key derivation
- **`AdditionalSymmetricKeyLabels`** — `{"ask"}` label triggers `SplitWithASK()` for the `ask_master` secret

## Integration with ConnConfig

All modifiers integrate with the existing ConnConfig builder pattern:

```go
// Create NTCP2 modifier chain with padding
aesModifier, _ := ntcp2.NewAESObfuscationModifier("aes", routerHash, iv)
sipModifier := ntcp2.NewSipHashLengthModifier("siphash", sipKeys, initialIV)
paddingModifier, _ := ntcp2.NewNTCP2PaddingModifierWithRatio("padding", 4, 32, false, 0.5) // 50% padding ratio

// Configure connection with NTCP2 modifiers
config := noise.NewConnConfig("XK", true).
    WithModifiers(aesModifier, sipModifier, paddingModifier).
    WithHandshakeTimeout(30 * time.Second)

// Create connection with NTCP2 modifications
conn, err := noise.NewNoiseConn(underlying, config)
```

## I2P NTCP2 Protocol Compliance

This implementation follows the I2P NTCP2 specification:

### Handshake Pattern: `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`

- **Base Pattern**: XK (static key known pattern)
- **Modifications**: `aesobfse` (AES obfuscation), `hs2` (handshake step 2), `hs3` (handshake step 3)
- **DH Function**: Curve25519 (`25519`)
- **Cipher**: ChaCha20-Poly1305 (`ChaChaPoly`)
- **Hash**: SHA-256 (`SHA256`)

### Security Properties

1. **Ephemeral Key Obfuscation**: Prevents DPI fingerprinting of Noise handshake patterns
2. **Length Obfuscation**: SipHash masks frame lengths to resist traffic analysis
3. **Message Padding**: Adds variable padding to obscure payload sizes
4. **Cryptographic Security**: Uses AES-256-CBC and SipHash-2-4 algorithms

## Testing

Test suite with coverage:

```bash
cd ntcp2
go test -v
```

Tests include:
- Roundtrip verification (obfuscate → deobfuscate = original)
- Phase-specific behavior validation
- Error handling for invalid parameters
- Integration testing with multiple modifiers

## Thread Safety

All modifiers are safe for concurrent use:
- **Separate State**: Outbound and inbound operations use independent state
- **No Shared Mutation**: Each modifier instance maintains its own state
- **Defensive Copying**: Input parameters are copied to prevent external modification

## Usage Notes

### Production Considerations

1. **Router Hash**: Must be Bob's (the responder's) 32-byte I2P router hash (RH_B). Both initiator and responder pass RH_B to `NewNTCP2Config()`.
2. **IV Sources**: Use network database published IV for reproducible handshakes
3. **SipHash Keys**: Derive from session keys using proper KDF
4. **Padding**: Uses cryptographically secure random padding by default for security
5. **Padding Ratios**: Configure appropriate ratios based on security/bandwidth trade-offs
6. **Block Validation**: I2P block format parsing prevents protocol attacks

### Protocol Extensions

The modifier system supports additional NTCP2 extensions:
- Custom obfuscation patterns
- Dynamic padding strategies  
- Protocol version negotiation

This implementation provides a foundation for I2P NTCP2 transport while maintaining the security guarantees of the Noise Protocol Framework.
