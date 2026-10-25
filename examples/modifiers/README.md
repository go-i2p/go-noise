# NTCP2 Handshake Modifier Example

This example demonstrates the handshake modifier system used by the I2P
transports. The modifier system provides extensible, chainable transformations
for Noise protocol handshake data, implementing the obfuscation and padding
extensions the I2P specifications define.

## Overview

The handshake framework consists of:

1. **HandshakeModifier Interface**: Core interface for all modifiers
2. **ModifierChain**: Chains multiple modifiers, applying them in order outbound
   and in reverse inbound
3. **PaddingEngine**: shared padding math and I2P block wire format used by the
   NTCP2 and SSU2 padding modifiers
4. **ConnConfig Integration**: builder-pattern support for modifiers

The modifiers themselves live in the transport packages, because each implements
a wire format defined by that transport's spec. This example uses the two NTCP2
modifiers:

- **AES ephemeral-key obfuscation** (`ntcp2.NewAESObfuscationModifier`):
  ntcp2.md §"Obfuscation of the ephemeral key" — the 32-byte ephemeral key in
  messages 1 and 2 is encrypted with AES-256-CBC, keyed with the peer's router
  hash and the IV published in the network database.
- **Padding** (`ntcp2.NewNTCP2PaddingModifier`): ntcp2.md §"Padding" — random
  padding, outside the AEAD frame for messages 1 and 2 and inside it from
  message 3 onward.

## A note on what this package does *not* provide

The `handshake` package previously exported a generic `XORModifier` (whole-message
XOR with a repeating key) and a `GenericPaddingModifier` (a
`[4-byte big-endian length][data][padding]` frame). Both were **removed as
non-compliant with the I2P specifications**, not merely discouraged:

- ntcp2.md §"Additions to the Framework" enumerates exactly five NTCP2
  extensions — AES obfuscation, cleartext/AEAD padding, the two-byte frame
  length, SipHash-2-4 length obfuscation, and the payload format. None of them is
  a whole-message XOR. The only XOR the spec defines is the SipHash-derived mask
  applied to the two-byte frame length (§"SipHash obfuscated length").
- ntcp2.md §"Session Request" gives message 1 the layout `AES(X) ‖ AEAD ‖ padding`
  with no length prefix, and §"Additions to the Framework" states "Message 1 and 2
  AEAD frames are fixed length", so a length-prefixed padding frame is not part of
  the NTCP2 wire format.

Consequently, obfuscation in this example means the spec's AES ephemeral-key
obfuscation, and padding means the spec's block-format padding.

## Features Demonstrated

### 1. Individual Modifiers

- **AES Obfuscation Modifier**: transforms the leading ephemeral key
- **Padding Modifier**: appends a self-describing I2P padding block

### 2. Modifier Chaining

- **Sequential Application**: modifiers applied in order for outbound data
- **Reverse Processing**: modifiers applied in reverse order for inbound data
- **Error Propagation**: rich error context with modifier names and chain information

### 3. Phase Awareness

- **Handshake Phases**: Initial, Exchange, Final, and Data
- **Phase-Specific Processing**: modifiers behave differently per phase, matching
  where each spec places padding

### 4. Data Analysis

- **Overhead Measurement**: shows padding overhead characteristics
- **Data Size Analysis**: demonstrates operation with various data sizes

## Running the Example

```bash
cd examples/modifiers
go run main.go
```

## Expected Output

The example shows:

- Original handshake data (83 bytes)
- AES obfuscation transformation and recovery
- Padding transformation and recovery
- Chain application (AES + Padding)
- Round-trip verification for each handshake phase
- Processing overhead across different data sizes

## Cleartext vs AEAD padding

This example uses the AEAD-padding variant (`useAEADPadding = true`), which
appends an I2P block (`[254][size][data]`) inside the authenticated frame. That
block is self-describing, so the modifier can locate and strip it symmetrically.

Cleartext padding for messages 1 and 2 is deliberately *not* demonstrated as a
modifier round trip. Its length is carried in the message's own options block
(`padLen`, ntcp2.md §"Session Request"), and the padding must be MixHashed into
the handshake state, so the NTCP2 framing layer reads and hashes exactly that
many bytes (`ntcp2/handshake.go`) rather than the modifier guessing at them.

## Key Design Principles

### 1. Security Preservation

- Modifiers maintain Noise protocol security guarantees.
- Padding uses cryptographically secure randomness (via `crypto/rand`), with
  fail-closed error handling on RNG failure.

### 2. Composability

- Modifiers can be chained without conflicts.
- Order matters: outbound applies sequentially, inbound applies in reverse.
- Each modifier is independent and reusable.

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
// Create the spec-defined NTCP2 modifiers.
aesMod, _ := ntcp2.NewAESObfuscationModifier("obfuscation", routerHash, iv)
padMod, _ := ntcp2.NewNTCP2PaddingModifier("padding", 16, 64, true)

// The second parameter to NewConnConfig, named isInitiator (bool), specifies
// whether this side is the initiator (true) or responder (false).
config := noise.NewConnConfig("XK", true).
    WithModifiers(aesMod, padMod).
    WithHandshakeTimeout(30 * time.Second)

// Modifiers are automatically applied during the handshake.
conn, err := noise.NewNoiseConn(underlying, config)
```

## Use Cases for I2P

### NTCP2 Transport (TCP-based) `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`

> **Pattern Explanation:**
> The pattern string follows the [Noise Protocol naming conventions](https://noiseprotocol.org/noise.html#naming-conventions), where:
> - `Noise_` is the prefix,
> - `XKaesobfse+hs2+hs3` specifies the handshake pattern and the protocol-specific
>   extensions (`aesobf` = AES obfuscation of the ephemeral key, `es`/`hs2`/`hs3`
>   mark the handshake-hash modifications),
> - `25519` is the DH function,
> - `ChaChaPoly` is the cipher,
> - `SHA256` is the hash function.

- **Ephemeral-key obfuscation**: AES-256-CBC on the message 1 and 2 keys, so a
  network observer cannot see them in the clear
- **Message padding**: randomized padding to obscure actual payload sizes
- **Frame-length obfuscation**: the two-byte data-phase length is XORed with a
  SipHash-2-4-derived mask
- **Handshake-hash binding**: padding and headers are MixHashed so tampering is
  detected

### SSU2 Transport (UDP-based) `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`

- **Header protection**: bytes 0-15 of every header are XORed with a ChaCha20
  mask derived from the intro key (ssu2.md §"Header Encryption"), which is the
  SSU2 analogue of NTCP2's obfuscation — it is not a general message-body XOR
- **Ephemeral-key obfuscation**: the X/Y values are ChaCha20-encrypted with the
  peer's intro key
- **Packet padding**: an I2P padding block fills packets toward a uniform size
- **Session management**: SSU2's session tags, relay entries, and acknowledgments
  are handled by the transport, not by handshake modifiers

## Implementation Notes

### Thread Safety

- All modifiers are safe for concurrent use.
- ModifierChain uses defensive copying to protect against external slice
  modification, preventing data races and unintended side effects.
- ConnConfig methods use defensive copying.

### Memory Management

- Modifiers create new byte slices to avoid data corruption.
- No shared mutable state between modifier instances.
- Copying with minimal allocations.

### Extensibility

- New modifiers implement the HandshakeModifier interface.
- Existing code works with new modifier types.
- Plugin-style architecture for custom transformations.

Any custom modifier added to an NTCP2 or SSU2 connection must produce the exact
byte layout the corresponding specification defines; a modifier that changes the
framing will break interoperability with i2pd and Java I2P.
