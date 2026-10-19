# ratchet — ECIES-X25519-AEAD-Ratchet Crypto Engine

Package `ratchet` provides the ECIES-X25519-AEAD-Ratchet cryptographic primitives
used by the I2P network for end-to-end garlic encryption and tunnel build record
encryption.

This package was extracted from [go-i2p/go-i2p](https://github.com/go-i2p/go-i2p)
into [go-i2p/go-noise](https://github.com/go-i2p/go-noise) to separate pure
cryptographic logic from I2P routing concerns.

## Overview

The package implements three main areas:

1. **Garlic Session Management** — Full ECIES-X25519-AEAD double-ratchet session
   lifecycle: New Session (ECIES handshake), Existing Session (symmetric ratchet),
   DH ratchet rotation, session tag generation, and LRU eviction.

2. **Tunnel Build Record Crypto** — ChaCha20-Poly1305 encryption/decryption of
   tunnel build reply records (I2P 0.9.44+).

3. **ECIES Build Request Crypto** — ECIES-X25519-AEAD encryption/decryption of
   tunnel build request records, identity hash verification.

## Protocol Compliance

- **Pattern**: `Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256`
- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305 AEAD
- **Hash**: SHA-256
- **Modifiers**:
  - `elg2`: Elligator2 encoding of ephemeral public keys (indistinguishable from random)
  - `hs2`: An extra `MixHash()` before the second handshake message (the New
    Session Reply) to mix in the session tag value. The responder's static key
    pre-message uses the RAW key (`h = SHA256(h || bpk)`), per `ecies.rst`
    §"KDF for Flags/Static Key Section" — `hs2` does **not** mean `Hash(s)`.

## Interfaces

All public API is defined via interfaces in [`interfaces.go`](interfaces.go):

| Interface | Purpose |
|---|---|
| `GarlicSessionManager` | Full encrypt/decrypt/lifecycle for garlic sessions |
| `GarlicEncryptor` | Encrypt-only subset (e.g., I2CP message router) |
| `GarlicDecryptor` | Decrypt-only subset (e.g., message processor) |
| `BuildRecordEncryptor` | ECIES encrypt/decrypt for tunnel build requests |
| `BuildReplyEncryptor` | ChaCha20-Poly1305/AES for build reply records |
| `TagResolver` | O(1) session tag lookup |

All interfaces use **primitive types** (`[32]byte`, `[8]byte`, `[]byte`) rather
than I2P-specific types, ensuring go-noise has zero dependency on go-i2p.

## Implementations

| Type | Implements |
|---|---|
| `SessionManager` | `GarlicSessionManager` (embeds `GarlicEncryptor` + `GarlicDecryptor`) |
| `BuildReplyCrypto` | `BuildReplyEncryptor` (ChaCha20-Poly1305 reply records) |
| `BuildRequestCrypto` | `BuildRecordEncryptor` (ECIES-X25519 request records) |
| `BuildRecordCrypto` | **Deprecated.** Combined wrapper; use `BuildReplyCrypto` or `BuildRequestCrypto` instead. Will be removed in the next major version. |

## Usage

### Garlic Session Encryption

```go
import "github.com/go-i2p/go-noise/ratchet"

// Create a session manager with our static private key
var privateKey [32]byte
// ... populate from key store ...
sm, err := ratchet.NewSessionManager(privateKey)
if err != nil {
    return err
}
defer sm.Close()

// Encrypt a garlic message for a destination
var destHash, destPubKey [32]byte
// ... populate from destination info ...
encrypted, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)

// Decrypt an incoming garlic message
plaintext, sessionTag, err := sm.DecryptGarlicMessage(encrypted)
```

### Tunnel Build Record Crypto

```go
import "github.com/go-i2p/go-noise/ratchet"

crypto := ratchet.NewBuildRecordCrypto()

// Encrypt a reply record (ChaCha20-Poly1305)
var replyKey [32]byte
var replyIV [16]byte
encrypted, err := crypto.EncryptReplyRecord(record, replyKey, replyIV)

// ECIES encrypt a build request
encrypted, err := crypto.EncryptBuildRequest(plaintext, recipientPubKey)
```

## Design Principles

- **No I2P imports**: This package depends only on `go-i2p/crypto` and
  standard library. Callers convert I2P types to primitives at the boundary.
- **Interface-first**: Consumers depend on interfaces, enabling mock injection
  for testing.
- **Thread-safe**: `SessionManager` is safe for concurrent use from multiple
  goroutines.
- **Compile-time checks**: All implementations are verified at compile time:
  ```go
  var _ GarlicSessionManager = (*SessionManager)(nil)
  var _ BuildRecordEncryptor = (*BuildRecordCrypto)(nil)
  var _ BuildReplyEncryptor  = (*BuildRecordCrypto)(nil)
  ```

## Testing

```bash
# Run all tests with race detection
go test -race -v ./ratchet/

# Run benchmarks
go test -bench=. -benchmem ./ratchet/
```

The test suite includes 46+ tests covering:
- New/Existing session encrypt→decrypt round-trips
- DH ratchet rotation at configurable intervals
- Session tag generation and lookup
- LRU eviction and concurrent access safety
- ECIES and ChaCha20-Poly1305 round-trips
- Error handling and edge cases

## Specification

For the full I2P ECIES-X25519-AEAD-Ratchet specification, see the official spec:
[ecies.rst](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst)
(`lastupdated: 2025-06`, `accuratefor: 0.9.67`). The original proposal is
[proposal 144](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/proposals/144-ecies-x25519-aead-ratchet.rst),
but `ecies.rst` is the design of record and is what the code citations refer to.

> Do not vendor a copy of the spec into this package. A previously checked-in
> copy (`ratchet.md`) had been edited away from the official text (notably the
> `hs2` pre-message), and code citations anchored to it propagated the error.
> Cite `ecies.rst` sections directly instead.
