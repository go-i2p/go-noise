# ratchet — ECIES-X25519-AEAD-Ratchet crypto engine

Package `ratchet` implements the ECIES-X25519-AEAD double ratchet that I2P uses
for end-to-end garlic encryption: New Session (NS) handshake, New Session Reply
(NSR), Existing Session (ES) messages, the DH ratchet, and session tag sets.

This package was extracted from [go-i2p/go-i2p](https://github.com/go-i2p/go-i2p)
into [go-i2p/go-noise](https://github.com/go-i2p/go-noise) to separate pure
cryptographic logic from I2P routing concerns.

## Scope

The package implements the garlic session of `ecies.md` and nothing else:

1. **Session lifecycle** — NS / NSR / ES encryption and decryption, DH ratchet
   rotation, tag set generation and look-ahead, session tag lookup, expiry and
   LRU eviction.
2. **Payload composition** — the block types the ratchet itself consumes
   (DateTime, NextKey, Ack, Ack Request, Message Number, Termination, Padding,
   Garlic Clove) and the per-message-type ordering rules.
3. **Response obligations** — receipt of an NS, NSR, Ack Request or NextKey block
   requires a response; the timers that track that are exposed for the host to
   sweep (see [`response_timer.go`](response_timer.go)).

Tunnel build-record crypto (ECIES build request records, ChaCha20-Poly1305 build
reply records) is deliberately **not** here. Those formats are defined in
`tunnel-ecies.md`, not `ecies.md`, and are a tunnel-layer concern; they belong in
`github.com/go-i2p/crypto` alongside the ECIES primitives they are built from.
The `BuildRecordEncryptor` / `BuildReplyEncryptor` interfaces and their
implementations were removed because they encoded ElGamal-era record sizes that
no ECIES record format in the spec uses — see the note in
[`interfaces.go`](interfaces.go).

## Protocol compliance

- **Pattern**: `Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256` (40 bytes)
- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305 AEAD
- **Hash**: SHA-256
- **Modifiers**:
  - `elg2`: Elligator2 encoding of the ephemeral public key, so it is
    indistinguishable from random.
  - `hs2`: an extra `MixHash()` of the session tag before the second handshake
    message (the New Session Reply). The responder's static key pre-message uses
    the RAW key (`h = SHA256(h || bpk)`), per `ecies.md` §"KDF for Flags/Static
    Key Section" — `hs2` does **not** mean `Hash(s)`.

## Public API

`NewSessionManager(privateKey [32]byte, opts ...SessionManagerOption)` returns the
one concrete type, `*SessionManager`:

| Method | Purpose |
|---|---|
| `EncryptGarlicMessage(destHash, destPubKey, plaintext)` | NS if unknown, ES if the session exists |
| `EncryptUnboundGarlicMessage(destPubKey, plaintext)` | one-shot NS with no binding or session (§1c/§1d) |
| `EncryptNewSessionReply(sessionHash, payload)` | NSR for a received NS |
| `DecryptGarlicMessage(encrypted)` | plaintext, session tag, session hash |
| `FindSessionByTag(tag)` | O(1) tag lookup that consumes the tag ([`TagResolver`]) |
| `RegisterOneTimeKey(tag, key)` | key for an unbound one-shot message |
| `ProcessReceivedNextKey(tag, info)` | apply a NextKey block out of band |
| `SweepResponses()` | sessions whose ratchet-layer response is overdue |
| `GetSessionCount` / `CleanupExpiredSessions` / `StartCleanupLoop` / `Close` | lifecycle |
| `GetPublicKey()` | this endpoint's static public key |

Consumers should depend on the interfaces in [`interfaces.go`](interfaces.go) —
`GarlicEncryptor`, `GarlicDecryptor`, `GarlicSessionManager`, `TagResolver` —
rather than the concrete type. All of them use primitive types (`[32]byte`,
`[8]byte`, `[]byte`) rather than I2P-specific ones, so go-noise has no dependency
on go-i2p.

## Usage

```go
import "github.com/go-i2p/go-noise/ratchet"

// Create a session manager with our static private key.
var privateKey [32]byte
// ... populate from the key store ...
sm, err := ratchet.NewSessionManager(privateKey)
if err != nil {
	return err
}
defer sm.Close()

// Encrypt a garlic message for a destination. An unknown destination starts a
// New Session; an established one is encrypted as an Existing Session message.
var destHash, destPubKey [32]byte
// ... populate from the destination's RouterInfo ...
encrypted, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)

// Decrypt an incoming garlic message.
plaintext, sessionTag, sessionHash, err := sm.DecryptGarlicMessage(encrypted)

// Answer a received New Session with a New Session Reply.
if sessionHash != nil {
	nsr, err := sm.EncryptNewSessionReply(*sessionHash, replyPayload)
}
```

## Design principles

- **No I2P imports**: this package depends on `go-i2p/crypto` and the standard
  library only. Callers convert I2P types at the boundary.
- **Interface-first**: consumers depend on interfaces, enabling mock injection.
- **Thread-safe**: `SessionManager` is safe for concurrent use. Lock order is the
  manager lock and then the session lock; never the reverse.
- **Key material is destroyed**: when a session is removed — expired, terminated,
  evicted, or dropped by `Close()` — its chain keys, root keys, tag ratchets, DH
  private keys and cached message keys are zeroed, not just unlinked. See
  `Session.destroyKeyMaterial`.
- **Compile-time checks**: `SessionManager`'s conformance to `GarlicSessionManager`
  is asserted in `session_manager.go`.

## Testing

```bash
go test -race -v ./ratchet/
go test -bench=. -benchmem ./ratchet/
```

`spec_compliance_ratchet_test.go` pins the requirements that were previously
violated — NSR tag set advancement and retention, inbound tag window sizing,
per-tagset sizing, message-number trimming, unknown blocks treated as padding,
reserved NextKey flag bits, key destruction on removal — each citing the
`ecies.md` section it comes from.

## Specification

The design of record is the I2P developer spec
[`ecies.md`](https://github.com/i2p/i2p.website/blob/main/content/en/docs/specs/ecies.md)
(`content/en/docs/specs/ecies.md` on `main`). Proposal 144 is the design history;
where the two disagree, the dev spec wins and the conflict is recorded in a code
comment.

> Do not vendor a copy of the spec into this package. A previously checked-in copy
> (`ratchet.md`) had been edited away from the official text (notably the `hs2`
> pre-message), and code citations anchored to it propagated the error. Cite the
> spec sections directly instead.
>
> Note also that the spec's pseudo-code uses inclusive-end slice notation
> (`keydata[0:31]` means 32 bytes). Check the prose byte count before reading an
> off-by-one into a slice bound.
