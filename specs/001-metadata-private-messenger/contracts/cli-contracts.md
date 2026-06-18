# CLI Contracts (Constitution V: Library-First & CLI-First)

Each capability ships a standalone CLI: **JSON or text in (stdin/args) → JSON out (stdout),
errors → stderr**, testable without the UI. Below are the command schemas. All are pure with
respect to the protocol/crypto logic in `protocol-core` / `crypto`.

## `protocol-core` CLI (`pcore`)

| Subcommand | Input (JSON stdin) | Output (JSON stdout) |
|---|---|---|
| `handshake-init` | `{ sharedSecret, role }` | `{ pairId, safetyNumber, sendCredential, recvCredential }` |
| `frame` | `{ pairId, plaintext, counter }` | `{ frame(256B, base64), writeToken, retrievalToken }` |
| `deframe` | `{ frame(base64), keysRef }` | `{ plaintext }` |
| `retrieval-token` | `{ senderId, receiverId, counter }` | `{ token }`  (keyed-PRF; non-recurrent) |
| `schedule-next` | `{ scheduleState, now }` | `{ roundId, action: send|retrieve|carrier }` |

## `crypto` CLI (`mcrypto`)

| Subcommand | Input | Output | Notes |
|---|---|---|---|
| `aead-seal` | `{ key, nonce, aad, plaintext }` | `{ ciphertext }` | libsodium ChaCha20-Poly1305 |
| `aead-open` | `{ key, nonce, aad, ciphertext }` | `{ plaintext }` | constant-time |
| `kdf` | `{ ikm, salt, info, len }` | `{ okm }` | Blake2b |
| `kem-encaps` | `{ pubkey }` | `{ ciphertext, sharedSecret }` | ML-KEM via liboqs (Phase D) |
| `kem-decaps` | `{ privkey, ciphertext }` | `{ sharedSecret }` | ML-KEM |
| `kat` | `{ suite }` | `{ pass: bool, vectors: n }` | runs FIPS/library known-answer tests |

`mcrypto kat` MUST exist and pass for every crypto suite a path uses (Constitution VI).

## `oblivious-sidecar` CLI (`obsx`)

| Subcommand | Input | Output | Notes |
|---|---|---|---|
| `store-write` | `{ roundId, batchSize, entries[] }` | `{ ok }` | access pattern by batch size only |
| `store-read` | `{ roundId, batchSize, tokens[] }` | `{ results[] }` | non-recurrent tokens enforced |
| `notify-aggregate` | `{ roundId, label, sealedTokens[] }` | `{ digests[] }` | OR + oblivious sort/compaction |
| `selftest` | `{}` | `{ constantTime: bool, obliviousInvariants: bool }` | primitive self-checks |

## `attestation` CLI (`attest`)

| Subcommand | Input | Output | Notes |
|---|---|---|---|
| `verify` | `{ evidence, verifierResult, signature, nonce, referenceValues[] }` | `{ accepted: bool, enclaveKey? }` | rejects on stale nonce / unpinned measurement |

`attest verify` MUST return `accepted:false` (and no `enclaveKey`) if the nonce is stale, the
signature fails, or the measurement is absent from the reference-value log (Constitution IX/X).

## `privacy-status` CLI (`pstatus`)

| Subcommand | Input | Output |
|---|---|---|
| `show` | `{}` | `{ backend, metadataPrivate: bool, label }` |

When `metadataPrivate` is false, `label` is `DEV, NO METADATA PRIVACY` (FR-016). CI asserts no
release artifact reports `metadataPrivate:false` (Constitution IV).
