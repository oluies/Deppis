# Engine API Contract: Flutter (Dart) ↔ Scala.js `protocol-core` Engine

A narrow, **versioned** message API between the Flutter UI and the Scala.js-compiled
`protocol-core` engine (D14, Constitution VII). **Dart holds presentation state only; all crypto
and protocol state live inside the engine.** Transport is a thin platform channel / embedded JS
runtime. Messages are JSON; `apiVersion` is mandatory on every call.

## Direction: Dart → Engine (commands)

| Command | Args | Effect |
|---|---|---|
| `addBuddy` | `{ sharedSecret, role }` | Run add-friend handshake; returns `safetyNumber` to compare out of band. |
| `confirmBuddy` | `{ pairId, matched: bool }` | Confirm/reject pairing after safety-number comparison. |
| `removeBuddy` | `{ pairId }` | Remove buddy; stops delivery without leaking prior existence (FR-018). |
| `sendMessage` | `{ pairId, plaintext }` | Frame + content-encrypt + enqueue for next round. |
| `tick` | `{ roundId }` | Advance the client schedule: emit one frame (real or carrier) + retrieval. |
| `setSchedule` | `{ intervalParams }` | Update the user-controlled retrieval schedule (FR-005). |

## Direction: Engine → Dart (events)

| Event | Payload | Meaning |
|---|---|---|
| `buddyConfirmed` | `{ pairId, safetyNumber }` | Pairing established. |
| `messageReceived` | `{ pairId, plaintext, receivedAt }` | Decrypted incoming message. |
| `notified` | `{ roundId }` | "Some buddy has mail" — which buddy is NOT exposed (FR-004). |
| `privacyStatus` | `{ backend, metadataPrivate: bool, label }` | Drives the mandatory UI label (FR-016). |
| `error` | `{ code, message }` | Never includes secret-dependent detail (Constitution II). |

## Hard rules

- The engine NEVER returns key material or raw tokens to Dart.
- `privacyStatus.metadataPrivate == false` ⇒ Dart MUST display `DEV, NO METADATA PRIVACY`
  prominently; the engine emits this whenever the active backend is dev/stub or attestation has
  not passed (FR-016, Constitution IV).
- Errors and logs surfaced to Dart MUST NOT vary on secret values.
- `apiVersion` mismatch ⇒ engine refuses the call (forward/backward-compat safety).
