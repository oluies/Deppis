# Engine API Contract: Flutter (Dart) ↔ Scala.js `protocol-core` Engine

A narrow, **versioned** message API between the Flutter UI and the Scala.js-compiled
`protocol-core` engine (D14, Constitution VII). **Dart holds presentation state only; all crypto
and protocol state live inside the engine.** Transport is a thin platform channel / embedded JS
runtime. Messages are JSON; `apiVersion` is mandatory on every call.

## Direction: Dart → Engine (commands)

| Command | Args | Effect |
|---|---|---|
| `addBuddy` | `{ sharedSecret, role, pqPrekey?: bool, initiatorKemPublicKey?: base64 }` | Run add-friend handshake; returns `safetyNumber` to compare out of band, plus optional PQ pairing-prekey material (see below). |
| `confirmBuddy` | `{ pairId, matched: bool, kemCiphertext?: base64, kemConfirmTag?: base64 }` | Confirm/reject pairing after safety-number comparison; the initiator carries the responder's `kemCiphertext` + `kemConfirmTag` here to key-confirm and complete the PQ prekey. |
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

## Post-quantum pairing prekey (US7, Option A)

An OPTIONAL hybrid-KEM (X25519 + ML-KEM-768) prekey exchange layered onto the pairing flow. Its
shared secret is folded into the **initial content root** that seeds the double ratchet
(`contentRoot' = HMAC(contentRoot(pairKey), "ks/pq-prekey" ++ kemSharedSecret)`), so an adversary who
harvests the (classical) out-of-band pairing secret today and later has a quantum computer still
cannot reconstruct the seed without also breaking the KEM.

Because a KEM is asymmetric, the two devices exchange real, distinct key material out of band
(carried as base64 in these JSON fields, alongside the safety-number comparison):

1. **Initiator** `addBuddy` with `pqPrekey: true` → generates a keypair, DEFERS seeding its ratchet,
   and returns `kemPublicKey` (base64). The app sends it to the peer out of band.
2. **Responder** `addBuddy` with `initiatorKemPublicKey` (base64) → encapsulates to it, mixes the
   shared secret into its content root, seeds its ratchet now, and returns `kemCiphertext` (base64)
   **plus a `kemConfirmTag` (base64)** — a key-confirmation tag over the mixed root.
3. **Initiator** `confirmBuddy` with `matched: true`, `kemCiphertext`, and `kemConfirmTag` (base64) →
   decapsulates, mixes the SAME shared secret into the SAME base content root, **constant-time verifies
   its own recomputed tag against the responder's `kemConfirmTag`**, and only then seeds its (deferred)
   ratchet. Both sides arrive at a byte-identical seed and interoperate.

- The **safety number / pairId are UNCHANGED** — still derived symmetrically from the out-of-band
  secret; only the content root gains the KEM secret.
- **Key confirmation (mandatory):** ML-KEM has *implicit rejection* — a **same-length** tampered
  `kemCiphertext` (or a substituted `kemPublicKey`) does NOT make decapsulation fail; it silently
  yields a different shared secret. The `kemConfirmTag` closes this: because the tag is derived from
  the mixed root (which depends on the KEM shared secret), ANY tamper of the KEM material changes the
  tag, so the initiator's constant-time comparison fails and `confirmBuddy` is refused with
  `pq_confirm_failed` (fail closed at pairing time) instead of establishing a confirmed-but-dead
  pairing that has silently lost its PQ hardening.
- **Fail closed:** once an initiator opts into `pqPrekey`, `confirmBuddy(matched: true)` WITHOUT both
  `kemCiphertext` and `kemConfirmTag` is refused (`pq_prekey_required`), and a tag mismatch is refused
  (`pq_confirm_failed`) — a PQ pairing never silently downgrades to the classical seed. In both cases
  the parked prekey is retained so a legitimate retry can complete. A pairing with no KEM material on
  either side is the classical (legacy / local-dev) path and is NON-PQ.
- **Argument-consistency (fail closed):** `addBuddy` rejects inconsistent PQ combinations with
  `invalid_arg` before the handshake — an Initiator given an `initiatorKemPublicKey`, or a Responder
  with `pqPrekey: true` but no `initiatorKemPublicKey` — so KEM material is never silently dropped
  into a non-PQ pairing.
- `kemPublicKey` / `kemCiphertext` / `kemConfirmTag` are PUBLIC (a KEM public key, ciphertext, and a
  one-way HMAC tag); no private key or shared secret ever crosses the boundary.

**HONEST LABELING (Constitution IV): this hardens ONLY the initial content root.** The ongoing
per-message X25519 DH ratchet REMAINS CLASSICAL — every subsequent message key still comes from a
classical X25519 step and is harvest-now-decrypt-later-exposed. This is **not** post-quantum
messaging; it PQ-protects the pairing seed only. Real metadata privacy remains gated on an attested
backend (`privacyStatus`), independently of this change.

## Hard rules

- The engine NEVER returns key material or raw tokens to Dart.
- `privacyStatus.metadataPrivate == false` ⇒ Dart MUST display `DEV, NO METADATA PRIVACY`
  prominently; the engine emits this whenever the active backend is dev/stub or attestation has
  not passed (FR-016, Constitution IV).
- Errors and logs surfaced to Dart MUST NOT vary on secret values.
- `apiVersion` mismatch ⇒ engine refuses the call (forward/backward-compat safety).
