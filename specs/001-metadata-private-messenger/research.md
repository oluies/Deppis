# Phase 0 Research: Metadata-Private Messenger

All Technical Context unknowns are resolved here. Format per decision/rationale/alternatives.
Numeric targets and backend choice are fixed by the spec Clarifications (PingPong enclave,
256-byte frames, 512 buddies, minute-order latency, real privacy in MVP, Pekko server, Flutter).

## D1. First real anonymity backend

- **Decision**: PingPong enclave oblivious store + sealed-notification subsystem as the first
  real target; Groove mixnet stubbed behind the same `AnonymityLayer` interface.
- **Rationale**: Clarify decision. Lower latency (meets SC-001 minute-order), and PingPong's
  notify-before-retrieval directly delivers the concurrent-conversation UX (FR-006). The
  oblivious store and sealed tokens are buildable/testable without an enclave; only the privacy
  *claim* requires it.
- **Alternatives considered**: Groove mixnet (differential privacy from a mixnet + noise,
  mobile-proven, trust a fraction `f` of honest servers) — kept as a stub and a later option;
  building both real — rejected as scope.

## D2. Trust assumption (PingPong path)

- **Decision**: Trust = an uncompromised SGX enclave running a measurement present in the
  transparency log, appraised by a Veraison verifier against CoRIM reference values, with a
  client freshness nonce. Threshold-split enclave key across replicas (Phase D).
- **Rationale**: Constitution IX/X. Attestation answers "genuine enclave running reviewed code
  X"; the transparency log closes "X is honest code." Identity (SPIFFE) is explicitly *not* a
  substitute.
- **Residual assumptions (recorded in threat model)**: uncompromised enclave; rollback, power,
  and transient-execution/side-channel attacks out of scope unless mitigated; single TEE vendor
  until heterogeneous TEEs added; a verifier + reference-value log the client trusts.
- **Alternatives**: mixnet honest-fraction `f` + route length — applies if Groove is later
  chosen; managed verifier (Intel Trust Authority / Azure Attestation) instead of self-hosted
  Veraison — supported as a config option.

## D3. Numeric targets

- **Decision**: 256-byte fixed message frames; up to 512 buddies/user; minute-order latency
  (single-digit rounds). Round interval a tuned parameter (start ~10–30 s, adjust to hold
  minute-order latency under uniform cover traffic).
- **Rationale**: Clarify decision (PingPong-style), consistent with SC-001/FR-015/FR-015a.
- **Alternatives**: Groove-style (~100-byte, 50 buddies, 30–60 s rounds) — rejected with the
  Groove backend.

## D4. Content cryptography

- **Decision**: ChaCha20-Poly1305 (AEAD) + Blake2b (hash/KDF) via libsodium; Signal-style
  double ratchet from an audited implementation (wrapped). Retrieval-token PRF = keyed Blake2b
  (or HMAC) over (sender id, receiver id, per-message counter), in `protocol-core`.
- **Rationale**: Constitution I/VI. Groove's choices; well-vetted; constant-time in libsodium.
  Tokens derived by a keyed PRF are non-recurrent by construction (counter monotone).
- **Alternatives**: AES-GCM/SHA-256 — fine but libsodium/Blake2b chosen for constant-time
  ergonomics and to match the reference papers; hand-rolled ratchet — forbidden (Constitution I).

## D5. Post-quantum primitives (Phase D)

- **Decision**: ML-KEM (FIPS 203) for key establishment, ML-DSA (FIPS 204) for signatures /
  key-transparency, via liboqs (or BoringSSL/corecrypto) through JVM FFI. Hybrid key agreement
  = X25519 ⊕ ML-KEM (combine both shared secrets via KDF) so a single break is not fatal.
- **Rationale**: corecrypto's selections; Constitution security section. Hybrid hedges PQ
  immaturity. FIPS KAT vectors provide known-answer tests.
- **Alternatives**: PQ-only (no hybrid) — rejected; reimplementation — forbidden.

## D6. Epoch forward secrecy

- **Decision**: Per-buddy and multi-device keys evolve once per epoch via a verifiable OPRF
  (DH-OPRF/VOPRF on a vetted group) run against the servers; output verified against the
  server's epoch public key. Old keys erased; no roll-forward past the window.
- **Rationale**: Groove's mechanism; Constitution security section. VOPRF gives verifiability so
  a malicious server can't silently substitute. Erasure delivers forward secrecy of the contact
  list and content (FR-013, SC-007).
- **Alternatives**: pure hash-ratchet epoch evolution (no server interaction) — simpler but
  loses the oblivious-delegation property Groove needs for multi-device; rejected for the
  multi-device path.

## D7. Message store (PONG role)

- **Decision**: `ObliviousStore` interface { write(token, frame); read(token) → frame }. **Dev**
  impl = in-memory / Postgres KV (no access-pattern privacy, labeled `DEV, NO METADATA
  PRIVACY`). **Target** impl = Rust sidecar oblivious hash table: stash + append-only bin buffer
  merged into larger message tables in the background, deamortized builds; unlinks writes from
  reads via non-recurrent tokens.
- **Rationale**: Constitution VIII; Scala cannot run inside an SGX enclave, so oblivious
  primitives (compare/choose/sort/compaction) live in the native sidecar the Scala server calls.
- **Alternatives**: full ORAM library — heavier; PONG's bin/table structure chosen per the
  paper for deamortized throughput.

## D8. Notification subsystem (PING role)

- **Decision**: Receiver generates one sealed notification token per buddy at add-buddy time and
  hands it to the buddy. Each token encrypts a one-hot bit-vector position + an aggregation
  label under the notification server's key, so a sender can only flip *its own* bit (no flood,
  no impersonation). Server aggregates by bitwise-OR over a shared label, injects an all-zero
  carrier per client for uniformity, then oblivious-sort + linear-scan + oblivious-compaction to
  emit one digest per client. Oblivious steps run in the same Rust sidecar.
- **Rationale**: Constitution security section (token direction receiver→sender preserved);
  FR-003/FR-004. Carrier injection gives traffic uniformity (FR-012).
- **Alternatives**: sender-generated tokens — rejected (enables flooding/impersonation).

## D9. Anonymity layer (Groove path)

- **Decision**: `AnonymityLayer` interface; Groove mixnet (circuits, dead drops over epochs,
  oblivious circuit setup, circuit tagging for uncoordinated replacement across a user's devices,
  oblivious fetch: return headers → shuffle through a fetch mixchain → fetch at shuffled
  indices). **Dev** = single honest shuffler, labeled "no differential-privacy guarantee".
- **Rationale**: keeps the door open to the Groove trust model without conflating it with the
  enclave model; Constitution VIII.
- **Alternatives**: omit entirely — rejected; spec requires architecture to leave room.

## D10. Service provider

- **Decision**: Untrusted helper buffering circuit-setup/messages and synchronizing a user's
  devices; storage Postgres or embedded KV with atomic transactions. Never trusted for privacy.
- **Rationale**: FR-010/FR-011; Groove oblivious delegation enables offline + multi-device and
  prevents two non-coordinating devices from de-anonymizing the user.
- **Alternatives**: trusted relay — rejected (violates threat model).

## D11. Attestation & identity

- **Decision**: RATS (RFC 9334) background-check model. Enclave emits evidence (SGX DCAP quote
  or TEE-agnostic token); **Veraison** verifier appraises against an appraisal policy pinning
  CoRIM reference values from the transparency log and returns a signed attestation result; the
  client (relying party) checks it with a freshness nonce before accepting the enclave public
  key and submitting the sealed notification token. Managed verifier (Intel Trust Authority /
  Azure Attestation) is a config alternative.
- **Rationale**: Constitution IX/X. Separates attestation ("is this a genuine enclave running X")
  from identity ("which service is this").
- **Alternatives**: passport model — viable but background-check chosen for centralized policy
  control; trusting service identity — forbidden.

## D12. Mesh identity (bounded SPIFFE/SPIRE role)

- **Decision**: SPIRE issues short-lived SVIDs to **non-enclave** services only (entry-node LBs,
  offline-user proxy, observability) for mTLS; delivered Istio-style (SPIRE node+workload
  attestation → SPIFFE CSI driver mounts Envoy SDS UDS → Envoy fetches X.509-SVID + trust
  bundles over SDS; SPIFFE federation across trust domains). For any SVID on a PING/PONG
  workload, an enclave-aware attestor gates issuance on a passing attestation result.
- **Rationale**: Constitution IX. SPIRE's pluggable attestors are the seam where enclave
  attestation gates issuance; identity never substitutes for attestation on PING/PONG.
- **Alternatives**: hand-managed certs — rejected (no rotation, drift).

## D13. Transport & rounds

- **Decision**: gRPC over TLS 1.3 between clients, service providers, and backend servers;
  asynchronous rounds with batching (ScalaPB; Pekko streams for round orchestration).
- **Rationale**: both papers; batching is required for the oblivious/mixnet steps and for cover
  traffic uniformity.
- **Alternatives**: REST/long-poll — rejected (batched binary rounds fit better).

## D14. Client architecture

- **Decision**: Flutter UI (presentation only) drives the Scala.js-compiled `protocol-core`
  engine over a thin, versioned platform channel / embedded JS runtime; crypto + protocol state
  stay inside the engine, Dart holds only presentation state. Servers are JVM Scala on
  **Pekko/Akka** actors.
- **Rationale**: Clarify decision (server Pekko/Akka, frontend Flutter) + Constitution VII
  (single source of truth). Avoids re-deriving protocol logic in Dart.
- **Alternatives (recorded, not selected)**: a local Scala/JVM sidecar process over a localhost
  socket — heavier runtime footprint on mobile; rejected in favor of the Scala.js engine.

## D15. Testing strategy

- **Decision**: ScalaCheck property tests for protocol state machines (handshake, schedule,
  framing) and for oblivious primitives' invariants; FIPS/library KATs for ML-KEM, ML-DSA, AEAD
  shipped with each crypto path; Rust `cargo test` + proptest for sidecar oblivious primitives;
  gRPC integration tests across engine ↔ server ↔ sidecar; a statistical indistinguishability
  test for cover traffic (active vs. idle traces).
- **Rationale**: Constitution VI (NON-NEGOTIABLE).
- **Alternatives**: example-based only — insufficient for state machines/primitives.

## D16. Notification-token round binding (per-round tokens)

- **Decision**: Bind `round_id` into the AEAD-sealed notification token plaintext
  (`[round(8 BE)][bit(2 BE)][label]`); the opener (Scala `DevNotificationServer` and the Rust
  sidecar) validates the bound round equals the signal's `round_id` and drops the token otherwise.
- **Rationale**: `round_id` is otherwise attacker-controlled cleartext, so a captured-and-replayed
  token could be submitted across many rounds to evict legitimate pending notifications (a
  notification-loss DoS, found by review). Binding the round into the authenticated plaintext makes
  cross-round replay impossible. Per-round signal caps + insertion-order round eviction remain as
  memory/CPU backstops (same-round replay is idempotent OR'ing).
- **Model change (amends FR-003)**: tokens are now **per-round** (round-bound) rather than issued
  once at add-buddy time and reused across rounds. The receiver issues a token for a specific round;
  a deployment provisions per-round tokens (this also fits attestation-gated key provisioning, D11).
- **Alternatives considered**: a server-clock round window (reject ids far from the sidecar's wall
  clock) — rejected as it commits `round_id` to being time-derived and needs a trusted clock;
  accepting the residual under the dev label — rejected in favor of closing it.
