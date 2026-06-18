# Implementation Plan: Metadata-Private Messenger

**Branch**: `001-metadata-private-messenger` | **Date**: 2026-06-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-metadata-private-messenger/spec.md`

## Summary

A text messenger whose primary requirement is **metadata privacy** — hiding which contact
messages whom, and when — from an observer who sees all traffic and runs some servers.
Technical approach: a pure, effect-free **Scala 3 `protocol-core`** module (the single source
of truth for handshake, notification codec, retrieval-token derivation, schedule, and framing)
cross-compiled to the JVM (servers, tests) and Scala.js (the Flutter client engine). Servers
are JVM Scala on **Pekko/Akka** actors, communicating in asynchronous batched rounds over
**gRPC/TLS 1.3**. The first real anonymity backend is the **PingPong enclave** oblivious store
+ sealed-notification subsystem, implemented as a native (Rust/C++) sidecar the Scala server
calls; the Groove mixnet is stubbed behind the same interface. Trust on the PING/PONG path
comes from **RATS attestation** (Veraison verifier, CoRIM reference values in a transparency
log), never from service identity. Per the clarify decision, **real metadata privacy is in
MVP scope**: the first shippable release is gated on the enclave backend + attestation; the
dev store exists only as a labeled test/dev implementation.

## Technical Context

**Language/Version**: Scala 3 (`protocol-core` cross-compiled JVM + Scala.js); JVM servers on
Pekko (Akka-API compatible); native sidecar in Rust (preferred) or C++; Flutter/Dart client UI.

**Primary Dependencies**:
- Content crypto: libsodium / NaCl (ChaCha20-Poly1305, Blake2b); an audited Signal double-ratchet implementation (wrapped, not rewritten).
- Post-quantum: liboqs (or BoringSSL/corecrypto bindings) for ML-KEM (FIPS 203) + ML-DSA (FIPS 204), via JVM FFI; X25519 from libsodium for the hybrid.
- OPRF: an audited DH-OPRF / VOPRF library on a vetted group, for epoch key evolution.
- Transport: gRPC + TLS 1.3 (ScalaPB on the JVM).
- Server runtime: Pekko (actors, streams) on the JVM.
- Oblivious primitives: native sidecar (oblivious compare/choose/sort/compaction) — Rust.
- Attestation: RATS (RFC 9334) background-check model; Veraison verifier; SGX DCAP quote / TEE-agnostic token; CoRIM reference values in an append-only transparency log.
- Mesh identity (bounded): SPIFFE/SPIRE + Envoy SDS for non-enclave services only.
- Persistence: Postgres or embedded KV (service provider buffer, dev store).

**Storage**: PingPong enclave oblivious store (target, native sidecar) for messages;
Postgres/embedded-KV for the untrusted service-provider buffer and the dev store.

**Testing**: ScalaTest + ScalaCheck (property-based) for protocol state machines and oblivious
primitives; known-answer tests from FIPS/library vectors for ML-KEM, ML-DSA, AEAD; Rust
`cargo test` + property tests for the sidecar's oblivious primitives; integration tests over
gRPC across client engine ↔ server ↔ sidecar.

**Target Platform**: JVM servers (Linux); native sidecar (Linux, SGX-capable host for the real
enclave); Flutter clients on mobile (iOS/Android) and desktop.

**Project Type**: Multi-component system — cross-compiled protocol library + JVM services +
native sidecar + mobile/desktop app.

**Performance Goals**: Minute-order end-to-end latency (single-digit rounds, SC-001); fixed
256-byte message frames; up to 512 buddies per user (FR-015); round interval tuned to meet
minute-order latency while preserving uniform cover traffic.

**Constraints**: Constant-time secret-dependent code; oblivious access depending only on public
batch sizes; non-recurrent retrieval tokens; cover traffic independent of real-message
presence; forward secrecy with per-epoch key erasure; no hand-rolled crypto; pinned deps;
reproducible enclave build with transparency-logged measurement.

**Scale/Scope**: v1 = text only (no voice/video/large-media/group — OOS-001..003), architecture
must leave room for them. 512 buddies/user; multi-device per user via untrusted service provider.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Gates derived from the constitution (v1.0.0). Initial evaluation (pre-research):

- [x] **I. No hand-rolled crypto** — PASS. All primitives sourced from named vetted libraries
  (libsodium, liboqs/BoringSSL, audited ratchet, audited OPRF). No in-repo primitive.
- [x] **II. Constant-time discipline** — PASS (design intent). Secret-dependent code lives in
  libraries or the native sidecar's oblivious primitives; DIT assumptions documented in
  research.md. Verified per-implementation in review.
- [x] **III. Metadata disclosure** — PASS. spec.md has an explicit "Metadata Protected vs.
  Leaked" section; each phase README repeats it.
- [x] **IV. Labeling rule (NON-NEGOTIABLE)** — PASS. Dev store / Groove-stub builds carry
  `DEV, NO METADATA PRIVACY` in code/logs/UI; MVP release gated on real enclave + attestation.
- [x] **V. Library-first & CLI-first** — PASS. `protocol-core`, `crypto`, `oblivious-sidecar`,
  `notify`, `store`, `attestation` each ship a JSON-stdin/stdout CLI testable without UI.
- [x] **VI. Test-driven (NON-NEGOTIABLE)** — PASS (process). Property tests + FIPS/library KATs
  written before implementation; KATs ship with each crypto path.
- [x] **VII. Single source of truth** — PASS. Handshake, notification codec, retrieval-token
  derivation, schedule, framing live only in `protocol-core`; clients use the Scala.js build.
- [x] **VIII. Pluggable trust backends** — PASS. `ObliviousStore` and `AnonymityLayer`
  interfaces with dev + target impls switchable by config.
- [x] **IX. Attestation, not identity (NON-NEGOTIABLE)** — PASS. PING/PONG trust = verified
  attestation result (freshness nonce, CoRIM appraisal); SVIDs never substitute; enclave key
  accepted only post-attestation.
- [x] **X. Reproducible builds & transparency log** — PASS. Enclave built reproducibly;
  measurement published to append-only log as CoRIM; clients pin logged measurements.
- [x] **XI. Pinned deps & no secrets** — PASS. All deps pinned; no secrets committed;
  reproducible builds.
- [x] **Security constraints** — PASS. Oblivious access by public batch size only; non-recurrent
  tokens; cover traffic independent of real messages; epoch keys erased / non-roll-forward;
  receiver-issued notification tokens.

**Result: PASS — no violations. Complexity Tracking empty.** Re-evaluated post-design (Phase 1):
still PASS (see end of plan).

## Project Structure

### Documentation (this feature)

```text
specs/001-metadata-private-messenger/
├── plan.md              # This file (/speckit-plan output)
├── spec.md              # Feature specification
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (gRPC + CLI + engine API contracts)
│   ├── messaging.proto
│   ├── notify.proto
│   ├── store.proto
│   ├── attestation.proto
│   ├── engine-api.md
│   └── cli-contracts.md
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
protocol-core/               # Scala 3, cross-compiled (JVM + Scala.js) — SINGLE SOURCE OF TRUTH
├── shared/src/main/scala/   #   handshake, notification codec, retrieval-token PRF,
│                            #   client schedule, message framing (pure, effect-free)
├── jvm/                     #   JVM-specific glue (server + tests)
├── js/                      #   Scala.js client engine bundle + narrow versioned Dart API
└── shared/src/test/scala/   #   ScalaCheck property tests + KAT harness

crypto/                      # Scala 3 JVM — thin wrappers over vetted libs (libsodium, liboqs,
│                            #   ratchet, OPRF) + FFI; KATs from FIPS/library vectors. CLI.
server/                      # JVM Scala on Pekko — async rounds, batching, gRPC/TLS endpoints
├── ping/                    #   notification subsystem (PING) front; calls sidecar
├── pong/                    #   message store (PONG) front; calls sidecar
├── provider/                #   untrusted service provider (buffer, device sync)
└── attestation/             #   RATS relying-party + Veraison client; appraisal + freshness

oblivious-sidecar/           # Rust — oblivious primitives + PONG store + sealed-notif aggregation
├── src/store/               #   oblivious hash table, stash, bins, deamortized builds
├── src/notify/              #   bitwise-or aggregation, oblivious sort/scan/compaction
└── src/primitives/          #   oblivious compare/choose/sort/compaction (constant-time)

anonymity/                   # AnonymityLayer interface + Groove mixnet (stub: single shuffler)
clients/flutter/             # Flutter UI (presentation only) driving the Scala.js engine
deploy/                      # SPIRE/Envoy SDS config (non-enclave services), reproducible builds
```

**Structure Decision**: Multi-component layout. `protocol-core` is the cross-compiled nucleus
(Constitution VII). `crypto` isolates all vetted-library calls (Constitution I/II) with KATs.
`server` (Pekko) hosts PING/PONG/provider/attestation fronts; the privacy-critical oblivious
work lives in the Rust `oblivious-sidecar` because Scala cannot run inside an SGX enclave.
Backends sit behind `ObliviousStore` / `AnonymityLayer` interfaces (Constitution VIII). The
Flutter client is presentation-only over the Scala.js engine.

## Phasing (build order; MVP release gate per Clarifications)

- **Phase A** — Content-encrypted messenger: buddy handshake, client schedule, cover traffic,
  message framing, `protocol-core` + `crypto`, end-to-end over gRPC, `ObliviousStore` **dev**
  impl labeled `DEV, NO METADATA PRIVACY`.
- **Phase B** — PING notification subsystem over the dev store; receiver-sealed tokens;
  concurrent-conversation UX (multiple buddies, never blocked).
- **Phase C** — Real PingPong **enclave oblivious store + notification aggregation** (Rust
  sidecar) and the **attestation flow** (Veraison verifier, CoRIM transparency-logged reference
  values, client-side appraisal with freshness nonce). Written trust assumptions. **SPIRE mesh
  identity** for non-enclave services may land alongside (independent of C). **← MVP release
  gate: the first shippable build is here, not before** (clarify decision: real privacy in MVP).
- **Phase D** (post-MVP) — Post-quantum hybrid key agreement (X25519 + ML-KEM), epoch forward
  secrecy via verifiable OPRF, multi-device oblivious delegation, threshold enclave key.

No metadata-privacy property is advertised until Phase C is real and assumptions are written
(Constitution IV).

## Complexity Tracking

> No constitution violations. No entries required.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| (none)    | —          | —                                   |

## Post-Design Constitution Re-Check

After Phase 1 (data-model, contracts, quickstart): **PASS.** Contracts keep secret-dependent
logic in `crypto`/sidecar; `engine-api.md` confirms Dart holds presentation state only;
`store.proto`/`notify.proto` expose access only by public batch size and non-recurrent tokens;
`attestation.proto` carries a freshness nonce and a verifier-signed result, with the enclave
key delivered only after appraisal. No new violations introduced.
