# Tasks: Metadata-Private Messenger

**Input**: Design documents from `specs/001-metadata-private-messenger/`

**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/ ✓

**Tests**: INCLUDED — Constitution Principle VI (Test-Driven) is NON-NEGOTIABLE. Property tests
for state machines/oblivious primitives and FIPS/library KATs for crypto are required and are
written before implementation.

**Organization**: Tasks grouped by user story (US1–US7 from spec.md). Build-order constraints
from plan.md: **`protocol-core` before `server` before clients; dev store before native
sidecar.** Phase labels (A/B/C/D) note the release phasing; MVP release is gated on Phase C.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no incomplete-task dependency)
- **[Story]**: US1–US7; Setup/Foundational/Polish have no story label

## Path Conventions

Multi-component layout (plan.md): `protocol-core/`, `crypto/`, `server/`, `oblivious-sidecar/`,
`anonymity/`, `clients/flutter/`, `deploy/` at repo root.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and pinned, reproducible build foundation (Constitution XI).

- [ ] T001 Create the multi-module layout per plan.md (`protocol-core/{shared,jvm,js}`, `crypto/`, `server/{ping,pong,provider,attestation}`, `oblivious-sidecar/`, `anonymity/`, `clients/flutter/`, `deploy/`)
- [ ] T002 Initialize the sbt cross-build (Scala 3) for `protocol-core` (JVM + Scala.js) and `crypto`/`server` JVM modules in `build.sbt`, with **pinned** dependency versions
- [ ] T003 [P] Initialize the Rust `oblivious-sidecar` crate with pinned deps in `oblivious-sidecar/Cargo.toml`
- [ ] T004 [P] Initialize the Flutter app skeleton in `clients/flutter/`
- [ ] T005 [P] Configure linting/formatting: scalafmt + scalafix (`/.scalafmt.conf`), rustfmt + clippy (`oblivious-sidecar/`), `dart format`/`flutter analyze`
- [ ] T006 [P] Add ScalaPB codegen for the contracts in `specs/001-metadata-private-messenger/contracts/*.proto` wired into `build.sbt`
- [ ] T007 [P] Add a reproducible-build + dependency-pinning CI check and a secret-scanning gate in `deploy/ci/` (Constitution XI)
- [ ] T008 [P] Add a CI gate asserting no release artifact reports `metadataPrivate:false` and that the `DEV, NO METADATA PRIVACY` label is present in dev builds (Constitution IV / FR-016)

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ CRITICAL**: No user-story work begins until this phase is complete. This is the
`protocol-core` + `crypto` nucleus and the pluggable-backend interfaces every story builds on.

- [X] T009 [P] KAT harness + FIPS/library vectors for AEAD (ChaCha20-Poly1305) and Blake2b in `crypto/jvm/src/test/scala/kat/` (write first; MUST fail before T011) — `crypto/src/test/scala/crypto/{CryptoSpec,CryptoKatSpec}.scala`: AEAD cross-checked byte-for-byte vs JDK ChaCha20-Poly1305; Blake2b cross-checked vs Bouncy Castle (256/512/keyed) + RFC 7693 `BLAKE2b-512("abc")` static vector; `mcrypto kat` runs the RFC vector. (Static RFC 8439 AEAD vector still a nice-to-have.)
- [X] T010 [P] Property-test skeleton (ScalaCheck) for protocol state machines + framing in `protocol-core/shared/src/test/scala/` (write first; MUST fail before T013–T016) — 11 props green (Frame/Token/Schedule/Privacy)
- [X] T011 [P] Implement `crypto` AEAD + KDF wrappers over libsodium (ChaCha20-Poly1305, Blake2b) in `crypto/jvm/src/main/scala/`, with `mcrypto aead-seal|aead-open|kdf|kat` CLI (Constitution I/II/V); make T009 pass — JDK FFM (Panama) binding to libsodium; `crypto/src/main/scala/crypto/`; 6 tests green
- [ ] T012 [P] Wrap an audited Signal double-ratchet implementation in `crypto/jvm/src/main/scala/ratchet/` (no hand-rolled ratchet — Constitution I)
- [X] T013 Implement message framing (fixed 256-byte frames, padding) in `protocol-core/shared/src/main/scala/frame/` (FR-015a)
- [X] T014 Implement retrieval-token PRF = keyed Blake2b/HMAC over (senderId, receiverId, counter) with monotone counter (non-recurrent) in `protocol-core/shared/src/main/scala/token/` + `pcore retrieval-token` CLI (FR-014) — JCA HMAC-SHA256 (not hand-rolled), length-prefixed fields, constant-time compare
- [X] T015 Implement the client schedule (uniform per-round send/retrieve/carrier decisions, cover traffic) in `protocol-core/shared/src/main/scala/schedule/` (FR-012) + `pcore schedule-next` CLI
- [X] T016 Define the `ObliviousStore` and `AnonymityLayer` interfaces (config-switchable backends) in `server/pong/src/main/scala/store/` and `anonymity/src/main/scala/` (Constitution VIII)
- [X] T017 [P] Implement `BuildPrivacyStatus` + `pstatus show` CLI emitting `{backend, metadataPrivate, label}` in `protocol-core/shared/src/main/scala/privacy/` (FR-016, Constitution IV)
- [X] T018 [P] Configure error handling/logging that never varies on secret values (Constitution II) in `server/src/main/scala/obs/` — `SafeLog` (constant redaction marker, no value/length leak) + `FailureReason` enum (fixed public messages); property-tested for content/length independence
- [ ] T019 Scaffold the Scala.js engine bundle + versioned Dart platform-channel API per `contracts/engine-api.md` in `protocol-core/js/` (Constitution VII)
- [ ] T020 [P] Stand up the Pekko/Akka server skeleton with gRPC/TLS 1.3 round orchestration in `server/src/main/scala/round/` (per `contracts/messaging.proto`)

**Checkpoint**: protocol-core + crypto + interfaces ready; user stories can begin.

---

## Phase 3: User Story 1 — Add a buddy once, out of band (Priority: P1) 🎯 MVP · Phase A

**Goal**: One-time, mutually authenticated out-of-band pairing (QR / safety number).

**Independent Test**: Two engines pair, compare matching safety numbers, both list a Confirmed
buddy; a tampered secret fails the comparison and is rejected; re-adding is recognized as a dup.

- [X] T021 [P] [US1] Property test for the add-friend handshake (match → Confirmed; mismatch → rejected; idempotent dup) in `protocol-core/shared/src/test/scala/handshake/` (write first, MUST fail) — HandshakeSpec + BuddySpec, green
- [ ] T022 [P] [US1] Contract test for engine `addBuddy`/`confirmBuddy` per `contracts/engine-api.md` in `protocol-core/js/src/test/`
- [X] T023 [US1] Implement the add-friend handshake + safety-number derivation in `protocol-core/shared/src/main/scala/handshake/` + `pcore handshake-init` CLI (FR-001) — symmetric HMAC-derived pairId/safetyNumber/pairKey; tamper ⇒ mismatch
- [X] T024a [P] [US1] Boundary test for the 512-buddy cap (accept up to 512; 513th rejected predictably; count correct after removals) in `protocol-core/shared/src/test/scala/buddy/` (FR-015) — write first, MUST fail [analyze C1]
- [X] T024 [US1] Implement `BuddyRelationship` state (`Pending→Confirmed→Removed`), uniqueness/no-dup, removal, AND enforcement of the **512-buddy cap** (reject the 513th predictably) in `protocol-core/shared/src/main/scala/buddy/` (FR-002, FR-015, FR-018)
- [ ] T025 [US1] Wire `addBuddy`/`confirmBuddy`/`removeBuddy` engine commands + `buddyConfirmed` event in `protocol-core/js/` (FR-001/FR-002/FR-018)
- [ ] T026 [US1] Flutter add-buddy + safety-number-compare UI in `clients/flutter/lib/buddy/`, showing the privacy-status label (FR-016)

**Checkpoint**: US1 fully functional and independently testable (Phase A begins).

---

## Phase 4: User Story 2 — Notified that *someone* wrote, without revealing who (Priority: P1) · Phase A→B

**Goal**: Receiver-sealed notification tokens; "mail waiting" without learning which buddy.

**Independent Test**: One message from one of several buddies notifies the receiver; the
notification server cannot determine the sender; receiver retrieves on its own schedule.

- [ ] T027 [P] [US2] Property test: sealed token lets holder flip only its own bit; no forge/flood (FR-003) in `protocol-core/shared/src/test/scala/notify/` (write first, MUST fail)
- [ ] T028 [P] [US2] Contract test for `notify.proto` Signal/FetchDigest in `server/ping/src/test/scala/`
- [X] T029 [US2] Implement receiver-generated sealed notification-token codec (one-hot position + aggregation label) in `protocol-core/shared/src/main/scala/notify/` (FR-003, token direction receiver→sender) — codec + Digest bit-vector in protocol-core; AEAD sealing in server/ping (JVM-only crypto)
- [X] T030 [US2] Implement the **dev** notification aggregation (bitwise-OR + carrier injection) behind the PING front in `server/ping/src/main/scala/` over the dev store, labeled `DEV, NO METADATA PRIVACY` (FR-004/FR-012/Constitution IV) [Phase B] — DevNotificationServer: seal/open, OR-by-label, carrier digest, anti-forge/tamper; oblivious sort/scan/compaction deferred to the sidecar (T053)
- [X] T031 [US2] Implement the **dev** `ObliviousStore` (in-memory/Postgres KV, no access-pattern privacy, labeled) in `server/pong/src/main/scala/store/dev/` (Constitution VIII/IV) [dev store before sidecar] — in-memory; enforces 256-byte frames, single-use non-recurrent tokens, no-token-reuse
- [ ] T032 [US2] Wire `sendMessage` (frame+enqueue) and the `notified` engine event in `protocol-core/js/` + Flutter notification indicator in `clients/flutter/lib/notify/` (FR-004)

**Checkpoint**: US1+US2 work; notify-before-retrieval UX over the labeled dev backend.

---

## Phase 5: User Story 3 — Several conversations at once, never blocked (Priority: P1) · Phase B

**Goal**: Concurrent conversations with no blocking between them.

**Independent Test**: Three buddies send in one round; receiver retrieves and replies to all
three with no ordering constraint between conversations.

- [ ] T033 [P] [US3] Integration test: 3 concurrent conversations in one round, none blocked, in `server/src/test/scala/integration/concurrency/` (write first, MUST fail) — PARTIAL: protocol-core independence shown in `ConversationsSpec`; server-round integration test still pending T035
- [ ] T033a [P] [US3] Scale test: a user holds up to 512 simultaneous conversations with no conversation blocking another in `server/src/test/scala/integration/scale/` (SC-005) — write first, MUST fail [analyze C4] — PARTIAL: protocol-core 512-conversation scale shown in `ConversationsSpec`; server-round (real-concurrency) scale test still pending T035
- [ ] T036a [P] [US3] End-to-end latency test: a two-party exchange completes within minute-order (single-digit rounds); asserts the tuned round interval meets SC-001, in `server/src/test/scala/integration/latency/` (SC-001) — write first, MUST fail [analyze C2]
- [X] T034 [US3] Implement per-buddy independent send/retrieve state (no cross-conversation blocking) in `protocol-core/shared/src/main/scala/session/` (FR-006) — immutable `Conversations`: per-buddy queue + monotone counter (non-recurrent tokens), keyed by pairId so conversations never block each other
- [ ] T035 [US3] Implement round retrieval of multiple frames with uniform/padded count in `server/pong/src/main/scala/` per `contracts/messaging.proto` Retrieve (FR-006/FR-012)
- [ ] T036 [US3] Flutter multi-conversation list/threading in `clients/flutter/lib/chat/`

**Checkpoint**: US1–US3 (all P1) complete — Phase B UX done over the labeled dev backend.

---

## Phase 6: User Story 4 — Send to and catch up while offline (Priority: P2) · Phase B

**Goal**: Asynchronous delivery to offline buddies; catch-up on return.

**Independent Test**: Send to an offline buddy; buddy returns and retrieves; multiple queued
messages all arrive in order.

- [ ] T037 [P] [US4] Integration test: offline send + ordered catch-up in `server/provider/src/test/scala/` (write first, MUST fail)
- [ ] T038 [US4] Implement the untrusted service-provider buffer (atomic transactions, retention window) in `server/provider/src/main/scala/` (FR-007/FR-008), bounded retention not leaking sender
- [ ] T039 [US4] Implement device `Online/Offline` + missed-round catch-up in `protocol-core/shared/src/main/scala/device/` (FR-008, no real-vs-idle leak on gaps)

**Checkpoint**: US4 complete; offline/async works.

---

## Phase 7: User Story 6 — Look identical whether chatting or idle (Priority: P2) · Phase B

**Goal**: Active vs. idle indistinguishable to a network observer.

**Independent Test**: Active and idle traces are statistically indistinguishable.

> Ordered before US5/US7 because cover-traffic uniformity underpins the multi-device and
> compromise stories.

- [ ] T040 [P] [US6] Statistical indistinguishability test (active vs idle traces) in `server/src/test/scala/integration/cover/` (write first, MUST fail)
- [ ] T041 [US6] Implement uniform per-round carrier frames on send AND fetch paths (shape independent of real-message presence) in `protocol-core/shared/src/main/scala/schedule/` + `server/src/main/scala/round/` (FR-012)
- [ ] T042 [US6] Verify carrier frames are wire-indistinguishable from real frames in `server/pong/` Retrieve responses (FR-012)

**Checkpoint**: US6 complete; cover traffic enforced.

---

## Phase 8: User Story 5 — Several devices via an untrusted helper (Priority: P2) · Phase B→D

**Goal**: Multi-device through an untrusted provider; no provider leak; no two-device de-anon.

**Independent Test**: Two devices both receive a buddy's message via the provider; a compromised
provider learns zero buddies/activity; two non-coordinating devices emit no linkable traffic.

- [ ] T043 [P] [US5] Integration test: 2-device delivery + provider-compromise yields nothing + non-coordination (FR-010/FR-011) in `server/provider/src/test/scala/multidevice/` (write first, MUST fail)
- [ ] T044 [US5] Implement provider-mediated device sync (buffer + reconcile divergent state) in `server/provider/src/main/scala/sync/` (FR-010)
- [ ] T045 [US5] Implement oblivious delegation so two non-coordinating devices don't emit duplicate/linkable traffic in `protocol-core/shared/src/main/scala/delegation/` (FR-011) [hardening continues in Phase D]

**Checkpoint**: US5 functional over dev backend; full guarantee lands with Phase C/D.

---

## Phase 9: User Story 7 — Survive device compromise without losing the past (Priority: P2) · Phase D

**Goal**: Forward secrecy of content and contact list under device compromise.

**Independent Test**: With all current key material captured, past ciphertext and past contacts
are unrecoverable.

- [ ] T046 [P] [US7] Property/integration test: post-compromise, zero past messages/contacts recoverable (FR-013/SC-007) in `crypto/jvm/src/test/scala/fs/` (write first, MUST fail)
- [ ] T047 [P] [US7] KAT harness + FIPS vectors for ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in `crypto/jvm/src/test/scala/kat/` (write first, MUST fail before T048)
- [ ] T048 [US7] Implement ML-KEM/ML-DSA wrappers via liboqs JVM FFI + `mcrypto kem-encaps|kem-decaps` and hybrid X25519⊕ML-KEM key agreement in `crypto/jvm/src/main/scala/pq/` (Constitution I); make T047 pass [Phase D]
- [ ] T049 [US7] Implement epoch key evolution via verifiable OPRF (verify vs epoch pubkey) + erasure / no roll-forward in `protocol-core/shared/src/main/scala/epoch/` + `crypto/.../oprf/` (FR-013, security section) [Phase D]

**Checkpoint**: US7 complete; forward secrecy + PQ hybrid in place.

---

## Phase 10: Real Privacy Backend & Attestation (Phase C) 🚀 MVP RELEASE GATE

**Purpose**: Replace the dev store with the real PingPong enclave oblivious store + attestation.
**Per the clarify decision, the first shippable release is gated here.** (Cross-cutting; serves
US2/US3/US5/US6's real guarantee.)

- [ ] T050 [P] Rust property tests for oblivious primitives (compare/choose/sort/compaction): access pattern depends only on batch size; `obsx selftest` in `oblivious-sidecar/src/primitives/` (write first, MUST fail)
- [ ] T051 Implement constant-time oblivious primitives in `oblivious-sidecar/src/primitives/` (Constitution II) [native sidecar after dev store]
- [ ] T052 Implement the PONG oblivious store (stash + bins + message tables, deamortized builds, unlinkable write/read, non-recurrent tokens) in `oblivious-sidecar/src/store/` + `obsx store-write|store-read` CLI (D7/FR-014)
- [ ] T053 Implement the PING sealed-notification aggregation (OR + oblivious sort/scan/compaction, carrier injection) in `oblivious-sidecar/src/notify/` + `obsx notify-aggregate` CLI (D8)
- [ ] T053a [P] Which-buddy anonymity test against the real enclave backend: with N buddies and one real sender, an observer (incl. the store/notify host) cannot identify the sending buddy better than 1/N in `server/src/test/scala/integration/anonymity/` (SC-002) — acceptance test; written up front, stays failing until the Phase C backend (T051–T056) is assembled [analyze C3]
- [ ] T054 Implement the enclave-target `ObliviousStore`/notification fronts in `server/{pong,ping}/src/main/scala/.../enclave/` calling the sidecar over gRPC (Constitution VIII)
- [ ] T055 [P] Contract test for `attestation.proto` (stale nonce / unpinned measurement / bad signature ⇒ rejected, no enclave key) in `server/attestation/src/test/scala/` (write first, MUST fail)
- [ ] T056 Implement the RATS relying-party + Veraison verifier client: appraise evidence vs CoRIM reference values, check freshness nonce, accept enclave key ONLY on pass, in `server/attestation/src/main/scala/` + `attest verify` CLI (Constitution IX/X)
- [ ] T057 Implement reproducible enclave build + publish measurement to the append-only transparency log as CoRIM reference values in `deploy/enclave/` (Constitution X)
- [ ] T058 Flip `metadataPrivate:true` ONLY when backend=enclave-target AND attestation passes; client submits sealed token only post-attestation; remove the dev label on real builds (FR-016/Constitution IV/IX)
- [ ] T059 [P] Write the Phase C threat model + trust assumptions (uncompromised enclave; rollback/side-channel out of scope; single TEE vendor; trusted verifier+log) into `specs/001-metadata-private-messenger/threat-model.md` and the phase README (Constitution III; spec Assumptions)

**Checkpoint**: Real metadata privacy active and attested — **MVP shippable**.

---

## Phase 11: Polish & Cross-Cutting Concerns

- [ ] T060 [P] SPIRE/SPIRE-Envoy SDS mesh identity for **non-enclave** services only; enclave-aware attestor gates any PING/PONG SVID on a passing attestation result; never a substitute (Constitution IX) in `deploy/spire/`
- [ ] T061 [P] Groove mixnet stub behind `AnonymityLayer` (single shuffler, labeled "no DP guarantee") in `anonymity/src/main/scala/groove/` (D9, leaves room without conflating trust models)
- [ ] T062 [P] Per-phase README updates stating exactly what metadata is protected vs leaked (Constitution III / FR-017) in repo root + `specs/.../`
- [ ] T063 [P] Threshold-split the enclave key across replicas/operators (Phase D) in `deploy/enclave/threshold/`
- [ ] T064 Run `quickstart.md` end-to-end validation (all 6 smoke steps) and record results
- [ ] T065 [P] Architecture-leaves-room notes for OOS-001..003 (voice/video, large media, group chats) in `specs/.../future-work.md`
- [ ] T066 Final constant-time + oblivious-invariant audit pass across `crypto/` and `oblivious-sidecar/` (Constitution II) and confirm all KATs/property tests green

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (P1)**: no deps.
- **Foundational (P2)**: depends on Setup; BLOCKS all stories. Embodies *protocol-core before
  server before clients*.
- **User Stories (P3–P9)**: depend on Foundational. P1 stories (US1–US3) first = MVP UX.
- **Phase C backend (P10)**: depends on US2/US3 fronts (dev store) existing — *dev store before
  native sidecar*. **MVP release gate.**
- **Polish (P11)**: after desired stories + Phase C.

### Critical build-order constraints (plan.md)

- `protocol-core` (T013–T019) → `server` (T020, T030–T035, T054) → `clients` (T026, T032, T036).
- Dev `ObliviousStore` (T031) → native sidecar store (T050–T052).

### Within Each User Story

- Tests written and FAILING before implementation (Constitution VI).
- Models/codecs → services/fronts → engine/UI wiring.

### Parallel Opportunities

- Setup: T003–T008 [P].
- Foundational: T009/T010 [P] (tests), T011/T012/T017/T018/T020 [P].
- Phase C: T050 and T055 tests [P]; T059/T060–T063 [P].

---

## Parallel Example: Foundational Phase

```bash
# Write failing tests first, in parallel:
Task: "KAT harness + AEAD/Blake2b vectors in crypto/jvm/src/test/scala/kat/"          # T009
Task: "ScalaCheck skeleton for state machines+framing in protocol-core/.../test/"      # T010
# Then implement in parallel where files don't collide:
Task: "crypto AEAD+KDF wrappers + mcrypto CLI"                                          # T011
Task: "Wrap audited double-ratchet"                                                     # T012
Task: "BuildPrivacyStatus + pstatus CLI"                                               # T017
```

---

## Implementation Strategy

### MVP scope (per Clarifications: real privacy in MVP)

The shippable MVP is **Setup + Foundational + US1–US3 (P1) + Phase C (T050–T059)**: the
notify-before-retrieval messenger with concurrent conversations running over the **real**
attested enclave backend. US4–US7 and Polish layer on after. No build advertises privacy before
T058 passes.

### Incremental delivery

1. Setup + Foundational → foundation ready.
2. US1 → US2 → US3 over the labeled dev backend → internal demo (NOT a release; dev label on).
3. US4, US6, US5 (Phase B hardening).
4. **Phase C (T050–T059)** → first shippable release (real privacy + attestation).
5. US7 + Phase D (PQ, epoch FS, multi-device, threshold key) → strengthen.

### Notes

- Commit after each task / logical group; roborev reviews every commit (`.roborev.toml`).
- Never let a dev/stub build present itself as private (Constitution IV).
- Keep secret-dependent logic in `crypto`/sidecar; verify constant-time in review (Constitution II).
- Analyze coverage gaps closed: **C1** FR-015 512-cap → T024 + T024a; **C2** SC-001 latency → T036a;
  **C3** SC-002 which-buddy anonymity → T053a; **C4** SC-005 512-conversation scale → T033a. All
  three previously-partial requirements (FR-015, SC-001, SC-002) and the LOW SC-005 gap now have
  dedicated enforcement/test tasks. Coverage = 27/27 buildable requirements.
