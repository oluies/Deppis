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
- [X] T003 [P] Initialize the Rust `oblivious-sidecar` crate with pinned deps in `oblivious-sidecar/Cargo.toml` — subtle (constant-time) + proptest, pinned; Cargo.lock committed
- [X] T004 [P] Initialize the Flutter app skeleton in `clients/flutter/` (web platform; `ProtocolEngine` bridge + `DevEngine` stand-in + AppState; widget + engine tests)
- [ ] T005 [P] Configure linting/formatting: scalafmt + scalafix (`/.scalafmt.conf`), rustfmt + clippy (`oblivious-sidecar/`), `dart format`/`flutter analyze` — PARTIAL: rustfmt + clippy (`-D warnings`) + `flutter analyze`+`flutter test` enforced in CI; `.scalafmt.conf` present (CI scalafmt check pending)
- [X] T006 [P] Add ScalaPB codegen for the contracts in `specs/001-metadata-private-messenger/contracts/*.proto` wired into `build.sbt` — sbt-protoc + ScalaPB in `transport` module; `messaging.proto` compiles to message + gRPC stubs
- [X] T007 [P] Add a reproducible-build + dependency-pinning CI check and a secret-scanning gate in `deploy/ci/` (Constitution XI) — `.github/workflows/ci.yml` hygiene job: pinned-sbt + Cargo.lock check + gitleaks secret scan
- [X] T008 [P] Add a CI gate asserting no release artifact reports `metadataPrivate:false` and that the `DEV, NO METADATA PRIVACY` label is present in dev builds (Constitution IV / FR-016) — CI labeling gate runs `pstatus show`, asserts metadataPrivate:false + the dev label on a build without the real backend

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ CRITICAL**: No user-story work begins until this phase is complete. This is the
`protocol-core` + `crypto` nucleus and the pluggable-backend interfaces every story builds on.

- [X] T009 [P] KAT harness + FIPS/library vectors for AEAD (ChaCha20-Poly1305) and Blake2b in `crypto/jvm/src/test/scala/kat/` (write first; MUST fail before T011) — `crypto/src/test/scala/crypto/{CryptoSpec,CryptoKatSpec}.scala`: AEAD cross-checked byte-for-byte vs JDK ChaCha20-Poly1305; Blake2b cross-checked vs Bouncy Castle (256/512/keyed) + RFC 7693 `BLAKE2b-512("abc")` static vector; `mcrypto kat` runs the RFC vector. (Static RFC 8439 AEAD vector still a nice-to-have.)
- [X] T010 [P] Property-test skeleton (ScalaCheck) for protocol state machines + framing in `protocol-core/shared/src/test/scala/` (write first; MUST fail before T013–T016) — 11 props green (Frame/Token/Schedule/Privacy)
- [X] T011 [P] Implement `crypto` AEAD + KDF wrappers over libsodium (ChaCha20-Poly1305, Blake2b) in `crypto/jvm/src/main/scala/`, with `mcrypto aead-seal|aead-open|kdf|kat` CLI (Constitution I/II/V); make T009 pass — JDK FFM (Panama) binding to libsodium; `crypto/src/main/scala/crypto/`; 6 tests green
- [X] T012 [P] Wrap an audited Signal double-ratchet implementation in `crypto/jvm/src/main/scala/ratchet/` (no hand-rolled ratchet — Constitution I) — wraps the audited maintained `org.signal:libsignal-client` (pinned 0.61.0; see T012a below) in `crypto/src/main/scala/ratchet/Ratchet.scala` (`RatchetParty`: publish X3DH bundle, establish session, encrypt/decrypt; never reimplements the ratchet). `RatchetSpec` (7): round-trip both ways, ratchet advances (same plaintext ⇒ different ciphertext), out-of-order delivery decrypts, PREKEY→WHISPER type transition, tampered-ciphertext rejected (auth failure surfaced), unknown-type rejected. **T012a (DONE):** migrated off archived/EOL `signal-protocol-java` to the maintained `org.signal:libsignal-client` 0.61.0 (Rust core + Java/JNI bindings, bundled native lib loaded at runtime). The thin `RatchetParty` wrapper was the only coupling point, so the change was localized to `Ratchet.scala`: `IdentityKeyPair.generate()` + `Curve.generateKeyPair()`/`calculateSignature` build the X3DH prekey records (the old `KeyHelper.generate*` convenience helpers were dropped); the classic 8-arg `PreKeyBundle` and 2-arg `SessionBuilder`/`SessionCipher(store, addr)` stayed API-compatible. All 7 `RatchetSpec` tests pass on the real native ratchet (PQXDH Kyber prekey arm intentionally unused).
- [X] T013 Implement message framing (fixed 256-byte frames, padding) in `protocol-core/shared/src/main/scala/frame/` (FR-015a)
- [X] T014 Implement retrieval-token PRF = keyed Blake2b/HMAC over (senderId, receiverId, counter) with monotone counter (non-recurrent) in `protocol-core/shared/src/main/scala/token/` + `pcore retrieval-token` CLI (FR-014) — JCA HMAC-SHA256 (not hand-rolled), length-prefixed fields, constant-time compare
- [X] T015 Implement the client schedule (uniform per-round send/retrieve/carrier decisions, cover traffic) in `protocol-core/shared/src/main/scala/schedule/` (FR-012) + `pcore schedule-next` CLI
- [X] T016 Define the `ObliviousStore` and `AnonymityLayer` interfaces (config-switchable backends) in `server/pong/src/main/scala/store/` and `anonymity/src/main/scala/` (Constitution VIII)
- [X] T017 [P] Implement `BuildPrivacyStatus` + `pstatus show` CLI emitting `{backend, metadataPrivate, label}` in `protocol-core/shared/src/main/scala/privacy/` (FR-016, Constitution IV)
- [X] T018 [P] Configure error handling/logging that never varies on secret values (Constitution II) in `server/src/main/scala/obs/` — `SafeLog` (constant redaction marker, no value/length leak) + `FailureReason` enum (fixed public messages); property-tested for content/length independence
- [X] T019 Scaffold the Scala.js engine bundle + versioned Dart platform-channel API per `contracts/engine-api.md` in `protocol-core/js/` (Constitution VII) — `engine.Engine` + `EngineCodec` (apiVersion-gated JSON boundary; never returns key material) in `shared/`, wiring Handshake+Buddy+Frame+Schedule+Privacy; implemented & tested on JVM (15 tests, real JCA `Kdf`), then cross-compiled to Scala.js. Only `kdf/Kdf` is platform-split (JVM=JCA, JS=`@noble/hashes` — both vetted/synchronous; noble is browser-safe so the bundle loads in Flutter web too, with a bundler/import-map resolving the bare specifiers). `@JSExportTopLevel("ProtocolEngine")` facade; `fullLinkJS` bundle verified loading in Node + driven through the engine-api contract (`engine-contract.cjs`); cross-platform KAT (noble HMAC ≡ JCA HMAC). `@noble/hashes` pinned in `package.json`/`package-lock.json`. CI `scalajs` job (npm ci → test → link → bundle e2e).
- [ ] T020 [P] Stand up the Pekko/Akka server skeleton with gRPC/TLS 1.3 round orchestration in `server/src/main/scala/round/` (per `contracts/messaging.proto`) — PARTIAL: gRPC `RoundService` (ScalaPB) implemented in `transport` + in-process round-trip test green; Pekko actor orchestration and TLS network binding (self-signed certs, bound port) still pending

**Checkpoint**: protocol-core + crypto + interfaces ready; user stories can begin.

---

## Phase 3: User Story 1 — Add a buddy once, out of band (Priority: P1) 🎯 MVP · Phase A

**Goal**: One-time, mutually authenticated out-of-band pairing (QR / safety number).

**Independent Test**: Two engines pair, compare matching safety numbers, both list a Confirmed
buddy; a tampered secret fails the comparison and is rejected; re-adding is recognized as a dup.

- [X] T021 [P] [US1] Property test for the add-friend handshake (match → Confirmed; mismatch → rejected; idempotent dup) in `protocol-core/shared/src/test/scala/handshake/` (write first, MUST fail) — HandshakeSpec + BuddySpec, green
- [X] T022 [P] [US1] Contract test for engine `addBuddy`/`confirmBuddy` per `contracts/engine-api.md` in `protocol-core/js/src/test/` — `engine.EngineSpec` (JVM, 15 tests) + `engine.EngineJsSpec` (JS/Node) drive the JSON boundary: addBuddy result shape, confirmBuddy→buddyConfirmed event, apiVersion refusal, no key-material leak, dev label
- [X] T023 [US1] Implement the add-friend handshake + safety-number derivation in `protocol-core/shared/src/main/scala/handshake/` + `pcore handshake-init` CLI (FR-001) — symmetric HMAC-derived pairId/safetyNumber/pairKey; tamper ⇒ mismatch
- [X] T024a [P] [US1] Boundary test for the 512-buddy cap (accept up to 512; 513th rejected predictably; count correct after removals) in `protocol-core/shared/src/test/scala/buddy/` (FR-015) — write first, MUST fail [analyze C1]
- [X] T024 [US1] Implement `BuddyRelationship` state (`Pending→Confirmed→Removed`), uniqueness/no-dup, removal, AND enforcement of the **512-buddy cap** (reject the 513th predictably) in `protocol-core/shared/src/main/scala/buddy/` (FR-002, FR-015, FR-018)
- [X] T025 [US1] Wire `addBuddy`/`confirmBuddy`/`removeBuddy` engine commands + `buddyConfirmed` event in `protocol-core/js/` (FR-001/FR-002/FR-018) — implemented in `engine.Engine`/`EngineCodec` and exported via `@JSExportTopLevel("ProtocolEngine")`; removeBuddy is silent (FR-018), confirmBuddy(match) emits `buddyConfirmed`
- [X] T026 [US1] Flutter add-buddy + safety-number-compare UI in `clients/flutter/lib/ui/add_buddy_screen.dart`, showing the privacy-status label (FR-016) — over the `ProtocolEngine` bridge (`DevEngine` stand-in until T019)

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
- [~] T032 [US2] Wire `sendMessage` (frame+enqueue) and the `notified` engine event in `protocol-core/js/` + Flutter notification indicator in `clients/flutter/lib/notify/` (FR-004) — DONE: Flutter UI (conversation send + `notified` indicator in `HomeScreen` that never names the buddy, + error banner, via `AppState`); engine-side `sendMessage`/`tick` in `engine.Engine`; the Flutter client drives the **real** engine via `ScalaJsEngine` over the JSON boundary, selected by `createEngine()` on web (guarded DevEngine fallback); `ScalaJsEngine` translates `notified`/`messageReceived`/`privacyStatus`/`buddyConfirmed` events (adapter unit-tested, fake handle). **T032a DONE:** `engine.Engine` now EMITS `notified`/`messageReceived` via a cross-platform `RoundTransport` seam — `tick` submits queued frames under directional retrieval tokens, polls "mail waiting?" and emits `notified` BEFORE retrieving (FR-004 order), then retrieves delivered frames and emits `messageReceived`. `RetrievalToken` rerouted through `Kdf` so it cross-compiles (JVM+JS). `RoundTransportSpec` (6, fake transport, both platforms); JVM `GrpcRoundTransport` bridges `EnclaveObliviousStore`/`EnclaveNotificationClient`; `EngineBackendE2ESpec` proves `engine.tick` does notify-before-retrieval against **real obsd** (CI `integration`). **T032b DONE (bridge):** `EngineJs` now optionally takes a host-supplied `JsTransport` + client label and wraps it as a `RoundTransport` via `JsRoundTransport`, so the SAME `tick` notify-before-retrieval logic drives a browser backend (`new ProtocolEngine(transport, label)`; no-arg stays local-only). Synchronous host-staging contract (the host pre-fetches the round's digest/frames and buffers submits, since browser I/O is async). `JsRoundTransportSpec` (Node) proves two engines over a fake JS transport surface `notified`+`messageReceived` through the bundle. **T032c DESIGNED (deployment):** `design/grpc-web-transport.md` + `deploy/envoy/envoy.yaml` give the concrete browser↔server wiring — Envoy translates gRPC-web ⇄ gRPC to the Scala `ObliviousStore`/`NotificationService`; the `JsTransport`↔proto mapping (submit→WriteBatch, fetchDigest→FetchDigest, retrieve→ReadBatch) + a connect-web reference host transport; and the resolution of the sync-engine/async-network tension (engine in a Web Worker with a SharedArrayBuffer/Atomics sync-over-async relay, or a plan/apply split). Not CI-testable without the live server+proxy (a docker-compose smoke harness is the follow-up); the engine, the `JsTransport` bridge (Node), and `GrpcRoundTransport` against real `obsd` are each proven in CI.

**Checkpoint**: US1+US2 work; notify-before-retrieval UX over the labeled dev backend.

---

## Phase 5: User Story 3 — Several conversations at once, never blocked (Priority: P1) · Phase B

**Goal**: Concurrent conversations with no blocking between them.

**Independent Test**: Three buddies send in one round; receiver retrieves and replies to all
three with no ordering constraint between conversations.

- [ ] T033 [P] [US3] Integration test: 3 concurrent conversations in one round, none blocked, in `server/src/test/scala/integration/concurrency/` (write first, MUST fail) — PARTIAL: protocol-core independence shown in `ConversationsSpec`; server-round integration test still pending T035
- [ ] T033a [P] [US3] Scale test: a user holds up to 512 simultaneous conversations with no conversation blocking another in `server/src/test/scala/integration/scale/` (SC-005) — write first, MUST fail [analyze C4] — PARTIAL: protocol-core 512-conversation scale shown in `ConversationsSpec`; server-round (real-concurrency) scale test still pending T035
- [X] T036a [P] [US3] End-to-end latency test: a two-party exchange completes within minute-order (single-digit rounds); asserts the tuned round interval meets SC-001, in `server/src/test/scala/integration/latency/` (SC-001) [analyze C2] — two parts: (1) the exchange itself is proven end-to-end through the real Rust `obsd` in `transport/.../TwoPartyE2ESpec`; (2) `schedule.Latency` pins the tuned round interval (15 s, in research D's 10–30 s window) + worst-case round counts, and `integration.latency.LatencySpec` asserts one-way + round-trip are single-digit rounds AND minute-order, guarding the interval as a regression-checked invariant.
- [X] T034 [US3] Implement per-buddy independent send/retrieve state (no cross-conversation blocking) in `protocol-core/shared/src/main/scala/session/` (FR-006) — immutable `Conversations`: per-buddy queue + monotone counter (non-recurrent tokens), keyed by pairId so conversations never block each other
- [X] T035 [US3] Implement round retrieval of multiple frames with uniform/padded count in `server/pong/src/main/scala/` per `contracts/messaging.proto` Retrieve (FR-006/FR-012) — `RoundServiceImpl.retrieve` (transport): reads each single-use token, pads misses with a carrier zero-frame so the response count is uniform; in-process gRPC test green
- [X] T036 [US3] Flutter multi-conversation list/threading in `clients/flutter/lib/ui/` (`home_screen.dart` buddy list + `conversation_screen.dart` per-buddy threading, over the engine bridge)

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

- [~] T040 [P] [US6] Statistical indistinguishability test (active vs idle traces) in `server/src/test/scala/integration/cover/` (write first, MUST fail) — PARTIAL: `RoundTransportSpec` asserts active and idle engines produce an identical **store-WRITE** trace (any buddy count) AND an identical, **non-recurrent FETCH** trace for a **single buddy** (one write + one read per round, fixed 256-byte frame, fixed 32-byte tokens, no token recurs). Remaining distinguishers: **multi-buddy** fetch token recurrence (T041b, per-buddy notify) and frame **content** (real plaintext vs all-zero carrier — T042, message ratchet in the frame path).
- [X] T041 [US6] Implement uniform per-round carrier frames on send AND fetch paths (shape independent of real-message presence) in `protocol-core/shared/src/main/scala/schedule/` + `server/src/main/scala/round/` (FR-012) — `Engine.tick` makes exactly one store WRITE per round (real frame under its directional token if queued, else a carrier under a fresh `random.Rand`-derived cover token) AND exactly one READ per round, both non-recurrent. See T041b for the per-buddy fetch mechanism that makes the read non-recurrent for ANY buddy count. Platform-split CSPRNG (JVM `SecureRandom` / JS Web-Crypto `getRandomValues`).
- [X] T041b [US6] Per-buddy notify so multi-buddy fetch is token-non-recurrent (FR-012/FR-014) — the PING digest carries one bit per buddy (512 bits, FR-015); `RoundTransport.fetchDigest` returns it and the engine reads EXACTLY the buddy whose bit is set this round (bit derived from the pair key via `notifyBit`). Because that buddy's message is present, the read is always a hit and its counter advances, so the per-round read-token stream is **non-recurrent for any buddy count** — closing the round-robin recurrence T041 left open. `RoundTransport.mailWaiting:Boolean` → `fetchDigest:Array[Byte]` (GrpcRoundTransport → `EnclaveNotificationClient.fetchDigest`; JsTransport facade updated). Tests: multi-buddy non-recurrence (read only the signaled buddy, A's frozen token never read), one-per-round delivery, real-obsd e2e signals `notifyBit`. **Edges (T041c):** distinct bit assignment (currently `notifyBit` can collide at birthday rate over 512 bits — a pairing-time bit-lease is collision-free) and the simultaneous-many-senders case (one delivered/round, others re-signal).
- [X] T042 [US6] Verify carrier frames are wire-indistinguishable from real frames (FR-012) — the engine now ENCRYPTS every frame (T042): a 256-byte wire frame is `nonce(12) ‖ ChaCha20-Poly1305(inner 228B)`. Real frames use a per-message AEAD key (directional, non-recurrent, derived from the pair key via `Kdf`); carrier frames encrypt an all-zero inner block under a fresh RANDOM key — so real and carrier are both 256B high-entropy blobs, byte-indistinguishable (closing the last active-vs-idle distinguisher). Cross-platform `aead.Aead` (JVM JCA / JS `@noble/ciphers`, both synchronous, vetted — Constitution I), pinned in `package.json`; cross-platform KAT (noble ≡ JCA, byte-for-byte). Engine encrypt-on-send / decrypt-on-retrieve; payload max is now 226B (256 − 12 nonce − 16 tag − 2 length). Tests: AEAD round-trip + tamper-reject + KAT (JVM+JS), frame-content indistinguishability (no plaintext on the wire, carrier ≠ zeros), encrypted delivery over **real obsd**. NOTE: this is the per-frame confidentiality+indistinguishability layer; the forward-secret double ratchet (T012) is an orthogonal inner layer (JVM today; a JS ratchet is the cross-platform follow-up).

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

- [X] T050 [P] Rust property tests for oblivious primitives (compare/choose/sort/compaction): access pattern depends only on batch size; `obsx selftest` in `oblivious-sidecar/src/primitives/` (write first, MUST fail) — 3 proptest properties green; selftest reports obliviousInvariants:true
- [X] T051 Implement constant-time oblivious primitives in `oblivious-sidecar/src/primitives/` (Constitution II) [native sidecar after dev store] — ct select/swap (subtle), data-oblivious bitonic sort, oblivious stable compaction
- [X] T052 Implement the PONG oblivious store (stash + bins + message tables, deamortized builds, unlinkable write/read, non-recurrent tokens) in `oblivious-sidecar/src/store/` + `obsx store-write|store-read` CLI (D7/FR-014) — oblivious slot-table store: write/read touch every slot identically (access pattern by public capacity only), single-use reads (non-recurrent), carrier-on-miss. Bins/deamortized-build throughput structure deferred; stateful store CLI ops belong to the gRPC service (T054)
- [X] T053 Implement the PING sealed-notification aggregation (OR + oblivious sort/scan/compaction, carrier injection) in `oblivious-sidecar/src/notify/` + `obsx notify-aggregate` CLI (D8) — oblivious nested-scan: every signal scanned for every client identically (access pattern by public counts only), constant-time bit-set (scans all digest bytes), carrier digest per client. Sort-based throughput optimization + stateful CLI deferred (gRPC service T054)
- [ ] T053a [P] Which-buddy anonymity test against the real enclave backend: with N buddies and one real sender, an observer (incl. the store/notify host) cannot identify the sending buddy better than 1/N in `server/src/test/scala/integration/anonymity/` (SC-002) — acceptance test; written up front, stays failing until the Phase C backend (T051–T056) is assembled [analyze C3]
- [X] T054 Implement the enclave-target `ObliviousStore`/notification fronts in `server/{pong,ping}/src/main/scala/.../enclave/` calling the sidecar over gRPC (Constitution VIII) — both fronts done in `transport`: `EnclaveObliviousStore` (store.proto, found-tag semantics) and `EnclaveNotificationClient` (notify.proto, signal/fetchDigest), each private only when attested, tested in-process incl. error channels. Separate follow-up: serving the Rust sidecar itself via tonic (real native sidecar vs. the Scala shim used in tests).
- [ ] T055 [P] Contract test for `attestation.proto` (stale nonce / unpinned measurement / bad signature ⇒ rejected, no enclave key) in `server/attestation/src/test/scala/` (write first, MUST fail)
- [ ] T056 Implement the RATS relying-party + Veraison verifier client: appraise evidence vs CoRIM reference values, check freshness nonce, accept enclave key ONLY on pass, in `server/attestation/src/main/scala/` + `attest verify` CLI (Constitution IX/X)
- [ ] T057 Implement reproducible enclave build + publish measurement to the append-only transparency log as CoRIM reference values in `deploy/enclave/` (Constitution X)
- [ ] T058 Flip `metadataPrivate:true` ONLY when backend=enclave-target AND attestation passes; client submits sealed token only post-attestation; remove the dev label on real builds (FR-016/Constitution IV/IX)
- [ ] T059 [P] Write the Phase C threat model + trust assumptions (uncompromised enclave; rollback/side-channel out of scope; single TEE vendor; trusted verifier+log) into `specs/001-metadata-private-messenger/threat-model.md` and the phase README (Constitution III; spec Assumptions)

**Checkpoint**: Real metadata privacy active and attested — **MVP shippable**.

---

## Phase 11: Polish & Cross-Cutting Concerns

- [ ] T060 [P] SPIRE/SPIRE-Envoy SDS mesh identity for **non-enclave** services only; enclave-aware attestor gates any PING/PONG SVID on a passing attestation result; never a substitute (Constitution IX) in `deploy/spire/`
- [X] T061 [P] Groove mixnet stub behind `AnonymityLayer` (single shuffler, labeled "no DP guarantee") in `anonymity/src/main/scala/groove/` (D9, leaves room without conflating trust models) — GrooveStub: single Fisher–Yates shuffler per round, multiset-preserving, labeled DEV/no-DP; 5 tests
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
