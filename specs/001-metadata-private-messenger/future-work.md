# Future Work — Intentionally Deferred (architecture-leaves-room notes)

> **Scope of this document (T065).** v1 of Deppis delivers **text messaging only**. This file
> records what the design *deliberately defers* and *why the current architecture leaves room for
> it without a rewrite*. Each item names the real seam it would extend and the rough open problem
> that remains. It is honest about what is unsolved.
>
> **Privacy-status caveat (Constitution IV).** None of the items below change the labeling rule:
> until the Phase C enclave store + attestation flow are live, every build is
> `DEV, NO METADATA PRIVACY` and says so in code, logs, and UI. Nothing here claims a dev build is
> private; the seams described are the places future work *would* attach, not features that exist.

The grounding spec (`spec.md` §"Out of Scope") names three explicit non-goals — OOS-001
voice/video, OOS-002 large media, OOS-003 group chats — and requires that "the design must not
foreclose them." The plan (`plan.md`) additionally phases post-quantum and multi-device hardening
into Phase D, and gates real metadata privacy on Phase C. This document covers all of those.

The load-bearing seams referenced throughout:

| Seam | Where | What it abstracts |
|---|---|---|
| `protocol-core` engine | `protocol-core/shared/.../engine/Engine.scala` | the per-round `tick` send/receive decision; single source of truth (Constitution VII) |
| `RoundTransport` | `protocol-core/shared/.../engine/RoundTransport.scala` | the engine ↔ backend seam (`submit` / `fetchDigest` / `retrieve`), opaque bytes only |
| `ObliviousStore` (PONG) | `server/pong/.../store/ObliviousStore.scala` | pluggable store backend (dev vs enclave), `metadataPrivate` flag |
| `AnonymityLayer` | `anonymity/` | pluggable anonymity backend (PingPong enclave vs Groove mixnet stub), Constitution VIII |
| Frame size | `protocol-core/shared/.../frame/` | the fixed **256-byte** wire frame (FR-015a) |
| Notify digest | `protocol-core/shared/.../notify/` | the **512-bit** one-hot PING digest (FR-015) |

---

## OOS-002 — Large media / attachments (vs the fixed 256-byte frame)

**Out of scope now.** Every wire frame is exactly **256 bytes** (`nonce(12) ‖ AEAD(inner 228) ‖
tag(16)`), capping the payload at 226 bytes (FR-015a). A photo or file does not fit, and v1 sends
none. The fixed size is not an accident — it is the cover-traffic invariant: real and carrier
frames must be byte-indistinguishable (US6/FR-012), which a variable-length frame would break.

**What accommodates it later.** The frame size is a *parameter* of `protocol-core`'s framing layer,
not a constant baked across the wire protocol; the `RoundTransport` and `ObliviousStore` move
opaque byte arrays and do not assume 256. Large media would be sent as a *sequence* of standard
256-byte frames (chunking) so each individual store write stays the uniform shape an observer sees —
i.e. the unit of cover traffic stays fixed while the message spans many rounds/tokens. The
non-recurrent retrieval-token PRF (per `(sender, receiver, counter)`) already produces an unlimited
stream of unlinkable tokens, so a multi-frame object reuses exactly that mechanism.

**Open problem.** Chunking re-introduces a *volume* side channel: a large attachment costs many
rounds of writes, and an observer counting a client's non-idle rounds could distinguish "sent a
photo" from "sent one line." Bounding this requires a padding/rate policy (e.g. a fixed media budget
per epoch, or constant-rate draining of a send queue) that trades latency for indistinguishability —
unsolved here. Storage-side, the enclave oblivious store's cost grows with object count, so large
media stresses the deamortized-build throughput that the sidecar (`oblivious-sidecar/src/store.rs`)
has deferred.

---

## OOS-001 — Voice / video (real-time media over the round + cover-traffic model)

**Out of scope now.** The protocol is fundamentally **round-based and asynchronous**: each `tick`
makes exactly one send and one receive decision, and the tuned round interval is minute-order
(single-digit rounds, SC-001; `schedule.Latency` pins ~15 s). Real-time media needs sub-second,
sustained, bidirectional flow — the opposite of the notify-before-retrieve, fetch-on-your-schedule
model that makes metadata privacy work. v1 ships no media path at all.

**What accommodates it later.** Voice/video would not run *over* the message rounds; it would attach
as a separate backend behind the **`AnonymityLayer`** seam (Constitution VIII), reusing the
out-of-band `pairKey` and the content ratchet (`engine.DoubleRatchet`) for media keys but
negotiating a dedicated, constant-bitrate, padded media channel. The architecture separates "which
backend provides
anonymity" from "the engine's protocol logic," so a streaming backend is an additive
implementation, not a rewrite of `protocol-core`. The handshake/`pairKey` hierarchy (one root per
buddy pair) gives such a channel its keys for free.

**Open problem.** Real-time metadata privacy is genuinely hard: a constant-bitrate padded stream
hides content and volume but a *call still happens at a wall-clock instant for a duration*, which
leaks "these two endpoints are both active now" to a global observer unless covered by continuous
dummy streams (expensive) or a mix network with bounded delay (raises latency past what voice
tolerates). There is no free lunch here; v1 correctly declines to pretend otherwise.

---

## OOS-003 — Group chats (fan-out under metadata privacy)

**Out of scope now.** All current state is **pairwise**: a `BuddyRelationship` is a symmetric link
between exactly two users, the `pairKey` is per-pair, and the notify digest assigns *one bit per
buddy*. There is no group entity in the data model. v1 is 1:1 text only.

**What accommodates it later.** The naive construction needs *no* new privacy primitive: an
*N*-member group is *N−1* pairwise sends per author (one to each other member), each a normal frame under its own
non-recurrent token through the existing `RoundTransport.submit`. Because the store and notify see
only opaque per-pair tokens and one-hot bits, fan-out is invisible to the backend — the group is a
purely client-side fan-out over seams that already exist. Sender-keys (one symmetric group key,
ratcheted) would later cut the *N×* per-message crypto cost without changing the wire model.

**Open problem.** Two real frictions. (1) **Notify-bit budget**: the digest is 512 bits matching the
512-buddy cap (FR-015); many large groups multiply a user's effective correspondent count and can
exhaust the bit space — group membership would need its own bit-leasing/aggregation scheme so the
digest stays fixed-width and uniform. (2) **Fan-out volume**: an author of a 50-person group emits
~50× the store writes of a 1:1 message in that round, a volume signature an observer can see;
hiding it needs the same rate-bounding/queue-draining policy that large media needs, plus
membership-change semantics (add/remove) that don't leak the group's existence (the same constraint
FR-018 already places on 1:1 buddy removal).

---

## Multi-device hardening (Phase D)

**Out of scope now (as a full guarantee).** US5 multi-device delivery works over the dev backend,
but the hard non-coordination requirement — two of a user's devices that cannot reach each other
must not, *between them*, emit traffic that links them (FR-011) — is Phase D. v1 does not harden it.

**What accommodates it later.** The untrusted service-provider buffer (`server/provider/`) already
sits between devices and the store as the mediation point, and the engine's `tick` is deterministic
given `(pairKey, counter)`, so two devices derive the *same* token stream rather than two
independent ones. Oblivious delegation
(`protocol-core/shared/.../delegation/`, tasks T045) attaches here: it lets the provider answer for
a device without either device duplicating the other's round traffic. The seam (provider front +
deterministic engine) exists; the de-amortized, non-coordinating delegation logic is the deferred
part.

**Open problem.** Coordinating "exactly one write + one read per user per round" across devices that
*cannot talk to each other*, through an *untrusted* provider, without the provider learning they are
the same user — this is the spec's own hardest stated requirement. The open question is the trust
split: how much can the provider arbitrate (it must not learn the user's identity or buddies, per
FR-010) versus how much the devices must pre-agree at pairing time.

---

## Post-quantum hybrid ratchet — BUILT, NOT VERIFIED (was Phase D)

> **Labeling, first.** "Built" is not "verified". Phase 5 formal analysis is done, **human security
> review is outstanding**, and `DEV, NO METADATA PRIVACY` **stands**. See
> `design/continuous-pq-ratchet.md` §0 and §6.3. Nothing below licenses a privacy claim.

**No longer deferred.** This section used to read as unbuilt future work; that is wrong as of
PRs #83–#85. The live content ratchet folds a hybrid **X25519 ⊕ ML-KEM-768** secret into its root:
`KeySchedule.pqContentRoot` at pairing, then a continuous epoch rekey driven by the state machine in
`Engine.scala` (keygen / encaps / decaps / confirm). Status header:
`design/continuous-pq-ratchet.md` — *"PHASES 1–3 IMPLEMENTED … PHASE 5 FORMAL ANALYSIS DONE"*.

**How it actually lands — not at the DH step.** Hybrid material rides `kem.HybridKem`, which is
already a cross-platform `protocol-core` seam (`protocol-core/{jvm,js}/src/main/scala/kem/`), the
JVM copy delegating to the vetted `crypto.HybridKem` (X25519 via JCA, ML-KEM-768 via liboqs). It
enters the ratchet as an **epoch fold into the root**, *not* by hybridizing the `x25519.X25519` DH
step — a 1216-byte hybrid public key cannot ride a 32-byte header slot. That is the core tension in
`design/continuous-pq-ratchet.md` §2.1, and why the KEM bytes are chunked over ARQ (`ChunkStream`)
inside the MK-sealed inner block instead. The ongoing per-message DH steps stay **classical X25519**
by design; the PQ hardening is the root fold, not the DH arm.

**Separately, and not this work:** the libsignal `RatchetParty` (T012, the JVM cross-check
reference) had its own *session handshake* go post-quantum — libsignal 0.8x makes the Kyber arm
mandatory, so it publishes a **PQXDH** bundle and cannot construct an X3DH-only one. Different
component, different key schedule. It covers neither the content ratchet nor the fold above.

**What genuinely remains.** Two primitives are built and KAT-tested in `crypto/` but **not wired
into the engine**, and both are JVM-only:

| | built | wired into the engine | cross-platform |
|---|---|---|---|
| Hybrid X25519 ⊕ ML-KEM-768 | yes | **yes** (`kem.HybridKem`) | yes (jvm + js) |
| ML-DSA-65 signatures (FIPS 204) | yes (`crypto.Oqs`) | **no** | no (JVM/liboqs only) |
| Epoch evolution, 2HashDH VOPRF | yes (`crypto.{Voprf,EpochEvolution}`) | **no** | no (JVM only) |

So the deferred work is *wiring and porting*, not building: attaching ML-DSA and the VOPRF epoch
evolution (with erasure / no-roll-forward) to the engine, and giving both a JS counterpart, since
the real client is Scala.js. Size pressure on the 226-byte payload budget (`ARCHITECTURE.md` §7)
remains the live constraint on any of it.

---

## Prekey lifecycle in the ratchet wrapper (rotation, replenishment, erasure)

**Out of scope now.** `RatchetParty` (`crypto/.../ratchet/Ratchet.scala`) generates one one-time
prekey, one signed prekey and one Kyber prekey, all with a **fixed id of 1**, once per party, and
never rotates, replenishes or erases them. This is a **dev/test harness shape, not a production key
lifecycle** — the wrapper is exercised only by `RatchetSpec` and the demo today.

**Why the tests do not catch it.** libsignal treats a bundle-published one-time prekey and Kyber
prekey as **single use** (`markKyberPreKeyUsed`). `InMemorySignalProtocolStore` no-ops that, which is
the only reason repeated sessions against the same published bundle work here. Any real store would
reject the second inbound PREKEY message against the same id, so this shape fails the moment the
store becomes persistent — it is not a latent-but-harmless simplification.

**Open problem.** Production needs prekey **rotation**, a **replenished one-time pool** sized against
consumption, and **erasure after use**. The last of these also carries the project's own rule that
key material must not outlive its epoch (Constitution II) — the current wrapper holds all three
prekeys for the lifetime of the party object and zeroes nothing.

---

## Dev backend → real Phase C enclave + attestation (MVP release gate)

**Out of scope now (as a shippable claim).** Every current build runs the **dev**
`ObliviousStore` / dev notify, which provide **no access-pattern privacy** and are labeled
`DEV, NO METADATA PRIVACY` (Constitution IV). Real metadata privacy is gated on Phase C and is the
MVP release gate — not yet crossed.

**What accommodates it later.** This is the cleanest seam in the system, because it was designed for
exactly this swap. The dev and enclave stores both satisfy the same `ObliviousStore` trait (its
doc-comment spells out the invariants the enclave impl must uphold and the dev one explicitly does
not); the `metadataPrivate: Boolean` flag on that trait drives the labeling rule end-to-end, and
`BuildPrivacyStatus` flips to `metadataPrivate:true` *only* when `backend=enclave-target` AND
attestation passes (task T058). The enclave-target fronts already exist
(`transport/.../EnclaveObliviousStore`, `EnclaveNotificationClient`) and call the Rust sidecar over
gRPC; the engine and `RoundTransport` are unchanged across the swap because they only ever moved
opaque bytes. Attestation is **attestation-not-identity** (Constitution IX): a freshness nonce binds
each quote, and the enclave key is released (via OpenBao) only post-appraisal — a service identity
never substitutes.

**Open problem.** What remains is real hardware/ops, not architecture: an SGX-capable host, Intel
DCAP collateral, the RATS/Veraison verifier appraising evidence against CoRIM reference values in an
append-only transparency log (tasks T056–T057), reproducible enclave build with logged measurement
(Constitution X), and the OpenBao attested key-release path. The PING aggregation front must also
become a standalone process that decouples *signal volume* from *real-message presence* so the
notify channel is uniform too (the honest caveat in `ARCHITECTURE.md` §6) — today the demo/tests
play that role. Until all of this is real and the trust assumptions are written
(`threat-model.md`, task T059), no build advertises privacy.
