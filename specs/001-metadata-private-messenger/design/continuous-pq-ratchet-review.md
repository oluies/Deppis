# Review guide — continuous post-quantum ratchet (Option B)

This document tells a **human security reviewer** what to check before the continuous-PQ-ratchet work
may change any privacy/PQ claim. It is a map, not a claim: it points at the artifacts and states, per
artifact, what to verify and what is already known *not* to hold.

**Read these first, in this order** — everything below assumes them:

| Doc | Why it is the frame for this review |
|---|---|
| [`threat-model.md`](../threat-model.md) | Defines the adversaries. The whole PQ question lives in **§3.5 Compromised endpoint** (post-compromise security) and **§3.1 Passive + active network observer** (harvest-now-decrypt-later, traffic pattern). |
| [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) | **§7 Encryption layers & key hierarchy** and the **256-byte fixed wire frame** (§7 "Wire frame layout") are the invariants this feature must not break. |
| [`constitution.md`](../../../.specify/memory/constitution.md) | **IV (Honesty/Labeling — NON-NEGOTIABLE)**, **I (No hand-rolled crypto)**, **II (Constant-time)**, **VI (Property + KAT tests)**. IV is the gate this review exists to satisfy. |
| [`continuous-pq-ratchet.md`](continuous-pq-ratchet.md) | The design. §1.2/§4/§6 are the security argument; the **§4.2 amendment** (tag keying) and the honesty header are load-bearing. |
| [`formal-analysis/README.md`](formal-analysis/README.md) | The proofs, the negative control, and the two honest limits. §5.2.1 links the rendered attack graphs. |

---

## 0. The decision this review must make

Everything else is verification. **One judgment is genuinely yours and the analysis cannot make it:**

> **Is an adversary that is _passive on the rekey exchange_ an acceptable threat model for whatever
> claim this build is to be permitted?**

The formal analysis proves the epoch fold gives post-compromise security **against that adversary**.
It also *proves* — does not merely caveat — that an adversary **active on the rekey exchange** defeats
it (see `graphs/hijack-attack.svg`). So the reviewer's decision is binary and consequential:

- **If "passive on rekey" is acceptable** for the intended claim → the analysis supports it, subject to
  the checklists below, *and* the still-undischarged traffic-pattern question (§4 here).
- **If it is not** (i.e. the threat model in `threat-model.md §3.1/§3.5` admits an active MITM on the
  pairing/rekey channel) → the property is **not** established; the hijack model is the thing to design
  against next, and no PQ post-compromise claim may be made.

Until this decision is recorded, the build label **`DEV, NO METADATA PRIVACY` stands** and the PQ
post-compromise property is documented as **unproven against an active attacker**. `Privacy.scala` was
deliberately **not** touched by any of this work — flipping a label is a human decision under
Constitution IV, not an artifact of the merge.

---

## 1. What was built (all merged to `main`)

Design doc [#82] → then five implementation phases. Each went through the adversarial review loop
(agent self-review → independent reviewer → fixes → clean) with CI green.

| Phase | PR | What | Where |
|---|---|---|---|
| — | #81 | **PQ-intent binding** — a *stripped* KEM key fails closed (`pq_prekey_required`); intent bound into the authenticated safety number | `engine/{Engine,Handshake,EngineCodec}.scala` |
| — | #82 | The design doc | `continuous-pq-ratchet.md` |
| 1 | #83 | **Epoch-fold KDF + confirmation tags** — pure, cross-platform, KAT-pinned | `engine/EpochKdf.scala` |
| 2 | #84 | **Chunked control sub-stream over ARQ** — KEM bytes ride the MK-sealed inner block; frames stay 256 B | `engine/ChunkStream.scala` |
| 3 | #85 | **Periodic-rekey state machine in the live ratchet** — root-index anchor, `EPOCH_COMMIT`, atomic fold | `engine/{Engine,DoubleRatchet}.scala` |
| 4 | #86 | **Model spec + fold properties** — ScalaCheck model of the fold under loss/reorder/dup | `engine/{DoubleRatchetModelSpec,PqRekeyModelSpec}.scala` |
| 5 | #87 | **Formal analysis** — Tamarin models of the fold + the non-vacuous PQ-PCS lemma | `formal-analysis/*.spthy`, `CRYPTO_PROOF.md` |
| — | #88 | **Reviewer artifacts** — rendered attack graphs + drift-checked regeneration script | `formal-analysis/graphs/`, `render-attack-graphs.sh` |

The **central design idea** (design §4, and the reason Phase 3 was hard): the two peers never sit on
the same ratchet root simultaneously — `dhRatchet` advances the root by two — so a fold cannot be "fold
the current root". It is anchored to a **root index** both sides pass through; gated liveness falls out
of the ratchet's own structure. Verify this framing survives your read of `DoubleRatchet.scala` before
trusting anything downstream of it.

---

## 2. What is proven (re-runnable in < 1 s)

The proofs are cheap — this is not a multi-hour proof search. **Reproduce, don't take on faith:**

```bash
# macOS: brew install tamarin-prover/tap/tamarin-prover   (installs Maude + GraphViz)
cd specs/001-metadata-private-messenger/design/formal-analysis
tamarin-prover ratchet-pq-epoch.spthy        --prove   # the positive result
tamarin-prover ratchet-pq-epoch-nofold.spthy --prove   # the NEGATIVE CONTROL (must falsify)
tamarin-prover ratchet-pq-epoch-hijack.spthy --prove   # the LIMIT (active hijack; PCS falsified)
tamarin-prover ratchet.spthy                 --prove   # the pre-existing lemmas still hold
tamarin-prover ratchet-unbounded.spthy       --prove   # (with the fold added)
tamarin-prover interactive .                            # GUI at http://127.0.0.1:3001 to walk any trace
```

**The load-bearing result** is that `pq_post_compromise_security` **verifies with the fold and
falsifies without it, every other lemma identical in both** — same model, same attacker, exactly one
line different: the anchor step derives `kdfEpoch(RK, ss)` (the fold) versus leaving `RK` unchanged (the
`-nofold` control). That flip is the proof the fold does work, i.e. that the lemma is not vacuously true
(design §6.2 explains why the *naive* lemma would be worthless: the Option-A pairing seed already blocks
a purely passive harvester, so a green tick that survives fold-removal certifies nothing).

To avoid a second copy of measured numbers that would drift, this guide does not restate the exact step
counts or the verbatim one-line `diff` recipe — **[`formal-analysis/README.md`](formal-analysis/README.md)
§5.2** owns the control's verbatim `diff` recipe and the fold/no-fold measured output; run the commands
above to reproduce the *result*.

What is mechanically enforced, and what is not, precisely: `render-attack-graphs.sh` confronts the
models with the docs on **every** run (not only `--check`) and fails if — the **no-fold** control stops
falsifying (§5.2's load-bearing claim, and this guide's §2 "falsifies without it") or the **hijack**
model stops falsifying (§5.3's claim); §5.2.1's table step counts drift from the prover; or the hijack
row's *structural* claims (`aenc(ss, pk(~ek))` present, no second `~ek`) no longer match a fresh trace.
Only the SVG byte-comparison is gated behind `--check`. **Not** machine-checked: §5.2's measured timings
and per-lemma counts, §5.3's step counts, and this guide — so confirm anything they state by running the
prover, not by trusting the prose.

The rendered counterexamples for reviewers who will not run the prover:
[`formal-analysis/graphs/nofold-attack.svg`](formal-analysis/graphs/nofold-attack.svg) (the attack the
fold prevents) and [`formal-analysis/graphs/hijack-attack.svg`](formal-analysis/graphs/hijack-attack.svg)
(the limit). There is deliberately **no** picture of the positive result: a verified all-traces lemma
has no trace to draw.

---

## 3. What is NOT proven — read before quoting any result

Two limits, both stated honestly in the artifacts, both material to the §0 decision:

1. **Authentic-rekey-channel assumption (abstraction A1).** The verified PQ-PCS result assumes the
   adversary is *passive on the rekey exchange*. Dropping A1 → `ratchet-pq-epoch-hijack.spthy`, which
   **finds a real active hijack** (witness verified; PCS falsified). The confirm tag cannot save it — it
   proves knowledge of `ss`, and an active attacker *chose* that `ss`, encapsulating it under the honest
   epoch public key it read off the compromised channel (it injects a ciphertext; it does not even need
   a key of its own). This is the crux of §0.
2. **Traffic pattern (design §5 / §9 Q3) is NOT formally discharged.** Tamarin has no notion of
   length/timing/count, so it *structurally* cannot answer whether the ~19-frame rekey burst is
   observable. A corollary the reviewer must internalise: `unlinkability.spthy` does **not** prove the
   256-byte frame uniformity its own argument rests on — that is a **code invariant fed into** the
   proof, not a result of it. Its enforcement lives in `Frame.scala` / `ChunkStream.scala` and is
   checked at the property-test level (Phase 4 measured every rekey frame at exactly 256 B), not by
   Tamarin. If unlinkability of the rekey burst matters to the claim, that argument is owed separately.

---

## 4. Review checklists per artifact

Each item is a concrete thing to verify against the tree. Ordered so an earlier failure blocks later
trust.

### 4a. Design & honesty (Constitution IV)
- [ ] `continuous-pq-ratchet.md` status header and §0 state **BUILT but NOT VERIFIED**, PQ-PCS
      **unproven** against an active attacker, and `DEV, NO METADATA PRIVACY` stands. No sentence claims
      PQ messaging.
- [ ] §4.2 specifies the **shipped** tag keying `HMAC(ss, "dr/pq-epoch-confirm/{i,r}")` — *not* the
      original `RK_epoch` sketch. (The implementation deviated for a sound reason; the spec was amended
      to match. Confirm the doc and `EpochKdf.scala` agree.)
- [ ] Passive-HNDL safety is stated **conditionally** (holds for a PQ-paired session; the default
      pairing is still classical and rests on the OOB secret's transport, not ML-KEM).

### 4b. Crypto primitive (Constitution I, II, VI)
- [ ] `EpochKdf.kdfEpoch` / confirm tags compose only `kdf.Kdf` (vetted HMAC-SHA256) — no new primitive.
- [ ] Secret-bearing intermediates are wiped (no un-wiped left-associative `++` chains); no
      secret-dependent branch. Compare against the reviewed `KeySchedule.pqContentRoot`.
- [ ] `EpochKdfCrossSpec` pins the KAT on **both** JVM and Scala.js (interop contract), asserts the fold
      **moves** the root, ties `KeyBytes` to `HybridKem.SharedSecretBytes`, and pins tag anti-reflection.
      Independent cross-check: the committed KAT digests were reproduced with Python `hmac` (design
      README notes this).

### 4c. Transport & the fixed-frame invariant (ARCHITECTURE §7)
- [ ] `ChunkStream` envelope lives **inside** the ARQ inner-block payload; the 256-B wire frame is
      byte-unchanged. Phase 2/3 *measured* chunk/content/cover frames at exactly 256 B — reproduce with
      the Phase 4 model, do not just read the assertion.
- [ ] Strict fail-closed decoding: every length bounds-checked; unknown type / `idx≥count` / conflicting
      duplicate / absurd count rejected; **bounded memory** (evict-oldest reclamation; `abandonBefore`);
      the reassembler is **one-instance-per-pair** (a shared instance is a cross-buddy DoS — verify the
      contract is honoured in `BuddyRuntime`).

### 4d. Ratchet integration (Constitution II; ARCHITECTURE §7)
- [ ] The fold is **atomic** — scratch-compute / commit-on-verify, mirroring `DoubleRatchet.decrypt`. A
      failed/aborted fold leaves the ratchet usable at the pre-rekey epoch and **does not strip a prior
      fold's hardening** (design §8.2).
- [ ] Confirm tags **constant-time** compared (`token.RetrievalToken.equalsCT`) *before* any state
      mutation; mismatch fails closed. Both directions covered.
- [ ] Epoch KEM keypair secret (2464 B) lifecycle: fresh per attempt, wiped after decaps/fold **and** on
      abort/timeout (design §4.4).
- [ ] The abort/timeout ("point of no return") stranding is **observable** (`RekeyStatus`,
      `lastAbort = "pq_rekey_stranded"`) — not a silent permanent stall.

### 4e. Tests are real, not theatre (Constitution VI)
This suite's own history is the warning: the "no fake tests" phase shipped fake tests three times (a
near-inert loss adversary; a contention counter true by construction; dead aggregate assertions), each
caught only by adversarial reading, none by CI. So:
- [ ] The lossy-network adversary drops **live frames** (swallows a `retrieve` that would have
      delivered), not append-only map entries — and the anti-vacuity assertion counts real losses.
- [ ] The mismatch/ML-KEM-implicit-rejection test's named body actually **runs** each iteration (not
      skipped behind an `epochFoldArmed` guard); assertions are `assert`-ed, not branched-on.
- [ ] Documented *uncaught* mutations (`safeToAbort` outside the horizon; reassembler dedup below `feed`)
      are stated as limits with reasons, and covered elsewhere (`PqRekeyCrossSpec`) — not silently
      claimed.

### 4f. Formal model faithfulness (the most important, and the easiest to get wrong)
- [ ] The Tamarin model matches the **shipped** protocol: `ss`-keyed tags (not `RK_epoch`), the
      root-index anchor, the KEM modelled as `asymmetric-encryption` of a fresh secret (design README
      records a discarded first model whose five green ticks sat next to a *failed* message-derivation
      check — a lesson worth reading).
- [ ] The negative control differs from the model by **exactly one line** (verify with the `diff` recipe in [`formal-analysis/README.md`](formal-analysis/README.md) §5.2).
- [ ] The hijack model's `executable` requires an honest `EPOCH_COMMIT` sender (an earlier version's only
      satisfying trace was an adversary forgery, certifying nothing — confirm the fix).

---

## 5. Sign-off criteria

A reviewer may recommend a labeling change **only** if all hold:

1. §0 decision recorded: the accepted adversary is written down, and it is **passive on the rekey
   exchange** (or the active-hijack gap is closed by new work, re-reviewed).
2. Every §4 checklist item verified against the tree (not this doc's summary of it).
3. The Tamarin results reproduced locally (§2), including the negative-control falsification.
4. The **traffic-pattern** question (§3.2) is either out of scope for the claim, or separately argued.
5. Constitution IV: the exact wording of any new label is justified by what the proofs support **and no
   more** — a PQ-PCS claim must say "against an adversary passive on the rekey exchange", not "PQ".

If any fails, the correct outcome is **no label change** and a written note of the gap. That is a valid,
honest result — the analysis was built to make an *un*-change defensible too.

---

## 6. Provenance & reproduction notes

- Tamarin `1.12.0` + Maude `3.5.1` + GraphViz `15.1.0`. Every step count in the docs is measured output.
  `render-attack-graphs.sh` mechanically checks the falsification, §5.2.1 step-count, and
  hijack-structural claims (§2 breaks the guards down). Its **CI-gating semantics differ by mode** (the
  `--check` byte-comparison is graphviz-layout-unstable; the default mode's exit code is stable-guard-only
  but rewrites the SVGs in place) — the exact, authoritative behaviour is documented in the **script's
  own header NOTE**; read that rather than a second-hand summary. As a human, run it and treat a non-zero
  result as a drift signal.
- All merges have CI green including the labeling gate (`JVM — sbt test + labeling gate`), which fails a
  build that claims metadata privacy without an attested backend.
- Deeper background: [`dh-ratchet.md`](dh-ratchet.md) (the classical ratchet this extends),
  [`CRYPTO_PROOF.md`](../../../CRYPTO_PROOF.md) (proof status across all lemmas),
  [`retry-safe-addressing.md`](retry-safe-addressing.md) (the ARQ layer Phase 2 rides on).
