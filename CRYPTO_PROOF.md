# Crypto proof — content-layer security of the metadata-private messenger

This is the assurance story for the **content** cryptography: the DH double ratchet with header
encryption (`engine.DoubleRatchet`). The ratchet gives messages **forward secrecy** (the one-way KDF
chain + key wiping) and **post-compromise security (PCS)** (the DH ratchet). What is *machine-checked
symbolically* here is **message secrecy + PCS** (forward secrecy is design-level, exercised by the
implementation tests — see the scope note). This document records what is proven, *how*, what the proof
rests on, and what is deliberately out of scope.

Artifacts (all under
[`specs/001-metadata-private-messenger/design/formal-analysis/`](specs/001-metadata-private-messenger/design/formal-analysis/),
detail in its [README](specs/001-metadata-private-messenger/design/formal-analysis/README.md)):
- Symbolic design proof — `ratchet.spthy` (bounded) and `ratchet-unbounded.spthy` (unbounded chain)
- Header unlinkability — `unlinkability.spthy` (+ `unlinkability-cleartext.spthy`, negative control)
- **Continuous-PQ epoch fold** — `ratchet-pq-epoch.spthy`, **plus two controls that are part of the
  result, not decoration**: `ratchet-pq-epoch-nofold.spthy` (negative control — **must falsify**) and
  `ratchet-pq-epoch-hijack.spthy` (scope control — finds the active post-compromise hijack)
- Executable implementation model — `engine.DoubleRatchetModelSpec` (ScalaCheck, in CI)
- Design specs — [`design/dh-ratchet.md`](specs/001-metadata-private-messenger/design/dh-ratchet.md),
  [`design/continuous-pq-ratchet.md`](specs/001-metadata-private-messenger/design/continuous-pq-ratchet.md)

---

## TL;DR

| Property | How it's established | Status |
|---|---|---|
| Message secrecy | Tamarin symbolic proof (Dolev-Yao) | ✅ verified (41 steps) |
| **Post-compromise security** | Tamarin symbolic proof (bounded, DH/CDH explicit) | ✅ **verified (21 steps)** |
| **PCS + forward secrecy, *unbounded* steps** (given per-step secret unguessability) | Tamarin, repeatable ratchet loop (reuse + induction) | ✅ **verified (no oracle)**; composition with the bounded model argued, not machine-linked |
| **Header unlinkability** (store can't link a chain's frames) | Tamarin observational equivalence (`--diff`) + negative control | ✅ **verified (2315 steps)** — **per-frame only** (see limits) |
| **PQ post-compromise security** after an epoch fold, vs a **CRQC** | Tamarin, new model + **no-fold negative control** | ✅ **verified (8 steps), non-vacuous** (control **falsifies**) — **bounded by an authentic-rekey-channel assumption** |
| **Rekey traffic pattern** (~19-frame burst distinguishable?) | — | ⚠️ **NOT DISCHARGED** — argued from engine invariants; Tamarin structurally cannot |
| Implementation invariants (correctness, atomicity, single-use, out-of-order) | ScalaCheck stateful model, every reachable interleaving | ✅ green in CI |
| Primitive soundness (X25519, HMAC, ChaCha20-Poly1305, ML-KEM) | **delegated** to vetted libraries (JCA / `@noble` / liboqs) | inherited |

```
tamarin-prover ratchet.spthy --prove        # Tamarin 1.12.0 + Maude 3.5.1, ~0.85 s
  executable                   (exists-trace): verified (7 steps)
  pcs_premise_reachable        (exists-trace): verified (8 steps)   # PCS premise reachable ⇒ non-vacuous
  message_secrecy              (all-traces):   verified (41 steps)
  post_compromise_security     (all-traces):   verified (21 steps)
  epoch_fold_premise_reachable (exists-trace): verified (9 steps)
  pcs_with_epoch_fold          (all-traces):   verified (7 steps)
  All wellformedness checks were successful.
tamarin-prover --diff unlinkability.spthy --prove     # header unlinkability (indistinguishability)
  Observational_equivalence: verified (2315 steps)
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # negative control: cleartext header
  Observational_equivalence: falsified (10 steps)             # ← intended: proves the test has teeth

# The continuous-PQ epoch fold (design/continuous-pq-ratchet.md Phase 5) — THE CRUX + ITS CONTROL
tamarin-prover ratchet-pq-epoch.spthy --prove          # PQ-PCS vs a CRQC
  pq_post_compromise_security (all-traces):   verified (8 steps)
tamarin-prover ratchet-pq-epoch-nofold.spthy --prove   # NEGATIVE CONTROL — one line changed: no fold
  pq_post_compromise_security (all-traces):   falsified - found trace (7 steps)   # ← intended: the fold IS load-bearing
```

---

## What actually drives the PCS proof

Post-compromise security is the claim: **after an attacker captures a device's chain state, the very
next uncompromised DH step re-secures the session** — future messages become unreadable to the attacker
again. What makes that true, and what the machine proof rests on, is one cryptographic fact applied to
the ratchet's structure:

### 1. The mechanism — fresh DH every step, mixed into the root

Each DH ratchet step derives the new root key as `RK' = KDF(RK, g^(a·b))`, where one of the two
exponents is **fresh randomness generated *after* the compromise** (the healing party's new ratchet
key). The message key for a post-heal message is `MK = msgK(RK')`. So to read that message the attacker
must obtain `RK'`, which requires the DH shared secret `g^(a·b)`.

### 2. The fact it rests on — Computational Diffie–Hellman (CDH)

The attacker, even holding the *pre-heal* root `RK` (the compromised state), cannot compute `g^(a·b)`
from the public values `g^a` and `g^b` alone — that is exactly the CDH assumption X25519 is built on.
And in this design the attacker doesn't even get `g^a`/`g^b` in the clear: **the ratchet public keys
travel only inside the encrypted header** (the metadata-privacy requirement — see below), so they are
doubly out of reach. Therefore `RK'` is independent of everything the compromise revealed, and the
post-heal message stays secret. **That independence — old state ⊥ new key, via a fresh CDH term — is
the whole engine of PCS.**

### 3. The proof that the *structure* actually delivers it

The mechanism is only PCS if the ratchet wires it up correctly — right key separation, right ordering,
no place where the old state leaks into the new key. That structural claim is what
[`ratchet.spthy`](specs/001-metadata-private-messenger/design/formal-analysis/ratchet.spthy) proves, in
the symbolic (Dolev-Yao) model where the attacker controls the entire network **and** can reveal chain
keys. The `post_compromise_security` lemma states it precisely:

```
All m2 b rk1 #s #h #r.
    ( HealedSend(m2, b)@s     // m2 sent on a chain healed by fresh DH key b
    & Heal(b, rk1)@h          // ...whose pre-heal root was rk1
    & RevealCK(rk1)@r         // ...and rk1 was REVEALED to the attacker
    & r < h )                 // ...before the heal (a genuine prior compromise)
  ==> not (Ex #k. K(m2)@k)    // the attacker never learns m2
```

The fresh key `b` correlates the heal and the send to one session; the reveal is of *that* session's
pre-heal root. Tamarin verifies this holds across **all** traces — i.e. there is no attacker strategy,
network manipulation, or key-reveal schedule that breaks it — and a companion `exists-trace` lemma
(`pcs_premise_reachable`) proves the reveal→heal→send scenario is actually reachable, so the all-traces
result is provably non-vacuous. Idealization (licensed by Constitution I, which delegates primitives):
DH is the `diffie-hellman` builtin (with CDH), AEAD is perfect, the HMAC KDFs are one-way functions.

### 4. The gap CDH leaves — and what the epoch fold does about it (continuous PQ, Phase 5)

Read §2 again: PCS here **rests on CDH**. A cryptographically-relevant quantum computer (CRQC) breaks
CDH. So an attacker that (a) captures a live ratchet root and (b) *later* gains a CRQC reconstructs every
subsequent X25519 step and never loses the session — the classical healing recovers against a *classical*
attacker but **not** a quantum one. That is the gap `design/continuous-pq-ratchet.md` exists to close, by
periodically folding a hybrid X25519+ML-KEM-768 epoch secret into the live root:

```
RK_epoch = HMAC(RK, "dr/pq-epoch" ‖ ss)        # engine.EpochKdf.kdfEpoch, at a root-INDEX anchor
```

**Why the obvious lemma would have been worthless.** "Under an attacker that breaks X25519 but not
ML-KEM, a post-fold message stays secret" is **vacuous**: the Option A pairing seed already binds every
root to the pairing ML-KEM secret, so that attacker can never compute any root **fold or no fold** — the
lemma would verify identically on a build with the fold deleted. `ratchet-pq-epoch.spthy` therefore models
the one thing that spends the seed's protection: a **state compromise of a live pre-fold root**, *plus* a
CRQC (every X25519 exponent handed over). `anchor_root_is_compromised` proves the attacker really does
compute the last root before the fold — the fold is the only thing left standing.

**The negative control is the result.** `ratchet-pq-epoch-nofold.spthy` is the same model with **one line
changed** (`rkf = kdfEpoch(rkn, ~ss)` → `rkf = rkn`) and it **falsifies**, returning exactly the gap above
as an attack trace. That, not the green tick, is what proves the fold load-bearing.

**The assumption that bounds it — do not quote the result without this.** The verified lemma assumes an
**authentic rekey channel** (the MK-sealed chain the KEM chunks ride in). That assumption is in tension
with the very compromise it models: an attacker holding a revealed root can derive that chain's message
keys and **forge the seal**. `ratchet-pq-epoch-hijack.spthy` drops the assumption and **finds the
attack** — it injects its own KEM ciphertext, and the confirmation tag does *not* save it, because the tag
proves knowledge of `ss` and the attacker genuinely *knows* the `ss` it chose. This is **not a new
vulnerability and not a defect in `EpochKdf`**: it is the standard PCS caveat (an active attacker holding
session state can MITM onward; Signal's DH PCS carries it identically), and Deppis's *existing* PCS results
above sit behind the same assumption — they model a *reveal*, not an *injection*. So the property proved is:

> PQ post-compromise secrecy against an attacker **active before** the rekey (it compromised the state)
> and **passive on** the rekey exchange itself — including one holding the KEM ciphertext and both tags.

That is a real, useful property — precisely the *harvest-then-go-quiet* / HNDL attacker. It is **not**
"PQ-PCS against any post-compromise attacker". Full detail, abstractions A1–A5, and the verbatim prover
output: [`formal-analysis/README.md`](specs/001-metadata-private-messenger/design/formal-analysis/README.md) §5.

---

## The other half — that the *implementation* matches the design

A verified design can still be mis-coded. `engine.DoubleRatchetModelSpec` (ScalaCheck, runs in CI)
generates random scripts of `send / deliver / tamper / replay` across both directions and checks, under
**every reachable interleaving**, that the Scala ratchet holds:

- **correctness** — every in-order genuine delivery decrypts to what was sent;
- **atomicity** — a tampered body is rejected *and* the genuine frame still decrypts (no-mutation-on-
  undecryptable — the exact bug a manual review caught earlier, now guarded mechanically);
- **single-use** — a consumed frame never decrypts twice;
- **out-of-order completeness** — any permutation of a `K < MaxSkip` batch decrypts fully.

Design proof + implementation property-testing are the two axes: neither alone is enough — a sound
design can be mis-implemented, and a well-tested implementation can faithfully realize a flawed design.

---

## Why running the prover mattered (not just authoring a model)

The Tamarin model was *reviewed by eye and by an LLM reviewer first*, and still had three defects that
only surfaced when `tamarin-prover` actually ran — a concrete argument against trusting unchecked formal
models:

1. **Circular header-key derivation** — the header was sealed under a key derived from the same DH value
   carried *inside* it. Tamarin's message-derivation check flagged it; the real design seals headers
   under a bootstrap/root-derived key the receiver already holds.
2. **Free-variable scoping bug** in the PCS lemma (`#h` bound in one existential, referenced in another)
   — a wellformedness failure that made the analysis unsound.
3. **Over-broad PCS quantifier** — the lemma ranged `m2` over *all* messages, so the prover **falsified**
   it by binding `m2` to a step-1 message and revealing that message's own key. A lemma bug, not a
   protocol flaw; scoping `m2` to healed-chain sends made it provable.

The first two are "the model doesn't even mean what you think"; the third is "your security claim is
subtly wrong." All three would have shipped in an authored-but-unrun artifact.

---

## What does *not* drive the proof (incl. the corecrypto question)

- **Primitive libraries — Apple corecrypto / CryptoKit, fiat-crypto, HACL\*, BoringSSL — do not and
  cannot drive this proof.** PCS is a *symbolic protocol* property over an abstract attacker model where
  the primitives are *idealized as perfect*. A primitive implementation lives one layer **below** what
  the proof reasons about; no crypto library can discharge a first-order trace lemma. corecrypto is also
  Apple-internal/licensed, not a cross-platform dependency we could take (we delegate primitives to JCA +
  `@noble` precisely for JVM + Scala.js portability). It *is* a reasonable option to back the **iOS**
  client's primitive seam with CryptoKit — but that is primitive substitution for one platform, pinned by
  the same KATs, and changes neither the ratchet nor this proof.
- **What does help drive it:** the symbolic-verification ecosystem (Tamarin — used here — plus ProVerif /
  CryptoVerif / DY\*) and the published double-ratchet analyses (Cohn-Gordon–Cremers–Dowling–Garratt–
  Stebila's Signal analysis; Alwen–Coretti–Dodis's security notions), which supply the lemma structure
  and the oracle/reuse patterns an unbounded proof would need.

---

## Scope and honest limits

- **Two proofs, bounded + unbounded — argued composition, not machine-linked.** `ratchet.spthy` covers
  bootstrap + one full heal (two DH steps) with the DH/CDH details explicit. `ratchet-unbounded.spthy`
  covers the complementary direction — PCS **and forward secrecy** across an *arbitrarily long* chain —
  *given* that each step's healing secret is unguessable (a modeling assumption here; the per-step CDH
  basis is what the bounded model establishes). The two models are not mechanically composed; the
  cross-model claim is argued. The literal `kdfRK(rk,~s)` term does not terminate under Tamarin's
  heuristics; the unbounded model uses fresh-name roots + an explicit forward-only `Derive` rule, with
  one-wayness encoded by *omitting* an inverse rule — so the FS lemma validates the schedule's structure
  *under* modeled one-wayness rather than proving one-wayness itself. Faithful and tractable.
- **Header unlinkability is proven separately** (it is an *indistinguishability* property, so it lives in
  Tamarin's observational-equivalence `--diff` mode, not the trace lemmas above). `unlinkability.spthy`
  proves the store cannot tell whether two frames belong to the same sending chain — `Observational_
  equivalence: verified (2315 steps)` — and `unlinkability-cleartext.spthy` is a negative control where
  the header is in the clear and equivalence correctly *falsifies*, showing the model captures the real
  linking threat. (Implementation echo: the `header encryption removes the linking tag` test.)
- **Constant-time / side channels (Constitution II) are out of scope of both artifacts.** On the JVM they
  are not achievable at the bytecode level (JIT + GC); they are left to the vetted native primitives and
  the Rust sidecar, as documented in dh-ratchet.md §9.
- **The PQ result is bounded by an authentic-rekey-channel assumption** (§4 above): PQ-PCS holds against
  an attacker *passive on the rekey exchange*; an *active* post-compromise hijack is found by
  `ratchet-pq-epoch-hijack.spthy` and is the standard PCS caveat, not a defect. The PQ models are also
  **bounded** (one compromise, one rekey, one fold), **assume** both peers derive the byte-identical
  `RK_epoch` at the anchor (an agreement property left to the implementation tests), and **idealize
  ML-KEM** as an independent hard problem — they say nothing about ML-KEM's cryptanalytic standing.
- **The rekey traffic pattern is NOT discharged** (`design/continuous-pq-ratchet.md` §5, §9 Q3). A rekey
  is a burst of ~19 frames. **Tamarin's symbolic terms have no length, no timing and no count**, so no
  artifact here can answer it — and note this also means `unlinkability.spthy` does *not* prove the
  256-byte size uniformity its frame-level argument rests on (that is a code invariant, `Frame.Size`,
  plus tests — an *input* to the proof, not an output). The burst reduces to the engine's FR-012
  one-write/one-notify/one-retrieve-per-round invariants, under which the store's per-round view is
  identical whether a pair is idle, chatting, or rekeying. **That reduction is argued, not verified**;
  discharging it needs a quantitative traffic model, not another `.spthy`. See
  [`formal-analysis/README.md`](specs/001-metadata-private-messenger/design/formal-analysis/README.md) §6.
- **None of this removes the dev label.** Per Constitution I's construction amendment, hand-assembled
  crypto ships behind `DEV, NO METADATA PRIVACY` until a **human security review** — for which these
  proofs are *inputs, not substitutes* — signs off. **Phase 5 delivers the formal analysis only**;
  `design/continuous-pq-ratchet.md` §6.3 gates any labeling change on formal analysis **and** human
  review. No label or label literal is touched by that work (`Privacy.scala` is untouched), and in
  particular **no metadata-privacy claim is supported** — the traffic-pattern question above is open.

---

## Reproduce

```bash
# Symbolic design proofs
brew install tamarin-prover/tap/tamarin-prover          # Tamarin + Maude + GraphViz
cd specs/001-metadata-private-messenger/design/formal-analysis
tamarin-prover ratchet.spthy --prove                          # secrecy + PCS (bounded) + epoch fold: all 6 lemmas verified, ~0.85 s
tamarin-prover ratchet-unbounded.spthy --prove                # PCS + FS across UNBOUNDED steps, incl. ACROSS epoch folds: all 11 verified
tamarin-prover --diff unlinkability.spthy --prove             # unlinkability: observational equivalence verified
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # negative control: falsifies (as intended)

# Continuous-PQ epoch fold (Phase 5). The CONTROLS ARE NOT OPTIONAL — a green tick on the first
# line means nothing unless the second FALSIFIES.
tamarin-prover ratchet-pq-epoch.spthy --prove                 # PQ-PCS vs a CRQC: verified
tamarin-prover ratchet-pq-epoch-nofold.spthy --prove          # NEGATIVE CONTROL: MUST falsify (fold is load-bearing)
tamarin-prover ratchet-pq-epoch-hijack.spthy --prove          # SCOPE control: finds the active post-compromise hijack

# The negative control must differ from the model by exactly ONE line — check it:
diff <(sed -n '/^begin/,$p' ratchet-pq-epoch.spthy) <(sed -n '/^begin/,$p' ratchet-pq-epoch-nofold.spthy)

# Executable implementation model (JDK 22+; macOS: export JAVA_HOME="$(/usr/libexec/java_home)")
sbt "protocolCore/testOnly engine.DoubleRatchetModelSpec"
```
