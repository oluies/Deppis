# Formal analysis of the DH double ratchet

Two complementary efforts strengthen the **human security review** the Constitution I *construction
amendment* requires before the hand-assembled ratchet (`engine.DoubleRatchet`) could ever back a build
that drops the `DEV, NO METADATA PRIVACY` label. They attack two different questions:

| Question | Artifact | Status |
|---|---|---|
| **Does the *implementation* hold its invariants under every reachable op sequence?** | `engine.DoubleRatchetModelSpec` (ScalaCheck stateful model) | ✅ runs in CI (JVM), green |
| **Does the *design* provide message secrecy + PCS against a Dolev-Yao attacker?** | `ratchet.spthy` (Tamarin symbolic model, bounded) | ✅ **machine-checked** — all 4 lemmas verified (Tamarin 1.12.0) |
| **Do PCS + FS hold across *arbitrarily many* steps, *given* per-step secret unguessability?** | `ratchet-unbounded.spthy` (Tamarin, unbounded loop) | ✅ **machine-checked** — PCS + FS verified (reuse/induction, no oracle); composition with §2 is argued, not machine-linked |
| **Can the store *link* two frames of one chain? (header unlinkability)** | `unlinkability.spthy` (Tamarin `--diff`) + negative control | ✅ **machine-checked** — observational equivalence verified; cleartext control falsifies |

This split mirrors the Constitution's own layering. **Primitives** (X25519, HMAC-SHA256,
ChaCha20-Poly1305) are delegated to vetted libraries — we *inherit* their verification (the same
fiat-crypto-verified Curve25519 that ships in BoringSSL/Firefox; the formally-verified primitive cores
in the corecrypto/HACL\* lineage). We do **not** re-verify primitives. What we hand-assembled is the
**protocol construction**, and that is what these two artifacts target.

---

## 1. ScalaCheck stateful model (implementation) — `engine.DoubleRatchetModelSpec`

Example-based tests (`DoubleRatchetSpec`) prove the invariants in chosen scenarios. The stateful model
proves them **mechanically over random op sequences**, and *shrinks* any failure to a minimal
counter-example. It generates random scripts of `Send / DeliverNext / TamperThenDeliver /
ReplayConsumed` across both directions and a reference oracle checks, after every step:

- **Correctness** — every in-order genuine delivery decrypts to exactly the plaintext sent.
- **Atomicity (no mutation on undecryptable)** — a tampered body is rejected AND the genuine frame for
  that position still decrypts afterward. *This is the property class of the bug review caught*: here
  it is asserted under every reachable interleaving, not one example, so a regression cannot slip back.
- **Single-use** — a consumed frame never decrypts twice.
- **Out-of-order completeness** — a batch of *K < MaxSkip* frames delivered in any permutation all
  decrypt (skipped-key recovery), with the recovered multiset equal to what was sent.

It is JVM-only (ScalaCheck is on the JVM test classpath; the ratchet logic is platform-independent and
the JVM↔JS *primitive* parity is already pinned byte-for-byte by `DoubleRatchetJsSpec` + the KATs). Run
it with the rest of the suite:

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 26)"
sbt "protocolCore/testOnly engine.DoubleRatchetModelSpec"
```

---

## 2. Tamarin symbolic model (design) — `ratchet.spthy`

`ratchet.spthy` models the ratchet for a **Dolev-Yao attacker** (full network control) with the
standard symbolic idealization our Constitution licenses: DH is the `diffie-hellman` builtin (with CDH —
the attacker cannot derive `g^(xy)` from `g^x`, `g^y`), AEAD is the `symmetric-encryption` builtin
(perfect), and the HMAC KDFs are one-way free functions. It captures the minimal trace that exhibits
healing — **Alice sends (step 1) → Bob receives + heals with a fresh DH `~b` → Bob replies (step 2) on
the healed chain** — plus a chain-key **reveal** rule, and states:

- `executable` — sanity: the protocol runs to completion.
- `pcs_premise_reachable` — sanity: the reveal→heal→healed-send scenario PCS quantifies over is
  reachable, so the all-traces PCS result is provably non-vacuous.
- `message_secrecy` — a message leaks only if the attacker revealed *the very chain root that protects
  it* (`ProtectedBy(m, ck)` binds the reveal to the message, so the lemma is not trivially discharged by
  any unrelated reveal).
- `post_compromise_security` — a message `m2` sent on a chain **healed** by a fresh DH `b` stays secret
  **even though** that chain's pre-heal root `rk1` was **revealed** before the heal. The fresh `b`
  correlates the healed send (`HealedSend(m2, b)`) with the heal (`Heal(b, rk1)`) of the *same session*,
  and the reveal is of *that* session's pre-heal root (`RevealCK(rk1)` with `r < h`) — so it is genuine
  post-compromise recovery, the formal statement of dh-ratchet.md §9 "Gained: PCS."

### ✅ Verification status — machine-checked

Run with **Tamarin 1.12.0 + Maude 3.5.1**, `tamarin-prover ratchet.spthy --prove` (<1 s, no oracle/reuse
lemma needed — the model is bounded to two steps so it closes automatically; `--auto-sources` is not
required):

```
executable               (exists-trace): verified (7 steps)
pcs_premise_reachable    (exists-trace): verified (6 steps)   # PCS premise is reachable ⇒ non-vacuous
message_secrecy          (all-traces):   verified (37 steps)
post_compromise_security (all-traces):   verified (16 steps)
All wellformedness checks were successful.
```

(The proof is **message secrecy + PCS**, not forward secrecy — there is no FS lemma here. The model has
one message per chain root, so within-chain FS is not what Tamarin checks; FS rests on the one-way KDF
chain + key wiping in the design, exercised by the single-use/replay tests in `DoubleRatchetModelSpec`.
`pcs_premise_reachable` is an `exists-trace` companion proving the reveal→heal→send scenario is
reachable, so the all-traces PCS result cannot be vacuously true.)

**Running the prover materially improved the model** — it caught three defects an "authored but
unchecked" draft would have shipped:
1. a **circular header-key derivation** (the header was sealed under a key derived from the same DH it
   carries — Tamarin's message-derivation check flagged it; the real design uses a bootstrap header key);
2. a **free-variable scoping bug** in the PCS lemma (`#h` bound in one existential, used in another);
3. an **over-broad PCS quantifier** — `m2` ranged over *all* messages, so the prover falsified it by
   binding `m2` to a step-1 message and revealing its own key (a lemma bug, not a protocol flaw). Scoping
   `m2` to healed-chain sends fixed it.

This is the concrete argument for *actually running the tool* rather than trusting a hand-written model.

**Scope:** this model is **bounded** to two steps (enough to exhibit one full heal) with the DH/CDH
details explicit. The complementary **unbounded** proof — that secrecy/PCS hold across *arbitrarily many*
ratchet steps — is `ratchet-unbounded.spthy` (§4 below).

### Run recipe

```bash
# macOS: brew install tamarin-prover/tap/tamarin-prover   (also installs Maude + GraphViz)
tamarin-prover ratchet.spthy --prove          # batch-prove all lemmas (<1 s)
tamarin-prover interactive ratchet.spthy      # GUI at http://127.0.0.1:3001 to inspect the proofs
```

---

## 3. Header unlinkability (observational equivalence) — `unlinkability.spthy`

The trace lemmas above are about *secrecy*; **unlinkability** is an *indistinguishability* property — the
store must not tell whether two frames belong to the same sending chain — so it needs Tamarin's
**observational-equivalence (`--diff`)** mode. This is the metadata-privacy crux: a DH ratchet's public
key is constant across a sending chain, so a cleartext header would be a perfect linking tag; the design
seals it under a header key the store never holds.

`unlinkability.spthy` puts two worlds side by side with `diff(L, R)`: **LEFT** = frame 2 shares frame 1's
chain (same header key, same ratchet pubkey); **RIGHT** = frame 2 is a different chain (fresh key, fresh
pubkey). Tamarin's auto-generated `Observational_equivalence` lemma proves the attacker can't tell them
apart ⇒ the store cannot link a chain's frames.

`unlinkability-cleartext.spthy` is the **negative control**: the same model with the header *in the
clear*. The pubkey is now visible, so same-vs-different chain is observable and equivalence must FAIL —
which it does. This is what gives the positive result meaning: the model genuinely captures the linking
threat rather than holding trivially. (The only difference between the two files is the `senc(…, ~hk)`
wrapper.)

```bash
tamarin-prover --diff unlinkability.spthy           --prove   # Observational_equivalence: verified (2315 steps)
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # Observational_equivalence: falsified (10 steps)  ← negative control
```

Scope: the header keys are modeled as fresh secrets the store never holds (they derive from the root
chain — dh-ratchet.md §5); the 12-byte frame nonce is the per-frame fresh value, itself not a linking
tag. The implementation-level echo of this property is the `header encryption removes the linking tag`
test in `DoubleRatchetSpec`.

---

## 4. Unbounded ratchet proof — PCS + FS across arbitrarily many steps, *given* per-step secret unguessability — `ratchet-unbounded.spthy`

`ratchet.spthy` (§2) is bounded to two steps with the DH/CDH details explicit. This file proves the
**structural / inductive** half: that the key schedule's security holds across an **arbitrary number** of
ratchet steps, **given** that each step's healing secret is unguessable. The two are a deliberate modular
decomposition (as the published Signal/Tamarin analyses do) — but they are **not mechanically composed**:
§2 establishes per-step secret unguessability (CDH) for *one* DH step; here that unguessability is taken
as a modeling assumption (`heal_secret_secret`, a fresh `~s`), and we prove the chain preserves security
under it. The cross-model claim "CDH holds at *every* step of an unbounded chain" is argued, not
machine-linked.

A `Step` rule consumes the current root and reproduces the next — so it fires arbitrarily many times (the
unbounded loop; `multi_step_reachable` is a *reachability sanity check* that ≥2 steps can chain — the
**unbounded coverage comes from the `use_induction` all-traces lemmas**, not from this witness). Roots
are fresh names with the one-way KDF relation `rk' = kdfRK(rk, s)` modeled by a `!Mix(rk', rk, s)` fact
plus an adversary `Derive` rule (old root + step secret → new root) and **no inverse rule**. This
expresses exactly the two facts the ratchet relies on while avoiding the non-terminating
term-deconstruction regress a literal `kdfRK(rk,~s)` term causes under an unbounded loop.

```
tamarin-prover ratchet-unbounded.spthy --prove          # ~0.1 s, no oracle, no --auto-sources
  executable / multi_step_reachable (exists-trace): verified      # sanity: the Step loop CAN chain
  heal_secret_secret / root_secrecy / step_input_is_root          # reuse + induction helpers, verified
  post_compromise_security (all-traces): verified                 # UNBOUNDED PCS (given the above)
  forward_secrecy          (all-traces): verified                 # UNBOUNDED FS, under modeled one-wayness
```

The `reuse` + `use_induction` helper lemmas are the standard technique that closes the unbounded loop
*without* a proof oracle. **Forward secrecy** here holds *because the KDF is modeled as one-way* (encoded
by omitting an inverse `Derive` rule): the lemma validates that the key *schedule* leaks no earlier root
under that assumption — it does not prove the KDF's one-wayness itself (that is the primitive's property,
delegated). Message confidentiality is the standard corollary: a message under `msgK(rk)` with perfect
AEAD is confidential iff its root `rk` is secret, which is exactly `root_secrecy`.

---

## What this does and does not buy

- **Together** the two artifacts cover both axes of assurance: the design (symbolic, Tamarin) and the
  implementation's faithfulness to it (executable, ScalaCheck). Neither alone is sufficient — a correct
  design can be mis-implemented, and a well-tested implementation can faithfully realize a flawed design.
- **Neither** removes the audit obligation or the dev label. Per Constitution I, hand-assembled crypto
  ships behind `DEV, NO METADATA PRIVACY` until a human security review — for which these are inputs,
  not substitutes — signs off, and the side-channel/constant-time properties (Constitution II) are not
  in scope of either artifact: on the JVM they are not achievable at the bytecode level and are left to
  the vetted native primitives and the Rust sidecar (documented in dh-ratchet.md §9).
