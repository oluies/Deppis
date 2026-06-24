# Crypto proof — content-layer security of the metadata-private messenger

This is the assurance story for the **content** cryptography: the DH double ratchet with header
encryption (`engine.DoubleRatchet`). The ratchet gives messages **forward secrecy** (the one-way KDF
chain + key wiping) and **post-compromise security (PCS)** (the DH ratchet). What is *machine-checked
symbolically* here is **message secrecy + PCS** (forward secrecy is design-level, exercised by the
implementation tests — see the scope note). This document records what is proven, *how*, what the proof
rests on, and what is deliberately out of scope.

Artifacts:
- Symbolic design proof — [`specs/001-metadata-private-messenger/design/formal-analysis/ratchet.spthy`](specs/001-metadata-private-messenger/design/formal-analysis/ratchet.spthy) (+ [README](specs/001-metadata-private-messenger/design/formal-analysis/README.md))
- Executable implementation model — `engine.DoubleRatchetModelSpec` (ScalaCheck, in CI)
- Design spec — [`design/dh-ratchet.md`](specs/001-metadata-private-messenger/design/dh-ratchet.md)

---

## TL;DR

| Property | How it's established | Status |
|---|---|---|
| Message secrecy | Tamarin symbolic proof (Dolev-Yao) | ✅ verified |
| **Post-compromise security** | Tamarin symbolic proof | ✅ **verified (16 steps)** |
| **Header unlinkability** (store can't link a chain's frames) | Tamarin observational equivalence (`--diff`) + negative control | ✅ **verified (2315 steps)** |
| Implementation invariants (correctness, atomicity, single-use, out-of-order) | ScalaCheck stateful model, every reachable interleaving | ✅ green in CI |
| Primitive soundness (X25519, HMAC, ChaCha20-Poly1305) | **delegated** to vetted libraries (JCA / `@noble`) | inherited |

```
tamarin-prover ratchet.spthy --prove        # Tamarin 1.12.0 + Maude 3.5.1, <1 s
  executable               (exists-trace): verified (7 steps)
  pcs_premise_reachable    (exists-trace): verified (6 steps)    # PCS premise reachable ⇒ non-vacuous
  message_secrecy          (all-traces):   verified (37 steps)
  post_compromise_security (all-traces):   verified (16 steps)
  All wellformedness checks were successful.
tamarin-prover --diff unlinkability.spthy --prove     # header unlinkability (indistinguishability)
  Observational_equivalence: verified (2315 steps)
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # negative control: cleartext header
  Observational_equivalence: falsified (10 steps)             # ← intended: proves the test has teeth
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

- **Bounded model.** The proof covers bootstrap + one full heal (two DH steps) — enough to exhibit PCS.
  An *unbounded* proof (arbitrarily many steps) is the known-hard Tamarin termination problem and needs
  reusable lemmas / a proof oracle; that is future work.
- **Header unlinkability is proven separately** (it is an *indistinguishability* property, so it lives in
  Tamarin's observational-equivalence `--diff` mode, not the trace lemmas above). `unlinkability.spthy`
  proves the store cannot tell whether two frames belong to the same sending chain — `Observational_
  equivalence: verified (2315 steps)` — and `unlinkability-cleartext.spthy` is a negative control where
  the header is in the clear and equivalence correctly *falsifies*, showing the model captures the real
  linking threat. (Implementation echo: the `header encryption removes the linking tag` test.)
- **Constant-time / side channels (Constitution II) are out of scope of both artifacts.** On the JVM they
  are not achievable at the bytecode level (JIT + GC); they are left to the vetted native primitives and
  the Rust sidecar, as documented in dh-ratchet.md §9.
- **None of this removes the dev label.** Per Constitution I's construction amendment, hand-assembled
  crypto ships behind `DEV, NO METADATA PRIVACY` until a **human security review** — for which these
  proofs are *inputs, not substitutes* — signs off.

---

## Reproduce

```bash
# Symbolic design proofs
brew install tamarin-prover/tap/tamarin-prover          # Tamarin + Maude + GraphViz
cd specs/001-metadata-private-messenger/design/formal-analysis
tamarin-prover ratchet.spthy --prove                          # secrecy + PCS: all 4 lemmas verified, <1 s
tamarin-prover --diff unlinkability.spthy --prove             # unlinkability: observational equivalence verified
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # negative control: falsifies (as intended)

# Executable implementation model (JDK 22+; macOS: export JAVA_HOME="$(/usr/libexec/java_home)")
sbt "protocolCore/testOnly engine.DoubleRatchetModelSpec"
```
