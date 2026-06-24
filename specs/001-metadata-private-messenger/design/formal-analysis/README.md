# Formal analysis of the DH double ratchet

Two complementary efforts strengthen the **human security review** the Constitution I *construction
amendment* requires before the hand-assembled ratchet (`engine.DoubleRatchet`) could ever back a build
that drops the `DEV, NO METADATA PRIVACY` label. They attack two different questions:

| Question | Artifact | Status |
|---|---|---|
| **Does the *implementation* hold its invariants under every reachable op sequence?** | `engine.DoubleRatchetModelSpec` (ScalaCheck stateful model) | ✅ runs in CI (JVM), green |
| **Does the *design* provide secrecy / forward secrecy / PCS against a Dolev-Yao attacker?** | `ratchet.spthy` (Tamarin symbolic model) | ✅ **machine-checked** — all 3 lemmas verified (Tamarin 1.12.0) |

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
message_secrecy          (all-traces):   verified (37 steps)
post_compromise_security (all-traces):   verified (16 steps)
All wellformedness checks were successful.
```

**Running the prover materially improved the model** — it caught three defects an "authored but
unchecked" draft would have shipped:
1. a **circular header-key derivation** (the header was sealed under a key derived from the same DH it
   carries — Tamarin's message-derivation check flagged it; the real design uses a bootstrap header key);
2. a **free-variable scoping bug** in the PCS lemma (`#h` bound in one existential, used in another);
3. an **over-broad PCS quantifier** — `m2` ranged over *all* messages, so the prover falsified it by
   binding `m2` to a step-1 message and revealing its own key (a lemma bug, not a protocol flaw). Scoping
   `m2` to healed-chain sends fixed it.

This is the concrete argument for *actually running the tool* rather than trusting a hand-written model.

**Out of scope (honest limits):**
- The DH ratchet's *unbounded* loop is the known-hard part for Tamarin termination; this model is
  deliberately **bounded** to two steps (enough to exhibit one full heal). An unbounded proof needs
  reusable lemmas / a proof `oracle`, as the published Signal/Tamarin analyses do.
- **Header unlinkability is NOT covered** — it is an *indistinguishability* property requiring Tamarin's
  **observational-equivalence (diff)** mode, a separate model (future work). The implementation-level
  evidence for it is the `header encryption removes the linking tag` test in `DoubleRatchetSpec`.

### Run recipe

```bash
# macOS: brew install tamarin-prover/tap/tamarin-prover   (also installs Maude + GraphViz)
tamarin-prover ratchet.spthy --prove          # batch-prove all lemmas (<1 s)
tamarin-prover interactive ratchet.spthy      # GUI at http://127.0.0.1:3001 to inspect the proofs
```

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
