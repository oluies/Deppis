# Formal analysis of the DH double ratchet

Two complementary efforts strengthen the **human security review** the Constitution I *construction
amendment* requires before the hand-assembled ratchet (`engine.DoubleRatchet`) could ever back a build
that drops the `DEV, NO METADATA PRIVACY` label. They attack two different questions:

| Question | Artifact | Status |
|---|---|---|
| **Does the *implementation* hold its invariants under every reachable op sequence?** | `engine.DoubleRatchetModelSpec` (ScalaCheck stateful model) | ✅ runs in CI (JVM), green |
| **Does the *design* provide secrecy / forward secrecy / PCS against a Dolev-Yao attacker?** | `ratchet.spthy` (Tamarin symbolic model) | ⚠️ authored, **not yet machine-checked** (see below) |

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
- `post_compromise_security` — the premise requires **reveal(`r`) < heal(`h`) < send(`s`)**: even with
  the step-1 chain root compromised, a message sent on a chain healed by a fresh DH *after* the
  compromise stays secret. Because the heal lives in its own rule (`B_recv1_heal`), distinct from the
  send (`B_send2`), `h < s` is satisfiable and the lemma is non-vacuous — it genuinely encodes "healing
  recovers from a compromise," the formal statement of dh-ratchet.md §9 "Gained: PCS," rather than mere
  secrecy in the absence of any compromise.

### ⚠️ Verification status — read this before citing it

**The model is authored against Tamarin syntax but has NOT been run through `tamarin-prover`** — Tamarin
(Haskell + Maude) is not installed in this environment or in CI. It is a **reviewed draft / starting
artifact**, not a completed proof. Honest caveats:

- It may need syntactic/well-formedness fixes on first real run.
- The DH-ratchet's *unbounded* loop is the known-hard part for Tamarin termination; this model is
  deliberately **bounded** to two steps. A general proof needs reusable lemmas and likely a proof
  `oracle` (the published Signal/Tamarin analyses do exactly this).
- **Header unlinkability is NOT covered here.** It is an *indistinguishability* property (the store must
  not tell two frames of one chain apart), which requires Tamarin's **observational-equivalence (diff)**
  mode — a separate model, tracked as future work. The trace lemmas above say nothing about it; the
  implementation-level evidence for unlinkability is the `header encryption removes the linking tag`
  test in `DoubleRatchetSpec`.

### Run recipe (for a reviewer with Tamarin installed)

```bash
# macOS: brew install tamarin-prover/tap/tamarin-prover   (pulls GHC + Maude; slow)
tamarin-prover ratchet.spthy --prove          # batch-prove all lemmas
tamarin-prover interactive ratchet.spthy      # GUI at http://127.0.0.1:3001 to drive proofs
```

A green `--prove` over `post_compromise_security` (after any refinement Tamarin needs to close it) is
the artifact that would let the security review sign off on the *design's* PCS claim — the lemma now
encodes the reveal→heal→send scenario, so a passing run is meaningful rather than vacuous. Until the run
is actually green it remains an honest work-in-progress.

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
