# Formal analysis of the DH double ratchet

Two complementary efforts strengthen the **human security review** the Constitution I *construction
amendment* requires before the hand-assembled ratchet (`engine.DoubleRatchet`) could ever back a build
that drops the `DEV, NO METADATA PRIVACY` label. They attack two different questions:

> **Companion document.** The repo-root [`CRYPTO_PROOF.md`](../../../../CRYPTO_PROOF.md) is the
> narrative assurance story (what is proven, what it rests on, what is out of scope). **This README is
> the artifact-level detail.** Both are updated together; where they overlap, the prover output quoted
> here is the source of truth.

| Question | Artifact | Status |
|---|---|---|
| **Does the *implementation* hold its invariants under every reachable op sequence?** | `engine.DoubleRatchetModelSpec` (ScalaCheck stateful model) | ✅ runs in CI (JVM), green |
| **Does the *design* provide message secrecy + PCS against a Dolev-Yao attacker?** | `ratchet.spthy` (Tamarin symbolic model, bounded) | ✅ **machine-checked** — all 6 lemmas verified (Tamarin 1.12.0), epoch fold included |
| **Do PCS + FS hold across *arbitrarily many* steps, *given* per-step secret unguessability?** | `ratchet-unbounded.spthy` (Tamarin, unbounded loop) | ✅ **machine-checked** — PCS + FS verified, incl. **across epoch folds** (reuse/induction, no oracle); composition with §2 is argued, not machine-linked |
| **Can the store *link* two frames of one chain? (header unlinkability)** | `unlinkability.spthy` (Tamarin `--diff`) + negative control | ✅ **machine-checked** — observational equivalence verified; cleartext control falsifies |
| **Does the PQ epoch fold restore post-compromise security against a *CRQC*?** | `ratchet-pq-epoch.spthy` + **`-nofold` negative control** (§5) | ✅ **machine-checked, non-vacuous** — verified; the no-fold control **falsifies**. **Bounded by an authentic-rekey-channel assumption — see §5.3** |
| **Is a ~19-frame rekey burst distinguishable? (traffic pattern)** | — | ⚠️ **NOT FORMALLY DISCHARGED** — reduced to an engine invariant and argued in §6; **no model covers it**, and Tamarin structurally cannot |

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
executable                   (exists-trace): verified (7 steps)
pcs_premise_reachable        (exists-trace): verified (8 steps)   # PCS premise reachable ⇒ non-vacuous
message_secrecy              (all-traces):   verified (41 steps)
post_compromise_security     (all-traces):   verified (21 steps)
epoch_fold_premise_reachable (exists-trace): verified (9 steps)   # NEW (Phase 5)
pcs_with_epoch_fold          (all-traces):   verified (7 steps)   # NEW (Phase 5)
All wellformedness checks were successful.
```

**Phase 5 update — the epoch fold is now in this model.** The `B_epoch_fold` / `B_send2_pq` rules fold a
PQ epoch secret into the live root of the healed chain, and the last two lemmas are new. **All four
original lemmas still verify.** Their step counts *moved* (`message_secrecy` 37→41,
`post_compromise_security` 16→21, `pcs_premise_reachable` 6→8) purely because the model grew two rules —
the properties are unchanged. `pcs_with_epoch_fold` is design §6.1's "a heal *plus* an epoch fold still
heals": its point is **not** that the fold adds strength here (against this file's classical attacker it
cannot — PCS already held) but that inserting the fold **does not break** the healing already proved
(design goal **G1**). **Nothing in `ratchet.spthy` is a post-quantum result** — its attacker is the
classical Dolev-Yao attacker for whom CDH *holds*, so the fold is merely one more unguessable secret to
it. The PQ claim lives in §5.

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
tamarin-prover ratchet-unbounded.spthy --prove          # ~0.16 s, no oracle, no --auto-sources
  executable                           (exists-trace): verified (4 steps)
  multi_step_reachable                 (exists-trace): verified (4 steps)   # sanity: Step CAN chain
  fold_in_chain_reachable              (exists-trace): verified (8 steps)   # NEW: step -> FOLD -> step
  heal_secret_secret                   (all-traces):   verified (56 steps)  # reuse helper
  root_secrecy                         (all-traces):   verified (81 steps)  # reuse + induction helper
  step_input_is_root                   (all-traces):   verified (10 steps)  # reuse + induction helper
  fold_input_is_root                   (all-traces):   verified (10 steps)  # NEW helper
  post_compromise_security             (all-traces):   verified (8 steps)   # UNBOUNDED PCS
  forward_secrecy                      (all-traces):   verified (5 steps)   # UNBOUNDED FS
  post_compromise_security_across_fold (all-traces):   verified (8 steps)   # NEW: PCS ACROSS AN EPOCH
  forward_secrecy_across_fold          (all-traces):   verified (5 steps)   # NEW: FS ACROSS AN EPOCH
```

**Phase 5 update — the epoch fold is a first-class root input here.** Design §6.1 required this model to
"model both step-DH and epoch-KEM inputs and show FS/PCS across epoch boundaries". The new `EpochFold`
rule does exactly that: structurally it is the same shape as `Step` (`root' = one-way(root, fresh
secret)`), which is *why* the induction still closes — `!Mix` and `Derive` are agnostic to *which* kind
of secret was mixed, so every root, step-born or fold-born, is covered by the same arguments. It
interleaves freely with `Step`, so the lemmas range over chains with arbitrarily many folds at arbitrary
positions (including none); `fold_in_chain_reachable` witnesses step→fold→step.

**All seven original lemmas still verify.** Step counts *moved* (`heal_secret_secret` 9→56,
`root_secrecy` 18→81, `executable` 3→4, `step_input_is_root` 9→10) because every root is now reachable by
two rules rather than one, so the induction has a second case everywhere — the properties are unchanged,
and PCS/FS still close at 8/5. **Again: no post-quantum claim lives here.** No attacker in this file
breaks CDH; `~ss` is just another unguessable secret. These lemmas say the fold *preserves* the chain's
existing FS/PCS — adding it breaks nothing. The PQ claim is §5's alone.

The `reuse` + `use_induction` helper lemmas are the standard technique that closes the unbounded loop
*without* a proof oracle. **Forward secrecy** here holds *because the KDF is modeled as one-way* (encoded
by omitting an inverse `Derive` rule): the lemma validates that the key *schedule* leaks no earlier root
under that assumption — it does not prove the KDF's one-wayness itself (that is the primitive's property,
delegated). Message confidentiality is the standard corollary: a message under `msgK(rk)` with perfect
AEAD is confidential iff its root `rk` is secret, which is exactly `root_secrecy`.

---

## 5. PQ post-compromise security of the epoch fold — `ratchet-pq-epoch.spthy` (+ 2 controls)

This is the **continuous-PQ-ratchet Phase 5 gate** (`design/continuous-pq-ratchet.md` §6.2, §7). It is
a **new model under a new attacker**, not a re-run: every lemma in §2/§4 is proved against a Dolev-Yao
attacker for whom **CDH holds**, and the entire purpose of the epoch fold is to defend an attacker for
whom it does **not** (a CRQC).

### 5.1 Why the obvious lemma would have been worthless

The tempting statement — *"under an adversary that breaks X25519 but not ML-KEM, a post-fold message
stays secret"* — is **vacuous**. Option A's pairing seed already binds every root to the pairing ML-KEM
secret, so that adversary can never compute any root **fold or no fold**; the lemma would verify
identically on a build with the fold deleted. It would distinguish nothing.

So the model instead reproduces the exact gap of design §1.2 — the one thing that spends the seed's
protection:

1. **`Reveal_root`** — a classical **state compromise** of a *live, pre-fold* root. The revealed root
   already embeds the pairing seed, so the seed's hardening is spent; only entropy mixed in *afterward*
   can help. (No rule ever reveals a *post*-fold root, so the lemma cannot be discharged by revealing
   its own target.)
2. **`Reveal_dh`** — the **CRQC**: the adversary is handed every X25519 ratchet *exponent*. Granting the
   exponents is granting the discrete logs, so it rebuilds `('g'^~a)^~b` itself — CDH is broken **for it
   alone**, while the ML-KEM arm (the `asymmetric-encryption` builtin: no inverse, no deconstruction)
   stays hard. This is how "breaks CDH but not ML-KEM" is expressed in a tool whose `dh` builtin has no
   CDH switch.

The adversary is thereby handed the pre-fold root *and* every classical secret after it, so it computes
every root the classical ratchet produces. `anchor_root_is_compromised` **proves that** (`exists-trace`,
verified): the adversary really does compute the last root before the fold. The fold is the only thing
left standing.

### 5.2 The negative control is the result

A green tick on the fold model means **nothing** by itself. `ratchet-pq-epoch-nofold.spthy` is the same
model with **one line changed** — verify that mechanically, since a control that drifted from the model
it controls would prove nothing:

```bash
diff <(sed -n '/^begin/,$p' ratchet-pq-epoch.spthy) \
     <(sed -n '/^begin/,$p' ratchet-pq-epoch-nofold.spthy)
#   -        rkf = kdfEpoch(rkn, ~ss)
#   +        rkf = rkn                   # *** THE FOLD IS REMOVED ***
```

**Measured** (`tamarin-prover 1.12.0` + Maude 3.5.1; all wellformedness checks pass in both):

```
tamarin-prover ratchet-pq-epoch.spthy --prove                    # ~0.44s
  executable                  (exists-trace): verified (3 steps)
  pq_pcs_premise_reachable    (exists-trace): verified (6 steps)   # reveal+CRQC+send IS reachable
  epoch_secret_secret         (all-traces):   verified (4 steps)
  anchor_root_is_compromised  (exists-trace): verified (8 steps)   # the pre-fold root IS broken
  pq_post_compromise_security (all-traces):   verified (8 steps)   # *** THE CRUX ***

tamarin-prover ratchet-pq-epoch-nofold.spthy --prove              # ~0.40s   NEGATIVE CONTROL
  pq_post_compromise_security (all-traces):   falsified - found trace (7 steps)   # *** EXPECTED RED ***
  (executable / pq_pcs_premise_reachable / epoch_secret_secret / anchor_root_is_compromised: verified,
   3 / 6 / 4 / 8 steps — identical to the fold model)
```

The control **falsifies**, and the trace Tamarin returns is precisely the §1.2 gap: revealed pre-fold
root + broken CDH ⇒ the adversary walks the classical chain forward and reads the message. **The fold is
load-bearing, and the lemma is therefore non-vacuous.** Note `epoch_secret_secret` still *verifies* in
the control — the epoch secret is still unguessable there, it is simply never mixed into anything. Only
the falsified lemma beside it reveals that a secret you don't fold in buys you nothing.

> **Running the prover materially fixed this model, again.** The first draft used a free function
> `kemct/2` and pattern-matched `ss` out of it. **All five lemmas "verified"** — while Tamarin's
> message-derivation check **failed** (`Rule Epoch_decaps_verify: Failed to derive Variable(s): ss`) and
> warned *"the analysis results might be wrong"*. That was unintended pattern matching: the rule
> extracted a value from a term nothing can invert. Those green ticks were discarded, not shipped; the
> KEM was remodelled on the `asymmetric-encryption` builtin (a KEM *is* PKE of a fresh random secret)
> with the tag check as an explicit `Eq` restriction. Same lesson as the circular header key in §2.

### 5.2.1 The attack graphs — look at these first

Tamarin draws the counterexample it finds. Two are committed under `graphs/`, so a reviewer can see
what the falsified lemmas *mean* without installing anything:

| Picture | What it is | Read it as |
|---|---|---|
| [`graphs/nofold-attack.svg`](graphs/nofold-attack.svg) | `ratchet-pq-epoch-nofold.spthy` :: `pq_post_compromise_security` — **falsified, 7 steps** | **The attack the fold prevents.** Follow `RevealRoot` → `kdfRK` → `Send`/`Out`: the adversary takes the revealed pre-fold root, walks the classical chain forward across the DH step (CDH is broken), and reads the message. This is the §1.2 gap, drawn. |
| [`graphs/hijack-attack.svg`](graphs/hijack-attack.svg) | `ratchet-pq-epoch-hijack.spthy` :: `pq_post_compromise_security` — **falsified, 14 steps** | **The limit of the positive result** (§5.3). With A1 dropped, an adversary *active on the rekey exchange* supplies its own KEM public key and folds a secret it chose. Note the confirm tag is present and verifies — it proves knowledge of `ss`, and the attacker knows the `ss` it picked. |

**There is deliberately no picture of the positive result.** `ratchet-pq-epoch.spthy`'s
`pq_post_compromise_security` is *verified*, and a verified all-traces lemma has no trace to draw — its
content is the **absence** of an attack, and absence has no picture. Anyone wanting to see that result
must read the model and re-run the prover; that asymmetry is honest, not an omission. The pair above is
the argument: **same model, same attacker, same lemmas — one line changed, and the attack appears.**

Regenerate (never hand-edit the SVGs — a committed picture that drifts from its model is precisely the
"asserts something the code does not do" failure this analysis keeps catching):

```bash
./render-attack-graphs.sh           # re-render graphs/*.svg from the models beside it
./render-attack-graphs.sh --check   # exit 1 if the committed SVGs are stale
```

The script **fails loudly if a lemma stops falsifying** — if the control ever verifies, the negative
control has silently stopped controlling anything, and no picture should be shipped until that is
understood. Rendered with `tamarin-prover 1.12.0` + `graphviz 15.1.0`; `dot` layout is not guaranteed
byte-stable across graphviz versions, so `--check` is a drift alarm for humans, not a CI gate.

### 5.3 What this does NOT prove — the assumption that bounds it

**`ratchet-pq-epoch.spthy` assumes an *authentic* rekey channel (its abstraction A1).** The KEM
ciphertext and both confirmation tags are `Out()`-put — so the result genuinely holds against an
adversary *holding* them — but they are **delivered** over `Auth_*` facts, modelling the MK-sealed
ratchet chain the chunks ride inside (design §4.2's session/transcript binding).

**That assumption is in tension with the very compromise the lemma models**, and this PR does not paper
over it. An adversary that revealed a live root can derive that chain's message keys and therefore
**forge the seal**. `ratchet-pq-epoch-hijack.spthy` removes A1 — sealing the control frames under
`msgK(rk)` explicitly, exactly as the implementation does — and **finds the attack**:

```
tamarin-prover ratchet-pq-epoch-hijack.spthy --prove              # ~1.3s
  executable                  (exists-trace): verified  (13 steps)  # honest rekey, NO compromise
  pq_active_hijack_witness    (exists-trace): verified  (23 steps)  # *** THE ATTACK IS FOUND ***
  pq_post_compromise_security (all-traces):   falsified (14 steps)  # the A1-free statement
```

The adversary suppresses the responder's ciphertext and injects its own, `aenc('evil', pk(ek))`, sealed
under the compromised chain's key. ML-KEM's implicit rejection means decaps doesn't throw; **the
confirmation tag does not save it** — the tag proves knowledge of `ss`, and the attacker genuinely
*knows* `'evil'`, so `confirmTag('evil','r')` verifies. The fold completes, is confirmed, and hardens
nothing. It needs **both** the revealed root (to forge the seal) *and* the CRQC (to compute the anchor
root) — neither alone suffices.

**This is not a new vulnerability and not a finding against the implementation.** It is the standard,
well-known caveat on post-compromise security: an *active* adversary holding session state can MITM from
that moment on, and no fresh key material re-injected into a hijacked session heals it, because the
adversary controls what "fresh" material the victim accepts. Signal's DH PCS carries the identical
caveat; the fold neither creates nor cures it. It is also **not a defect in `EpochKdf`**: no tag keyed on
`ss` can distinguish "the peer knows `ss`" from "the attacker chose `ss`". Deppis's **existing** classical
PCS results (§2, §4) sit behind the same assumption — they model a *reveal*, not an *injection*.

It is recorded here because **design §6.2's proposed lemma text does not state it**, and a reader could
otherwise over-read the green tick. **The property actually proved is:**

> PQ post-compromise security against an adversary that is **active before** the rekey (it compromised
> the state) and **passive on** the rekey exchange itself — including one that holds the KEM ciphertext
> and both confirmation tags.

That is a real and useful property — it is exactly the *harvest-then-go-quiet* adversary, and the
realistic HNDL threat. It is **not** "PQ-PCS against any post-compromise adversary" and must never be
quoted as such.

### 5.4 Other abstractions (in the model header as A1–A5)

- **A2 — one shared root chain, roles abstracted.** The real peers traverse one chain at *offset*
  positions and are never simultaneously on the same root — the whole reason the fold is anchored to a
  root **index** and the tags cannot be keyed on `RK_epoch` (§4.2 amendment;
  `DoubleRatchet.scala:186-208`). The model collapses this to one chain object, so it **assumes** rather
  than proves that both sides derive the byte-identical `RK_epoch` at the anchor. That is a
  liveness/agreement property, exercised by Phase 4's tests, **not** here.
- **A3 — chunking is transport.** The ~9-frame pubkey / ~8-frame ciphertext transfers are single atomic
  messages; ARQ/loss/reorder are discharged by the ARQ property tests.
- **A4 — not modelled:** the ~19-frame traffic pattern (§6 below), the rekey state machine's
  `Committed`/`Stranded` liveness (design §8.2), key wiping, and all side-channel/constant-time
  properties (Constitution II — out of scope for *every* Tamarin artifact here).
- **A5 — bounded:** one compromise, one rekey, one anchor step, one post-fold send. The unbounded
  structural half is §4, which now carries the fold; the two are **not mechanically composed**.

---

## 6. Traffic pattern of the ~19-frame rekey burst — **NOT formally discharged**

Design §5 and §9 Q3 ask whether a rekey — a burst of ~19 frames — is distinguishable under the
cover-traffic model. **This PR does not discharge that question, and does not claim to.** What follows is
the honest reduction, with the boundary marked.

### 6.1 What Tamarin covers here — and a limit worth stating plainly

`unlinkability.spthy` **re-verifies unchanged**, as expected: the epoch fold changes no wire format (KEM
material rides the MK-sealed *inner block*, never the header; the header is still
`DHs.pub(32) ‖ PN(4) ‖ Ns(4)` and the frame is still 256 B).

```
tamarin-prover --diff unlinkability.spthy           --prove   # Observational_equivalence: verified (2315 steps), ~2.7s
tamarin-prover --diff unlinkability-cleartext.spthy --prove   # falsified (10 steps)  ← negative control still has teeth
```

But note what that result **is not**. **Tamarin's symbolic terms have no length, no timing, and no
count.** So `unlinkability.spthy` does *not* prove the 256-byte size uniformity that §5's frame-level
argument rests on — that is a **code invariant** (`Frame.Size = 256`, `Frame.scala:3-11`) plus tests, not
a Tamarin result. Tamarin proves that *given* two frames the attacker cannot correlate their sealed
contents. Length equality is an input to that, not an output. A rekey-chunk frame being
indistinguishable from a content frame follows from the same argument **only because** both are 256 B
and both seal an opaque inner block — and the first of those two facts lives in the code, not the model.

### 6.2 The reduction (argued, grounded in the engine)

The burst is unobservable **iff** rekey frames obey the same per-round budget as content frames. The
engine's FR-012 invariants make each round's observable **constant by construction**:

| Per-round observable | Mechanism | Code |
|---|---|---|
| Exactly **one 256-B store write** | idle rounds write a **cover frame**; a rekey chunk *replaces* that write under the pair's round token (design §3.1 a-i) | `Engine.scala:1338-1350` ("Exactly ONE store write per round … one same-shaped 256-byte write per round either way (active/idle uniform)") |
| Exactly **one notify signal** | real to a peer, or a **decoy** to a per-client `voidNotifyLabel` nobody fetches | `Engine.scala:221-226`, `:1477-1480` |
| Exactly **one retrieve** | **cover reads** under a `coverKey`-derived token when there is nothing to fetch | `Engine.scala:1491-1493`, `:1602-1603` |
| Exactly **one digest fetch** | one PING digest fetch per round | `Engine.scala:1336-1337` |

If those hold, then **the store's per-round view is identical whether the pair is idle, chatting, or
rekeying** — so there is no "run of busy rounds" to observe in the first place, and the ~19-frame burst
has no signature. Under (a-i) a chunk write *replaces* a cover write; under the invariant, replacement is
not observable.

### 6.3 What is therefore NOT covered — read this before quoting §6.2

- **No model checks any of this.** §6.2 is an *argument over code invariants*, not a machine-checked
  result. It is exactly as strong as those invariants, and their enforcement for *rekey* frames
  specifically is an implementation property verified by tests, not by anything in this directory.
- **Tamarin structurally cannot discharge it.** Timing, volume, round-counting and message length are
  all outside its symbolic model. Discharging this properly needs a different formalism (a quantitative
  / probabilistic traffic model), not another `.spthy`. That is unbudgeted work, not a small edit.
- **Scheduler perturbation is the live risk.** The argument fails the moment a rekey causes a round to
  deviate — an extra write, a delayed notify, a skipped cover read. Design §3.1's (a-ii) multiplexer and
  the head-of-line tradeoff (§9 Q2) are exactly where that could creep in.
- **Endpoint-observable latency is out of scope entirely.** A rekey occupying the single stop-and-wait
  in-flight slot delays user messages (§9 Q2). That is invisible to the *store* under the invariant, but
  it is not nothing — it is simply not a property any artifact here models.
- **The `Ns`/`MaxSkip` interaction (§9 Q5) is unexamined** by every model here.

**Bottom line: design §9 Q3 remains OPEN.** The per-frame half is machine-checked (and unchanged); the
timing/volume half is argued from engine invariants and **not verified**.

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

### Labeling status after Phase 5 (Constitution IV)

**`DEV, NO METADATA PRIVACY` stands. This PR changes no label and no label literal** (`Privacy.scala`
is untouched). Design §6.3 gates any labeling change on formal analysis **and** human security review.
Phase 5 delivers **only the first**; the second is a human's call and cannot be discharged from inside
this work.

**What the proofs now support** — and the precise wording that is defensible:

> For a session that completes an epoch fold, a message sent after the fold retains post-compromise
> secrecy **against a CRQC**, even though a live pre-fold root was compromised and every X25519 secret
> is known to the adversary — **provided that adversary did not actively inject into the rekey
> exchange itself**. Machine-checked, symbolically, and shown non-vacuous by a negative control that
> falsifies without the fold.

**What they do NOT support** (each of these would be an overclaim):

1. **Not** PQ-PCS against an *active* post-compromise adversary — §5.3 *finds that attack* and it is
   real (though a standard, well-known PCS caveat, not a defect in this implementation).
2. **Not** any *metadata-privacy* claim. The rekey traffic pattern (design §9 Q3) is **not discharged**
   (§6) and Tamarin structurally cannot discharge it. The unlinkability result is per-frame only, and
   even its size-uniformity premise is a code invariant, not a Tamarin output.
3. **Not** an implementation claim. Every result here is about the **design**, symbolically. That the
   shipped `EpochKdf`/`DoubleRatchet` faithfully realize the modelled fold is the job of the ScalaCheck
   model + KATs (§1), and abstraction **A2** in particular *assumes* the both-sides-same-`RK_epoch`
   agreement rather than proving it.
4. **Not** proof of the primitives. ML-KEM is idealized as an independent hard problem; symbolic
   models say nothing about ML-KEM's actual cryptanalytic standing.
5. **Not** side-channel/constant-time coverage (Constitution II) — out of scope for every artifact here.

**What a labeling change would still require, beyond this PR:**

- **Human security review** of these models — *especially* whether abstraction **A1** (§5.3) is an
  acceptable assumption for the threat model actually being claimed, since it is the single load-bearing
  assumption under the headline result.
- A **decision on design §9 Q3** (traffic pattern): either a quantitative traffic model, or an explicit,
  reviewed acceptance of the §6.2 argument-from-invariants with its residuals.
- A **decision on §9 Q1** (cadence `N`) — it bounds the PQ-PCS window and is a threat-model call, not a
  code default.
- Resolution of the **default-pairing** question: `addBuddy` still defaults to the **classical** path
  (`Engine.scala:302-303`), so a fold's benefit depends on which pairing path ran (design §6.3).
- The **Constitution I** construction-amendment review of the hand-assembled construction as a whole.
