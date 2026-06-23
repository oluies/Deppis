# Design: X25519 DH ratchet — post-compromise security for the content path

**Status:** design (Stage 2 spec). Stage 1 — the X25519 primitive seam (`x25519.X25519`, RFC 7748
KATs, `@noble/curves` dep) and the Constitution amendment that authorizes this construction — has
shipped. This document is the contract Stage 2 (the state machine) is built and reviewed against.

**Constitution basis:** Principle I, *construction amendment v1.1.0* (2026-06-23). No audited
cross-platform double ratchet exists to wrap (libsignal-client is JVM-only native; nothing exists for
Scala.js, the real client). The ratchet is therefore *assembled* from vetted primitives —
`x25519.X25519` (JCA / `@noble/curves`), `kdf.Kdf.hmacSha256`, `aead.Aead` (ChaCha20-Poly1305) — under
the amendment's safeguards: KATs for every primitive (done, Stage 1), property tests for the
construction's invariants (Stage 2), and this threat-model note. **No primitive is hand-rolled.**

---

## 1. Why — the gap the symmetric ratchet leaves

The shipped `engine.KeySchedule` (PR #44) gives **forward secrecy**: per-direction content chains,
each message key wiped after use, `contentRoot` wiped after seeding. A device-state compromise cannot
decrypt *prior* messages.

It does **not** give **post-compromise security (PCS)**. An attacker who captures a live content chain
key reads *every future* message on that chain — forever — because the chain only advances via a
public one-way HMAC the attacker can run too. There is no fresh secret mixed in. PCS ("healing") is
exactly what the Diffie–Hellman half of a double ratchet adds: each ratchet step mixes a **fresh random
X25519 shared secret** into the root key, so once one uncompromised DH step lands, the attacker is
locked out again.

This is the second half of a Signal-style double ratchet, adapted to our metadata-privacy model.

---

## 2. The one thing that makes our ratchet different: header encryption is mandatory

A DH ratchet must tell the receiver which ratchet public key a frame was sent under, plus message
counters (`N`, `PN`) so the receiver can derive/skip keys. In vanilla Signal these travel in a
**cleartext header** — fine there, because Signal's server already knows who is talking to whom.

**Our store must not be able to link frames.** The whole point of the system is unlinkability: the
store sees fixed-size random-looking writes addressed by non-recurrent retrieval tokens, and must not
be able to group a conversation's frames together. A cleartext ratchet public key is **constant across
an entire sending chain** — so it would be a perfect linking tag: every frame in a chain would carry
the same 32 bytes, and the store could cluster them instantly. That breaks FR-014 (non-recurrent
addressing) at the content layer.

Therefore the header is **encrypted** (the Signal "header encryption" variant). The ratchet maintains
a **header-key chain** alongside the message chains; the header (ratchet pubkey + counters) is
AEAD-sealed under a header key `HK` that itself ratchets each DH step. The receiver **trial-decrypts**
incoming headers against its current and next header keys (`HKr`, `NHKr`) to detect a DH step without
ever seeing the pubkey in clear. To the store, header ciphertext is just more uniform random bytes.

This roughly doubles the construction's complexity versus vanilla Signal and is the main reason Stage
2 is a separate, property-tested PR.

---

## 3. State

Per buddy, replacing the two bare chain keys (`sendCK`/`recvCK`) of the current `BuddyRuntime`:

| Field        | Bytes | Meaning |
|--------------|-------|---------|
| `RK`         | 32    | Root key — mixes in each DH shared secret |
| `DHs`        | 32+32 | Our current ratchet key pair (priv, pub) |
| `DHr`        | 32    | Peer's current ratchet public key (or `None` until first received) |
| `CKs`        | 32    | Sending chain key (or `None`) |
| `CKr`        | 32    | Receiving chain key (or `None`) |
| `HKs`/`HKr`  | 32    | Current sending / receiving **header** keys |
| `NHKs`/`NHKr`| 32    | Next-step sending / receiving header keys (for trial-decrypt of a DH step) |
| `Ns`/`Nr`    | int   | Message number in the current sending / receiving chain |
| `PN`         | int   | Length of the *previous* sending chain (sent in the header so the receiver can skip) |
| `MKSKIPPED`  | map   | `(HKr-epoch, N) → MK` for out-of-order / missed messages, **bounded** (§7) |

`addrKey` (retrieval tokens + notify bit) is unchanged and stays on its own HMAC branch — the DH
ratchet touches **content only**. The public addressing layer is deliberately not forward-secret /
not PCS (the store observes it anyway); see `KeySchedule` doc.

---

## 4. KDFs — all HMAC-SHA256, reusing the `kdf.Kdf` seam

Two functions, same primitive and labelled-info discipline as `KeySchedule` (cross-platform, vetted):

**Root KDF** — advance the root key and derive a new chain key + header keys from a DH output:

```
KDF_RK(RK, dh) :
  k   = HMAC(RK, "dr/rk" ‖ dh)          # 32-byte PRK from the fresh DH secret
  RK' = HMAC(k, "dr/root")
  CK  = HMAC(k, "dr/chain")
  NHK = HMAC(k, "dr/hdr")               # becomes the next header key for this direction
  wipe(k)
  (RK', CK, NHK)
```

**Chain KDF** — advance a content chain, identical shape to the shipped symmetric ratchet:

```
KDF_CK(CK) :
  MK  = HMAC(CK, "dr/msg")              # == KeySchedule.messageKey semantics
  CK' = HMAC(CK, "dr/next")             # == KeySchedule.nextChain semantics
  (MK, CK')                             # caller wipes the old CK and, after AEAD, MK
```

`dh` is the raw 32-byte `X25519.sharedSecret(DHs.priv, DHr)`. HKDF is not required: HMAC-SHA256 with
distinct, fixed info labels over a uniformly-random PRK is the same construction the symmetric ratchet
already uses and KATs.

---

## 5. Bootstrap — no interactive prekey exchange

We already share a high-entropy `contentRoot` from the handshake (`Handshake.init`). Rather than add an
X3DH prekey round, we **bootstrap deterministically** from it:

1. Both sides derive the **responder's initial ratchet key pair** deterministically:
   `DHseed = HMAC(contentRoot, "dr/bootstrap-ratchet")`, then `DHs(responder) = X25519` keypair from
   `DHseed` (clamped). The initiator learns `DHr = X25519.publicKey(DHseed)` the same way — so it can
   send immediately, no round trip.
2. `RK₀ = HMAC(contentRoot, "dr/root0")`; initial header keys
   `HKs/HKr/NHKs/NHKr = HMAC(contentRoot, "dr/hdr/<role>/<dir>")`. Both sides compute the same four.
3. The initiator performs the **first DH ratchet step immediately** with a *fresh random* `DHs`,
   sealing its real public key in the (encrypted) header. From that first step on, every ratchet
   secret is fresh randomness — that is where PCS healing comes from. The deterministic bootstrap key
   is only ever used to seal/open the very first header and is then ratcheted away.

This keeps the security property that matters — **healing depends on fresh randomness, not on the
bootstrap secret** — while avoiding an interactive prekey protocol the symmetric pairing model does
not have.

> Security note: because the bootstrap ratchet key is derived from `contentRoot`, the *first* chain is
> only as forward-secret as the handshake (same as today). PCS and full FS kick in at the first random
> DH step. This is an explicit, documented trade for not running X3DH; revisit if the pairing model
> gains an async prekey store.

---

## 6. Wire format — staying inside the fixed 256-byte store frame

The store frame is immovably 256 bytes (`frame.Frame.Size`); real and carrier frames must stay
byte-indistinguishable. Today: `nonce(12) ‖ AEAD(MK, inner=228)`, `maxPayload = 226`.

Stage 2 packs an encrypted header in front of the message, under **one** frame nonce reused across the
two AEADs — safe because `HK` and `MK` are independent keys (ChaCha20-Poly1305's nonce-uniqueness
requirement is per-key):

```
256-byte wire frame:
  nonce(12) ‖ AEAD(HK, header)(52) ‖ AEAD(MK, inner)(192)
  where header   = DHs.pub(32) ‖ PN(2) ‖ Ns(2)        = 36 plaintext  → +16 tag = 52
        inner    = len(2) ‖ payload ‖ zero-pad         = 176 plaintext → +16 tag = 192
  ⇒ maxPayload = 174 bytes   (was 226)
```

The header nonce is **derived from `Ns`** (`nonce_hdr = LE(Ns) ‖ 0…`), not random: `HK` is constant
across a whole sending chain, so a random 96-bit nonce would risk a birthday collision over a long
chain; `Ns` is unique per message within the chain, guaranteeing no `HK`-nonce reuse. The message
nonce is the random frame `nonce` (MK is already unique per message, so reuse is impossible). Both are
recoverable by the receiver from the same frame bytes / decrypted header.

**Receiver flow per frame** (constant-time on the secret-dependent branches — Constitution II):
1. Trial-open `AEAD(HKr, …)`. Success ⇒ same DH epoch: read `PN`, `N`; if `N > Nr` skip+stash the
   intermediate `MK`s into `MKSKIPPED`; derive `MK`, open the message.
2. Else trial-open `AEAD(NHKr, …)`. Success ⇒ a **DH ratchet step**: finish the prior receiving chain
   up to `PN` (stashing skipped keys), run `DHRatchet(header.DHpub)` to roll
   `RK/CKr/HKr/NHKr/HKs/NHKs`, then proceed as (1) on the new chain.
3. Else check `MKSKIPPED` for a stored key (out-of-order delivery of an old chain).
4. Else the frame is not for us / undecryptable ⇒ treated exactly like a carrier (no error that varies
   on content; matches the current `decryptFrame ⇒ None` path).

The ≈226→174 payload shrink is acceptable for chat text. If a future payload needs more room, the
documented relaxation is to lift the per-frame plaintext cap by spanning multiple store frames at the
transport layer (out of scope here); the ratchet format does not change.

---

## 7. Skipped / out-of-order keys — bounded

Out-of-order and dropped frames are normal (the store is a mailbox; carrier rounds interleave). On a
gap of `N - Nr` messages the receiver derives and **stashes** the intermediate `MK`s in `MKSKIPPED`,
keyed by `(receiving-header-epoch, N)`. Bounds (DoS-resistant, like libsignal):
- **`MAX_SKIP = 1000`** keys per chain step — a header claiming a larger jump is rejected as a carrier
  (no memory blow-up, no distinguishable error).
- **`MAX_SKIP_CHAINS`** retained receiving epochs — oldest evicted FIFO; its stashed keys are wiped.
- Every stashed `MK` is wiped on use or on eviction. A stashed key is plaintext-equivalent to a live
  message key, so the bound is a forward-secrecy knob, not just memory hygiene: smaller = tighter FS,
  larger = more out-of-order tolerance. Default 1000 mirrors Signal.

---

## 8. Ratchet diagram

```mermaid
graph TD
  RK0["RK (root key)"] -->|"KDF_RK(RK, DH1)"| RK1["RK'"]
  DH1["X25519(DHs, DHr)<br/>fresh random step"] --> RK1
  RK1 --> CKs0["CKs (send chain key)"]
  RK1 --> NHKs["NHKs (next send header key)"]
  CKs0 -->|"KDF_CK"| MK0["MK#0  → AEAD(payload)"]
  CKs0 -->|"KDF_CK"| CKs1["CKs'"]
  CKs1 -->|"KDF_CK"| MK1["MK#1  → AEAD(payload)"]
  CKs1 -->|"KDF_CK"| CKs2["CKs''  …"]
  HKs["HKs (send header key)"] -->|"AEAD(header = DHs.pub ‖ PN ‖ Ns)"| HDR["sealed header"]
  classDef fresh fill:#eef7ee,stroke:#3a3,color:#143;
  class DH1 fresh
```

Each DH step replaces the chain *and* the header keys, so a compromise of `CKs`/`HKs` is healed once
one fresh `DH1` the attacker did not see is mixed into `RK`.

---

## 9. Threat model delta

**Gained:** post-compromise security on content. After a device-state compromise, the first
uncompromised DH ratchet step (fresh randomness on either side) re-secures all subsequent messages —
the attacker can no longer derive future message keys from the captured state.

**Unchanged / still out of scope (honest labeling):**
- The **public addressing layer** (retrieval tokens, notify bit, frame timing/size) is not affected —
  it never was forward-secret/PCS by design; the store observes it. PCS is a *content* property.
- The **bootstrap chain** before the first random DH step is only as strong as the handshake (§5).
- This is **assembled, not wrapped, crypto.** Per the Constitution amendment it carries the audit
  obligation: every primitive KATed (Stage 1 ✔), every invariant property-tested (Stage 2), and a
  human security review of the state machine before it can back any build that drops the
  `DEV, NO METADATA PRIVACY` label. Until then it ships behind the dev label like everything else.
- Constitution II (no secret-dependent error/timing variance) governs the trial-decrypt path: a
  non-matching header MUST be indistinguishable from a carrier frame — same `None`/drop path, no
  early-out that leaks which key matched.

**What the store still cannot see** (the property header encryption protects): it cannot link a
chain's frames via the ratchet public key, cannot tell a real frame from a carrier, and cannot read
counters — header ciphertext is uniform random bytes under a key it never holds.

---

## 10. Stage-2 test plan

Primitive KATs (X25519 RFC 7748) already pass cross-platform (Stage 1). Stage 2 adds, in
`protocol-core/shared/src/test` (so they run on JVM **and** Node):

1. **PCS healing (property):** capture `CKs/CKr/HKs/HKr` at message *k*; after one fresh DH step the
   captured state cannot derive message *k+Δ*'s key. The core PCS assertion.
2. **Forward secrecy (property):** retained state at message *k* cannot derive any message *< k*
   (extends the existing symmetric-ratchet FS test across DH steps).
3. **Out-of-order & skipped:** deliver a chain permuted / with gaps ≤ `MAX_SKIP`; all decrypt. A gap
   `> MAX_SKIP` is dropped as a carrier (no throw, no distinguishable error).
4. **Header unlinkability:** the 12-byte+ header-ciphertext region differs across two frames of the
   *same* sending chain (same `DHs.pub` underneath) — i.e. encryption removes the linking tag. Plus:
   a third party without `HKr` cannot distinguish a real header region from random.
5. **Cross-platform parity:** a chain driven on the JVM decrypts on Node and vice-versa (the X25519 ≡
   contract, now end-to-end through the ratchet).
6. **Two-engine + `obsd` E2E:** extend `scripts/run-demo.sh` / the round-transport spec so two engines
   exchange messages across several DH steps through the real oblivious sidecar, asserting healing
   after a simulated state capture.
7. **Constant-time trial-decrypt:** assert the non-matching-header path is the same code path as a
   carrier (structural/property check; Constitution II).

---

## 11. Stage-2 implementation surface (forecast, not yet built)

- `engine/DoubleRatchet.scala` (shared) — the state machine: `DHRatchet`, `ratchetEncrypt`,
  `ratchetDecrypt`, `skipMessageKeys`, header seal/open. Pure over `x25519.X25519`, `kdf.Kdf`,
  `aead.Aead`; wipes on every retired key (`RK`, `CK`, `MK`, `HK`, stashed keys, DH privs).
- `engine/Engine.scala` — `BuddyRuntime` holds a `DoubleRatchet` instead of bare `sendCK/recvCK`;
  `encryptFrame`/`decryptFrame` gain the header section; payload cap 226 → 174.
- `KeySchedule` — keep (`addrKey` branch unchanged); the content-chain seeding is superseded by the
  ratchet bootstrap (§5), so `chain0/messageKey/nextChain` either move under `DoubleRatchet` or stay
  as the labelled-HMAC helpers it calls.
- No new dependency — `@noble/curves` (Stage 1) is the only addition the ratchet needs.
