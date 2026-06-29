# T041c — Collision-free notify bits (design)

Status: **IMPLEMENTED — Option A** (per-round rotated bit + cover-on-ambiguity). The receiver-side
mechanism lives in `Engine.tick` + `NotifyDigest.bit(pairKey, roundId)`; GAP #1 in
`RecurrenceGapsSpec` is flipped to assert non-recurrence, and `AnonymitySpec`'s claim is now
unconditional. Option B (static in-band lease) was rejected (larger change, residual bootstrap leak).
A separate follow-up wires `RoundTransport.signal` so the engine drives notify end-to-end (Open
question 1 below). Closes GAP #1 (`RecurrenceGapsSpec`): two of a
receiver's buddies can hash to the same 512-bit notify bit, so a set bit is ambiguous, the
fairness cursor can mis-target the idle buddy, its `retrieve` misses, its read counter stays
frozen, and the **same read token recurs** — a clustering handle that breaks FR-014 / SC-002.

This doc specifies two mechanisms that both achieve the goal (collision-free, non-recurrent
reads) and asks for a pick before any code lands.

## Goal

Each read token a receiver issues must be **single-use**: a buddy's read token must never be
re-presented to the store. Equivalent property: the receiver issues a buddy's read token only
when that buddy's frame is actually present (a guaranteed hit), so its counter always advances.

## Architectural constraints (from the surface map)

These bound what is buildable:

1. **No online pairing channel.** `Engine.addBuddy`/`confirmBuddy` and `Handshake.init` are
   pure local derivation from the shared secret on each side independently
   (`Handshake.scala:17`, `Engine.scala:166`). There is no message exchange at pairing into
   which a receiver could put "use bit N for me".
2. **Retrieval is notify-gated.** `Engine.tick` reads a buddy's slot only when that buddy's bit
   is set in the fetched digest (`Engine.scala:312`). So the *only* cross-party channel is the
   message frames themselves — and reading those frames already depends on notify working.
3. **The bit is symmetric per pair.** Both sides derive `bit = NotifyDigest.bit(pairKey)`
   (`NotifyDigest.scala:16`). One bit per pair suffices for both directions because the digest
   is keyed by the *receiver's label*, so bit `b` in Alice's digest and bit `b` in Bob's digest
   are independent.
4. **Collision is receiver-local.** Bit uniqueness must hold among *one receiver's* buddy set.
   Only the receiver knows its full buddy set; a sender (one of that receiver's buddies) does
   not, so the sender cannot compute a globally-free bit on its own.
5. **obsd is agnostic.** `oblivious_aggregate` just ORs `bit` into `label`'s digest
   (`notify.rs`); `grpc_notify.rs` opens the sealed `[round][bit][label]` and ORs. **No obsd /
   `notify.proto` change is needed for either option.**
6. **The encrypted frame header is full.** `nonce(12) ‖ AEAD(HK,header)(56) ‖ AEAD(MK,inner)`;
   the 40-byte header plaintext is DH-pubkey(32)+PN(4)+Ns(4) with no spare
   (`DoubleRatchet.scala:31`). The **inner block has ~128 B of padding headroom** (InnerSize
   172) — the only place an in-band control field could ride.
7. **Sizes are fixed by FR-015:** 512-bit (64-byte) digest; `Buddy.MaxBuddies = 512`.
8. **Signaling lives outside the engine today.** `RoundTransport` has `submit`/`fetchDigest`/
   `retrieve` but **no `signal`** method; the sender-side notify emission is done by the
   transport/demo/e2e (`DeppisDemo.scala:133`, `EngineBackendE2ESpec`). Both options touch the
   shared `NotifyDigest.bit` derivation and every signaling site that computes it.

---

## Option A — per-round rotated bit + cover-on-ambiguity  *(recommended)*

**Idea.** Make the bit depend on the public `roundId` as well as the pair key, so a collision is
*transient* (re-randomized every round); and on the receiver, only ever serve a buddy whose set
bit is *unambiguous this round* — which is then a guaranteed hit. No new channel.

### Mechanism

- **Derivation.** `NotifyDigest.bit(pairKey, roundId) = H(pairKey, "notify-bit", roundId) mod
  512`. Both sides already share `pairKey` and the public `roundId`, so no negotiation.
- **Sender (has mail for the receiver in round R).** Seal `[R][bit(pairKey,R)][label]` (the
  send sites already seal per-round tokens; they just compute the bit with `R`).
- **Receiver (`Engine.tick`, round R).** Compute `bit_i = bit(addrKey_i, R)` for each confirmed
  buddy `i`. A buddy is a *candidate* if its bit is set in the digest. Partition candidates by
  bit value:
  - **Unambiguous candidate** — the only confirmed buddy mapping to that set bit this round.
    Because only someone holding `pairKey_i` can seal a valid signal for `bit_i`, a *set*
    `bit_i` with no colliding sibling ⟹ buddy `i` signaled ⟹ buddy `i` has mail ⟹ reading it is
    a **guaranteed hit** ⟹ its counter advances ⟹ its read token never recurs.
  - **Ambiguous candidates** — two+ confirmed buddies share that exact set bit this round. The
    receiver cannot tell which signaled, so it serves **none of them**; they re-signal next
    round, where rotation almost certainly separates them.
  - Serve one unambiguous candidate (existing fairness cursor). If there are none, issue a
    **fresh cover read** (the existing "no buddy signaled" branch). A buddy's read token is thus
    issued **only on a guaranteed hit** — FR-014 restored unconditionally.

### Why both halves are needed

- Rotation alone still allows rare false-positive reads of an idle buddy (≈1/512 per round per
  colliding pair), each re-issuing that buddy's frozen token → residual recurrence. The
  ambiguity rule removes *all* false reads.
- The ambiguity rule alone (static bit) would make a permanently-colliding pair **never
  deliverable** (ambiguous every round → always cover). Rotation makes the collision transient
  so delivery resumes next round. Both together: non-recurrent **and** live.

### Liveness cost

A buddy's frame waits one extra round whenever its bit collides with another *active* buddy's
bit that round (geometric, mean ≈ collision probability; ~1/512 per concurrently-active sibling
for small active sets). Negligible for realistic active sets; graceful degradation as the active
set approaches the 512 cap. No privacy cost — delay, never a leak. (Worth a `log`/comment noting
the bound; no silent cap.)

### Changes

| Area | File | Change |
|---|---|---|
| Derivation | `NotifyDigest.scala` | `bit(pairKey)` → `bit(pairKey, roundId)`; keep `isSet` |
| Receiver | `Engine.scala` (recv path ~312–343) | compute per-round bits; drop colliding candidates; serve only unambiguous; cover otherwise. Update the FR-014 comments (remove "T041c unimplemented") |
| Buddy state | `Buddy.scala` | **none** (no stored lease) |
| Sender sites | `DeppisDemo`, `EngineBackendE2ESpec`, `TwoPartyE2ESpec`, real `GrpcRoundTransport` signaling | compute the bit with `roundId` |
| Tests | `AnonymitySpec`, `RoundTransportSpec`, `JsRoundTransportSpec`, `RecurrenceGapsSpec` | `bitOf`/`signalMail` helpers take `roundId`; **GAP #1 flips** to assert non-recurrence + cover-on-ambiguity; AnonymitySpec precondition becomes "distinct per round" (or drop, now structural) |
| obsd / proto | — | **none** |

### Residual risks

- Slight delivery delay under collision (above) — bounded, no leak.
- A peer that is pending here (the confirm window) or that keeps signaling after removal can also set
  a bit. **Handled:** ambiguity ranges over ALL of the client's relationships (`BuddyBook.relationships`,
  any state), not just confirmed, so such a peer's colliding bit still defers the confirmed buddy to a
  cover read rather than a missed serve. Covered by a `RecurrenceGapsSpec` test (pending-peer collision
  ⇒ no recurrence). [roborev Medium, addressed]

---

## Option B — static in-band pairing lease  *(faithful to the documented mechanism)*

**Idea.** Each side, as a *receiver*, assigns each buddy a unique incoming bit (lowest free in a
local 512-bit lease bitmap) and **announces it in-band** to that buddy; the sender adopts it for
signaling. This is the literal "pairing-time bit-lease."

### Mechanism

- **Lease bitmap.** Each engine keeps a 512-bit `leased` set for *its own* incoming notifications.
  On `confirmBuddy`, assign `myIncomingBit = lowest free index`; store
  `BuddyRelationship.leasedNotifyBit: Option[Int]` and the peer's announced
  `peerIncomingBit: Option[Int]`.
- **Announcement channel.** Carry `myIncomingBit` (2 bytes) in a control field inside the
  **inner block padding** of this side's frames (the only spare space). Needs a small inner-block
  framing change (a control tag + value) parsed before `Frame.unpad`. Cover frames omit it
  (random), so the announcement only rides real frames.
- **Bootstrap (the hard part).** Reading a frame is notify-gated, but the lease is *inside*
  frames — chicken-and-egg. Resolution: bootstrap with the **derived bit** (current behavior) for
  the first exchange so the announcement frame can be delivered, then upgrade to the leased bit
  once each side has received the other's announcement. During bootstrap the derived bit can
  still collide → a **transient residual leak** until the upgrade lands (one or a few rounds).
- **Sender.** Signal `peerIncomingBit` once known, else the derived bootstrap bit.

### Changes

| Area | File | Change |
|---|---|---|
| Buddy state | `Buddy.scala` | add `leasedNotifyBit`, `peerIncomingBit` (Options); lease bitmap in `Engine` |
| Pairing | `Engine.scala` add/confirm | assign lowest-free bit; lifecycle on remove (free the bit) |
| Frame | `DoubleRatchet`/`Frame.scala` | inner-block control tag to carry a 2-byte announcement; parse + strip before message |
| Receiver | `Engine.scala` recv path | interpret via leased bit; handle pre-lease bootstrap fallback |
| Sender sites | as Option A | signal leased-or-bootstrap bit |
| Tests | as Option A **plus** lease-assignment, free-on-remove, bootstrap-then-upgrade, control-field parsing | larger |
| obsd / proto | — | none |

### Residual risks

- **Transient bootstrap leak** (derived bit until the announcement is delivered) — the very thing
  we're fixing, just smaller/temporary. Hard to eliminate given constraint #2.
- **Lease exhaustion / churn:** with the 512 cap and add/remove churn, free-and-reuse must be
  exact or two live buddies collide again. More state, more edges.
- **Frame-format change** touches the wire and the inner-block invariants (padding/unpad), the
  most safety-critical layout in the system; needs its own KAT + the Tamarin/ScalaCheck framing
  models revisited.
- More moving parts → larger review surface; the bootstrap is genuinely subtle.

---

## Comparison

| | A: rotated + ambiguity-cover | B: static in-band lease |
|---|---|---|
| Non-recurrence (FR-014) | **Unconditional** after change | Unconditional **except** bootstrap window |
| New channel / wire change | **None** | Inner-block control field (wire change) |
| Buddy/lease state | None | Lease bitmap + 2 fields + free-on-remove |
| Liveness cost | ~1-round delay under collision | None steady-state; bootstrap rounds |
| Residual leak | None | Transient bootstrap collision |
| Change size / review | Small, mostly receiver-local | Large, touches frame format |
| Formal-model impact | Notify isn't in the `.spthy` ratchet model; ScalaCheck/round tests update | Same + frame-framing model revisited |
| Fidelity to documented T041c | Different mechanism, same guarantee | Faithful |

## Recommendation

**Option A.** It restores FR-014 *unconditionally* with no new wire format, no bootstrap leak,
and a small, mostly receiver-local change; the only cost is a bounded, leak-free delivery delay
under collision. Option B is faithful to the documented static-lease wording but trades a clean
guarantee for a larger change *and* a residual bootstrap leak that constraint #2 makes hard to
remove — i.e. it is both more work and (transiently) less safe. If we pick A, update `tasks.md`
and the threat-model "Known gaps" note to record that T041c's *goal* is met via per-round
rotation + ambiguity-avoidance rather than a static lease, and flip `RecurrenceGapsSpec` GAP #1.

## Test plan (either option)

- **Flip `RecurrenceGapsSpec` GAP #1** to assert the loser's read token does **not** recur
  (A: it's dropped as ambiguous → cover read; B: leased bits never collide post-bootstrap).
- **New:** a multi-buddy collision scenario driven through `Engine.tick` asserting (i) one
  read/round, (ii) every issued *buddy* read token is a hit (no misses), (iii) delivery still
  completes (liveness), (iv) cover reads on ambiguous rounds are fresh tokens.
- **Update** `AnonymitySpec` precondition + `RoundTransportSpec`/`JsRoundTransportSpec` helpers
  to the new `bit(pairKey, roundId)` signature; keep the shape/anonymity assertions.
- **Restore** the unconditional FR-014/SC-002/SC-003 wording in `threat-model.md`, `Engine`
  comments, `RoundTransport` doc, and `tasks.md`, gated on the new tests passing.
- Re-run the obsd e2e (`EngineBackendE2ESpec`) — bit derivation changes, aggregation does not.

## Open questions

1. Wire the sender-side notify **into the engine/transport** (`RoundTransport.signal`) as part of
   this, or keep signaling external (demos/e2e) and only change the derivation? (Recommend: add
   `signal` to the transport seam so the engine drives notify end-to-end and the property is
   tested through one path — modest extra scope, removes the "signaling lives in tests" smell.)
2. For Option A, do we want a `log`/diagnostic counter for collision-deferred deliveries (no
   silent delay)?
