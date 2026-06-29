# Retry-safe addressing — closing GAP #2 + GAP #3

Status: **IMPLEMENTED** (Option A — round-derived addressing + stop-and-wait ARQ). Stage 1 (#61) landed
the ARQ inner-block framing + ack carriage; Stage 2 flipped addressing to round-derived and made the
ARQ load-bearing (retransmit-until-acked, advance-on-ack, ack-only frames, de-dup). `Engine.tick`
writes this round's token and reads the **previous** round's writes (`readRound = roundId - 1`), a
one-round latency needing no write/read barrier. `RecurrenceGapsSpec` now asserts NON-recurrence for
all three concerns. Closes the addressing-layer recurrence residuals:

- **GAP #2 (write-side, `sendCounter`)** — a rejected `submit` doesn't advance `sendCounter`, so the
  retry next round reuses the same outgoing token → FR-014 recurrence + active-vs-idle tell.
- **GAP #3 (read-side, `recvCounter`)** — a falsely-notified read (e.g. a removed peer's bit collides
  with a confirmed idle buddy) misses, doesn't advance `recvCounter`, so the same read token recurs.

## Why it's intrinsic to the current model

Each addressing token is `PRF(addrKey, direction, k)` for a per-pair sequence `k`. The token is
simultaneously three things, and under a transient failure they conflict:

1. an **unlinkable** address (the store can't cluster — needs a fresh-looking token per frame);
2. a **rendezvous** address (sender and receiver must derive the SAME token for frame `k`);
3. a **single-use** credential (must never recur — FR-014).

The counters advance **only on success** to keep (2) — sender's `k` and receiver's `k` stay in
lockstep, and the store is **persistent store-and-forward**: frame `k` waits under token-`k` until the
receiver reads it. That persistence is what makes delivery **reliable** (a missed/deferred read just
waits; nothing is lost). But it is also exactly why a transient failure recurs the token: on a reject
(send) or a false-notify miss (recv), `k` doesn't advance, so token-`k` is presented again.

You cannot get unlinkable + rendezvous + single-use + reliable all at once for free. Something must
give under failure.

## What is and isn't a leak

- The **recurrence** (token presented twice) is the FR-014 metadata leak — a clustering handle for the
  untrusted store.
- A **strand** (a frame the sender considers sent but the receiver never reads) is a **reliability**
  problem, not a privacy leak.

So the privacy goal is to kill recurrence; reliability is a separate axis we can choose how much to pay
for.

## Key enabler: notify is already round-synchronized

The sender signals round `R` (`signal(R, …)`); the receiver fetches round `R`'s digest in round `R`
(`fetchDigest(R, …)`); obsd buckets signals by round. So **the receiver is notified in the same round
the sender wrote.** This is what makes round-derived addressing viable: the receiver reads the round it
is signaled for, so a per-round token rendezvouses without a shared counter.

## Options

### Option A — round-derived addressing + lightweight acks  *(complete fix; recommended if we invest)*

- **Token** = `PRF(addrKey, direction, roundId)` (replaces the counter). Fresh every round ⇒ inherently
  non-recurrent. **Fixes #2 and #3 outright**: a reject just retries next round under a new round token;
  a false-notify miss reads a round token used once and never again.
- **Reject reliability (free):** advance/signal only on successful submit; on reject, hold the frame and
  retry next round under the new round token. No recurrence, no loss. (No ack needed for this case.)
- **Contention reliability (needs acks):** if two real senders collide on the T041c notify bit in the
  same round, the receiver serves one (one read/round); the other sender advanced on its successful
  write, so its round-token frame would **strand** (round-derived has no cross-round persistence).
  Restore reliability with **piggybacked acks**: the receiver echoes the highest in-order content
  sequence it has received (in the inner-frame padding — there is headroom); the sender retransmits the
  unacked head frame each round (under that round's fresh token) until acked, then advances. Reliable +
  non-recurrent.
- Cost: a real (if small) reliable-transport layer — ack field in the frame, retransmit-until-acked,
  in-order/dedup on the receiver. Interacts with the content ratchet's own sequence (Ns) — likely reuse
  it. Multi-PR.

### Option B — round-derived addressing, best-effort  *(fixes the leak; accepts rare strand)*

Same token change as A (kills recurrence #2/#3), advance/signal on success, retry held frame on reject.
**No acks**: under genuine multi-sender bit-collision (~1/512 per round per colliding pair) the loser's
round frame can strand (sender advanced, receiver served the other). Documented as best-effort; the app
layer (or the user) resends. Smaller than A; the residual flips from a *privacy* leak (recurrence) to a
rare *reliability* nuisance. Silent loss is the downside.

### Option C — keep counter-based; treat #2/#3 as documented residuals  *(no code)*

The gaps are transient-failure-induced and narrow (a store that *selectively rejects* writes; a removed
peer that *keeps signaling* and birthday-collides with a confirmed idle buddy), and real metadata
privacy is gated on the attested backend regardless. Keep the `RecurrenceGapsSpec` pins + threat-model
notes; revisit when the backend lands. Smallest, most conservative.

### Why not a counter-based skip-window

A receiver-side skip window (advance past gaps) cannot distinguish an **empty-because-skipped** slot
from an **empty-because-not-yet-arrived** slot, so it either loses not-yet-arrived frames (advance on
miss) or recurs (don't advance) — it doesn't cleanly fix #3, and one-read-per-round (FR-012) limits it
to one probe per round anyway. Round-synchronized notify (above) is the better lever, which is why A/B
are round-derived.

## Recommendation

If we want the residuals *closed*, **Option A** is the correct, complete answer — it kills the
recurrence (privacy) and keeps delivery reliable via minimal piggybacked acks, leveraging the existing
round-synchronized notify and the content ratchet's sequence. It is the largest change (a small
reliable-transport layer) and would land as 2–3 PRs (token change + ack/retransmit + tests, with the
Tamarin/ScalaCheck and T041c interactions re-checked).

If the appetite is smaller, **Option B** still closes the *privacy* leak (the only part that's a leak)
and accepts a rare, documented reliability strand; **Option C** defers entirely behind the existing
honest pins.

## Chosen: Option A — implementation plan (stop-and-wait ARQ + round-derived tokens)

**Refinement (severity of the strand).** Round-derived tokens drop the persistent-store reliability the
current counter scheme relies on for *concurrency*, not just for transient failures: with one read per
round, whenever a receiver has ≥2 buddies sending the same round it serves one and the rest strand. So
the ack/retransmit layer is REQUIRED for correctness, not optional — round-derived addressing must not
land without it.

**ARQ design (stop-and-wait, per pair):**
- **Ack field.** Carve a fixed 8-byte ack from the ratchet inner block: inner = `[ackSeq(8)][message]`
  (message padding shrinks by 8). `ackSeq` = the highest in-order content sequence (ratchet `Ns`) this
  side has received from the peer. Carried on EVERY frame (real, reply, ack-only, and decoy/cover for
  uniformity — a cover frame carries a current ack too).
- **Sender (stop-and-wait):** retransmit the head message each round (peek the ratchet at its current
  `Ns`, fresh round token + fresh nonce) until the peer's `ackSeq ≥ headNs`; then `commitSend` (advance
  `Ns`) and move to the next queued message. One message in flight per pair.
- **Receiver (dedup + ack):** decrypt the header (HK, not consumed) → `Ns`. If the body decrypts
  (message key still available) → deliver, `highRecv = max(highRecv, Ns)`. If `Ns ≤ highRecv` (a
  retransmit whose key was already consumed) → don't re-deliver, but it confirms receipt. Always set
  outgoing `ackSeq = highRecv`.
- **Ack delivery:** acks reach the sender only via addressed frames, so the receiver must sometimes send
  an ack-only frame to the sender (a real frame with an empty message + the ack). Send-path priority per
  round: a queued real message (carries its ack) > an owed ack (ack-only frame to that peer) > cover.
  Acks thus share the one-write-per-round budget — inherent to a one-op-per-round private channel; not a
  leak (the store sees one uniform sealed write + one notify, as today).

**Staging (each stage keeps `main` correct and is independently reviewable):**
1. **Stage 1 — ARQ infra on the CURRENT counter-based addressing.** Add the ack field, retransmit-
   until-acked, receiver dedup/ack, and ack-only frames. On counter-based this is reliability-neutral
   (the store already persists), so no regression — it just establishes and tests the ARQ machinery
   (advance-on-ack instead of advance-on-submit). Frame-format change lands here.
2. **Stage 2 — flip addressing to round-derived** (`dirToken(addrKey, dir, roundId)`), removing the
   addressing counters. Now retransmit-until-acked is load-bearing and prevents the strand; GAP #2/#3
   recurrence is gone. Flip `RecurrenceGapsSpec` #2/#3 to assert non-recurrence.

## Cross-cutting (any option that changes the token)

- Re-verify the FR-012 store-write uniformity (round-derived real tokens must stay
  byte-indistinguishable from cover tokens — both are 32-byte PRF outputs, so fine).
- Re-check T041c: round-derived addressing changes the collision-deferral story (deferral no longer
  "waits under the persistent counter token"); this is the source of the strand in A/B.
- Update `RecurrenceGapsSpec` (#2/#3 flip to assert non-recurrence), `threat-model.md`, and this doc.
