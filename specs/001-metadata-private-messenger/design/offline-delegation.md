# Offline delegation to the service provider — T037 / T038 (US4, FR-007/FR-008)

Status: **PROPOSED.** Nothing here is implemented. This document picks the mechanism for US4
("send to and catch up while offline") before any code is written, because the obvious
implementation leaks exactly what the task forbids ("no real-vs-idle leak on gaps").

Revision 2 replaces the first draft's "hand over a bundle when you go offline" with an
always-on provider front and a standing bundle, after design review (roborev job 2345) showed
that the first draft didn't cover abrupt disconnects and leaked presence to the backend through
connection switching.

## 1. What already works, and the one case that doesn't

Messaging today is round-based stop-and-wait ARQ over round-derived tokens
(`retry-safe-addressing.md`). Each round a device makes exactly one store write, one notify
signal, one digest fetch (for the previous round) and one store read. A sender **retransmits its
head message every round, under that round's fresh token, until the peer acks it**. The wire is
cached, so a retransmit does not advance the ratchet and an absent peer stays inside `MaxSkip`.

That gives most of US4 for free:

| Case | Today |
|---|---|
| B offline, A stays online | **Works.** A retransmits every round; when B returns it reads the current slot, acks, and the queue drains in order. `RoundTransportSpec:469` covers 1500 offline rounds. |
| B offline with several messages queued from A | **Works**, in order, one message per round trip (stop-and-wait). |
| A sends, then **A goes offline before B returns** | **Fails.** A's retransmits stop when A stops ticking. The frame A wrote in round r sits under round r's token, but B, when it returns in round R > r + 1, only reads round `R − 1`. Nothing delivers it until A comes back. |
| A device is offline at all | **Leaks presence.** An offline device makes no per-round operations, so the backend sees online vs offline directly. |

The receiver doesn't need history on return: as long as the sender is still retransmitting,
normal operation *is* the catch-up. The gap is that **the sender's retransmissions must outlive
the sender's device**, and that an absent device must look the same as a present one.

On mobile, "offline" usually means the app was killed, the OS suspended it, the battery died or
the network dropped. None of these gives the device a chance to announce anything, so the
mechanism cannot depend on the device saying "I'm leaving".

`device.Device` (T039) computes a missed-round range on reconnect. Under this design the engine
does not replay that range; `Device` remains the presence state machine.

## 2. Options

### Option 1 — replay missed rounds from the store on return (rejected)

Keep frames in the store for the retention window; on reconnect, read every missed round's slot
for every buddy.

- **Leaks the gap length.** The returning device issues a burst of reads proportional to how
  long it was away, which T039's text rules out and which breaks one-read-per-round (FR-012).
- **Cost.** Up to 512 buddies × missed rounds of reads, most of them misses.
- **Doesn't fix presence.** The absence is still visible as silence.

### Option 2 — hand the provider a bundle when going offline (rejected, revision 1)

The first draft. It fails on both counts above: an abrupt disconnect uploads nothing, and when
traffic moves from the device's connection to the provider's and back, the backend sees the
switch.

### Option 3 — the provider fronts every round; a standing bundle covers absences (recommended)

This is the Groove model `research.md` D10 already chose for the provider.

- **All of a device's backend traffic goes through its provider, always.** The backend (store
  and PING) only ever talks to providers, never to devices. Whether a given round's operations
  came from the live device or from a precomputed slot is invisible to the backend.
- **The device keeps a standing bundle at the provider.** It covers the next H rounds and is
  refreshed on a fixed cadence while the device is online. The provider holds it but only uses a
  slot when the device's live operations for that round don't arrive in time.
- **Per round, the provider runs exactly one operation set for the device:** the live one if it
  arrived before the cutoff, otherwise the bundle slot.

An abrupt disconnect is then just a run of missed cutoffs. Nothing has to be announced, and the
backend sees the same shape throughout.

## 3. Rounds at the provider

### 3.1 Operation set

Live operations and bundle slots have the **same format**, so the provider cannot tell them
apart by content:

| Field | Size | Content |
|---|---|---|
| `writeToken` | 32 B | `dirToken(addrKey, self, peer, r)` for the buddy whose head goes out in round `r`, else a fresh cover token from `coverKey` |
| `frame` | 256 B | that head's wire **re-sealed under a fresh nonce** (§4.1), an ack-only frame (§3.4), or a cover frame |
| `sealedSignal` | fixed | the round-`r` notify signal — real peer `(label, bit_r)` or the decoy to the void label — **sealed to the PING enclave** (§4.2) |
| `readToken` | 32 B | the read for round `r − 1`: a buddy's `dirToken` (live only, notify-guided) or a fresh cover-read token |

Each round `r`, the provider executes the chosen set:

1. `submit(writeToken, frame)` to the store.
2. `signal(r, sealedSignal)` to PING.
3. `fetchDigest(r − 1, clientLabel)`. This is the previous round, exactly as `Engine.tick` reads
   `readRound = roundId − 1`; round `r`'s digest is still being written during round `r`. The
   result is **sealed to the device** (§4.3).
4. `retrieve(readToken)`.
5. Return to the device a **receipt** for round `r`: which source ran (live or slot), the sealed
   digest, and the retrieved frame if any. If the device is away, the provider keeps receipts for
   the rounds it ran from slots, at most H of them, and deletes them on delivery.

Because the provider is the only party that fetches digests, each `(round, label)` digest is
fetched exactly once, including across absences and returns.

### 3.2 Arbitration and the cutoff

The provider accepts the device's live set for round `r` until a **cutoff** inside the round
(proposed: 10 s into the 15 s round, leaving time to execute). A live set that arrives later is
dropped, never run, and the slot runs instead. The provider never runs both for the same round, so
the device makes exactly one write per round and no token is presented twice.

From the device's side, every round ends with a receipt that says what actually ran:

- **Live ran.** The device applies the read result and digest as `Engine.tick` does today.
- **Slot ran** (the device was away, or late). The device treats its own live set for that round
  as never sent. Nothing in it can recur: a dropped write token was round-bound to `r` and is
  never used again; cover counters advance whether or not the value was used (§3.3). An
  unacknowledged head is still cached and simply goes out again next round.

When the device reconnects, it collects the receipts for the rounds the provider ran on its
behalf and resumes at `max(lastExecuted + 1, currentRound)`. If the provider itself was down, the
device does not tick past rounds; those rounds were silent for every user of that provider (§6).

### 3.3 The standing bundle

- **Contents.** One slot (§3.1) for each round in `[s, s + H)`, where `s` is the round after the
  upload. Slots retransmit whatever heads are open at build time (re-sealed, §4.1), rotated across
  buddies as `Engine.tick` rotates senders; the remaining slots are covers. Slot read tokens are
  always cover reads, because nothing guides a read while the device is away and nothing needs
  receiving until the device can decrypt it.
- **Fixed size.** H is a network-wide constant. The bundle is the same size whether the outbox is
  empty or full.
- **Fixed cadence.** The device uploads a fresh bundle every F rounds while it is online (proposed
  F = 240 rounds, one hour), whether or not anything changed. A refresh triggered by the outbox
  changing would tell the provider when real messages are queued. The upload replaces the old
  bundle atomically.
- **Counters.** Building a bundle advances `coverCounter` and `coverReadCounter` past every value
  in it, used or not, so a cover token can never recur (FR-014).
- **Size.** About 400 B a slot. At the 15 s round interval (`schedule.Latency`), H = 5,760 (one
  day) is about 2.3 MB per refresh. See open question 2.

A bundle can be up to F rounds stale when it starts running: a head acked in that window is still
retransmitted (the peer can't decrypt the copies and re-acks; wasteful but harmless), and a message
queued after the last refresh isn't in it. The device can reduce staleness by refreshing more
often, but only on the fixed cadence.

### 3.4 What building a bundle may do to engine state

Building a bundle must not step the ratchet more than a normal tick would. The rule:

- **A buddy with queued content but no open head:** the builder opens the head **exactly as
  `Engine.tick` would** — consults `ChunkScheduler`, advances `nextSendSeq`, encrypts once. That is
  one ratchet step, the same step the next live tick would have taken. Without it, the message
  typed just before an abrupt disconnect (the very case in §1, row 3) would not be in the bundle.
- **A buddy we owe an ack:** the builder encrypts **one** ack-only frame (one ratchet step) and
  re-seals it into the slots that would otherwise be covers for that buddy's rotation share. The
  peer decrypts the first copy and stops retransmitting its current head; later copies fail to
  decrypt and are ignored. The peer's *next* message then waits for the device's return (§6).
- **Nothing else.** Re-sealing (§4.1) does not touch chain state. `sendCursor` and the rekey state
  are left as they were. Bundle building never starts a rekey attempt (§4.4).

The invariant the tests check: building a bundle opens at most one head and makes at most one
ack-only frame per buddy, and after that no ratchet step happens until the device itself ticks
again.

## 4. What has to change so the provider and backend learn nothing

### 4.1 Re-seal retransmits under a fresh nonce

`Engine.tick` caches `headWire` and resubmits the **same 256 bytes** every round. Through a
provider — and in a bundle, where real slots would repeat while covers are fresh — that tells the
provider which slots belong to one pending message.

**Change:** a `DoubleRatchet` operation that re-seals an already-built message under a **fresh
nonce** with the same header key, message key and plaintexts, without advancing any chain. The
frame layout shares one random 12-byte nonce between both AEADs (`DoubleRatchet.scala:32-36`), so
this is "seal again with a new random nonce" using the existing `Aead.seal`. Under random 96-bit
nonces, H ≤ 10⁴ copies per key is far inside the birthday bound. The receiver is unaffected: the
first copy decrypts and consumes the message key; later copies fail to decrypt, as cached
retransmits do today. It applies to **all** retransmits, live and bundled, so the format never
differs between them.

Control heads re-seal safely too. `Engine.tick` encrypts an `EPOCH_COMMIT` exactly once because its
anchor is valid only at the chain position it was built at (`Engine.scala:1468-1471`). A re-seal
keeps the same message key and so the same position; only the nonce changes.

**Key retention.** Re-sealing needs the head's message key (MK) and header key (HK) after
`encrypt` returns, which departs from the rule that every retired key is wiped
(`DoubleRatchet.scala:25-26`). The rule becomes:

- Each `BuddyRuntime` holds at most one retained `(MK, HK)` pair: its current head's.
- It is wiped when the head is dropped on ack, when `abortRekey` drops a control head, when the
  buddy is removed, and when the engine is closed. Nothing else holds it.
- Property test: once a head drains (or is aborted, or its buddy removed), its MK is unrecoverable
  from engine state.

**Forward-secrecy cost.** A device compromise while a head is unacknowledged exposes that head's
MK. The plaintext of that same head is still in the outbox until it is acked, so the compromise
already reveals the message; retaining MK adds nothing there. Retaining HK lets a compromise
decrypt the headers of this device's own frames on the current sending chain, which links them.
That goes in the threat model as a residual.

### 4.2 Seal notify signals to the PING enclave, on the device, every round

On the real path the device sends `(round, bit, label)` to the attested enclave front, which seals
it; in dev, `GrpcRoundTransport` seals with the dev notify key. A provider relaying that would see
the **peer's notify label**, which is a buddy relationship (FR-010/SC-008).

**Change:** the device encrypts every signal — live and bundled, real and decoy — to the PING
enclave's **attested public key**, the key `AttestedProvisioning` releases only on a passing
appraisal. PING opens it inside the enclave and ORs the bit as today. Labels are already
fixed-width (`NotifyDigest.labelTag`), so real and decoy ciphertexts have the same length.

**Key lifetime.** A bundle seals signals up to H rounds ahead, so:

- The enclave's sealing key has an epoch of at least H + F rounds, and the enclave keeps retired
  keys for H rounds after rotating.
- A signal sealed to a key the enclave no longer holds is dropped **silently**: PING's `signal`
  already responds uniformly, and it must not return a distinguishable error.
- The device seals a new bundle only with a key whose appraisal is at most F rounds old. A key
  appraised once and then trusted for a day would weaken the attestation rule.

An alternative with the same effect is the mechanism FR-003 describes and
`DevNotificationServer.issueToken` already implements: the receiver issues sealed, round-bound
tokens to the sender. Since T041c rotates the bit every round, a receiver would have to pre-issue
H rounds × 512 buddies of them, so sender-side sealing is the recommendation.

**Construction.** Constitution I forbids composing this ourselves from X25519 + AEAD + KDF.
`protocol-core` has neither dependency today: Bouncy Castle is a main dependency only of
`transport` (and test-only in `crypto`), and `crypto/Sodium.scala` does not bind
`crypto_box_seal`. Candidates, decided by what exists on both platforms (open question 3):

- **HPKE (RFC 9180)** — Bouncy Castle's `HPKE` on the JVM (moving `bcprov` into `crypto`'s main
  scope) and `@hpke/core` for Scala.js, cross-checked with RFC 9180 test vectors.
- **libsodium sealed box** — a new `crypto_box_seal` binding in `crypto/Sodium.scala` (FFM) and
  `libsodium-wrappers` for Scala.js, cross-checked against libsodium's own vectors.

Either way, the construction gets library known-answer tests on both platforms before any code
depends on it.

### 4.3 Seal digests to the device, every round

`fetchDigest(roundId, clientLabel)` returns the receiver's bitmap in the clear. A provider fetching
it would learn when mail arrives and from how many buddies.

**Change:** PING returns every digest sealed to a **digest key** the device registers.

- **Registration.** The device registers its digest public key with the PING enclave over the
  attested channel, bound to its `clientLabel`. Only the device holding the label's registration
  can replace it.
- **Rotation.** The device rotates the digest key on the same cadence as the enclave sealing key;
  the enclave keeps the previous one until the device's bundle that might fetch with it has
  expired.
- The provider gets an opaque blob of fixed size every round and returns it in the receipt. While
  the device is away the provider simply stores the receipts; the device can discard old digests on
  return, since senders are still retransmitting (§1).

### 4.4 Rekeys and absences

`PqRekey.TimeoutRounds` is 2,000 rounds (`Engine.scala:88`), less than H. Counted in wall-clock
rounds, a day's absence would time out any rekey in flight: a pre-commit attempt would be aborted
after the peer may already have processed it, and a committed one would be stranded, so the pair
never rekeys again.

**Change:** the rekey timeout counts only rounds in which **the device itself ran** (live receipts),
not rounds the provider covered from a bundle. An absence then pauses an attempt instead of timing
it out. In detail:

- A control head open at bundle-build time is retransmitted from the bundle like any head
  (re-sealed, §4.1), so the rekey keeps progressing on the peer's side.
- Bundle building never starts a new attempt; `maybeStartRekey` runs only in live ticks.
- Content queued behind a control head waits, as it does today when a control head holds the slot.

Test: start a rekey, drop the device abruptly, keep it away for more than `TimeoutRounds` rounds,
bring it back; the queued content is delivered and the pair completes (or can later start) a rekey.

## 5. Bounded retention at the provider

The provider holds, per device: one standing bundle (H slots), the receipts for rounds it ran
while the device was away (at most H), and nothing else. A slot is deleted when its round passes,
whether or not it ran; a receipt is deleted when delivered. Nothing older than H rounds survives.
No stored value identifies a sender: tokens are PRF outputs, frames, signals and digests are
ciphertext (FR-008, "bounded retention not leaking sender").

Slots are round-bound, so a misbehaving provider can only delay or drop traffic, which it could do
anyway by going down. A slot replayed in another round is a miss (round-derived token) or rejected
(PING checks the sealed round). A slot replayed in the same round reuses a single-use write token,
which the store rejects.

## 6. What each party learns

| | Learns | Does not learn |
|---|---|---|
| **Provider** | when the device is present (live sets arriving, inherent to having a helper); the user's `clientLabel` | which buddies the user has; whether any slot or live set carries a real message; whether the user has mail waiting; any content or ratchet state |
| **Backend** (store, PING) | that a provider submitted one operation set per user per round | whether the device behind it is online, offline or late; anything new about network identity — devices no longer connect to it at all |

The backend claim holds only because all traffic goes through the provider and the sealed formats
(§4.1–§4.3) are used on **every** round. A deployment where online devices talk to the backend
directly would leak presence through the connection switch and must not claim this property.

**Residuals for the threat model:**

- **Presence to the provider** — inherent; matches FR-010's model. Must not be combined with
  anything that links presence to buddies.
- **Provider downtime** — every user of that provider goes silent at once. That reveals provider
  availability, not any one user's presence.
- **One message per buddy while away.** Stop-and-wait advances only on an ack the provider can't
  read, so a bundle retransmits each buddy's current head only. Messages queued behind it go out
  on return. See open question 1.
- **One ack per peer while away.** The bundle's ack-only frame stops a peer's current head; the
  peer's next message waits until the device returns.
- **Staleness.** A bundle is up to F rounds old: it can retransmit an already-acked head
  (harmless) and won't contain messages queued since the last refresh (they go out on return).
- **Retained HK** (§4.1) — a device compromise links the device's own frames on its current
  sending chain.
- **Provider–backend collusion** — the provider knows which operation sets it submitted for which
  of its users. The backend alone does not.

## 7. Phased plan

Each phase is reviewable on its own and keeps the labeling rule: provider routing runs labeled
`DEV, NO METADATA PRIVACY` until Phase 4 has landed.

1. **T037 — failing tests first**, in `server/provider/src/test/scala/`:
   - A queues a message to B while B is offline; A **disconnects abruptly** (no announcement); B
     returns; the message arrives, then a second queued message arrives in order after A returns.
   - Across disconnect → reconnect, every `(round, label)` digest is fetched exactly once and the
     device makes exactly one write per round.
   - The rekey-across-absence test from §4.4.
2. **Engine side (protocol-core).**
   - `DoubleRatchet` re-seal with retained `(MK, HK)` and its wipe points (§4.1).
   - The bundle builder under the §3.4 rules, and `Engine.applyReceipt` (live or slot ran).
   - The live-tick rekey timeout (§4.4).
   - Property tests: slots pairwise byte-distinct and the same shape with an empty or a full
     outbox; no token recurs across build → absence → resume; the §3.4 ratchet-step bound; MK
     unrecoverable after the head drains.
3. **T038 — `server/provider/`, and routing through it.**
   - An untrusted `ProviderBuffer`: atomic bundle replace, the per-round arbiter with the cutoff,
     receipts, and the §5 retention bounds. In-memory first, behind an interface that Postgres or
     an embedded KV can implement later (`plan.md`). The storage key is the **user**, not the
     device (open question 4).
   - A `ProviderRoundTransport` so online clients reach the backend only through their provider,
     replacing direct use of `GrpcRoundTransport` by devices. Makes T037 pass.
4. **Sealing (privacy-bearing).**
   - Choose and bind the sealing construction, with library known-answer tests on JVM and Scala.js.
   - Signals sealed to the PING enclave key every round, with the key epoch and silent-drop rules
     (§4.2).
   - Digest-key registration, rotation and sealed digests (§4.3), in both the Scala dev PING and
     the Rust sidecar.
   - Only after this phase can provider routing be part of a `METADATA PRIVATE` build.
5. **Docs.** Threat-model entries for the §6 residuals and a README note on what the provider can
   and cannot see (T062).

## 8. Open questions

1. **More than one message per buddy while away.** (a) Accept it — the queue drains on return.
   (b) Let a bundle cycle the first k queued messages; the receiver de-duplicates by sequence and
   accepts only the next in order, so this delivers in order at about k rounds per message, but it
   needs k retained key pairs per buddy and ARQ bookkeeping for more than one frame in flight.
   Recommendation: ship (a).
2. **H and F.** One day (H = 5,760) refreshed hourly (F = 240) gives about 55 MB a day of uploads
   per device, which is too much for mobile. Options: a smaller H (say 6 h), a delta upload that
   only replaces slots that changed (it must not reveal *which* changed, so the delta has to be a
   fixed-size rewrite of the next F slots), or both. H must be one network-wide constant either way;
   a per-device H is a fingerprint.
3. **Sealing construction.** HPKE (Bouncy Castle + `@hpke/core`) or libsodium sealed box
   (new FFM binding + `libsodium-wrappers`). Decide by the Scala.js side: whichever has a vetted,
   maintained implementation there.
4. **Multi-device (US5, T043–T045).** With all traffic through the provider, two devices of one
   user can share one per-user schedule at the provider: one operation set per user per round, fed
   by whichever device is live. That is likely the FR-011 non-coordination mechanism, which is why
   Phase 3 keys storage by user. Out of scope here.
