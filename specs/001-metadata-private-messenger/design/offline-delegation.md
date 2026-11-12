# Offline delegation to the service provider — T037 / T038 (US4, FR-007/FR-008)

Status: **PROPOSED.** Nothing here is implemented. This document picks the mechanism for US4
("send to and catch up while offline") before any code is written, because the obvious
implementation leaks exactly what the task forbids ("no real-vs-idle leak on gaps").

Revision 2 replaced the first draft's "hand over a bundle when you go offline" with an
always-on provider front and a standing bundle, after design review (roborev job 2345) showed
that the first draft didn't cover abrupt disconnects and leaked presence to the backend through
connection switching. Revision 3 (roborev job 2346) splits the provider round in two so live
reads stay notify-guided (§3.1), and adds the rule that a repeated frame must never make the peer
step its ratchet (§4.5). Without that rule a long absence pushes the pair past `MaxSkip`.
Revision 4 (roborev job 2366) adds §4.6: store requests are sealed to the store enclave and
store responses to the device. Without that, a provider serving both ends of a conversation links
them, because the sender's write token *is* the receiver's read token one round later. It also
moves attestation and key registration behind the provider (§4.2, §4.3), gates the rekey timeout on
both sides (§4.4), and places the engine tests in protocol-core (§7). Revision 5 (roborev jobs
2367, 2369) makes the client label self-certifying so the provider can't register its own keys
(§4.3), bounds the rekey pause so a silent peer still times out (§4.4), fixes one response key
(§4.6), and recomputes sizes for the sealed formats (§3.3). Revision 6 (roborev job 2370) delivers the signed registration to both enclaves, makes failure responses well-formed seals under a throwaway key, and requires registration state to survive restarts or the sealing key to rotate (§4.3, §4.6).

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

| Field | Sealed to | Holds inside the seal |
|---|---|---|
| `sealedWrite` | store enclave (§4.6) | `writeToken` — `dirToken(addrKey, self, peer, r)` for the buddy whose head goes out in round `r`, else a fresh cover token from `coverKey` — and the 256-byte `frame`: that head's wire **re-sealed under a fresh nonce** (§4.1), an ack-only frame (§3.4), or a cover frame |
| `sealedSignal` | PING enclave (§4.2) | the round-`r` notify signal — real peer `(round, bit_r, labelTag)` or the decoy to the void label |
| `sealedRead` | store enclave (§4.6) | `readToken` — a buddy's `dirToken(…, r − 1)` chosen from digest(r − 1) (live only), or a fresh cover-read token — and the device's `labelTag`, which names the registered key the response is sealed to |

Every field has a fixed size (sizes in §3.3). The plaintext tokens and frame exist only on the
device and inside the enclaves; the provider never sees them. Dev builds before Phase 4 carry them
in the clear, which is one reason provider routing stays labeled `DEV, NO METADATA PRIVACY` until
then (§6).

`Engine.tick` fetches the digest **before** it picks its read, so the read is notify-guided
(FR-004). The provider round therefore has two phases:

**Phase A — round start.**

1. `fetchDigest(r − 1, clientLabel)`. This is the previous round, exactly as `Engine.tick` reads
   `readRound = roundId − 1`; round `r − 1`'s signals are complete by then. The result is
   **sealed to the device** (§4.3).
2. Push the sealed digest to the device if it is connected; otherwise keep it with the round's
   receipt.

**Phase B — at the cutoff**, run the chosen set (live if it arrived, else the slot):

3. `submit(sealedWrite)` to the store — `(writeToken, frame)` sealed to the store enclave (§4.6).
4. `signal(r, sealedSignal)` to PING.
5. `retrieve(sealedRead)` — `readToken` sealed to the store enclave. The store answers with a
   fixed-size response **sealed to the device** whether or not a frame was found (§4.6).
6. Return a **receipt** for round `r`: which source ran (live or slot) and the sealed read
   response. While the device is away, the provider keeps receipts (with their phase-A digests)
   for the rounds it ran from slots, at most H of them, and deletes them on delivery.

So the provider handles only ciphertext: it never sees a token, a frame, or whether a read hit.

The device builds its live set for round `r` only after it has the phase-A digest: it opens the
digest, picks the read exactly as `Engine.tick` does today, and submits before the cutoff. This
splits today's `Engine.tick` into `beginRound(sealedDigest) → liveSet` and `applyReceipt(receipt)`
(Phase 2), with the same `readRound = roundId − 1` rule and the same one-round latency. A device
that receives the digest too late to make the cutoff simply misses the round, and the slot runs.

Because the provider is the only party that fetches digests, and fetches one in phase A of every
round whatever happens in phase B, each `(round, label)` digest is fetched exactly once, including
across absences and returns.

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
- **Size.** For a classical seal (X25519-based HPKE or sealed box: 32 B encapsulation + 16 B tag =
  48 B overhead per sealed field):

  | Field | Inside the seal | Sealed size |
  |---|---|---|
  | `sealedWrite` | token 32 + frame 256 | 336 B |
  | `sealedSignal` | round 8 + bit 2 + label tag 32 | 90 B |
  | `sealedRead` | token 32 + label tag 32 | 112 B |
  | **per slot** | | **≈ 540 B** |

  Each cadence point (every F rounds) adds, **for each of the two enclaves** (PING and the
  store), an attestation fetch (≈ 80 B) and a registration request (≈ 160 B, §4.3): about 480 B per
  cadence point, H / F ≈ 24 of them per bundle, about 12 KB. At the 15 s round interval
  (`schedule.Latency`), H = 5,760 (one day) is therefore about **3.1 MB per refresh**.

  If the seals must be post-quantum like the rest of the stack (hybrid X25519 + ML-KEM-768
  HPKE, about 1,120 B of encapsulation per field), each slot grows to about 3.9 KB and a one-day
  bundle to about 22 MB. See open question 2.

A bundle can be up to F rounds stale when it starts running: a head acked in that window is still
retransmitted, and a message queued after the last refresh isn't in it. The peer can't decrypt
those copies. That is only harmless because of §4.5: under today's receive path every undecryptable
copy triggers a freshly encrypted re-ack, one chain step each. The device can reduce staleness by refreshing more
often, but only on the fixed cadence.

### 3.4 What building a bundle may do to engine state

Building a bundle must not step the ratchet more than a normal tick would. The rule:

- **A buddy with queued content but no open head:** the builder opens the head **exactly as
  `Engine.tick` would** — consults `ChunkScheduler`, advances `nextSendSeq`, encrypts once. That is
  one ratchet step, the same step the next live tick would have taken. Without it, the message
  typed just before an abrupt disconnect (the very case in §1, row 3) would not be in the bundle.
- **A buddy we owe an ack:** the builder uses that pair's **cached ack-only wire** for the current
  `highRecv` (§4.5), encrypting it only if none exists yet for that value. It re-seals copies into
  the slots that would otherwise be covers for that buddy's rotation share. The live path uses the
  same cached wire, so a refresh never creates an ack-only frame the live path would not also have
  sent. The peer decrypts the first copy and stops retransmitting its current head; later copies
  are recognised as duplicates and change nothing (§4.5). The peer's *next* message then waits for
  the device's return (§6).
- **Nothing else.** Re-sealing (§4.1) does not touch chain state. `sendCursor` and the rekey state
  are left as they were. Bundle building never starts a rekey attempt (§4.4).

The invariant the tests check: building a bundle opens at most one head per buddy and creates at
most one ack-only frame per `(buddy, highRecv)` value **across all refreshes**. After that, no
ratchet step happens until the device itself ticks again.

## 4. What has to change so the provider and backend learn nothing

### 4.1 Re-seal retransmits under a fresh nonce

`Engine.tick` caches `headWire` and resubmits the **same 256 bytes** every round. Through a
provider — and in a bundle, where real slots would repeat while covers are fresh — that tells the
provider which slots belong to one pending message.

**Change:** a `DoubleRatchet` operation that re-seals an already-built message under a **fresh
nonce** with the same header key, message key and plaintexts, without advancing any chain. The
frame layout shares one random 12-byte nonce between both AEADs (`DoubleRatchet.scala:32-36`), so
this is "seal again with a new random nonce" using the existing `Aead.seal`. Under random 96-bit
nonces, H ≤ 10⁴ copies per key is far inside the birthday bound. The receiver's decrypt is unchanged: the
first copy decrypts and consumes the message key; later copies fail to decrypt, as cached
retransmits do today; §4.5 says what the receiver must do with them. It applies to **all** retransmits, live and bundled, so the format never
differs between them.

Control heads re-seal safely too. `Engine.tick` encrypts an `EPOCH_COMMIT` exactly once because its
anchor is valid only at the chain position it was built at (`Engine.scala:1468-1471`). A re-seal
keeps the same message key and so the same position; only the nonce changes.

**Key retention.** Re-sealing needs a frame's message key (MK) and header key (HK) after
`encrypt` returns, which departs from the rule that every retired key is wiped
(`DoubleRatchet.scala:25-26`). The rule becomes: each `BuddyRuntime` holds **at most two**
retained `(MK, HK)` pairs, and nothing else in the engine holds either.

| Pair | Purpose | Wiped when |
|---|---|---|
| **head** | re-seal the current head (content or control) | the head drops on ack; `abortRekey` drops a control head; buddy removed; engine closed |
| **ack** | re-seal the cached ack-only wire (§4.5) | `highRecv` advances; a content frame carries the ack instead; buddy removed; engine closed |

Property test (Phase 2): after each wipe event in the table, the corresponding MK and HK are
unrecoverable from engine state, and at no point does a `BuddyRuntime` hold more than these two
pairs.

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
- **Attestation goes through the provider too.** The device fetches evidence (with its fresh
  nonce) and appraises it itself, but the request and response travel through the provider, like
  every other backend call. Freshness comes from the nonce, so the relay can't replay old evidence.
  These fetches run on a fixed network-wide cadence, once every F rounds. While the device is away,
  its bundle carries a precomputed, identically shaped fetch for each cadence point in its window.
  The backend therefore sees attestation traffic at the same rate whether the device is present or
  not.

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

**Change:** PING returns every digest sealed to a **device key** the device registers. The same
key seals the store's read responses (§4.6). PING and the store are separate enclaves with separate
attested keys, so the device sends **the same signed registration to both**, each sealed to that
enclave's key, and each enclave verifies it independently with the rules below. There is one
registration *format* and one device key, delivered twice. No enclave-to-enclave channel is needed,
and neither enclave trusts the other's view of the key.

**Who may register a key for a label.** Sealing a registration to the enclave keeps it secret but
proves nothing about who sent it, and the label is not a secret: the provider knows it (§6) and so
does every buddy that signals to it. Whoever registers a key for the label receives that label's
digests and read responses, so an unauthenticated registration would hand the provider exactly
what this section hides. The fix is to make the label **self-certifying**:

- **Identity key.** At enrolment the device generates a long-lived identity signing key with a
  vetted library (Constitution I). Ed25519 is available on both platforms (libsodium on the JVM,
  `@noble/curves` in Scala.js); whether it must be hybrid with ML-DSA-65 (liboqs, already bound;
  `@noble/post-quantum` in JS) follows the project's PQ policy. That is open question 3.
- **Label.** The client's raw label is a hash of the identity public key,
  `clientLabel = H("deppis-label" ‖ identityPub)`, and the wire label is `labelTag(clientLabel)` as
  today. Buddies still receive the label at pairing exactly as now; it just stops being arbitrary.
- **Registration.** Inside the seal, a registration carries `identityPub`, the new device public
  key, a strictly increasing counter, and a signature by the identity key over
  `(labelTag, devicePub, counter)`. The enclave accepts it only if
  `labelTag(H("deppis-label" ‖ identityPub))` equals the label being registered, the signature
  verifies, and the counter exceeds the last accepted one. The first registration is protected the
  same way, so there is no trust-on-first-use window and no direct enrolment channel to the
  backend: no one but the identity key's holder can produce a registration the enclave accepts.
- **Replay and rollback.** The counter stops the provider replaying an old registration to roll the
  key back to one it might later learn. That only works while the enclave remembers the counter,
  and the provider can keep an old sealed registration for as long as the enclave's sealing key can
  still open it (an epoch of at least H + F rounds, plus H for retired keys, §4.2). So each enclave
  must do one of two things:
  - keep its per-label `(counter, device key)` state **durably and rollback-protected** across
    restarts (sealed storage anchored to a monotonic counter the host can't reset), or
  - if it restarts without that state, **generate a fresh sealing key and never open anything
    sealed to an older one**, so no registration from before the restart can be replayed.

  The second option is the fallback, and it costs availability. Bundled requests sealed to the old
  key fail for the rest of their bundle: signals are dropped silently, writes are lost (the sender
  retransmits once it is live again), reads come back as misses. The label has no registered key
  until the device's next cadence registration. That is listed as a residual in §6.
- **Dummies.** A bundle-carried dummy registration is marked as a dummy **inside** the seal; the
  enclave opens it and applies nothing. A dummy can never replace a key, and outside the seal it
  looks like a real registration.
- **Uniform responses.** A registration that fails any check gets a response identical to a
  successful one.

**Cadence and rotation:**

- **Cadence.** Registration and rotation requests run on the same fixed cadence as attestation
  fetches (§4.2), one to each enclave, and a bundle carries an identically shaped dummy for each
  enclave at each cadence point. The backend never sees a device-timed request.
- **Rotation.** PING seals each round's digest (and the store each read response) to whichever key
  is registered at that moment; neither keeps anything old. The constraint is on the **device**: it
  keeps each retired private device key for H rounds after rotating, so it can still open receipts
  the provider stored during an absence. A digest or response it can no longer open is discarded.
  Nothing is lost by that: senders are still retransmitting (§1), so the live round after return
  shows the same mail.
- The provider gets an opaque blob of fixed size every round and returns it in the receipt.

Tests (Phase 4), run against **both** PING and the store: a registration or rotation forged by the
provider, or by a buddy who knows the label, is rejected, and its response is indistinguishable
from an accepted one; a replayed older registration is rejected; a dummy registration changes
nothing; after an enclave restart, replaying a registration from before the restart is rejected
(whichever of the two restart rules the enclave uses).

### 4.4 Rekeys and absences

`PqRekey.TimeoutRounds` is 2,000 rounds (`Engine.scala:88`), less than H. Counted in wall-clock
rounds, a day's absence would time out any rekey in flight: a pre-commit attempt would be aborted
after the peer may already have processed it, and a committed one would be stranded, so the pair
never rekeys again.

Both ends are affected. The absent device's clock keeps running in wall-clock rounds, and so
does its **online peer's** (`maybeTimeoutRekey`, `Engine.scala:576`). The bundle can't answer
control frames because it can't read, so the peer sees the attempt stall and times it out after
2,000 rounds as well.

**Change:** on both ends, the timeout clock pauses while the pair looks absent, **for a bounded
time only**. A round counts toward `TimeoutRounds` if this device ran it live (a live receipt, not a
bundle slot) and either

- it has received a decryptable frame from that buddy within the last W rounds (W a small constant
  covering a round trip, say 4), or
- the attempt has already spent its **pause allowance**: P = H + F live rounds without such a
  frame, counted across the attempt.

An absence of up to H rounds on either side (plus up to F rounds of bundle staleness) therefore
pauses the attempt instead of timing it out. A peer that stays silent for longer — one that aborted
its own side, or is gone for good — still times out, at most `TimeoutRounds` + P live rounds after
the attempt started. That bounds how long the initiator's KEM secret stays resident and guarantees
the pair can eventually rekey again. A peer that is live and still sending decryptable frames but
stuck times out after `TimeoutRounds`, as today. Gating on peer frames alone, without the
allowance, would freeze the clock forever against a silent peer: its re-sealed duplicates never
decrypt again (§4.1, §4.5) and an idle peer sends only covers. In detail:

- A control head open at bundle-build time is retransmitted from the bundle like any head
  (re-sealed, §4.1). The peer decrypts the first copy, so the attempt still advances by that step.
- Bundle building never starts a new attempt; `maybeStartRekey` runs only in live ticks.
- Content queued behind a control head waits, as it does today when a control head holds the slot.
- The stranded-attempt diagnostic (`strandedAttemptAgeRounds`) uses the same clock, so an absence
  within the allowance doesn't report a stranding, and a silent peer is still reported stranded
  within the same bound (`Engine.scala:580-586` requires it to stay reportable).

Tests, five variants:

- **Absence (four variants):** the absent device as initiator and as responder, each before and
  after commit. Start a rekey, drop one device abruptly, keep it away for more than
  `TimeoutRounds` rounds but less than H while its peer stays online, bring it back. Neither end
  aborts or strands the attempt, the queued content is delivered, and the pair completes the rekey
  (or can start a new one).
- **Silent peer:** the peer stays online but stops answering the attempt (or aborts its own side).
  A pre-commit attempt on the other end aborts, and a committed one is reported stranded, within
  `TimeoutRounds` + P live rounds; after the abort the pair can start a new attempt and the KEM
  secret is gone.

### 4.5 A repeated frame must never make the peer step its ratchet

Under delegation a peer can receive the same frame (re-sealed) hundreds or thousands of times: a
stale head, or the bundle's ack-only frame. Today's receive path turns each one into a ratchet step
on the **peer's** sending chain. A frame that fails to decrypt sets `ackOwed`
(`Engine.scala:1583`), and the ack-only frame that pays it is a fresh `encrypt`
(`Engine.scala:1493-1501`). An online, idle peer reading one of the device's bundle copies per slot
would therefore step its chain toward the absent device up to H times. `DoubleRatchet.MaxSkip` is
1,000 and a larger jump is rejected as a carrier (`DoubleRatchet.scala:57-60`), so after about a
thousand copies the returning device can no longer decrypt that peer, and nothing resets it. The
same mechanism also breaks today's receive-side assumption that ack-only frames are always
encrypted fresh and so always decode.

**Rule:** no frame that is sent more than once — re-sealed retransmit, bundle slot, re-ack — may
cause the receiver to step its ratchet. Two changes in the engine:

1. **Re-acks re-seal a cached ack-only wire.** Each pair caches its ack-only wire together with the
   `highRecv` it carries and its retained `(MK, HK)` (as for heads, §4.1). While `highRecv` is
   unchanged, a re-ack is a re-seal of that wire under a fresh nonce: **zero chain steps**. A new
   ack-only frame is encrypted only when `highRecv` advances, which is bounded by the content the
   peer actually delivers. The cached keys are wiped when `highRecv` advances, when a content frame
   carries the ack instead, on buddy removal and on close. Bundles reuse the same cache (§3.4).
2. **Duplicate ack-only copies don't owe an ack.** The header still decrypts for a re-sealed
   duplicate (same header key), so the receiver can see its chain position. It records the
   positions of the ack-only frames it has consumed (the last few per pair) and does not set
   `ackOwed` for a duplicate at one of those positions. That stops two peers bouncing re-sealed
   acks at each other indefinitely. Duplicates whose header no longer decrypts (an older chain)
   still set `ackOwed`, but by rule 1 that costs a re-seal, not a step.

   This needs a ratchet API change. `DoubleRatchet.decrypt` deliberately returns a bare `None`
   for every undecryptable frame and never mutates state for one (`DoubleRatchet.scala:316-319`).
   Rule 2 needs a third outcome, "header valid, position already consumed", which carries the
   position. The new result type must keep the no-mutation guarantee for every non-delivering
   outcome, and it must also recognise headers matched through the header keys of stashed
   skipped-key epochs, not only the current and next ones.

Rule 1 alone is what keeps every pair inside `MaxSkip`. Rule 2 removes useless traffic.

Test (Phase 1): A disconnects abruptly while B is online and idle; A stays away for more than
`MaxSkip` of its bundle's slots to B; when A returns, B's later messages decrypt at A, and B's
sending chain advanced by at most one step per content message A actually delivered.

### 4.6 Seal store requests to the store enclave, and responses to the device

Today the store's interface is plain: `submit(token, frame)`, and `retrieve(token)` returns `None`
on a miss and the exact 256 bytes on a hit (`RoundTransport.scala:29`). Relayed by a provider,
that leaks two things:

- **Whether a read hit.** A cover read always misses and a notify-guided read hits whenever mail
  is waiting, so the provider learns when the user receives mail.
- **Who talks to whom, when both ends share a provider** (the normal deployment). Round-derived
  addressing gives the sender's write and the receiver's read the **same token**:
  `dirToken(addrKey, A, B, r)` is written by A in round r and read by B in round r + 1. The frame
  bytes match too. A provider seeing both sides links A and B as buddies — exactly what
  FR-010/SC-008 forbid.

Sealing only the read response would fix the first leak but not the second, because the token
itself matches. So:

**Change:**

- **Requests are sealed to the store enclave.** The device seals `(writeToken, frame)` and
  `readToken` to the store's attested public key, with the same key-lifetime, silent-drop and
  appraisal-age rules as §4.2. The store opens them inside the enclave (or oblivious sidecar),
  where the oblivious-access guarantees already apply. The provider sees fixed-size ciphertext,
  fresh each time.
- **Responses are sealed to the device's registered key.** The sealed read names the device's
  `labelTag`; the store looks up the device key registered **with the store** for that label (§4.3:
  the device sends the store its own copy of the signed registration, verified by the store
  itself, with the same rotation and device-side retention rules) and answers
  **every** read — hit or miss — with a response of the same fixed size, sealed under that key and
  freshly randomized, so it never matches the bytes that were submitted. Per-request response keys
  were considered and rejected: they would need a pre-generated key per bundle slot, and they add
  nothing once registration is authenticated.
- **Uniform failures.** If the enclave can't open a request (retired enclave key, malformed) or no
  key is registered for the label, it has nothing to seal a response to. Random bytes would not do:
  a real X25519-based seal starts with an encoded public key, which always has its top bit clear
  and lies on the curve, and uniform random bytes fail those checks about half the time (ML-KEM
  ciphertexts have structure too). Instead the enclave **generates a throwaway key pair for that
  request and seals a well-formed miss to it**, then discards the private key. The response has
  exactly the distribution of a real sealed miss; the device can't open it and treats it as a miss.
  So a failure and a miss look the same to the provider and to the backend host, and behave the same
  on the device.

With this, nothing the provider handles for A's write in round r matches anything it handles for
B's read in round r + 1. In dev builds the store has no enclave key, so this phase lands behind the
`DEV, NO METADATA PRIVACY` label like the rest of §4.

## 5. Bounded retention at the provider

The provider holds, per device: one standing bundle (H slots), the receipts for rounds it ran
while the device was away (at most H), and nothing else. A slot is deleted when its round passes,
whether or not it ran; a receipt is deleted when delivered. Nothing older than H rounds survives.
No stored value identifies a sender: store requests and signals are sealed to the enclaves, and
read responses and digests are sealed to the device (FR-008, "bounded retention not leaking
sender").

Slots are round-bound, so a misbehaving provider can only delay or drop traffic, which it could do
anyway by going down. A slot replayed in another round is a miss (round-derived token) or rejected
(PING checks the sealed round). A slot replayed in the same round reuses a single-use write token,
which the store rejects.

## 6. What each party learns

| | Learns | Does not learn |
|---|---|---|
| **Provider** | when the device is present (live sets arriving, inherent to having a helper); the user's `clientLabel` | which buddies the user has, even when it also serves them (§4.6); whether any slot or live set carries a real message; whether a read hit; whether the user has mail waiting; any content or ratchet state |
| **Backend** (store, PING) | that a provider submitted one operation set per user per round, and attestation / key-registration requests on a fixed cadence | whether the device behind it is online, offline or late; anything new about network identity — devices never connect to it directly, including for attestation and key registration (§4.2, §4.3) |

Both columns hold only if **all** device traffic goes through the provider, including attestation
and key registration, and the sealed formats (§4.1–§4.3, §4.6) are used on **every** round, live
or delegated. A deployment where online devices talk to the backend directly would leak presence
through the connection switch, and one that skips §4.6 lets a shared provider link buddies. Neither
may claim these properties.

**Residuals for the threat model:**

- **Presence to the provider** — inherent; matches FR-010's model. Must not be combined with
  anything that links presence to buddies.
- **Provider downtime** — every user of that provider goes silent at once. That reveals provider
  availability, not any one user's presence.
- **Enclave restart without durable state** (§4.3 fallback) — the enclave rotates its sealing key,
  so bundled requests sealed to the old key fail until each device refreshes: delegated signals are
  dropped, writes are lost until the sender retransmits live, reads miss, and labels have no
  registered key until the next cadence registration. This affects availability for every user at
  once, not any one user's privacy.
- **One message per buddy while away.** Stop-and-wait advances only on an ack the provider can't
  read, so a bundle retransmits each buddy's current head only. Messages queued behind it go out
  on return. See open question 1.
- **One ack per peer while away.** The bundle's ack-only frame stops a peer's current head; the
  peer's next message waits until the device returns.
- **Staleness.** A bundle is up to F rounds old: it can retransmit an already-acked head
  (harmless) and won't contain messages queued since the last refresh (they go out on return).
- **Retained HK** (§4.1, §4.5) — a device compromise links the device's own frames on its current
  sending chain. At most two retained pairs per buddy (§4.1 table).
- **Until Phase 4 lands**, a provider relays plaintext tokens and frames: one serving both ends of
  a conversation can link them, and it can see read hits. This is why provider routing stays
  labeled `DEV, NO METADATA PRIVACY` until then.
- **One skipped key per pair from a bundle-built ack.** If a refresh built the cached ack-only frame
  and a live content frame then carries the ack instead, the ack-only position is never delivered.
  The peer stashes that one skipped message key until `MaxSkipStore` (2,000) evicts it. Because
  the cache is per `highRecv` value (§4.5), repeated refreshes add no further skipped keys.
- **Provider–backend collusion** — the provider knows which operation sets it submitted for which
  of its users. The backend alone does not.

## 7. Phased plan

Each phase is reviewable on its own and keeps the labeling rule: provider routing runs labeled
`DEV, NO METADATA PRIVACY` until Phase 4 has landed.

1. **T037 — failing tests first**, split by where the behavior lives so each later phase is
   verified by its own tests:
   - **protocol-core** — **landed** in
     `protocol-core/crosstest/src/test/scala/engine/OfflineDelegationCrossSpec.scala`. It is in
     `crosstest/`, not `shared/`, because the rekey scenarios need ML-KEM and every engine-level
     rekey test already lives there; it runs on both the JVM and Scala.js. An absent device stops
     ticking, and a simulated stale bundle replays its head on the wire.
     - the five rekey-timeout variants: four across an absence, one with a silent peer (§4.4);
     - the MaxSkip-across-absence test (§4.5).

     The four absence tests and the MaxSkip test fail today for the predicted reasons
     (`pq_rekey_timeout` / `pq_rekey_stranded` during an absence, and nothing delivered once a
     peer's chain has run past `MaxSkip`; a 300-round control absence delivers fine). They are
     wrapped in `pendingUntilFixed`, so CI stays green and the wrapper must come off in the
     Phase 2 PR that makes them pass. The silent-peer tests pass today and must keep passing.
     The §3.4 ratchet-step bound is a property of the bundle builder, so it lands with the builder
     in Phase 2.

     Phase 2 must also update the existing `PqRekeyCrossSpec` test "stranding is OBSERVABLE",
     which pins a stranding report at exactly `TimeoutRounds + 1` rounds of silence; under §4.4 the
     report moves to the end of the pause allowance.
   - **End to end** (`server/provider/src/test/scala/`, created with T038):
     - A queues a message to B while B is offline; A **disconnects abruptly** (no
       announcement); B returns; the message arrives, then a second queued message arrives in
       order after A returns.
     - Across disconnect → reconnect, every `(round, label)` digest is fetched exactly once and
       the device makes exactly one write per round.
2. **Engine side (protocol-core).** Makes the protocol-core tests from Phase 1 pass.
   - `DoubleRatchet` re-seal with the two retained `(MK, HK)` pairs and their wipe points (§4.1).
   - The `DoubleRatchet` decrypt-result change that distinguishes "position already consumed"
     from a carrier without mutating state (§4.5).
   - Split `Engine.tick` into `beginRound(sealedDigest) → liveSet` and `applyReceipt(receipt)`
     (§3.1), keeping `readRound = roundId − 1` and the one-round latency; the existing
     `RoundTransportSpec` suite must pass unchanged on top of the split.
   - Cached, re-sealed re-acks and duplicate-ack suppression (§4.5), with the receive-path
     comments updated to match.
   - The bundle builder under the §3.4 rules.
   - The paused-but-bounded rekey timeout, on both ends, with the pause allowance P (§4.4).
   - Property tests: slots pairwise byte-distinct and the same shape with an empty or a full
     outbox; no token recurs across build → absence → resume; the §3.4 ratchet-step bound; after
     N refreshes with no live sends, the peer holds at most one skipped key from bundle builds;
     the §4.1 wipe table.
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
   - The identity key and self-certifying label, and signed, counter-protected device-key
     registration with in-seal dummies and rotation (§4.3), delivered to **both** enclaves and
     verified by each: the Scala dev PING and the Rust sidecar, and the Scala dev store and the Rust
     `obsd`. Restart handling per §4.3 (durable rollback-protected state, or rotate the sealing key
     on restart). The forged / replayed / dummy / restart-replay registration tests run against
     both enclaves.
   - Sealed digests (§4.3).
   - Store requests sealed to the store enclave and fixed-size responses sealed to the device,
     with throwaway-key sealed misses on failure (§4.6), in both the Scala dev store and the Rust
     `obsd`. Test: failure responses pass the same encoding checks as real sealed misses.
   - Attestation fetches and key registrations relayed through the provider on the fixed cadence,
     with bundle-carried dummies during absences (§4.2, §4.3).
   - Test: for a provider serving both A and B, the bytes it handles during a real A → B delivery
     are indistinguishable in shape from a cover round, and no token, frame or response byte string
     appears in both A's and B's traffic.
   - Only after this phase can provider routing be part of a `METADATA PRIVATE` build.
5. **Docs.** Threat-model entries for the §6 residuals and a README note on what the provider can
   and cannot see (T062).

## 8. Open questions

1. **More than one message per buddy while away.** (a) Accept it — the queue drains on return.
   (b) Let a bundle cycle the first k queued messages; the receiver de-duplicates by sequence and
   accepts only the next in order, so this delivers in order at about k rounds per message, but it
   needs k retained key pairs per buddy and ARQ bookkeeping for more than one frame in flight.
   Recommendation: ship (a).
2. **H and F.** With the sealed formats (§3.3), one day (H = 5,760) refreshed hourly (F = 240) is
   about 3.1 MB per refresh, **about 74 MB a day** of uploads per device with classical seals, and
   about 22 MB per refresh (over 500 MB a day) with post-quantum hybrid seals. Both are too much
   for mobile. Options:
   - a smaller H (6 h cuts it fourfold);
   - a fixed-size rewrite of only the next F slots each refresh instead of the whole bundle (it must
     not reveal *which* slots changed, so it rewrites all F of them every time), which cuts upload
     by H / F ≈ 24×;
   - for post-quantum seals, encapsulating once per refresh and deriving per-slot keys from it,
     instead of one encapsulation per field — but only if a vetted library offers that construction
     (Constitution I), not by composing it ourselves.

   H must be one network-wide constant either way; a per-device H is a fingerprint.
3. **Sealing and signing constructions.** For seals: HPKE (Bouncy Castle + `@hpke/core`) or
   libsodium sealed box (new FFM binding + `libsodium-wrappers`), decided by whichever has a vetted,
   maintained Scala.js implementation. Whether seals, and the §4.3 identity signature, must be
   post-quantum hybrid follows the project's PQ policy, and it drives the size question above.
4. **Multi-device (US5, T043–T045).** With all traffic through the provider, two devices of one
   user can share one per-user schedule at the provider: one operation set per user per round, fed
   by whichever device is live. That is likely the FR-011 non-coordination mechanism, which is why
   Phase 3 keys storage by user. Out of scope here.
