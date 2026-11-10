# Offline delegation to the service provider — T037 / T038 (US4, FR-007/FR-008)

Status: **PROPOSED.** Nothing here is implemented. This document picks the mechanism for US4
("send to and catch up while offline") before any code is written, because the obvious
implementation leaks exactly what the task forbids ("no real-vs-idle leak on gaps").

## 1. What already works, and the one case that doesn't

Messaging today is round-based stop-and-wait ARQ over round-derived tokens
(`retry-safe-addressing.md`). Each round a device makes exactly one store write, one notify
signal, one digest fetch and one store read. A sender **retransmits its head message every
round, under that round's fresh token, until the peer acks it**. The wire is cached, so a
retransmit does not advance the ratchet and an absent peer stays inside `MaxSkip`.

That gives most of US4 for free:

| Case | Today |
|---|---|
| B offline, A stays online | **Works.** A retransmits every round; when B returns it reads the current round's slot, acks, and the queue drains in order. `RoundTransportSpec:469` covers 1500 offline rounds. |
| B offline with several messages queued from A | **Works**, in order, one message per round trip (stop-and-wait). |
| A sends, then **A goes offline before B returns** | **Fails.** A's retransmits stop when A stops ticking. The frame A wrote in round r sits under round r's token, but B, when it returns in round R > r + 1, only ever reads round `R − 1`. Nothing delivers it until A comes back. |
| A device is offline at all | **Leaks presence.** An offline device makes no per-round writes, signals, fetches or reads, so the backend sees online vs offline directly. |

So the gap is not "the receiver needs to catch up". On return the receiver doesn't need history:
as long as the sender is still retransmitting, normal operation *is* the catch-up. The gap is
that **the sender's retransmissions must outlive the sender's device**, and that an offline
device's traffic must look like an online one's.

`device.Device` (T039) computes a missed-round range on reconnect. Under this design the engine
does not replay that range; `Device` is still used for the presence state and for the horizon
bookkeeping in §5.

## 2. Options

### Option 1 — replay missed rounds from the store on return (rejected)

Keep frames in the store for the retention window; on reconnect, read every missed round's slot
for every buddy.

- **Leaks the gap length.** The returning device issues a burst of reads proportional to how
  long it was away. That is the "real-vs-idle leak on gaps" T039's own text rules out, and it
  breaks the one-read-per-round invariant (FR-012).
- **Cost.** Up to 512 buddies × missed rounds of reads, most of them misses.
- **Doesn't fix presence.** The offline period is still visible as silence.

### Option 2 — the provider runs the device's rounds while it is away (recommended)

Before going offline, the device precomputes its next **H** rounds of traffic and hands them to
its service provider as a *delegation bundle*. Each round the provider performs that round's
operations against the backend exactly as the device would have. The provider holds no keys and
makes no decisions: every operation is a precomputed, opaque, round-bound value.

This is the Groove-style oblivious delegation `research.md` D10 already chose for the provider.
It fixes the failing case (the sender's head keeps being retransmitted) and the presence leak
(the backend sees the same per-round shape whether the device is online or not), and the
returning device needs no replay.

## 3. The delegation bundle

For each round `r` in `[R0, R0 + H)` the bundle holds one **slot**:

| Field | Size | Content |
|---|---|---|
| `writeToken` | 32 B | `dirToken(addrKey, self, peer, r)` for the buddy whose head is retransmitted in `r` (send-side rotation as in `Engine.tick`), else a fresh cover token from `coverKey` |
| `frame` | 256 B | that head's wire, **re-sealed under a fresh nonce for this slot** (§4.1), else a cover frame |
| `sealedSignal` | fixed | the round-`r` notify signal — the real peer's `(label, bit_r)` or the decoy to the void label — **sealed to the enclave** (§4.2) |
| `readToken` | 32 B | a fresh cover-read token (§4.3) |

About 400 B a slot. At the 15 s round interval (`schedule.Latency`), one day is 5,760 rounds,
about 2.3 MB. `H` is a fixed protocol constant, never a function of how much the user has queued,
so the bundle's size reveals nothing.

What the provider does per round `r`:

1. `submit(writeToken_r, frame_r)` to the store.
2. `signal(r, sealedSignal_r)` to PING.
3. `fetchDigest(r, clientLabel)` and **drop** the result (it is sealed to the device, §4.3).
4. `retrieve(readToken_r)` and drop the result (a cover read).
5. Delete slot `r` (bounded retention, §5).

The provider never interprets anything. If it skips, delays or reorders slots, messages are
delayed, which it could cause anyway by going down. Every slot is bound to its round: the token is
round-derived, and the sealed signal binds `r` (`DevNotificationServer` already rejects a token
for the wrong round). A slot replayed in another round is a miss; a slot replayed in the same
round reuses a single-use write token, which the store rejects.

## 4. What has to change so the provider learns nothing

Three things the current code does are fine when the device talks to the backend directly but
leak once an untrusted provider relays the traffic.

### 4.1 Retransmits are byte-identical today

`Engine.tick` caches `headWire` and resubmits the **same 256 bytes** every round. In a bundle,
real slots would then repeat while cover slots are fresh random frames, so the provider could see
"this device has a pending message, retransmitted from round x to y", and which slots belong to
the same message.

**Change:** a `DoubleRatchet` operation that re-seals an already-built message under a **fresh
nonce** with the same header key and message key and the same plaintexts, without advancing any
chain. The frame layout already shares one random 12-byte nonce between both AEADs
(`DoubleRatchet.scala:32-36`), so this is "seal again with a new random nonce". Under random
96-bit nonces, H ≤ 10⁴ copies per key is far inside the birthday bound. The receiver is
unaffected: the first copy decrypts and consumes the message key, and later copies fail to decrypt
exactly as cached retransmits do today. This also removes the same repetition from what the store
sees when the device is online, so it should apply to all retransmits, not only bundles.

The re-seal stays inside `DoubleRatchet` and calls the existing `Aead.seal`. No new primitive
(Constitution I).

### 4.2 Notify signals are sealed by the backend, not the device

On the real path the device sends `(round, bit, label)` to the attested enclave front, which seals
it; in dev, `GrpcRoundTransport` seals with the dev notify key. A provider relaying a precomputed
signal would see the **peer's notify label**. That is a buddy relationship, and exactly what
FR-010/SC-008 forbid the provider from learning.

**Change:** the device encrypts each slot's `(r, bit, labelTag)` to the enclave's **attested public
key** (the key `AttestedProvisioning` already releases only on a passing appraisal) with a vetted
public-key sealing construction, either HPKE (RFC 9180, Bouncy Castle) or libsodium's
`crypto_box_seal`. PING opens it inside the enclave and ORs the bit as today. Labels are already
fixed-width (`NotifyDigest.labelTag`), so real and decoy ciphertexts have the same length.

An alternative with the same effect is the mechanism FR-003 describes and
`DevNotificationServer.issueToken` already implements: the *receiver* issues sealed, round-bound
tokens to the sender, so the sender only ever holds opaque blobs. Since T041c rotates the bit every
round, a receiver would have to issue one token per future round, which is a large pre-issue for
H rounds × 512 buddies. Sealing on the sender to the enclave key is cheaper and is the
recommendation.

### 4.3 Digests are plaintext to whoever presents the client label

`fetchDigest(roundId, clientLabel)` returns the receiver's bitmap in the clear and consumes it
(`digestAndReset`). A provider fetching on the device's behalf would learn which rounds had mail
and how many buddies wrote: the user's incoming activity, again an SC-008 violation. A provider
that simply doesn't fetch breaks the uniform per-round shape.

**Change:** PING returns the digest **sealed to a device-registered key**, so the provider can
fetch it on schedule and drop the opaque bytes. The device doesn't need the dropped digests: on
return it reads the live digest of the current round, because senders are still retransmitting
(§1).

Reads made by the provider are therefore always **cover reads**. No read is guided by
notifications while the device is away, which is fine, because nothing needs to be received until
the device can decrypt it anyway.

## 5. Handoff, horizon and retention

**Going offline (device).** At round `R0` the device builds the bundle for `[R0, R0 + H)`, uploads
it in one atomic provider transaction, and stops ticking. Covers and cover reads consume counter
values; the device advances `coverCounter` and `coverReadCounter` **past every value it put in the
bundle**, whether or not the provider ends up using it, so a cover token can never recur after
return (FR-014).

**Coming back (device).** At round `R'` the device asks the provider to **revoke** the bundle from
round `R' + 1` on. The revoke is atomic with the provider's round cursor (this is the "atomic
transactions" in T038). The provider either has already executed slot `R'` or never will, and it
returns the last round it executed. The device resumes ticking at that round + 1. The device and
the provider never both act in one round: two writes in a round would break the one-write rule, and
a reused round token would be rejected.

**Ratchet and ARQ state on return.** Bundles never advance a ratchet (§4.1 re-seals), so the
device's state is exactly as it left it. If a peer acked the head while the device was away, the
device learns that from the peer's next frame (the peer keeps re-acking a retransmit it can't
decrypt — existing behavior), drops the head, and moves on. A rekey started before going offline
falls under the existing `maybeTimeoutRekey`.

**Horizon expiry.** If the device stays away past `R0 + H`, the provider runs out of slots and the
device goes silent: a presence leak after H rounds, and its head stops being retransmitted. H is a
fixed trade between bundle size and how long the leak and the strand are deferred. The
`Device.Retention` window (10,000 rounds, about 42 h) is a natural upper bound; a day (5,760
rounds) is a reasonable default. A device can refresh its bundle while online without changing its
traffic shape, since uploading to its own provider is not backend traffic.

**Retention.** The provider holds only unexecuted slots and deletes each one when it executes it,
so it holds at most H slots per device, none older than the current round. A slot contains no
sender identity: tokens are PRF outputs, frames and signals are ciphertext (FR-008, "bounded
retention not leaking sender").

## 6. What the provider learns, and what it doesn't

| The provider learns | The provider does not learn |
|---|---|
| that this device delegated, and when it came back (presence is inherent to having a helper) | which buddies the user has (tokens are per-round PRF outputs; signals are sealed to the enclave) |
| the bundle's size (constant H) | whether any slot is a real retransmit or cover (§4.1) |
| the user's own client label (needed to fetch the digest) | whether the user has mail waiting (§4.3) |
| | any message content or ratchet state |

Within the backend, a delegated device's traffic is identical to an online device's. So the
backend learns **less** than it does today, where an offline device is visibly silent.

**Residuals to state in the threat model:**

- The provider sees presence. That is inherent to having a provider and matches FR-010's model
  (the provider "participates on the user's behalf"); it must not be combined with anything that
  links presence to buddies.
- **One message per buddy while the sender is away.** Stop-and-wait advances only on an ack the
  provider can't read, so a bundle can retransmit only each buddy's current head. Messages queued
  behind it go out when the device returns. See open question 1.
- Provider and backend colluding: the provider knows which tokens it submitted for this user. Since
  the backend already sees those tokens arrive from the provider's connection, this is the same
  exposure as today's client→backend connection, where the backend learns the client's network
  identity. Nothing new is linked.

## 7. Phased plan

Each phase is reviewable on its own and keeps the labeling rule: delegation runs labeled
`DEV, NO METADATA PRIVACY` until Phase 4 has landed.

1. **T037 — failing test first.** An integration test in `server/provider/src/test/scala/`: A
   queues a message to B; B is offline; A goes offline before B returns; B comes back; the message
   arrives, then a second queued message arrives in order. It fails today (row 3 of §1).
2. **Engine side (protocol-core).** `DoubleRatchet` re-seal (§4.1, applied to all retransmits);
   `Engine.delegate(R0, H): DelegationBundle` and `Engine.resume(lastExecutedRound)`; counter
   advancement past bundled covers. Property tests:
   - bundle slots are pairwise byte-distinct and the same shape whether the outbox is empty or
     full;
   - no token recurs across delegate → resume → normal ticking;
   - the engine's state after resume equals its state before delegate, apart from counters.
3. **T038 — `server/provider/`.** An untrusted `ProviderBuffer`: atomic `upload` / `revoke`
   against a per-device round cursor, a round driver that executes one slot per round and deletes
   it, and at most H slots per device. In-memory first, behind an interface that a Postgres or
   embedded-KV store can implement later (`plan.md`). Makes T037 pass.
4. **Sealing (privacy-bearing).** Device-side sealing of signals to the enclave key (§4.2) and
   sealed digests (§4.3), with PING changes in both the Scala dev server and the Rust sidecar. Only
   after this phase can delegation be part of a `METADATA PRIVATE` build.
5. **Docs.** Threat-model entries for the §6 residuals and a README note on what the provider can
   and cannot see (T062).

## 8. Open questions

1. **More than one message per buddy while away.** Options: (a) accept it — the queue drains on
   return; (b) let a bundle cycle the first k queued messages (msg 1, msg 2, …, msg 1, …). The
   receiver de-duplicates by sequence number and only accepts the next in order, so this delivers
   in order at a cost of about k rounds per message. It needs the ratchet to pre-encrypt k sends,
   which it can, and `headWireAck` / ARQ bookkeeping that tolerates more than one in-flight frame.
   Recommendation: ship (a), keep (b) for later.
2. **H.** One day (5,760 rounds) as a default? It could be configurable per device, but then H
   itself becomes a fingerprint. Prefer a single network-wide constant.
3. **Sealing construction for §4.2.** HPKE via Bouncy Castle (already a dependency) or libsodium
   `crypto_box_seal` (already bound over FFM, and available in the browser through
   `@noble`/libsodium-wrappers for the Scala.js engine). The JS side decides it: whichever has a
   vetted implementation on both platforms.
4. **Multi-device (US5, T043–T045).** Two devices of one user each delegating would emit two
   shapes. The FR-011 non-coordination design should reuse the bundle format (one provider-held
   schedule per user, not per device) rather than invent a second mechanism. Out of scope here,
   but Phase 3's storage key should be the user, not the device, so it doesn't need migrating.
