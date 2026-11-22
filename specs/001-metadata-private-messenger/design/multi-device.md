# Multi-device — T043 / T044 / T045 (US5, FR-009/FR-010/FR-011)

Status: **PROPOSED.** Nothing here is implemented. This document picks how one user runs several
devices before any code is written. The mechanism tasks.md assumes for T044 ("provider-mediated
device sync … reconcile divergent state") turns out to be unsafe for the ratchet. §2 explains why.

It builds on `offline-delegation.md` (the provider fronts every round, standing bundles, sealed
formats) and changes nothing in it.

## 1. What US5 asks for, and what exists

US5's three acceptance scenarios and its edge case:

1. A buddy messages the user, and the message is **available on both devices**.
2. A **fully compromised provider** cannot determine the user's contacts or whether the user is
   active (FR-010, SC-008).
3. Two of the user's devices that **cannot reach each other** take part in the same round, and
   their combined traffic does not reveal that they belong to the same user (FR-011).
4. Two devices reconnect after a partition with **divergent state**, and they reconcile without
   emitting traffic that distinguishes the user.

What exists today is single-device: an `Engine` holds one double ratchet per buddy pair. It makes
one write, one signal and one read per round, through its provider. Offline delegation covers its
absences. The buddy book is capped at 512 pairs (`Buddy.MaxBuddies`), one notify bit each.

## 2. The constraint: a sending chain has exactly one writer

Every message is encrypted under a message key taken from the pair's sending chain, and the chain
advances once per message. The DH ratchet adds a fresh key pair whenever the sending direction
turns. If two devices advance **the same pair's state** independently, the ratchet **forks**:

- **Messages are lost.** Both devices encrypt at the same chain position. The frame nonce is random
  (`DoubleRatchet.scala`), so this doesn't expose plaintext outright, but the receiver consumes that
  position's key once. Whichever copy arrives second never decrypts.
- **The pair breaks for good.** At a DH step each device generates its own key pair. The buddy
  follows one fork, and the other device can't decrypt anything sent after it. Nothing in the
  protocol re-joins them.
- **Retired keys come back.** A device that resumes from an older state re-derives message keys
  that were already used and wiped. That undoes forward secrecy for those positions: a later
  compromise of the device exposes the new messages under keys that should no longer exist.

Any design that lets two devices share one pair's ratchet state therefore needs two guarantees:

- **One writer at a time.** At most one device advances a pair's state at any moment.
- **No rollback.** A device that takes over starts from the **latest** state, never an older one.

FR-011 says the devices cannot talk to each other directly. The only place left to coordinate is
the provider, and the provider is untrusted. That decides the options below.

## 3. Options

### Option 1 — one shared identity, ratchet state synchronised through the provider (rejected)

This is what T044's wording and research D10 ("synchronizing a user's devices") suggest. The user
has one label, one schedule and one set of pairs. Devices take turns holding the ratchet state,
which they hand over as encrypted snapshots stored at the provider.

- **Rollback is undetectable.** The provider can accept a device's new snapshot and then serve the
  previous one to the other device. That device resumes at chain positions already used and
  forks the pair (§2). Encrypting the snapshots doesn't help: the
  old snapshot is genuine, just stale. The devices can't compare notes (FR-011), so only a
  rollback-protected monotonic counter **outside the provider** can catch it. That means a new
  enclave dependency, needed for safety and not just privacy.
- **An abrupt disconnect strands the state.** A device killed mid-round may have encrypted and
  submitted a frame before its snapshot reached the provider. Taking over from the last snapshot
  reuses that position. Writing the snapshot first narrows the window but needs the same trusted
  counter to order "snapshot, then send".
- **The DH ratchet couples the directions.** A buddy's reply is encrypted to the DH key of the
  device that last sent. The other device can't decrypt it until it has that device's private
  key, so every receive waits for a state handover.
- **Two live devices compete for one slot.** One operation set per user per round means one of
  two live devices always has its live set dropped.

Its one real advantage: buddies and the provider see one user, so device count stays hidden.
That is listed as a residual of the recommendation (§6).

### Option 2 — one pair, a separate sending chain per device (rejected)

Each device gets its own sending chain inside one buddy pair, so there is never a second writer.
The receiving side is shared, and receiving is safe to duplicate because it only derives keys.
But the double ratchet's DH step ties sending and receiving together: each device's new DH key
changes what the buddy encrypts to. Making that work means sharing DH private keys between devices,
which brings back Option 1's synchronisation problem, or dropping the DH ratchet and its
post-compromise security, which US7 forbids.

### Option 3 — every device is a full client; devices and buddies pair per device (recommended)

This is how Signal handles linked devices (Sesame). Each device is a complete client with its own
identity key, label, provider registration, standing bundle and engine. A user's devices pair with
each other as ordinary buddies. A buddy pairs with each of the user's devices, and the user's
devices are introduced to a buddy over an existing authenticated pair (§4.3).

- **One writer per chain, by construction.** No ratchet state is ever shared, copied or
  handed over. Nothing can roll back.
- **Nothing new at the provider or the backend.** Each device's traffic is a single-device client's
  traffic, which `offline-delegation.md` already makes private. T044's provider sync component
  disappears.
- **Non-coordination comes free.** Each device runs its own schedule and needs nothing from the
  others in any round (§5).

The cost is fan-out: a message goes once per recipient device, plus once per sibling device as a
sent-copy. Buddies also learn the user's device count. Both are covered in §6.

## 4. Design

### 4.1 A device is a client

Each device has everything a single-device user has today: an identity key and self-certifying
label (`offline-delegation.md` §4.3), a provider registration, a standing bundle and an `Engine`.
The backend sees as many independent clients as there are devices.

**Providers.** Devices may use the same provider or different ones. On one provider they register
as **unrelated accounts**: there is no "user" record linking them, and the provider must not be
told they belong together. §5 covers what a shared provider can still infer.

### 4.2 Contacts and pairs

The engine gains a **contact** layer above pairs:

- A **contact** is a person: a display name plus the set of pairs to that person's devices.
- A **self contact** holds the pairs to the user's own other devices.
- **Pairs are unchanged.** Each one is the existing buddy pair, with its own ratchet, ARQ, tokens,
  notify bit and bundle share.

A pair counts against `MaxBuddies` exactly as today. The 512-pair budget now covers
`Σ contacts × their devices + (own devices − 1)`. A user with three devices whose contacts have two
each can hold about 255 contacts. The notify-bit space needs no change, because it is per pair.

### 4.3 Linking a device, and introductions

**Linking.** A new device D2 pairs with an existing device D1 out of band, exactly as two buddies
pair today: a shared secret by QR code. Both screens are in the same hands, so the safety-number
comparison is the same step the user already does for buddies. The pair is marked self.

**Introductions.** D2 now needs a pair with every device of every contact. For each contact device
Bj that D1 is paired with, D1:

1. draws a fresh random pairing secret `s` (32 bytes, OS CSPRNG);
2. sends `INTRO(s, role = responder, label = D2's label)` to Bj over the D1–Bj pair;
3. sends `INTRO(s, role = initiator, label = Bj's label, contact = B)` to D2 over the D1–D2 pair.

Bj and D2 each run `addBuddy(s, role, peerNotifyLabel)` and confirm. The new pair's root comes from
`s`, which travelled only inside two authenticated, encrypted pairs.

- **Authentication.** Bj trusts "this is the user's new device" exactly as much as it trusts D1,
  because the introduction arrives on a pair it has already verified. The new pair is recorded as
  **verified by introduction**, with D1 as the introducer, and its safety number is still derived
  and can be shown.
- **Visibility.** Bj's app tells its user "Alice added a device". That is a feature: it is the
  check against an introduction the user didn't make.
- **Both sides multi-device.** When contact B has several devices, D1 is paired with each of them,
  so the loop above covers the full mesh. When **B** adds a device, B's existing device introduces
  it to every device of every contact, including all of the user's.
- **Wire.** `INTRO` is a new control kind in the existing control-frame path (the one `KEM_CHUNK` and
  `EPOCH_COMMIT` use), delivered with ARQ like any head. Its payload is about 80 bytes, so several
  fit in one 256-byte frame for D2, and `ChunkStream` already carries longer payloads.
- **Post-quantum.** `s` is as quantum-safe as the pairs that carry it. Once the continuous PQ
  ratchet runs on every pair, that holds. Until then an introduced pair can run the existing PQ
  pairing prekey (`addBuddy` with `pqPrekey`) over the same introduction. That is open question 3.

**Time to link.** Introductions are ordinary messages at one write per round. Introducing D2 to
200 contact devices takes about 200 rounds on the B side, spread across D1's pairs, plus about 70
frames to D2. That is roughly an hour at 15 s rounds, during which D2 already works for the
contacts introduced so far. The UI shows progress.

### 4.4 Sending, and sent-copies

When the user sends text to contact B from device D1, the engine enqueues:

- one copy per pair to B's devices, each encrypted under its own pair (FR-006: these are
  independent conversations, so a slow device of B never blocks the others; T033 shows this);
- one **sent-copy** per self pair, a sync item saying "sent to B at t: text", so the user's other
  devices show the conversation in full.

Every copy is a separate head on a separate pair, with its own key, token and nonce. No two copies
share ciphertext bytes or tokens, so fan-out creates no duplicate traffic (§5).

### 4.5 Receiving

Each device receives directly from each contact device, so a message sent to the user arrives on
every one of the user's devices without any device-to-device step (scenario 1). Sent-copies arrive
over self pairs. Optional read markers ("read up to n on D1") are sync items too.

### 4.6 Divergent state (the edge case)

What can diverge between devices: sent history, the contact list (adds, removals, renames), the
device list, and read markers. Received messages can't diverge: each device receives its own copy.

- **Every change is a sync item** sent over the self pairs, with ARQ and standing-bundle coverage.
  So a partition just means the items wait, exactly like messages to an offline buddy.
- **Merging.** Sent-copies and received messages are append-only, ordered per pair, and need no
  merge. Contact-list entries and read markers merge last-writer-wins on `(lamport, deviceLabel)`.
  Removing a contact is a tombstone that wins over a concurrent rename.
- **Traffic.** Reconciling after a partition sends sync items in normal write slots, which already
  carry either a real frame or a cover. The traffic shape doesn't change (edge case 4).

### 4.7 Removing a device

A lost or retired device is removed by any remaining device. It sends `REVOKE(label)` to every
contact device and to every self device. Each receiver runs `removeBuddy` on its pair with the
revoked device, with the existing FR-018 removal semantics. The revoked device's bundle runs out
within H rounds, and its provider account can be dropped.

A stolen device can revoke the legitimate ones just as easily. Who may revoke whom is open
question 2.

## 5. What each party learns (FR-010, FR-011)

| | Learns | Does not learn |
|---|---|---|
| **Backend** | one operation set per device per round, as for any client | that two clients belong to one user: they share no token, frame, label or key |
| **Provider** (Phase 4 formats) | each device's presence, as for any client; on a shared provider, co-presence over time (§6) | which accounts are one user's; contacts; whether sync traffic or real messages flow |
| **A contact** | the user's device count, and each add or remove | anything about the user's other contacts |
| **Network observer** | as for single-device clients | which clients are one user |

**FR-011, in detail.** The devices never coordinate: each runs its own schedule and makes one
operation set per round, whatever the others do. Nothing in two devices' traffic repeats across
them:

- Tokens are per pair: `dirToken(addrKey, self, peer, r)` differs because each pair has its own
  `addrKey`.
- Ciphertexts are per pair, with fresh nonces.
- Labels and identity keys are per device.
- Fan-out copies to one contact are encrypted under different pairs.

The "duplicate or conflicting traffic" FR-011 warns about is what Option 1 risks when two devices
hold one identity. Under Option 3 the devices simply don't share an identity.

Self-pair traffic is ordinary buddy traffic. A shared provider relaying both ends of a self pair is
the case `offline-delegation.md` §4.6 already closes for any two buddies on one provider.

## 6. Residuals and costs

- **Device count to contacts.** Contacts see how many devices the user has and when one is added
  or removed. Option 1 would hide this, at the cost of §3's safety problems. Padding with dummy
  device pairs would hide it but spends pair budget. That is open question 1.
- **Co-presence on a shared provider.** A provider serving two of a user's devices as unrelated
  accounts sees their presence patterns, which may correlate (same commute, same sleep). That is a
  statistical signal, not a protocol link. Separate providers remove it; the app may offer that.
- **Pair budget.** `MaxBuddies` = 512 now counts device pairs (§4.2).
- **Throughput.** Each device still makes one write per round. A message to a contact with m
  devices from a user with n devices takes m + n − 1 writes across the sender's rounds,
  stop-and-wait per pair.
- **Linking time.** §4.3: on the order of an hour for a few hundred contact devices.
- **Trust in introductions.** A compromised device can introduce a device the user doesn't
  control. Contacts are told (§4.3), but a user who ignores the notice is exposed. The same holds
  for Signal's linked devices.
- **More copies of history.** Each device stores its own copy, which widens what a device
  compromise exposes (US7). Forward secrecy holds per device as today.

## 7. Effect on the tasks, and a phased plan

T043–T045 keep their goals, but T044 moves from the provider into protocol-core, because the
provider needs no new code:

- **T043 — tests first.**
  - **Two-device delivery:** a contact's message reaches both devices, and a sent-copy reaches the
    sibling.
  - **Non-coordination:** over many rounds with both devices live, the two devices' traffic shares
    no token, frame or label, and each device makes exactly one operation set per round.
  - **Partition:** both devices change the contact list while apart, and after the partition they
    converge with no change in traffic shape.
  - **Provider compromise:** structural in dev builds; the real guarantee lands with
    offline-delegation Phase 4.

  Engine-level tests go in `protocol-core/crosstest` (both platforms). The server-round versions go
  in `transport/src/test/scala/integration/multidevice/`, on `integration.RoundStack` (T033).
- **T044 — linking, introductions, sync** in `protocol-core/shared/src/main/scala/contact/` and
  the engine: self pairs, `INTRO`, sync items and their merge rules, `REVOKE`. The task's old path
  `server/provider/src/main/scala/sync/` is dropped.
- **T045 — contacts and fan-out** in the engine: the contact layer, fan-out sending, the pair
  budget. "Oblivious delegation so non-coordinating devices don't emit linkable traffic" is
  satisfied by construction (§5). T045 keeps the tests that prove it.

Phases, each reviewable alone and labeled `DEV, NO METADATA PRIVACY` like all provider routing
until offline-delegation Phase 4:

1. T043 failing tests (engine level first).
2. Contact layer and fan-out (T045), with no linking yet: contacts with several devices paired by
   hand.
3. Self pairs, `INTRO` and `REVOKE` control kinds (T044).
4. Sync items and merge rules (T044).
5. Flutter: link a device by QR, the device list, and the "added a device" notice.

## 8. Open questions

1. **Hide device count from contacts?** Pad every user to a fixed number of device pairs with
   dummy pairs (which cost pair budget and fan-out writes), or accept the residual (§6).
2. **Who may revoke whom?** Any device (simple, and a thief can lock out the owner), the oldest
   device, or a quorum of self devices.
3. **PQ for introductions.** Rely on the carrying pairs' PQ state, or run the PQ pairing prekey on
   every introduced pair.
4. **Research D6/D9 (Groove).** Groove's per-epoch OPRF key evolution and circuit tagging exist to
   make shared-identity devices safe without coordination. Option 3 needs neither for multi-device.
   D6 remains a candidate for epoch forward secrecy on its own merits.
