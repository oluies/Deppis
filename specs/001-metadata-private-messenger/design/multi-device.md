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

**Limits (decided: raise, keep 512 contacts).** FR-015's 512 is a limit on **contacts**. Pairs are
capped separately, sized for a full contact list at the device cap:

- **Devices per user:** at most 4 (`MaxDevices`, proposed).
- **Pairs per device:** at most 512 × 4 + 3 = 2,051 (`MaxPairs`): every device of every contact,
  plus the user's other devices. `MaxBuddies` = 512 stays as the contact limit.
- **Notify digest:** from 512 to 4,096 bits (64 B to 512 B), one bit per pair with headroom, so
  per-round bit rotation still rarely collides. This grows each digest fetch, each sealed digest
  (`offline-delegation.md` §4.3) and the PING enclave's per-label state eightfold.

The exact values are set in T045 against measured digest and enclave costs. They must stay
network-wide constants, since a per-user digest size would be a fingerprint.

### 4.3 Linking a device, and introductions

**Linking.** A new device D2 pairs with an existing device D1 out of band, exactly as two buddies
pair today: a shared secret by QR code. Both screens are in the same hands, so the safety-number
comparison is the same step the user already does for buddies. The pair is marked self.

**Introductions.** A device needs a pair with every device of every contact. Introductions
create them. The introducer only **relays public key shares**: X and Y agree on the new pair's
secret themselves, so the introducer never learns it (decided, open question 5). One introduction
of device X to contact device Y by an introducer D:

1. D sends `INTRO(id, role = initiator, label = Y's label, contact = Y's contact)` to X over the
   D–X self pair, and `INTRO(id, role = responder, label = X's label)` to Y over the D–Y pair.
2. X and Y each generate an ephemeral X25519 key pair (the vetted library already used for the
   ratchet, Constitution I) and answer `INTRO_SHARE(id, pub)` to D on the pair the `INTRO` came
   on.
3. D forwards each share to the other side as `INTRO_PEER(id, pub)`.
4. X and Y each compute `s = X25519(own private, peer public)`, wipe the private key, run
   `addBuddy(s, role, peerNotifyLabel)` (whose existing KDF derives every pair key from `s`), and
   wipe `s`.

D sees two public shares and nothing else, so a later compromise of D learns nothing about the
pair. D still vouches for whose shares they are, and at introduction time it could substitute its
own; that is the trust in the introducer that §6 already accepts. The shares travel only inside
D's encrypted pairs, never in the clear.

**When to introduce: a standing rule, not a one-shot.** Introductions are not a loop run once at
link time, because the set of devices keeps changing on both sides. Each device D applies this rule
whenever its view changes:

- **D introduces device X to device Y** when D holds verified pairs to both, at least one of X
  and Y is a sibling of D, and the synced pair lists (§4.6) show no confirmed X–Y pair. This covers
  a sibling and a contact device, and also two siblings: a third device linked to D1 is introduced
  to D3 the same way, so the user's own devices always form a full mesh of self pairs.
- **One introducer.** Of all devices that could introduce X–Y, only the one with the smallest label
  does. Every candidate computes this from labels it already knows.
- **Races resolve the same way at both ends.** Pair lists can be stale, so two introductions of
  the same X–Y can still happen. Each receiver keeps the introduction whose introducer has the
  smaller label, replacing an unconfirmed pair from the other one. X and Y apply the same rule to
  the same two introductions, so they always keep the same one.
- **Pair lists report confirmed pairs only.** An introduction counts as done when the new pair has
  confirmed (its first frame decrypted at both ends), not when D's messages are acked. A failed
  introduction therefore never shows up as a pair, and the rule tries again.

This one rule covers every case: linking a device (D1 introduces the new D2 to each contact
device), a contact linking a device (B1 introduces B2 to each of the user's devices), both at once
(the D2–B2 pair appears once D1–B2 or B1–D2 exists, introduced by one side only), and a contact
added after linking (D1 pairs with C1 by QR, then introduces D2 to C1).

**Authority.** An introduction or revocation is honoured only within the scope of the pair it
arrives on:

- An `INTRO` arriving on **contact C's pair** files the new pair under C, whatever its `contact`
  field says. A contact can introduce its own devices to the user, never a device claiming to be
  the user's, and never another contact's.
- The `contact` field is honoured only on a **self pair**: a sibling may name any contact, or
  self. A device becomes a self device only by the QR link or by an `INTRO` that arrives on a self
  pair.
- Each receiver rejects an `INTRO` that breaks these rules, and tells its user.

**Erasure.** X and Y hold their ephemeral private key only until the peer's share arrives, and
`s` only until `addBuddy` has derived the pair's keys. D holds public shares only. If either side
hasn't answered after H rounds (the same bound as a standing bundle), D drops the introduction and
sends `INTRO_CANCEL(id)` to the side that did answer, which discards its private key. Only the
device that sent `INTRO(id)` may cancel it. No pair exists yet at that point, because neither side
runs `addBuddy` until it has the other's share. The standing rule introduces the pair
afresh when both are next live.

- **Authentication.** Y trusts "this is the user's new device" exactly as much as it trusts D,
  because the introduction arrives on a pair it has already verified. The new pair is recorded as
  **verified by introduction**, with D as the introducer, and its safety number is still derived
  and can be shown.
- **Visibility.** Y's app tells its user "Alice added a device". That is a feature: it is the
  check against an introduction the user didn't make.
- **Wire.** `INTRO`, `INTRO_SHARE`, `INTRO_PEER` and `INTRO_CANCEL` are new control kinds in the existing
  control-frame path (the one `KEM_CHUNK` and `EPOCH_COMMIT` use), delivered with ARQ like any head.
  Each is well under 100 bytes, inside the 156-byte control envelope (`ChunkStream.EnvelopeBytes` =
  `ArqFrame.PayloadBytes`), so one fits per frame. Batching several into one chunked object
  (145 bytes per chunk) needs a new chunked envelope kind; today only `KEM_CHUNK` uses one.
- **Post-quantum.** The shares are classical X25519, but they only ever travel inside D's pairs, so
  a harvest-now attacker sees nothing to break unless it first breaks those pairs. The new pair's
  content gets post-quantum keys from its own PQ rekey, run directly between X and Y once they are
  paired, with no relay. Relaying an ML-KEM exchange through D instead (`initiatePqPrekey`: a
  1,216-byte public key and a 1,120-byte ciphertext, about 17 chunks per pair) would make linking
  several times slower. That is open question 3.

**Time to link.** Each introduction is four relayed messages written by D: two `INTRO`s and two
`INTRO_PEER`s. The bottleneck is the D–X self pair, which carries two of them per introduction under
stop-and-wait (about two rounds per message). Introducing D2 to 200 contact devices is therefore
about 800 rounds, roughly **3.5 hours** at 15 s rounds; batching through a chunked envelope roughly
halves that. D2 works for each contact as soon as that contact's introduction completes, and the
UI shows progress.

### 4.4 Sending, and sent-copies

When the user sends text to contact B from device D1, the engine enqueues:

- one copy per pair to B's devices, each encrypted under its own pair (FR-006: these are
  independent conversations, so a slow device of B never blocks the others, as T033's
  `ConcurrentConversationsSpec` shows over a real server round);
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
device list, each device's list of pairs (the peer labels it holds, which the §4.3 standing rule
reads), and read markers. Received messages can't diverge: each device receives its own copy.

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
revoked device, with the existing FR-018 removal semantics.

A `REVOKE` is honoured only within the scope of the pair it arrives on, as for `INTRO` (§4.3). On
contact C's pair it can remove only one of C's devices. On a self pair it can remove only a self
device. Labels are not secret, so without this rule any contact could cut pairs it doesn't own. The revoked device's bundle runs out
within H rounds, and its provider account can be dropped.

**Any of the user's devices may revoke another (decided).** A self-side `REVOKE` is applied when
it arrives from any self device. A stolen device can therefore also revoke the user's other devices.
The user recovers by linking them again from a device they still hold, and contacts see each
removal and addition (§4.3).

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

- **Device count to contacts (accepted).** Contacts see how many devices the user has and when one
  is added or removed. Option 1 would hide this, at the cost of §3's safety problems. Padding with
  dummy device pairs was considered and rejected: it spends pair budget and fan-out writes on
  every message.
- **Co-presence on a shared provider.** A provider serving two of a user's devices as unrelated
  accounts sees their presence patterns, which may correlate (same commute, same sleep). That is a
  statistical signal, not a protocol link. Separate providers remove it; the app may offer that.
- **Pair budget and digest size.** 2,051 pairs per device and a 4,096-bit digest (§4.2): an
  eightfold larger digest and PING state, in exchange for keeping 512 contacts.
- **Throughput.** Each device still makes one write per round. A message to a contact with m
  devices from a user with n devices takes m + n − 1 writes across the sender's rounds,
  stop-and-wait per pair.
- **Linking time.** §4.3: roughly 3.5 hours for 200 contact devices, about half that with batching.
- **Revocation by a stolen device.** Any self device may revoke the others (§4.7), so a thief can
  remove the user's remaining devices. The user re-links them; contacts are told of each change.
- **Trust in introductions.** A compromised device can introduce a device the user doesn't
  control, or substitute its own key shares while relaying an introduction. Contacts are told (§4.3), but a user who ignores the notice is exposed. The same holds
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
  - **Introductions:** concurrent linking on both sides, a contact added after linking, a third
    device linked (full self mesh), and two introducers racing on one pair each end with exactly
    one working pair per device pair. The introducer never holds anything
    from which a token of an introduced pair can be derived, at any point.
  - **Authority (negative):** an `INTRO` claiming self, or naming another contact, that arrives on
    a contact's pair is rejected. So is a `REVOKE` for a label outside the sending contact.
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

1. ~~**Hide device count from contacts?**~~ **Decided: no.** The residual is accepted (§6).
2. ~~**Who may revoke whom?**~~ **Decided: any of the user's devices** (§4.7).
3. **PQ for introductions.** Rely on the new pair's own PQ rekey between X and Y (§4.3), or relay
   an ML-KEM exchange through the introducer at about 17 chunks per pair.
4. **Research D6/D9 (Groove).** Groove's per-epoch OPRF key evolution and circuit tagging exist to
   make shared-identity devices safe without coordination. Option 3 needs neither for multi-device.
   D6 remains a candidate for epoch forward secrecy on its own merits.
5. ~~**Keep the introducer from learning the root.**~~ **Decided: yes.** The introducer relays
   X25519 public shares and never learns the pair's secret (§4.3).
6. ~~**FR-015/SC-005 against the pair cap.**~~ **Decided: raise the limits** and keep 512
   contacts (§4.2). Still open: the device cap of 4 and the final digest size, settled in T045.
