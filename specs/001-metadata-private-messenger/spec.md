# Feature Specification: Metadata-Private Messenger

**Feature Branch**: `001-metadata-private-messenger`

**Created**: 2026-06-18

**Status**: Draft

**Input**: Build a text messenger whose primary goal is hiding who talks to whom from an
observer who sees all network traffic and can run some of the servers. Content end-to-end
encryption is assumed; the harder target is the metadata.

## Overview

This product is a text messenger whose **primary goal is hiding communication metadata** —
which of a user's contacts is messaging them, and when — from an observer who can watch all
network traffic and operate some of the servers. End-to-end content encryption is assumed;
the distinctive, harder property is concealing the *pattern* of communication, not only its
contents.

Two people become **buddies** once, out of band, and from then on exchange messages on a
schedule each controls. A user is told that *some* contact has a message waiting without the
system learning *which* contact; the user retrieves on their own schedule and can hold many
conversations at once. The product works when buddies are offline, across a user's several
devices, and with the help of an untrusted service provider, while remaining
indistinguishable — to a network observer — from a user who is merely idle.

## Metadata Protected vs. Leaked *(mandatory — Constitution Principle III)*

Stated per the trust assumptions chosen in planning. The MVP labeling rule (Constitution
Principle IV) governs how truthfully each build advertises these.

**Protected (target guarantees, once the real privacy backend is in place):**

- Whether any two users are buddies (the social graph).
- Which contact is sending to a given user at a given time.
- Whether a user is actively conversing or idle.
- Past contact lists and past message contents, even after a device is compromised
  (forward secrecy).
- The user's identity behind an untrusted service provider, even if that provider is
  compromised.

**Leaked / out of protected scope (must be stated plainly in each phase README):**

- That a person *uses the service at all*, and the coarse volume of their participation
  (cover traffic makes activity uniform, not invisible).
- Message timing and size only to the precision the fixed round schedule and fixed message
  size allow; these are public parameters, not secrets.
- Anything a build using the **dev** store or **single-shuffler** stub claims: such builds
  provide **no metadata privacy** and MUST say so (Principle IV).
- Residual trust: the integrity of the chosen privacy backend (an enclave, or a fraction of
  honest mixnet servers) and of the verifier / reference-value log. Side channels, rollback,
  and traffic-analysis outside the stated model are out of scope unless explicitly mitigated.

## Clarifications

### Session 2026-06-18

- Q: Which anonymity backend is the first real target (the other is stubbed)? →
  A: **PingPong enclave** — enclave-based oblivious store + notification, trust an enclave
  vendor + attestation, lower latency. The Groove mixnet is stubbed.
- Q: Is real metadata privacy in scope for the MVP, or does the MVP ship the full UX over a
  dev backend that provides none? → A: **Real metadata privacy IS in scope for the MVP.** The
  first shippable release is gated on the real PingPong enclave store and its attestation
  flow being in place (build Phases A→B→C, but the MVP release = through Phase C, not before).
  The dev store survives only as a pluggable test/dev implementation and is always labeled
  `DEV, NO METADATA PRIVACY`; it is never a shippable release.
  *(Note: this deliberately tightens the original block-4 phasing, which shipped a dev backend
  first.)*
- Q: Which size/latency/buddy targets should the protocol be dimensioned for? → A:
  **PingPong-style** — 256-byte messages, up to 512 buddies per user, minute-order latency
  (single-digit rounds).
- Q: How does the Flutter UI reach the Scala protocol engine? → A: **Server uses Akka/Pekko
  actors; frontend is Flutter.** Servers are JVM Scala on Pekko/Akka. `protocol-core` remains
  the single cross-compiled source of truth (Constitution VII); the Flutter client drives it
  via the Scala.js-compiled engine over a thin platform channel (the localhost Scala-sidecar
  alternative is recorded but not selected).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Add a buddy once, out of band (Priority: P1)

Two users establish a one-time mutual relationship by exchanging a shared secret out of band
— scanning a QR code in person, or comparing a safety number over an existing trusted
channel — exactly as Signal does. After this single step, the pair can message indefinitely;
no further setup or re-introduction is required.

**Why this priority**: Buddyship is the root of every other capability. Without a correct,
one-time, mutually authenticated pairing there is no relationship to protect, and the
direction of the notification credential (receiver → sender) that prevents flooding cannot be
established.

**Independent Test**: Two fresh users complete the out-of-band exchange and each sees the
other listed as a confirmed buddy with a matching safety number; tampering with the exchanged
secret causes the safety-number comparison to fail and the pairing to be rejected.

**Acceptance Scenarios**:

1. **Given** two users who have never paired, **When** they exchange the shared secret out of
   band and both confirm the safety number, **Then** each user's app lists the other as a
   confirmed buddy and they can exchange messages.
2. **Given** an attacker who alters the exchanged secret in transit, **When** the users
   compare safety numbers, **Then** the comparison does not match and the pairing is refused.
3. **Given** two users already buddies, **When** they attempt to add each other again,
   **Then** the system recognizes the existing relationship rather than creating a duplicate.

---

### User Story 2 - Be notified that *someone* wrote, without revealing who (Priority: P1)

A user receives a notification that one or more of their contacts has a message waiting,
**without the system learning which contact**. The user then retrieves messages on a schedule
they control, rather than being dialed into a specific conversation.

**Why this priority**: This notify-before-retrieval model is the core metadata-privacy
behavior and the central usability advance over dial-before-converse: it is what lets a user
hold several conversations at once and fetch on their own time.

**Independent Test**: A user with several buddies receives one message from one buddy; the
user is notified that mail is waiting; an observer of the notification cannot determine which
buddy sent it; the user retrieves and reads the message on their own schedule.

**Acceptance Scenarios**:

1. **Given** a user with multiple buddies and one incoming message, **When** the notification
   is delivered, **Then** the user learns that a message is waiting but the system does not
   learn which buddy it is from.
2. **Given** a notified user, **When** the user runs their next scheduled retrieval, **Then**
   they receive the waiting message(s).
3. **Given** a user with no incoming messages, **When** a round elapses, **Then** the user's
   notification and retrieval activity is indistinguishable from the case where a message was
   waiting.

---

### User Story 3 - Hold several conversations at once, never blocked (Priority: P1)

A user can participate in multiple conversations simultaneously and is never forced to finish
or close one conversation before another can make progress.

**Why this priority**: Concurrency without blocking is the usability property that makes the
product feel like a normal messenger rather than a one-call-at-a-time channel; it is the
explicit improvement the notify-before-retrieval model provides.

**Independent Test**: A user is buddies with three people who all message within the same
round; the user receives all three conversations' messages and can reply to each, with no
conversation blocked waiting on another.

**Acceptance Scenarios**:

1. **Given** a user with three active conversations, **When** all three buddies send within
   one round, **Then** the user can retrieve and reply to all three without ordering
   constraints between them.
2. **Given** an in-progress conversation, **When** a new buddy sends a first message,
   **Then** the new conversation proceeds without interrupting or waiting on the existing one.

---

### User Story 4 - Send to and catch up while offline (Priority: P2)

A user can send a message to a buddy who is currently offline, and that buddy retrieves it
later. A user who goes offline can catch up on everything addressed to them after they return.

**Why this priority**: Asynchronous delivery is table stakes for a real messenger and a
precondition for mobile use, but it depends on the buddy and notification mechanics of P1.

**Independent Test**: User A sends to offline User B; B comes online later and retrieves the
message; B then goes offline while several messages arrive and, on return, retrieves all of
them in order.

**Acceptance Scenarios**:

1. **Given** buddy B is offline, **When** A sends a message, **Then** the message is held and
   delivered when B next retrieves.
2. **Given** a user who was offline while multiple messages arrived, **When** they return and
   retrieve, **Then** they receive all waiting messages.

---

### User Story 5 - Use several devices via an untrusted helper (Priority: P2)

A user runs the app on several devices. An untrusted service provider buffers messages and
takes part in the privacy protocol on the user's behalf, so the user's phone need not be
online constantly. Compromising the service provider must not reveal the user's contacts or
activity, and two of the user's own devices that cannot reach each other must not, between
them, leak the user by sending duplicate or conflicting traffic.

**Why this priority**: Multi-device with offline tolerance is what makes the product usable on
a phone, but it layers on top of the core single-device privacy behavior and adds the hardest
non-coordination requirement.

**Independent Test**: A user's laptop and phone both participate through the service provider;
messages sent to the user appear on both devices; an operator with full visibility into the
service provider cannot determine the user's buddies or whether they are active; the two
devices, without communicating directly, never emit traffic that distinguishes the user.

**Acceptance Scenarios**:

1. **Given** a user with two devices and an untrusted service provider, **When** a buddy
   messages the user, **Then** the message is available on both devices.
2. **Given** a fully compromised service provider, **When** it inspects everything it stores
   and relays, **Then** it cannot determine the user's contacts or whether the user is active.
3. **Given** two of the user's devices that cannot reach each other, **When** both participate
   in the same round, **Then** their combined traffic does not reveal that they belong to the
   same user.

---

### User Story 6 - Look identical whether chatting or idle (Priority: P2)

Whether two users are buddies, and whether a user is actively chatting or merely idle, looks
the same to a network observer. Cover traffic and a fixed interaction pattern provide this
indistinguishability.

**Why this priority**: Indistinguishability is what upgrades "the contents are hidden" to
"the relationship and the activity are hidden," which is the product's reason to exist; it
sits at P2 because it is meaningful only once real messages flow (P1).

**Independent Test**: Two observation traces — one of a user in an active conversation, one of
the same user idle with no real messages — are statistically indistinguishable to an observer
of network timing and volume.

**Acceptance Scenarios**:

1. **Given** a user who is actively conversing and a user who is idle, **When** an observer
   compares their network traffic over equal periods, **Then** the observer cannot reliably
   tell which is which.
2. **Given** any user in any round, **When** they have no real message to send, **Then** they
   still emit the same shape of traffic as a user who does.

---

### User Story 7 - Survive device compromise without losing the past (Priority: P2)

If a device is later compromised, the attacker still cannot decrypt past messages or recover
the past contact list.

**Why this priority**: Forward secrecy bounds the damage of the most realistic real-world
failure (a lost or seized device); it is essential but builds on the key-management
established by earlier stories.

**Independent Test**: After capturing all current key material on a device, an attacker is
given previously recorded ciphertext and cannot recover earlier message contents or the
historical list of contacts.

**Acceptance Scenarios**:

1. **Given** an attacker who fully compromises a device now, **When** they attempt to decrypt
   messages from before the compromise, **Then** they cannot.
2. **Given** the same compromise, **When** the attacker attempts to reconstruct contacts the
   user had before the compromise window, **Then** they cannot.

---

### Edge Cases

- A sender attempts to flood a user with notifications, or to forge a notification as though
  from another contact — the system MUST prevent this (the notification credential is issued
  by the receiver to the sender at add-buddy time and only lets the sender flip its own bit).
- A user removes a buddy — subsequent messages from that ex-buddy MUST NOT reach the user, and
  the removal MUST NOT itself reveal to an observer that a relationship existed.
- A message is sent to a buddy who never comes back online — the system MUST bound how long
  undelivered messages are retained without that retention leaking who the sender was.
- Two devices of the same user reconnect after a partition with divergent state — the system
  MUST reconcile without emitting traffic that distinguishes the user.
- A round is missed (device asleep, no connectivity) — the user MUST be able to catch up on a
  later round without the gap revealing real-vs-idle activity.
- The same retrieval credential is presented twice — the system MUST treat retrieval
  credentials as single-use (non-recurrent).
- A user reaches the maximum number of buddies — the system MUST handle the limit gracefully
  and predictably (target set in planning).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST let two users become buddies through a single out-of-band exchange
  of a shared secret (QR scan or safety-number comparison), with mutual authentication, and
  MUST reject the pairing if the comparison does not match.
- **FR-002**: Adding a buddy MUST be the only per-pair setup step and MUST occur exactly once
  per pair; the system MUST recognize and not duplicate an existing relationship.
- **FR-003**: At add-buddy time, the **receiver** MUST issue to the **sender** a notification
  credential that lets the sender signal "I have a message for you" and nothing more — a
  sender MUST NOT be able to forge another contact's signal or send more than its allotted
  signal (anti-flooding, anti-impersonation).
- **FR-004**: System MUST notify a user that one or more contacts have a message waiting
  **without the system learning which contact**.
- **FR-005**: Users MUST retrieve waiting messages on a schedule they control, rather than
  being bound into a specific conversation at notification time.
- **FR-006**: A user MUST be able to participate in multiple conversations concurrently and
  MUST NOT be blocked on one conversation in order to progress another.
- **FR-007**: System MUST allow sending to an offline buddy and MUST deliver the message when
  that buddy next retrieves.
- **FR-008**: A user who is offline MUST be able to catch up on all messages addressed to them
  after returning.
- **FR-009**: System MUST support a single user operating multiple devices.
- **FR-010**: An untrusted service provider MUST be able to buffer messages and participate in
  the privacy protocol on the user's behalf so the user's device need not be continuously
  online; compromising the service provider MUST NOT reveal the user's contacts or activity.
- **FR-011**: Two of a user's own devices that cannot communicate directly MUST NOT, between
  them, emit traffic that links them to the same user (no duplicate/conflicting traffic that
  de-anonymizes).
- **FR-012**: System MUST make an actively-conversing user and an idle user indistinguishable
  to a network observer, using cover traffic and a fixed interaction pattern; per-round
  traffic shape MUST NOT depend on whether a real message exists.
- **FR-013**: System MUST provide forward secrecy: compromising a device MUST NOT allow
  decryption of past messages or recovery of the past contact list.
- **FR-014**: Retrieval credentials MUST be single-use (non-recurrent); presenting one twice
  MUST NOT succeed or leak.
- **FR-015**: System MUST enforce a maximum number of buddies per user — target **512** — and
  behave predictably at the limit.
- **FR-015a**: Messages MUST be carried in fixed-size frames of **256 bytes** (payloads are
  padded to this size); frame size MUST NOT vary with real content length.
- **FR-016**: Every build MUST truthfully signal its privacy status: a build lacking the real
  privacy backend MUST present a "no metadata privacy" label in code, logs, and UI, and MUST
  NOT advertise any metadata-privacy guarantee.
- **FR-017**: Each release MUST document, in plain words, exactly what metadata it protects
  and what it leaks under the stated trust assumptions.
- **FR-018**: A user MUST be able to remove a buddy such that future messages from that
  ex-buddy no longer reach them, without the removal revealing to an observer that a
  relationship existed.

### Out of Scope (future work — architecture MUST leave room)

- **OOS-001**: Voice and video calling.
- **OOS-002**: Large media attachments.
- **OOS-003**: Group chats.

These are explicitly deferred; the design must not foreclose them, but v1 delivers
text messaging only.

### Key Entities *(include if feature involves data)*

- **User**: A person using the service, potentially across several devices. Has a set of
  buddies and a controllable retrieval schedule.
- **Device**: One installation belonging to a user; participates in rounds, possibly via the
  service provider.
- **Buddy relationship**: A one-time, mutually authenticated, symmetric link between two
  users, the root of all messaging between them; carries the per-pair notification
  credential direction (receiver → sender).
- **Notification credential**: A receiver-issued, sender-held token that lets a sender signal
  "message waiting" for that receiver and nothing more.
- **Message**: A text payload addressed from one buddy to another, content-encrypted,
  retrievable asynchronously via a single-use retrieval credential.
- **Retrieval credential**: A single-use (non-recurrent) token that authorizes fetching one
  waiting message without linking the fetch to the sender.
- **Round**: The fixed-interval unit of interaction in which notification, sending, and
  retrieval occur uniformly for all participants.
- **Service provider**: An untrusted helper that buffers messages and participates in the
  protocol for a user's devices; never trusted for privacy.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user on a laptop and a user on a phone can exchange messages with latency on
  the order of one minute (single-digit rounds), end to end.
- **SC-002**: Given a user with multiple buddies, a passive network observer cannot determine
  which buddy is messaging the user better than random guessing among the user's buddies,
  subject to the trust assumptions chosen in planning.
- **SC-003**: An observer comparing equal-length traces of an actively-conversing user and an
  idle user cannot distinguish them better than chance.
- **SC-004**: A new pair of users can complete the one-time add-buddy step in under two
  minutes, including the out-of-band comparison.
- **SC-005**: A user can hold simultaneous conversations with up to the full set of their
  buddies (target 512) with no conversation blocking another.
- **SC-006**: Messages sent to an offline buddy are delivered on the buddy's next retrieval in
  100% of cases within the configured retention window.
- **SC-007**: After full compromise of a device's current key material, zero past messages and
  zero past contacts are recoverable from previously recorded traffic.
- **SC-008**: Compromise of the service provider yields zero of the user's buddies and no
  determination of whether the user is active.
- **SC-009**: Every shipped build correctly displays its privacy status; no build lacking the
  real backend presents itself as private (100% compliance, enforced in review).

## Assumptions

- Message content end-to-end encryption is assumed as a baseline; the differentiator is
  metadata privacy, not content secrecy.
- Out-of-band buddy setup assumes users can scan a QR code in person or compare a safety
  number over a channel they already trust, as in Signal.
- Numeric targets are resolved (see Clarifications): 256-byte fixed message frames, up to 512
  buddies per user, minute-order (single-digit-round) latency. The exact round interval is a
  planning tuning parameter consistent with minute-order latency.
- The first real privacy backend is the **PingPong enclave** store + attestation; the Groove
  mixnet is stubbed. Real metadata privacy is in scope for the MVP (the first shippable
  release is gated on the enclave backend + attestation), per the Clarifications.
- A network observer can see all traffic and may operate some servers; the privacy guarantee
  is stated relative to the specific backend's trust model chosen in planning.
- The first version targets text messaging only; voice, video, large media, and group chats
  are deferred but must not be architecturally foreclosed.
- Until the real privacy backend and its attestation are in place, builds are development
  builds that provide no metadata privacy and are labeled as such.
