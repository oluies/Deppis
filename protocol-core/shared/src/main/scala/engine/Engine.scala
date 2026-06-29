package engine

import buddy.Buddy
import buddy.Buddy.{BuddyBook, BuddyRelationship, BuddyState}
import frame.Frame
import handshake.Handshake
import privacy.Privacy
import schedule.Schedule
import token.RetrievalToken

import java.nio.charset.StandardCharsets.UTF_8
import scala.collection.mutable

/** The protocol engine (T019) — the single source of truth (Constitution VII) behind the narrow,
  * versioned API in `contracts/engine-api.md`. The Flutter UI holds presentation state only; ALL
  * protocol/crypto state lives here.
  *
  * This is pure cross-platform Scala: it compiles unchanged to the JVM (tested here with the real
  * JCA `Kdf`) and to Scala.js (where `Kdf` is provided per-platform). The JSON boundary
  * ([[Engine.handle]]) and the `@JSExportTopLevel` facade are what Dart talks to.
  *
  * Hard rules enforced (engine-api.md):
  *   - The engine NEVER returns key material or raw tokens to the caller (only `pairId` /
  *     `safetyNumber` leave the boundary; `pairKey` never does).
  *   - Every call carries `apiVersion`; a mismatch is refused (forward/backward-compat safety).
  *   - Errors carry a fixed `code` + a non-secret-dependent `message` (Constitution II).
  *
  * Real metadata privacy needs an attested backend; with no backend wired the engine reports the
  * dev privacy status, so the UI shows `DEV, NO METADATA PRIVACY` (FR-016, Constitution IV). */
object EngineApi:
  /** API version the engine speaks. The Dart bridge sends this on every call. */
  val Version: String = "1"

/** Add-friend role. The handshake is symmetric (both sides derive the same values from the shared
  * secret), so the role does not change the derivation; it is validated and recorded for clarity. */
enum BuddyRole:
  case Initiator, Responder

object BuddyRole:
  def parse(s: String): Either[EngineError, BuddyRole] = s match
    case "initiator" => Right(Initiator)
    case "responder" => Right(Responder)
    case _ => Left(EngineError("invalid_arg", "role must be initiator or responder"))

/** Fixed, non-secret-dependent error (Constitution II). */
final case class EngineError(code: String, message: String)

/** Engine → caller events (engine-api.md). No event ever carries key material. */
sealed trait EngineEvent
object EngineEvent:
  final case class BuddyConfirmed(pairId: String, safetyNumber: String) extends EngineEvent
  final case class MessageReceived(pairId: String, plaintext: String, at: Long) extends EngineEvent
  final case class Notified(roundId: Long) extends EngineEvent
  final case class PrivacyStatus(backend: String, metadataPrivate: Boolean, label: String)
      extends EngineEvent

/** Result of `addBuddy` — the comparable safety number for out-of-band comparison. NEVER the key. */
final case class AddBuddyResult(pairId: String, safetyNumber: String)

/** Per-round client decision from the schedule (`tick`). `kind`/`retrieve` only — no payload. */
final case class RoundDecision(roundId: Long, carrier: Boolean, retrieve: Boolean)

/** Stateful engine instance. Single-threaded by contract (one engine per client session); the JS
  * runtime is single-threaded and the JVM tests drive it from one thread.
  *
  * `transport` is the optional PONG/PING backend (T032a). With `None` the engine is purely local
  * (schedule decisions only, no delivery) — the dev/bundle-less default. With a [[RoundTransport]],
  * `tick` submits queued frames, polls notifications (emitting `notified` before retrieval, FR-004),
  * and retrieves delivered frames (emitting `messageReceived`). `clientLabel` is this client's notify
  * aggregation label — opaque to the engine; the backend uses it to answer "mail for me?". */
final class Engine(
    transport: Option[RoundTransport] = None,
    clientLabel: Array[Byte] = Array.emptyByteArray
):
  private var book = BuddyBook.empty
  private val outbox = mutable.Map.empty[String, Vector[Array[Byte]]]
  private val events = mutable.ArrayBuffer.empty[EngineEvent]
  // Per-buddy delivery runtime: the role fixes the token direction; counters are non-recurrent.
  private val runtime = mutable.Map.empty[String, BuddyRuntime]
  // Per-session cover-traffic key + counter. Cover (carrier) writes go to fresh, random-looking
  // tokens derived from this key, so a carrier round's store write is indistinguishable from a real
  // one (FR-012 cover traffic). The key never leaves the engine.
  private val coverKey = random.Rand.bytes(32)
  private var coverCounter = 0L // send-path cover frames
  private var coverReadCounter = 0L // fetch-path cover reads
  // A per-client VOID notify label for decoy signals: every round the engine emits exactly one notify
  // signal (FR-012 at the notify layer), real to a peer or a decoy to this label, so the untrusted host
  // sees uniform signal-RPC volume. Nobody fetches this label, so a decoy bit set in its digest is
  // harmless. Derived from the cover key (never leaves the engine; opaque to the host inside a sealed
  // token). A fresh array per use so a transport can't retain/mutate it.
  private def voidNotifyLabel: Array[Byte] = RetrievalToken.derive(coverKey, "notify-void", "", 0L)
  // Positive diagnostic for the unreachable orphan branch in `tick` (an outbox entry with no
  // runtime/book). Stays 0 in correct operation; a non-zero value means an internal invariant broke.
  private var orphanedDrops = 0L

  private final class BuddyRuntime(val role: BuddyRole, contentRoot: Array[Byte]):
    // ADDRESSING counters (which store slot) — separate from the content ratchet's internal Ns/Nr.
    // The role fixes the token direction; both stay non-recurrent.
    var sendCounter: Long = 0L
    var recvCounter: Long = 0L
    // The CONTENT ratchet: the full DH double ratchet with header encryption (post-compromise
    // security). The initiator can send immediately; the responder's sending chain opens only once it
    // has received the initiator's first frame (initiator-sends-first; see DoubleRatchet/dh-ratchet.md
    // §5). It OWNS the 256-byte wire framing (header + message), replacing the old per-direction
    // symmetric chains. `contentRoot` is consumed synchronously here, then wiped by the caller.
    val ratchet: DoubleRatchet = role match
      case BuddyRole.Initiator => DoubleRatchet.initInitiator(contentRoot)
      case BuddyRole.Responder => DoubleRatchet.initResponder(contentRoot)

  private def peerRole(r: BuddyRole): BuddyRole = r match
    case BuddyRole.Initiator => BuddyRole.Responder
    case BuddyRole.Responder => BuddyRole.Initiator

  // Per-buddy notify bit derivation lives in `NotifyDigest` (one source of truth; tests use it too).
  // Fairness cursor: when several buddies signal the SAME round, rotate which one is served so no
  // (e.g. higher-pairId) buddy is starved under the one-read-per-round limit.
  private var recvCursor = 0L

  // A directional retrieval token: messages FROM `from` TO `to` for the given counter. Both parties
  // derive the same token from the shared pair key + the (symmetric) role pair, so the receiver can
  // reconstruct exactly what the sender stored.
  private def dirToken(
      pairKey: Array[Byte],
      from: BuddyRole,
      to: BuddyRole,
      counter: Long
  ): Array[Byte] =
    RetrievalToken.derive(pairKey, from.toString, to.toString, counter)

  // Frame-content encryption (T042 + the DH double ratchet). A wire frame is exactly the store's 256
  // bytes; the per-buddy `DoubleRatchet` owns the layout — nonce(12) ‖ AEAD(HK, header) ‖ AEAD(MK,
  // inner) — sealing both the encrypted DH header (so the store cannot link a chain's frames) and the
  // message. The plaintext block it seals per message is `DoubleRatchet.InnerSize` (so `sendMessage`
  // pads to that). The retrieval token + notify bit still derive from the retained `addrKey` (a
  // separate root); the content root is wiped, and each DH step mixes a fresh secret (PCS).
  private val InnerSize = DoubleRatchet.InnerSize // the plaintext the ratchet seals per message

  /** Zero a key buffer in place (cross-platform; the forward-secrecy boundary depends on wiping old
    * key material so it cannot be recovered from memory). */
  private def wipe(a: Array[Byte]): Unit =
    var i = 0
    while i < a.length do
      a(i) = 0.toByte
      i += 1

  /** A cover (carrier) wire frame: 256 uniformly-random bytes. A real ratchet frame is a random nonce
    * followed by AEAD ciphertext+tag, which is computationally indistinguishable from random — so a
    * random block is a perfect cover (FR-012), byte-indistinguishable in size and entropy. */
  private def coverFrame(): Array[Byte] = random.Rand.bytes(DoubleRatchet.WireSize)

  /** The current build privacy status. Dev backend ⇒ not private ⇒ the mandatory dev label. */
  def privacyStatus: EngineEvent.PrivacyStatus =
    // The label reflects the ACTUAL backend (T058): a local-only engine (no transport) is dev; a
    // connected engine surfaces its transport's attestation-gated status, so the UI shows
    // `METADATA PRIVATE` only against a real, attested enclave backend (Constitution IV/IX).
    val s = transport
      .map(_.privacyStatus)
      .getOrElse(Privacy.BuildPrivacyStatus(Privacy.Backend.Dev, attestationPassed = false))
    EngineEvent.PrivacyStatus(s.backend.toString, s.metadataPrivate, s.label)

  /** Drain events emitted since the last call (engine → Dart event stream). */
  def drainEvents(): Seq[EngineEvent] =
    val out = events.toVector
    events.clear()
    out

  private def emit(e: EngineEvent): Unit = events += e

  /** Run the add-friend handshake. Derives `pairId`/`safetyNumber`/`pairKey` from the shared
    * secret (symmetric), records a Pending relationship, and returns ONLY the comparable values —
    * the derived `pairKey` never leaves the engine. */
  def addBuddy(
      sharedSecret: Array[Byte],
      role: BuddyRole,
      peerNotifyLabel: Array[Byte] = Array.emptyByteArray
  ): Either[EngineError, AddBuddyResult] =
    if sharedSecret.isEmpty then Left(EngineError("invalid_arg", "shared secret required"))
    else
      val init = Handshake.init(sharedSecret)
      // Forward-secrecy root split: derive the retained addressing root (tokens + notify bit) and the
      // content-chain root, then WIPE the raw pair key so the content root is not recomputable from
      // anything we keep. `addrKey` cannot derive `contentRoot` (different HMAC branch).
      val addrKey = KeySchedule.addrKey(init.pairKey)
      val contentRoot = KeySchedule.contentRoot(init.pairKey)
      wipe(init.pairKey)
      // `peerNotifyLabel` is the label the PEER fetches under (so we can fire their "mail waiting" when
      // we send them a real frame). Empty ⇒ local-only for this buddy. Cloned so the caller's array
      // can't mutate our copy.
      val rel =
        BuddyRelationship(
          init.pairId,
          init.safetyNumber,
          BuddyState.Pending,
          addrKey,
          peerNotifyLabel.clone()
        )
      book.add(rel) match
        case Right(nb) =>
          book = nb
          runtime(init.pairId) = BuddyRuntime(role, contentRoot) // seeds the per-direction chains
          wipe(contentRoot) // chains are seeded; the content root must not linger
          Right(AddBuddyResult(init.pairId, init.safetyNumber)) // no key material
        case Left(reason) =>
          wipe(contentRoot)
          wipe(addrKey) // not retained in a relationship on this path either
          // reason is a fixed, non-secret string ("duplicate buddy" / "buddy cap 512 reached").
          Left(EngineError("add_failed", reason))

  /** Confirm/reject a pairing after the out-of-band safety-number comparison. On match, emits
    * `buddyConfirmed`; on mismatch the relationship is removed and nothing is established. */
  def confirmBuddy(pairId: String, matched: Boolean): Either[EngineError, Unit] =
    book.confirm(pairId, matched) match
      case Right(nb) =>
        book = nb
        if matched then
          book.get(pairId).foreach(r => emit(EngineEvent.BuddyConfirmed(r.pairId, r.safetyNumber)))
        Right(())
      case Left(reason) => Left(EngineError("confirm_failed", reason))

  /** Remove a buddy. Stops future delivery (FR-018) without leaking prior existence — no event. */
  def removeBuddy(pairId: String): Either[EngineError, Unit] =
    book.remove(pairId) match
      case Right(nb) => book = nb; outbox.remove(pairId); runtime.remove(pairId); Right(())
      case Left(reason) => Left(EngineError("remove_failed", reason))

  /** Frame + enqueue a message for the next round to a confirmed buddy. Returns the queue depth;
    * never echoes the plaintext (Constitution II). Real delivery is layered on the backend. */
  def sendMessage(pairId: String, plaintext: String): Either[EngineError, Int] =
    book.get(pairId) match
      case Some(r) if r.state == BuddyState.Confirmed =>
        Frame.pad(
          plaintext.getBytes(UTF_8),
          InnerSize
        ) match // ratchet inner block (172B; sealed with the encrypted header into a 256B wire frame)
          case Right(fr) =>
            val q = outbox.getOrElse(pairId, Vector.empty) :+ fr
            outbox(pairId) = q
            Right(q.size)
          case Left(_) =>
            // Fixed message — length is derivable from plaintext, so do not report it.
            Left(EngineError("message_too_long", "message exceeds the frame payload limit"))
      case _ => Left(EngineError("unknown_pair", "no confirmed buddy for that pair"))

  /** Advance the client schedule by one round. Emits exactly one shape-identical plan: a real
    * frame if one is queued (for any buddy), else a carrier — the decision never reveals which.
    * Returns the (carrier?, retrieve) decision; the frame bytes stay inside the engine.
    *
    * With a [[RoundTransport]] this round also: submits the queued frame under its directional
    * retrieval token, polls "mail waiting?" and emits `notified` BEFORE retrieving (FR-004), then
    * retrieves any delivered frames and emits `messageReceived`. With no transport none of that
    * happens (the local-only default). */
  def tick(roundId: Long): Either[EngineError, RoundDecision] =
    val nextReal = outbox.collectFirst { case (pid, q) if q.nonEmpty => (pid, q) }
    // We only consume the plan's `kind`/`retrieve`/`roundId`; its built frame is UNUSED (the wire
    // frame is the encrypted one from `encryptFrame` below). So pass an empty sentinel payload to get
    // the Real-vs-Carrier decision without unpadding the real plaintext or building a stray frame.
    val plannerPayload = Option.when(nextReal.isDefined)(Array.emptyByteArray)
    Schedule.planRound(roundId, plannerPayload) match
      case Right(plan) =>
        val carrier: Boolean = transport match
          case None =>
            // Local-only: consume the queued frame (no delivery) — preserves prior behavior.
            nextReal.foreach { case (pid, q) => dropHead(pid, q) }
            plan.kind == Schedule.FrameKind.Carrier
          case Some(t) =>
            // Poll notifications FIRST — before any send side effect. This emits `notified` (FR-004,
            // still before retrieval) and, crucially, lets a transport reject the round up front
            // (e.g. an out-of-range round id) so an invalid round fails atomically without a
            // half-applied send (no submitted frame, no advanced counter).
            // One PING digest fetch per round (may also reject an out-of-range round atomically,
            // before any send side effect). The set bits say exactly which buddies signaled mail.
            val digest = t.fetchDigest(roundId, clientLabel)
            // Exactly ONE store write per round (cover traffic, FR-012): a real frame under its
            // outgoing token if one is queued, otherwise a carrier frame under a fresh random-looking
            // cover token. So the store-write trace (one 256-byte write per round, random 32-byte
            // token) is identical whether or not a real message is sent — active and idle clients are
            // indistinguishable. A real frame is dropped + advances the counter only on a successful
            // submit; on failure it stays queued and retries next round (its failed attempt is still
            // this round's one write — no extra write, no silent loss).
            //
            // KNOWN GAP — retry-safe addressing (pinned in RecurrenceGapsSpec): `sendCounter` advances
            // ONLY on a successful submit (to keep sender/receiver tokens in lockstep), so a REJECTED
            // submit makes the next round retry under the SAME outgoing token. An idle client always
            // writes a fresh cover token, so an untrusted store that rejects a write and then sees the
            // same token recur learns the client is actively retrying a real send — an FR-014 token
            // recurrence AND an active-vs-idle tell. Closing it needs round-id-derived addressing or a
            // bounded receiver-side skip window; until then the active-vs-idle claim below holds only
            // against a store that does not selectively reject writes.
            var realSubmitted = false
            // The peer to notify this round, if we actually sent them a real frame AND know their notify
            // label: (label, addrKey). Otherwise we emit a DECOY signal below — exactly one signal/round.
            var realSignal: Option[(Array[Byte], Array[Byte])] = None
            nextReal match
              case Some((pid, q)) if runtime.get(pid).exists(_.ratchet.canSend) =>
                (runtime.get(pid), book.get(pid)) match
                  case (Some(rt), Some(rel)) =>
                    // Seal the inner frame at the current ratchet position (peek, no advance — a failed
                    // submit must retry at the same position). The 256-byte wire carries the encrypted
                    // DH header + message.
                    val wire = rt.ratchet.encryptPending(q.head)
                    if t.submit(
                        dirToken(rel.addrKey, rt.role, peerRole(rt.role), rt.sendCounter),
                        wire
                      )
                    then
                      rt.ratchet
                        .commitSend() // advance + wipe the old chain key only on a real send
                      rt.sendCounter += 1
                      dropHead(pid, q)
                      realSubmitted = true
                      if rel.peerNotifyLabel.nonEmpty then
                        realSignal = Some((rel.peerNotifyLabel, rel.addrKey))
                  case _ =>
                    // Defensive: an outbox entry always has a runtime + book entry (sendMessage
                    // requires a confirmed buddy; removeBuddy clears both), so this is unreachable via
                    // the API. Drop the orphaned frame to avoid a stuck queue and record a POSITIVE
                    // diagnostic (orphanedDrops) — a break surfaces as a non-zero counter, not just a
                    // missing write. We do NOT emit a masking cover write that would hide the loss.
                    dropHead(pid, q)
                    orphanedDrops += 1
              case _ =>
                // Either nothing is queued, OR the only queued message is for a responder that cannot
                // send yet (no sending chain until it has received) — in both cases this round is a
                // carrier and any queued message simply waits. A 256-byte random-looking wire frame is
                // byte-indistinguishable from a real one, so holding a message looks like any idle round.
                coverCounter += 1
                t.submit(RetrievalToken.derive(coverKey, "cover", "", coverCounter), coverFrame())
            // Exactly ONE notify signal per round (FR-012 cover traffic at the NOTIFY layer, mirroring
            // the single store write above): notify the PEER we just sent a real frame to, else emit a
            // DECOY to this client's void label that nobody fetches. Either way the untrusted host sees
            // one same-shaped (sealed) signal RPC per round, so notify timing/volume can't distinguish an
            // active client from an idle one. The bit is round-rotated (T041c) in both cases.
            realSignal match
              case Some((label, addrKey)) =>
                t.signal(roundId, label, NotifyDigest.bit(addrKey, roundId))
              case None =>
                val void = voidNotifyLabel
                t.signal(roundId, void, NotifyDigest.bit(void, roundId))
            // Exactly ONE retrieve per round (the schedule's one-retrieve invariant, FR-012 fetch
            // path), NOTIFY-GUIDED per-buddy (FR-004). T041c (collision-free notify): each buddy's
            // notify bit is ROTATED per round (NotifyDigest.bit(addrKey, roundId)), so a collision
            // between two of this receiver's buddies is transient, not permanent. We serve a buddy ONLY
            // when its set bit is UNAMBIGUOUS this round — no OTHER active relationship of this client
            // maps to that bit — which makes the read a GUARANTEED hit (only the holder of the pair key could
            // have sealed that bit), so the read counter always advances and the read-token stream is
            // non-recurrent (FR-014) UNCONDITIONALLY over collisions. On an ambiguous round we cannot
            // tell which party signaled, so we serve none and issue a fresh cover read; the colliding
            // buddies re-signal next round, where rotation almost surely separates them (a bounded
            // ~1-round delivery delay under collision, never a token recurrence / leak).
            val confirmed = runtime.toSeq.flatMap { case (pid, rt) =>
              book
                .get(pid)
                .filter(_.state == BuddyState.Confirmed)
                .map(rel => (pid, rt, rel, NotifyDigest.bit(rel.addrKey, roundId)))
            }
            // How many of THIS client's ACTIVE relationships (Pending ∪ Confirmed — bounded by the 512
            // cap) map to each bit this round. Pending is included because a peer that confirmed first
            // signals during our confirm window. A confirmed candidate is safe to serve only if its bit
            // is unique across this set (else the set bit might be another party's, so serving the
            // confirmed buddy would miss and recur its token). Removed relationships are EXCLUDED so the
            // set stays bounded — they are retained forever for duplicate-add detection, and a peer that
            // keeps signaling long AFTER we removed it is the same counter-frozen-on-miss residual as the
            // rejected-submit gap, resolved by the same retry-safe addressing (see RecurrenceGapsSpec #2).
            val bitCount: Map[Int, Int] =
              book.relationships.iterator
                .filter(_.state != BuddyState.Removed)
                .foldLeft(Map.empty[Int, Int]) { (m, rel) =>
                  val b = NotifyDigest.bit(rel.addrKey, roundId);
                  m.updated(b, m.getOrElse(b, 0) + 1)
                }
            val candidates = confirmed.filter { case (_, _, _, b) => NotifyDigest.isSet(digest, b) }
            // Mail is waiting iff some buddy's bit is set (FR-004), even on an ambiguous round.
            if candidates.nonEmpty then emit(EngineEvent.Notified(roundId))
            val signaled =
              candidates.filter { case (_, _, _, b) => bitCount.getOrElse(b, 0) == 1 }.sortBy(_._1)
            if signaled.nonEmpty then
              // Serve one UNAMBIGUOUSLY-signaled buddy per round, ROTATING the start so co-signaling
              // buddies are not starved (the rest re-signal next round).
              val (pid, rt, rel, _) =
                signaled((Math.floorMod(recvCursor, signaled.size.toLong)).toInt)
              recvCursor += 1
              // Guaranteed hit (unambiguous set bit ⇒ that buddy signaled ⇒ its frame is present) ⇒
              // recvCounter advances ⇒ the next read token is fresh. No recurrence is possible.
              val c = rt.recvCounter
              t.retrieve(dirToken(rel.addrKey, peerRole(rt.role), rt.role, c)).foreach { wire =>
                rt.recvCounter += 1 // consumed (single-use) ⇒ advance regardless of decode outcome
                // Run the frame through the DH double ratchet: it trial-decrypts the encrypted header,
                // performs a DH step + skipped-key handling as needed (PCS), and returns the inner block
                // — or None for a carrier / non-matching frame, WITHOUT advancing the ratchet.
                rt.ratchet
                  .decrypt(wire)
                  .flatMap(inner => Frame.unpad(inner, InnerSize).toOption)
                  .foreach(p =>
                    emit(EngineEvent.MessageReceived(pid, new String(p, UTF_8), roundId))
                  )
              }
            else
              // No unambiguously-signaled buddy (idle OR an ambiguous collision round): a cover read
              // under a fresh token (one-read-per-round, fresh) — never a buddy's frozen read token.
              coverReadCounter += 1
              t.retrieve(RetrievalToken.derive(coverKey, "cover-read", "", coverReadCounter)): Unit
            // Report the round as a carrier unless a real frame was ACTUALLY submitted — a failed or
            // absent send is then indistinguishable from any other carrier round (a fail+retry does
            // not produce two "real-payload" rounds). (Full store-level cover traffic — a carrier
            // write every round so the store-write pattern itself is uniform — is the broader FR-012
            // integration, gated on Phase C.)
            !realSubmitted
        Right(RoundDecision(plan.roundId, carrier = carrier, plan.retrieve))
      case Left(reason) => Left(EngineError("tick_failed", reason))

  private def dropHead(pid: String, q: Vector[Array[Byte]]): Unit =
    val rest = q.drop(1)
    if rest.isEmpty then outbox.remove(pid) else outbox(pid) = rest

  /** Active (non-removed) buddy count — presentation helper; carries no key material. */
  def buddyCount: Int = book.size
  def confirmedCount: Int = book.confirmedCount

  /** Count of internal invariant breaks hit in `tick` (orphaned outbox entries). Always 0 in
    * correct operation — a non-zero value is a positive diagnostic that something is wrong. */
  def internalAnomalyCount: Long = orphanedDrops
