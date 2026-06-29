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

  private final class BuddyRuntime(val role: BuddyRole, contentRoot: Array[Byte]):
    // Stop-and-wait ARQ state (retry-safe-addressing.md, Stage 2). Addressing is now ROUND-DERIVED
    // (dirToken keyed by roundId, not a per-pair counter), so a reject/miss never recurs a token; the
    // head message is held and RETRANSMITTED each round under a fresh round token until the peer ACKs
    // it. The content sequence is engine-level (carried encrypted in the inner block, independent of
    // the ratchet's internal Ns).
    var nextSendSeq: Long = 0L // sequence to assign the NEXT new outgoing (head) message
    var headSeq: Long =
      ArqFrame.NoSeq // the in-flight head's sequence, or NoSeq if nothing in flight
    // The head's encrypted 256-byte wire, CACHED so a retransmit resubmits the SAME bytes under a fresh
    // round token rather than re-`encrypt`ing (which would advance the ratchet every round and push an
    // offline peer past MaxSkip). Re-encrypted only when the head changes or our ack (`highRecv`)
    // advances — both bounded by message count, not rounds — so `Ns` cannot grow unboundedly.
    var headWire: Array[Byte] = null
    var headWireAck: Long =
      ArqFrame.NoSeq // the highRecv baked into headWire (refresh the ack on change)
    var peerAcked: Long = ArqFrame.NoSeq // highest sequence the PEER has acknowledged from us
    var highRecv: Long =
      ArqFrame.NoSeq // highest sequence we have received (dedup + our outgoing ack)
    var ackOwed: Boolean = false // we were signaled by/received from the peer ⇒ owe it an ack
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
  // Send-side fairness cursor: with one write per round, rotate which sending buddy is (re)transmitted
  // so a slow/offline peer's held head cannot monopolize the slot and starve the others.
  private var sendCursor = 0L

  // A directional retrieval token: messages FROM `from` TO `to` in a given ROUND (T041c/retry-safe
  // addressing). Both parties derive the same token from the shared pair key + the (symmetric) role
  // pair + the public roundId. ROUND-DERIVED (not a per-pair counter): every wire write — real, cover,
  // retransmit — uses a fresh token, so a rejected submit or a missed/false-notified read can never
  // recur a token (GAP #2/#3). Sender and receiver rendezvous because notify is round-synchronized
  // (the sender signals round R; the receiver reads round R's token), and reliability comes from the
  // ARQ retransmit-until-acked rather than from the store persisting a fixed-counter slot.
  private def dirToken(
      pairKey: Array[Byte],
      from: BuddyRole,
      to: BuddyRole,
      roundId: Long
  ): Array[Byte] =
    RetrievalToken.derive(pairKey, from.toString, to.toString, roundId)

  // Frame-content encryption (T042 + the DH double ratchet). A wire frame is exactly the store's 256
  // bytes; the per-buddy `DoubleRatchet` owns the layout — nonce(12) ‖ AEAD(HK, header) ‖ AEAD(MK,
  // inner) — sealing both the encrypted DH header (so the store cannot link a chain's frames) and the
  // message. The plaintext block it seals per message is `DoubleRatchet.InnerSize` (so `sendMessage`
  // pads to that). The retrieval token + notify bit still derive from the retained `addrKey` (a
  // separate root); the content root is wiped, and each DH step mixes a fresh secret (PCS).

  // Stop-and-wait ARQ framing lives in [[ArqFrame]] (pure + unit-tested): the ratchet inner block is
  // [ackSeq(8)][msgSeq(8)][padded message], encrypted inside the ratchet so the store never sees it.
  // The message region is the remaining bytes.
  private val MsgPayloadInner =
    ArqFrame.PayloadBytes // padded-message region (InnerSize - 16 = 156B)

  /** Padded-empty payload for an ack-only frame (no message; the frame just carries the ackSeq). */
  private def emptyPayload: Array[Byte] =
    Frame.pad(Array.emptyByteArray, MsgPayloadInner).toOption.get

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
          MsgPayloadInner
        ) match // padded message region; the ARQ [ackSeq][msgSeq] header is prepended at send time
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
            // Round-derived addressing has no write/read barrier within a round, so we WRITE under this
            // round's token (`roundId`) but READ the PREVIOUS round's writes (`readRound`), which are
            // guaranteed complete — a one-round delivery latency. The notify digest and read token both
            // target `readRound`; the store write + outgoing signal target `roundId`.
            val readRound = roundId - 1
            // Poll notifications FIRST — before any send side effect. This emits `notified` (FR-004,
            // still before retrieval) and lets a transport reject the round up front (e.g. an
            // out-of-range round id) so an invalid round fails atomically without a half-applied send.
            // One PING digest fetch per round; the set bits say which buddies wrote in `readRound`.
            val digest = t.fetchDigest(readRound, NotifyDigest.labelTag(clientLabel))
            // Exactly ONE store write per round (cover traffic, FR-012), under a ROUND-DERIVED token so
            // a reject/retry never recurs (retry-safe addressing, GAP #2). Priority for the one write:
            //   1. (RE)TRANSMIT a queued head to a confirmed buddy that can send — the head is HELD and
            //      retransmitted each round under a fresh round token until the peer ACKs it. The
            //      encrypted wire is CACHED (re-encrypted only on head/ack change), so the ratchet does
            //      not advance per round (an offline peer stays within MaxSkip). Senders are rotated
            //      (sendCursor) so no slow peer's head monopolizes the slot.
            //   2. else an ACK-ONLY frame to a confirmed buddy we owe an ack (so it stops retransmitting),
            //      when we have no real frame for it (a real frame already carries our ack). Ack-only is
            //      encrypted FRESH each time so it always decodes (distinguishable from a cached-content
            //      retransmit, whose decrypt fails after the first delivery — see the receive path).
            //   3. else a COVER write under a fresh cover token.
            // The store sees one same-shaped 256-byte write per round either way (active/idle uniform).
            var realSubmitted = false
            var realSignal: Option[(Array[Byte], Array[Byte])] = None
            def confirmedSendable(pid: String): Option[(BuddyRuntime, BuddyRelationship)] =
              for
                rt <- runtime.get(pid)
                rel <- book.get(pid) if rel.state == BuddyState.Confirmed && rt.ratchet.canSend
              yield (rt, rel)
            // Sending buddies (non-empty outbox, can send), rotated fairly by sendCursor.
            val sendable = outbox.iterator
              .collect {
                case (pid, q) if q.nonEmpty =>
                  confirmedSendable(pid).map((rt, rel) => (pid, rt, rel, q))
              }
              .flatten
              .toVector
              .sortBy(_._1)
            val txTarget =
              if sendable.isEmpty then None
              else
                val tgt = sendable((Math.floorMod(sendCursor, sendable.size.toLong)).toInt)
                sendCursor += 1
                Some(tgt)
            val ackTarget = runtime.keysIterator
              .flatMap { pid =>
                if outbox.get(pid).exists(_.nonEmpty) then
                  None // a real frame to them carries the ack
                else
                  confirmedSendable(pid).collect { case (rt, rel) if rt.ackOwed => (pid, rt, rel) }
              }
              .nextOption()
            def submitWire(rt: BuddyRuntime, rel: BuddyRelationship, wire: Array[Byte]): Unit =
              if t.submit(dirToken(rel.addrKey, rt.role, peerRole(rt.role), roundId), wire) then
                rt.ackOwed = false // our outgoing frame carried our ack
                realSubmitted = true
                if rel.peerNotifyLabel.nonEmpty then
                  realSignal = Some((rel.peerNotifyLabel, rel.addrKey))
            txTarget match
              case Some((_, rt, rel, q)) =>
                if rt.headSeq == ArqFrame.NoSeq then
                  rt.headSeq = rt.nextSendSeq
                  rt.nextSendSeq += 1
                  rt.headWire = null
                // (Re)encrypt the head wire only when it's new or our ack advanced; otherwise resubmit
                // the cached bytes so the ratchet does not advance per retransmit.
                if rt.headWire == null || rt.headWireAck != rt.highRecv then
                  rt.headWire = rt.ratchet.encrypt(ArqFrame.encode(rt.highRecv, rt.headSeq, q.head))
                  rt.headWireAck = rt.highRecv
                submitWire(rt, rel, rt.headWire)
              case None =>
                ackTarget match
                  case Some((_, rt, rel)) =>
                    submitWire(
                      rt,
                      rel,
                      rt.ratchet.encrypt(ArqFrame.encode(rt.highRecv, ArqFrame.NoSeq, emptyPayload))
                    )
                  case None =>
                    coverCounter += 1
                    t.submit(
                      RetrievalToken.derive(coverKey, "cover", "", coverCounter),
                      coverFrame()
                    )
            // Exactly ONE notify signal per round (FR-012 cover traffic at the NOTIFY layer, mirroring
            // the single store write above): notify the PEER we just sent a real frame to, else emit a
            // DECOY to this client's void label that nobody fetches. Either way the untrusted host sees
            // one same-shaped (sealed) signal RPC per round, so notify timing/volume can't distinguish an
            // active client from an idle one. The bit is round-rotated (T041c) in both cases.
            // Labels are tagged to a FIXED width (NotifyDigest.labelTag) so a real and a decoy signal —
            // and signals to buddies whose raw labels differ in length — are byte-length identical on the
            // wire; otherwise the sealed-token size would leak active-vs-idle / which-buddy.
            realSignal match
              case Some((label, addrKey)) =>
                t.signal(roundId, NotifyDigest.labelTag(label), NotifyDigest.bit(addrKey, roundId))
              case None =>
                val void = voidNotifyLabel
                t.signal(roundId, NotifyDigest.labelTag(void), NotifyDigest.bit(void, roundId))
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
                .map(rel => (pid, rt, rel, NotifyDigest.bit(rel.addrKey, readRound)))
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
                  val b = NotifyDigest.bit(rel.addrKey, readRound);
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
              // Read this buddy's ROUND-DERIVED token (retry-safe addressing): a false notify or a
              // collision serves a token used at most once this round, so a miss can never recur it.
              t.retrieve(dirToken(rel.addrKey, peerRole(rt.role), rt.role, readRound)).foreach {
                wire =>
                  // Run the frame through the DH double ratchet: it trial-decrypts the encrypted header,
                  // performs a DH step + skipped-key handling as needed (PCS), and returns the inner
                  // block — or None for a carrier / a CACHED content retransmit we already consumed.
                  rt.ratchet.decrypt(wire) match
                    case None =>
                      // A frame WAS present but didn't decrypt: a cached CONTENT retransmit whose ratchet
                      // key we consumed on first delivery (ack-only frames are encrypted fresh and always
                      // decode, so they never land here). The peer is still retransmitting ⇒ we owe it a
                      // (re-)ack so it stops. (A genuine carrier here is harmless to re-ack.)
                      rt.ackOwed = true
                    case Some(inner) =>
                      // ARQ inner block: [ackSeq][msgSeq][padded message].
                      // 1) Consume the PEER's ack: it reports the peer's highest received sequence FROM
                      //    US, so once it covers our in-flight head, that head is delivered+acked — drop
                      //    it + clear its cached wire (advance-on-ack; stops our retransmits).
                      val ackSeq = ArqFrame.ackSeqOf(inner)
                      if ackSeq > rt.peerAcked then rt.peerAcked = ackSeq
                      if rt.headSeq != ArqFrame.NoSeq && rt.peerAcked >= rt.headSeq then
                        outbox.get(pid).filter(_.nonEmpty).foreach(q => dropHead(pid, q))
                        rt.headSeq = ArqFrame.NoSeq
                        rt.headWire = null
                      // 2) De-duplicate + deliver by sequence (a retransmit re-presents an already-seen
                      //    msgSeq; an ack-only frame carries NoSeq). Owe an ack ONLY for a content frame
                      //    (msgSeq != NoSeq) — never for an ack-only, so acks don't ping-pong.
                      val msgSeq = ArqFrame.msgSeqOf(inner)
                      if msgSeq != ArqFrame.NoSeq then
                        rt.ackOwed = true // received content ⇒ owe the peer an ack
                        if ArqFrame.isNewMessage(msgSeq, rt.highRecv) then
                          Frame
                            .unpad(ArqFrame.payloadOf(inner), MsgPayloadInner)
                            .toOption
                            .foreach { p =>
                              rt.highRecv = msgSeq // advance only on successful delivery
                              emit(EngineEvent.MessageReceived(pid, new String(p, UTF_8), roundId))
                            }
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
