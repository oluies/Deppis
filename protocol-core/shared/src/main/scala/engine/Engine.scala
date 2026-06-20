package engine

import buddy.Buddy
import buddy.Buddy.{BuddyBook, BuddyRelationship, BuddyState}
import frame.Frame
import handshake.Handshake
import privacy.Privacy
import schedule.Schedule

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
    case _           => Left(EngineError("invalid_arg", "role must be initiator or responder"))

/** Fixed, non-secret-dependent error (Constitution II). */
final case class EngineError(code: String, message: String)

/** Engine → caller events (engine-api.md). No event ever carries key material. */
sealed trait EngineEvent
object EngineEvent:
  final case class BuddyConfirmed(pairId: String, safetyNumber: String)             extends EngineEvent
  final case class MessageReceived(pairId: String, plaintext: String, at: Long)     extends EngineEvent
  final case class Notified(roundId: Long)                                          extends EngineEvent
  final case class PrivacyStatus(backend: String, metadataPrivate: Boolean, label: String) extends EngineEvent

/** Result of `addBuddy` — the comparable safety number for out-of-band comparison. NEVER the key. */
final case class AddBuddyResult(pairId: String, safetyNumber: String)

/** Per-round client decision from the schedule (`tick`). `kind`/`retrieve` only — no payload. */
final case class RoundDecision(roundId: Long, carrier: Boolean, retrieve: Boolean)

/** Stateful engine instance. Single-threaded by contract (one engine per client session); the JS
  * runtime is single-threaded and the JVM tests drive it from one thread. */
final class Engine:
  private var book                 = BuddyBook.empty
  private val outbox               = mutable.Map.empty[String, Vector[Array[Byte]]]
  private val events               = mutable.ArrayBuffer.empty[EngineEvent]

  /** The current build privacy status. Dev backend ⇒ not private ⇒ the mandatory dev label. */
  def privacyStatus: EngineEvent.PrivacyStatus =
    val s = Privacy.BuildPrivacyStatus(Privacy.Backend.Dev, attestationPassed = false)
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
  def addBuddy(sharedSecret: Array[Byte], role: BuddyRole): Either[EngineError, AddBuddyResult] =
    if sharedSecret.isEmpty then Left(EngineError("invalid_arg", "shared secret required"))
    else
      val init = Handshake.init(sharedSecret)
      val rel  = BuddyRelationship(init.pairId, init.safetyNumber, BuddyState.Pending, init.pairKey)
      book.add(rel) match
        case Right(nb) =>
          book = nb
          Right(AddBuddyResult(init.pairId, init.safetyNumber)) // no pairKey
        case Left(reason) =>
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
      case Right(nb)    => book = nb; outbox.remove(pairId); Right(())
      case Left(reason) => Left(EngineError("remove_failed", reason))

  /** Frame + enqueue a message for the next round to a confirmed buddy. Returns the queue depth;
    * never echoes the plaintext (Constitution II). Real delivery is layered on the backend. */
  def sendMessage(pairId: String, plaintext: String): Either[EngineError, Int] =
    book.get(pairId) match
      case Some(r) if r.state == BuddyState.Confirmed =>
        Frame.pad(plaintext.getBytes(UTF_8)) match
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
    * Returns only the (carrier?, retrieve) decision; the frame bytes stay inside the engine. */
  def tick(roundId: Long): Either[EngineError, RoundDecision] =
    val nextReal = outbox.collectFirst { case (pid, q) if q.nonEmpty => (pid, q) }
    val payload  = nextReal.map { case (_, q) => Frame.unpad(q.head).getOrElse(Array.emptyByteArray) }
    Schedule.planRound(roundId, payload) match
      case Right(plan) =>
        nextReal.foreach { case (pid, q) =>
          val rest = q.drop(1)
          if rest.isEmpty then outbox.remove(pid) else outbox(pid) = rest
        }
        Right(RoundDecision(plan.roundId, carrier = plan.kind == Schedule.FrameKind.Carrier, plan.retrieve))
      case Left(reason) => Left(EngineError("tick_failed", reason))

  /** Active (non-removed) buddy count — presentation helper; carries no key material. */
  def buddyCount: Int = book.size
  def confirmedCount: Int = book.confirmedCount
