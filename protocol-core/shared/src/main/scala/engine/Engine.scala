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
  // Positive diagnostic for the unreachable orphan branch in `tick` (an outbox entry with no
  // runtime/book). Stays 0 in correct operation; a non-zero value means an internal invariant broke.
  private var orphanedDrops = 0L

  private final class BuddyRuntime(val role: BuddyRole, contentRoot: Array[Byte]):
    var sendCounter: Long = 0L
    var recvCounter: Long = 0L
    // Forward-secret content chains (the symmetric ratchet), direction-separated so the two parties'
    // chains line up: Alice's send chain == Bob's recv chain for the same direction.
    private var sendCK: Array[Byte] =
      KeySchedule.chain0(contentRoot, role.toString, peerRole(role).toString)
    private var recvCK: Array[Byte] =
      KeySchedule.chain0(contentRoot, peerRole(role).toString, role.toString)

    /** Message key for the next send WITHOUT advancing — a retry reuses the same chain position. */
    def sendKey(): Array[Byte] = KeySchedule.messageKey(sendCK)

    /** Ratchet the send chain forward and wipe the old chain key — call after a confirmed submit. */
    def advanceSend(): Unit =
      val old = sendCK
      sendCK = KeySchedule.nextChain(old)
      wipe(old)

    /** Message key for a received frame, ratcheting + wiping (each frame is consumed exactly once). */
    def nextRecvKey(): Array[Byte] =
      val mk = KeySchedule.messageKey(recvCK)
      val old = recvCK
      recvCK = KeySchedule.nextChain(old)
      wipe(old)
      mk

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

  // Frame-content encryption (T042). A wire frame is exactly the store's 256 bytes:
  // nonce(12) ‖ ChaCha20-Poly1305(inner). The inner plaintext block is therefore 228 bytes. Every
  // wire frame — real or carrier — is encrypted, so real and carrier are uniform random-looking
  // bytes (the last active-vs-idle distinguisher).
  private val WireSize = frame.Frame.Size // 256, the store's fixed size
  private val InnerSize = WireSize - aead.Aead.NonceBytes - aead.Aead.TagBytes // 228

  // The per-message AEAD key now comes from the forward-secret content ratchet (`BuddyRuntime`
  // sendKey/nextRecvKey, via `KeySchedule`), NOT a static derivation from the pair key. The retrieval
  // token + notify bit derive from the retained `addrKey` (a separate root); the content chain root is
  // wiped, so a device-state compromise cannot recover past message keys (forward secrecy).

  /** Zero a key buffer in place (cross-platform; the forward-secrecy boundary depends on wiping old
    * chain keys so they cannot be recovered from memory). */
  private def wipe(a: Array[Byte]): Unit =
    var i = 0
    while i < a.length do
      a(i) = 0.toByte
      i += 1

  /** Encrypt a 228-byte inner block into a 256-byte wire frame (`nonce ‖ ciphertext‖tag`). Wipes the
    * per-message key after use — it is a fresh, non-retained buffer, so zeroing it keeps a spent
    * message key from lingering on the heap (consistent with the chain-key wiping). */
  private def encryptFrame(key: Array[Byte], inner: Array[Byte]): Array[Byte] =
    val nonce = random.Rand.bytes(aead.Aead.NonceBytes)
    val ct = aead.Aead.seal(key, nonce, inner)
    wipe(key)
    nonce ++ ct

  /** Decrypt a 256-byte wire frame back to the 228-byte inner block; `None` on auth failure. Wipes
    * the per-message key after use (see `encryptFrame`). */
  private def decryptFrame(key: Array[Byte], wire: Array[Byte]): Option[Array[Byte]] =
    if wire.length != WireSize then None
    else
      val out =
        aead.Aead.open(key, wire.take(aead.Aead.NonceBytes), wire.drop(aead.Aead.NonceBytes))
      wipe(key)
      out

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
      // Forward-secrecy root split: derive the retained addressing root (tokens + notify bit) and the
      // content-chain root, then WIPE the raw pair key so the content root is not recomputable from
      // anything we keep. `addrKey` cannot derive `contentRoot` (different HMAC branch).
      val addrKey = KeySchedule.addrKey(init.pairKey)
      val contentRoot = KeySchedule.contentRoot(init.pairKey)
      wipe(init.pairKey)
      val rel = BuddyRelationship(init.pairId, init.safetyNumber, BuddyState.Pending, addrKey)
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
        ) match // 228-byte inner block (encrypted to 256)
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
            var realSubmitted = false
            nextReal match
              case Some((pid, q)) =>
                (runtime.get(pid), book.get(pid)) match
                  case (Some(rt), Some(rel)) =>
                    // Encrypt the inner frame under the current forward-secret content-chain key
                    // (peek, no advance — a failed submit must retry at the same chain position).
                    val wire = encryptFrame(rt.sendKey(), q.head)
                    if t.submit(
                        dirToken(rel.addrKey, rt.role, peerRole(rt.role), rt.sendCounter),
                        wire
                      )
                    then
                      rt.advanceSend() // ratchet forward + wipe the old chain key only on a real send
                      rt.sendCounter += 1
                      dropHead(pid, q)
                      realSubmitted = true
                  case _ =>
                    // Defensive: an outbox entry always has a runtime + book entry (sendMessage
                    // requires a confirmed buddy; removeBuddy clears both), so this is unreachable via
                    // the API. Drop the orphaned frame to avoid a stuck queue and record a POSITIVE
                    // diagnostic (orphanedDrops) — a break surfaces as a non-zero counter, not just a
                    // missing write. We do NOT emit a masking cover write that would hide the loss.
                    dropHead(pid, q)
                    orphanedDrops += 1
              case None =>
                coverCounter += 1
                // Carrier: encrypt an all-zero inner block under a fresh RANDOM key (never decrypted)
                // ⇒ a 256-byte random-looking wire frame, byte-indistinguishable from a real one.
                val coverWire =
                  encryptFrame(random.Rand.bytes(aead.Aead.KeyBytes), Frame.carrier(InnerSize))
                t.submit(RetrievalToken.derive(coverKey, "cover", "", coverCounter), coverWire)
            // Exactly ONE retrieve per round (the schedule's one-retrieve invariant, FR-012 fetch
            // path), NOTIFY-GUIDED per-buddy (FR-004): read EXACTLY the buddy whose digest bit is set
            // this round. Because that buddy's message is actually present, the read is a hit and its
            // counter advances — so the per-round read-token stream is non-recurrent (FR-014) for ANY
            // buddy count, active or idle. When no buddy's bit is set, a cover read under a fresh
            // token keeps the fetch trace one-read-per-round.
            val signaled = runtime.toSeq
              .flatMap { case (pid, rt) =>
                book.get(pid).filter(_.state == BuddyState.Confirmed).map(rel => (pid, rt, rel))
              }
              .filter { case (_, _, rel) =>
                NotifyDigest.isSet(digest, NotifyDigest.bit(rel.addrKey))
              }
              .sortBy(_._1) // stable order; the cursor below rotates fairly within it
            if signaled.nonEmpty then
              emit(EngineEvent.Notified(roundId)) // some buddy has mail (FR-004)
            if signaled.nonEmpty then
              // Serve one signaled buddy per round, ROTATING the start so co-signaling buddies are
              // not starved (the rest re-signal next round — T041c covers the multi-sender edge).
              val (pid, rt, rel) = signaled((Math.floorMod(recvCursor, signaled.size.toLong)).toInt)
              recvCursor += 1
              // Non-recurrence note: a signaled buddy normally HAS its message present (hit ⇒
              // recvCounter advances ⇒ next read token is fresh). It only fails to advance on a
              // birthday-rate bit COLLISION (a wrong buddy signaled) — so non-recurrence is
              // conditional on collision-freedom, which the T041c bit-lease makes unconditional.
              val c = rt.recvCounter
              t.retrieve(dirToken(rel.addrKey, peerRole(rt.role), rt.role, c)).foreach { wire =>
                rt.recvCounter += 1 // consumed (single-use) ⇒ advance regardless of decode outcome
                // Decrypt under the next forward-secret recv-chain key (ratchets + wipes), then unpad.
                decryptFrame(rt.nextRecvKey(), wire)
                  .flatMap(inner => Frame.unpad(inner, InnerSize).toOption)
                  .foreach(p =>
                    emit(EngineEvent.MessageReceived(pid, new String(p, UTF_8), roundId))
                  )
              }
            else
              // No buddy signaled: a cover read under a fresh token (one-read-per-round, fresh).
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
