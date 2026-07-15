package engine

import buddy.Buddy
import buddy.Buddy.{BuddyBook, BuddyRelationship, BuddyState}
import frame.Frame
import handshake.Handshake
import kem.HybridKem
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

/** Result of `addBuddy` — the comparable safety number for out-of-band comparison. NEVER a private
  * key. `kemPublicKey`/`kemCiphertext`/`kemConfirmTag` are PUBLIC hybrid-KEM pairing-prekey material
  * (public key, ciphertext, and the responder's `/r` key-confirmation tag — none are secrets) the app
  * carries out of band to the peer: an initiator ⇒ `kemPublicKey`; a PQ responder ⇒ `kemCiphertext` +
  * `kemConfirmTag` (the responder's `"ks/pq-confirm/r"` tag — see `KeySchedule.pqConfirmTagResponder`).
  * All are absent on the classical (non-PQ) path. See [[Engine.addBuddy]]. */
final case class AddBuddyResult(
    pairId: String,
    safetyNumber: String,
    kemPublicKey: Option[Array[Byte]] = None,
    kemCiphertext: Option[Array[Byte]] = None,
    kemConfirmTag: Option[Array[Byte]] = None
)

/** Result of `confirmBuddy`. On the PQ INITIATOR completion path it carries `initiatorConfirmTag` —
  * the initiator's `"ks/pq-confirm/i"` tag (PUBLIC; see `KeySchedule.pqConfirmTagInitiator`) — which
  * the app relays out of band to the responder so the responder can constant-time verify it and ALSO
  * fail closed on KEM tampering (bidirectional confirmation, US7). Absent (`None`) on every other path
  * (responder completion, classical, mismatch). NEVER key material. */
final case class ConfirmResult(
    initiatorConfirmTag: Option[Array[Byte]] = None
)

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
  // Post-quantum pairing prekey (US7): an INITIATOR that opts into the PQ path generates a hybrid-KEM
  // keypair at `addBuddy` and DEFERS seeding its ratchet until the responder's ciphertext arrives at
  // `confirmBuddy`. Until then it parks the KEM SECRET key + the base content root here, keyed by
  // pairId. Both are secret byte arrays and are WIPED on completion, mismatch, removeBuddy, and any
  // error path (Constitution II) — the map is the only place an initiator's un-completed prekey secret
  // lives, so wiping on removal from it is the whole forward-secrecy boundary for this state.
  private val pendingPq = mutable.Map.empty[String, PendingPq]
  // Post-quantum pairing prekey (US7), RESPONDER side: a PQ responder `encaps`es and SEEDS its ratchet
  // at `addBuddy` but stays in a PENDING-confirm state — it does NOT emit `BuddyConfirmed` until it has
  // verified the INITIATOR's `"ks/pq-confirm/i"` tag. Until then it parks the EXPECTED initiator tag
  // (`KeySchedule.pqConfirmTagInitiator(rootP)`, precomputed while `rootP` is live) here, keyed by
  // pairId. This is the responder half of bidirectional confirmation: if an attacker swaps the
  // initiator's `kemPublicKey` in transit, the responder encapsulates to the wrong key, so the real
  // initiator can never reproduce this tag ⇒ the responder fails closed (`pq_confirm_failed`) instead
  // of a "confirmed-but-dead" pairing. Wiped on completion / removeBuddy / safety-number mismatch (a
  // tag mismatch RETAINS it for a legitimate retry). The parked tag is a one-way HMAC (not the seed),
  // but is wiped anyway for uniformity with every other pairing secret.
  private val pendingResponderTag = mutable.Map.empty[String, Array[Byte]]
  // Post-quantum pairing prekey (US7), INITIATOR side: after a successful `completePqInitiator` we
  // RETAIN the initiator's `"ks/pq-confirm/i"` tag (PUBLIC — a one-way HMAC, not the seed) keyed by
  // pairId, so a repeat `confirmBuddy(matched = true)` on an already-Confirmed PQ initiator can
  // IDEMPOTENTLY return the SAME `initiatorConfirmTag` (no re-seed, no duplicate `BuddyConfirmed`). The
  // tag is one-shot in the `ConfirmResult`; if the app loses it (crash, dropped wire response, UI
  // dismissal) the RESPONDER would otherwise be stranded in pending-confirm forever with no way to
  // recover the value it must verify. Wiped + removed on `removeBuddy` (the pairing is gone).
  private val completedInitiatorTag = mutable.Map.empty[String, Array[Byte]]
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

  /** Parked initiator PQ pairing-prekey state (see `pendingPq`). Holds the hybrid-KEM secret key and
    * the base content root — BOTH secret — until the responder's ciphertext arrives. Only ever an
    * INITIATOR's state (a responder seeds its ratchet synchronously at `addBuddy`), so the role is
    * implicit. `wipe()` zeroes both arrays in place; it is called when the parked state is CONSUMED
    * (successful completion), and on removeBuddy — never on a failed/retryable completion. */
  private final class PendingPq(
      val kemSecret: Array[Byte],
      val baseContentRoot: Array[Byte]
  ):
    def wipe(): Unit =
      Engine.this.wipe(kemSecret)
      Engine.this.wipe(baseContentRoot)

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
    * the derived `pairKey` never leaves the engine.
    *
    * ==Post-quantum pairing prekey (US7, Option A)==
    * Optionally layers a hybrid-KEM (X25519+ML-KEM-768) prekey exchange whose shared secret is folded
    * into the INITIAL content root via `KeySchedule.pqContentRoot`, WITHOUT touching the DH ratchet:
    *   - '''Initiator''' with `initiatePqPrekey = true`: generate `(kemPub, kemSecret)`, park the
    *     secret + base content root in `pendingPq`, DEFER ratchet seeding, and return `kemPublicKey`
    *     for the app to send to the peer out of band. The relationship is Pending with no runtime yet.
    *   - '''Responder''' given `initiatorKemPublicKey`: `encaps` to it, mix the shared secret into the
    *     content root, seed the ratchet NOW, and return `kemCiphertext` + the responder's `/r` confirm
    *     tag for the app to return to the initiator. It stays in a PENDING-confirm state (parks the
    *     expected initiator `/i` tag) and does NOT emit `BuddyConfirmed` until `confirmBuddy` verifies
    *     the initiator's tag — so a `kemPublicKey` swapped in transit makes it fail closed rather than
    *     confirm a dead ratchet (bidirectional confirmation). The KEM shared secret is wiped after mixing.
    *   - '''Classical (legacy / local-only)''': no KEM material ⇒ seed the ratchet from the classical
    *     content root exactly as before. This path is NON-PQ (the pairing seed is only as strong as
    *     the classical OOB secret); a PQ pairing must instead flow KEM material on both sides.
    *
    * ==PQ-intent binding (US7, strip-downgrade defense)==
    * `pqRequired` is the authenticated out-of-band pairing intent ("this pairing MUST be
    * post-quantum"). BOTH sides set it from the SAME OOB agreement. It does two things:
    *   - '''Fail closed on a stripped key''': a '''RESPONDER''' with `pqRequired = true` but NO
    *     `initiatorKemPublicKey` is refused (`pq_prekey_required`) rather than seeding a classical
    *     pairing — so an attacker who STRIPS the initiator's `kemPublicKey` from the OOB delivery can no
    *     longer silently demote a responder that expected PQ. An '''INITIATOR''' with `pqRequired = true`
    *     IMPLIES `initiatePqPrekey` (the PQ prekey path), so it can never accidentally seed a classical
    *     pairing under a PQ intent.
    *   - '''Bind intent to the authenticated channel''': `pqRequired` is folded (domain-separated) into
    *     the `Handshake` derivation (see `Handshake.init`), so a MITM who flips the intent bit on one
    *     side makes the two sides derive DIFFERENT `pairId`/`safetyNumber` ⇒ the out-of-band safety
    *     number comparison fails. Backward compat: `pqRequired = false` leaves the derivation
    *     byte-identical to the classical pairing.
    *
    * HONEST LABELING (Constitution IV): even on the PQ path this hardens ONLY the initial content
    * root; the ongoing per-message X25519 DH ratchet stays classical (see `KeySchedule.pqContentRoot`
    * / the engine-api doc). `kemPublicKey`/`kemCiphertext` are PUBLIC; no private key leaves the
    * engine. A PQ pairing does NOT silently downgrade — once an initiator opts in, `confirmBuddy`
    * requires the ciphertext (fail closed). */
  def addBuddy(
      sharedSecret: Array[Byte],
      role: BuddyRole,
      peerNotifyLabel: Array[Byte] = Array.emptyByteArray,
      initiatorKemPublicKey: Option[Array[Byte]] = None,
      initiatePqPrekey: Boolean = false,
      pqRequired: Boolean = false
  ): Either[EngineError, AddBuddyResult] =
    // A `pqRequired` INITIATOR MUST take the PQ prekey path — imply it (the cleaner of the two options
    // in the design: `pqRequired` semantically demands PQ, so opting into the prekey is the intent, not
    // an error). A responder never generates a prekey; its PQ path is driven by `initiatorKemPublicKey`.
    val wantInitiatorPq = initiatePqPrekey || (role == BuddyRole.Initiator && pqRequired)
    if sharedSecret.isEmpty then Left(EngineError("invalid_arg", "shared secret required"))
    // Reject inconsistent PQ argument combinations BEFORE the handshake — never silently drop KEM
    // material into a non-PQ (classical) pairing (fail closed):
    //   - an Initiator is never given a peer KEM public key (it generates its own);
    //   - a Responder that sets `pqPrekey` must also supply the initiator's KEM public key to encaps to.
    else if role == BuddyRole.Initiator && initiatorKemPublicKey.isDefined then
      Left(EngineError("invalid_arg", "initiator must not be given a KEM public key"))
    else if role == BuddyRole.Responder && initiatePqPrekey && initiatorKemPublicKey.isEmpty then
      Left(EngineError("invalid_arg", "responder pqPrekey requires the initiator KEM public key"))
    // STRIP-DOWNGRADE DEFENSE (fail closed): a responder that expected PQ (`pqRequired = true`) but
    // received NO `initiatorKemPublicKey` refuses rather than seeding a classical pairing. This is the
    // key removal an attacker performs to silently demote the responder to non-PQ; with the intent bound
    // to the (authenticated) OOB pairing, its absence is now detectable and terminal.
    else if role == BuddyRole.Responder && pqRequired && initiatorKemPublicKey.isEmpty then
      Left(
        EngineError("pq_prekey_required", "PQ intent set but no initiator KEM public key arrived")
      )
    else
      // Bind the PQ intent into the derivation (domain-separated; byte-identical when false), so a MITM
      // flipping the bit on one side yields a mismatching safety number (OOB comparison fails).
      val init = Handshake.init(sharedSecret, pqRequired)
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
      (role, initiatorKemPublicKey) match
        case (BuddyRole.Responder, Some(peerPub)) =>
          addResponderPq(init, rel, addrKey, contentRoot, peerPub)
        case (BuddyRole.Initiator, _) if wantInitiatorPq =>
          addInitiatorPq(init, rel, addrKey, contentRoot)
        case _ =>
          addClassical(init, rel, addrKey, contentRoot, role)

  /** Classical (non-PQ) add: seed the ratchet immediately from the content root, as before. */
  private def addClassical(
      init: Handshake.PairInit,
      rel: BuddyRelationship,
      addrKey: Array[Byte],
      contentRoot: Array[Byte],
      role: BuddyRole
  ): Either[EngineError, AddBuddyResult] =
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

  /** PQ responder add: `encaps` to the initiator's hybrid public key, fold the shared secret into the
    * content root, seed the responder ratchet NOW, and return the ciphertext + the responder's `/r`
    * confirmation tag. The responder stays in a PENDING-confirm state (no `BuddyConfirmed` yet): it
    * PARKS the expected initiator `/i` tag and defers final confirmation until `confirmBuddy` verifies
    * the initiator's tag — so a `kemPublicKey` swapped in transit makes the responder fail closed
    * rather than confirm a dead ratchet (bidirectional confirmation, US7). `encaps` runs (and can
    * reject a malformed/low-order peer key) BEFORE any book mutation, so a bad key adds nothing. */
  private def addResponderPq(
      init: Handshake.PairInit,
      rel: BuddyRelationship,
      addrKey: Array[Byte],
      contentRoot: Array[Byte],
      peerPub: Array[Byte]
  ): Either[EngineError, AddBuddyResult] =
    val encapsed =
      try Right(HybridKem.encaps(peerPub))
      catch case _: Throwable => Left(EngineError("pq_prekey_failed", "invalid KEM public key"))
    encapsed match
      case Left(err) =>
        wipe(contentRoot); wipe(addrKey)
        Left(err)
      case Right((ct, ss)) =>
        // Mix the KEM secret into the content root, then wipe the KEM secret + the base root in a
        // `finally` so both are zeroed even if the mixing throws; only the PQ-hardened seed (`rootP`,
        // itself wiped after seeding) reaches the ratchet.
        val rootP =
          try KeySchedule.pqContentRoot(contentRoot, ss)
          finally
            wipe(ss)
            wipe(contentRoot)
        // Both confirmation tags, derived BEFORE `rootP` is consumed/wiped. PUBLIC (domain-separated
        // HMACs of the root that leak nothing about the seed):
        //   - `confirmTag` (the responder's `/r` tag) travels to the initiator, which verifies it.
        //   - `expectedInitTag` (the initiator's `/i` tag) is PARKED so the responder can constant-time
        //     verify the initiator's returned tag before it confirms (fail closed on a `kemPublicKey`
        //     tampered in transit — the real initiator's `rootP`, hence its tag, would then differ).
        val confirmTag = KeySchedule.pqConfirmTagResponder(rootP)
        val expectedInitTag = KeySchedule.pqConfirmTagInitiator(rootP)
        book.add(rel) match
          case Right(nb) =>
            book = nb
            try runtime(init.pairId) = BuddyRuntime(BuddyRole.Responder, rootP)
            finally wipe(rootP) // chains seeded; the PQ content root must not linger
            // Park the expected initiator tag; the responder stays Pending until it verifies it.
            pendingResponderTag(init.pairId) = expectedInitTag
            Right(
              AddBuddyResult(
                init.pairId,
                init.safetyNumber,
                kemCiphertext = Some(ct),
                kemConfirmTag = Some(confirmTag)
              )
            )
          case Left(reason) =>
            wipe(rootP); wipe(addrKey); wipe(expectedInitTag)
            Left(EngineError("add_failed", reason))

  /** PQ initiator add: generate a hybrid-KEM keypair, PARK the secret + base content root, and DEFER
    * ratchet seeding until the responder's ciphertext arrives at `confirmBuddy`. Returns the public
    * key for out-of-band delivery. No runtime/ratchet exists for this buddy until completion. */
  private def addInitiatorPq(
      init: Handshake.PairInit,
      rel: BuddyRelationship,
      addrKey: Array[Byte],
      contentRoot: Array[Byte]
  ): Either[EngineError, AddBuddyResult] =
    // Generate the keypair BEFORE any book mutation (mirrors addResponderPq's encaps-first ordering),
    // so a generation failure adds nothing to unwind.
    val generated =
      try Right(HybridKem.keypair())
      catch case _: Throwable => Left(EngineError("pq_prekey_failed", "prekey generation failed"))
    generated match
      case Left(err) =>
        wipe(contentRoot); wipe(addrKey)
        Left(err)
      case Right((kemPub, kemSecret)) =>
        book.add(rel) match
          case Right(nb) =>
            book = nb
            // `kemSecret` + `contentRoot` ownership transfers to the parked state (wiped when the
            // prekey is consumed on completion, or on removeBuddy).
            pendingPq(init.pairId) = PendingPq(kemSecret, contentRoot)
            Right(AddBuddyResult(init.pairId, init.safetyNumber, kemPublicKey = Some(kemPub)))
          case Left(reason) =>
            wipe(kemSecret); wipe(contentRoot); wipe(addrKey)
            Left(EngineError("add_failed", reason))

  /** Confirm/reject a pairing after the out-of-band safety-number comparison. On match, emits
    * `buddyConfirmed`; on mismatch the relationship is removed and nothing is established.
    *
    * ==Bidirectional PQ key confirmation (US7)==
    * Confirmation is BIDIRECTIONAL — BOTH sides fail closed on any KEM tampering. The role is fixed by
    * which parked state exists for `pairId`:
    *   - '''INITIATOR''' (parked KEM secret): the responder's `kemCiphertext` + `kemConfirmTag` (the
    *     `/r` tag) are delivered HERE. On match the ciphertext is `decaps`-ed, folded into the content
    *     root, the responder's `/r` tag is constant-time verified, the deferred ratchet is seeded, and
    *     the result carries the initiator's own `/i` tag (`initiatorConfirmTag`) for the app to relay
    *     back to the responder.
    *   - '''RESPONDER''' (parked expected `/i` tag; ratchet already seeded at addBuddy): the initiator's
    *     `initiatorConfirmTag` is delivered HERE and constant-time verified against the parked expected
    *     tag. Only on a match does the responder emit `BuddyConfirmed` — a `kemPublicKey` swapped in
    *     transit yields a mismatching tag and is refused (`pq_confirm_failed`), so the responder never
    *     lands in a confirmed-but-dead state.
    *   - '''CLASSICAL''' (no parked state, ratchet seeded at addBuddy): confirm/reject as before.
    *
    * A repeat matched `confirmBuddy` on an ALREADY-completed PQ initiator is IDEMPOTENT: it re-returns
    * the same `initiatorConfirmTag` (the tag is retained, PUBLIC) WITHOUT re-seeding or re-emitting
    * `BuddyConfirmed`, so an app that lost the first `ConfirmResult` can still recover the value the
    * responder must verify (otherwise the responder would be stranded in pending-confirm).
    *
    * Fail closed — a matched PQ pairing missing the required tag(s) is refused (`pq_prekey_required`;
    * it must not silently downgrade to the classical seed), and a tag mismatch is refused
    * (`pq_confirm_failed`) with the parked state RETAINED so a legitimate retry can complete. On a
    * safety-number mismatch the parked secret/tag is wiped and nothing is established. */
  def confirmBuddy(
      pairId: String,
      matched: Boolean,
      kemCiphertext: Option[Array[Byte]] = None,
      kemConfirmTag: Option[Array[Byte]] = None,
      initiatorConfirmTag: Option[Array[Byte]] = None
  ): Either[EngineError, ConfirmResult] =
    pendingPq.get(pairId) match
      case Some(pending) =>
        if !matched then
          pending.wipe()
          pendingPq.remove(pairId)
          book.confirm(pairId, matched) match
            case Right(nb) => book = nb; Right(ConfirmResult())
            case Left(reason) => Left(EngineError("confirm_failed", reason))
        else
          (kemCiphertext, kemConfirmTag) match
            case (Some(ct), Some(tag)) => completePqInitiator(pairId, pending, ct, tag)
            case _ =>
              Left(
                EngineError(
                  "pq_prekey_required",
                  "responder KEM ciphertext and confirmation tag required to confirm"
                )
              )
      case None if matched && completedInitiatorTag.contains(pairId) =>
        // Idempotent replay: this PQ initiator already completed (prekey consumed, ratchet seeded,
        // BuddyConfirmed already emitted). Re-return the SAME /i tag WITHOUT re-seeding or re-emitting,
        // so an app that lost the first ConfirmResult can still relay it to the responder. A COPY is
        // handed back so the caller cannot mutate our retained value.
        Right(ConfirmResult(initiatorConfirmTag = completedInitiatorTag.get(pairId).map(_.clone())))
      case None =>
        pendingResponderTag.get(pairId) match
          case Some(expectedInitTag) =>
            completePqResponder(pairId, expectedInitTag, matched, initiatorConfirmTag)
          case None =>
            // Classical/legacy: no parked PQ state; the ratchet was seeded at addBuddy. Any stray KEM
            // material is ignored here — only a parked PQ role consumes one.
            book.confirm(pairId, matched) match
              case Right(nb) =>
                if matched then
                  // Defense in depth (fail closed): a matched confirm MUST have a seeded ratchet — the
                  // classical path seeds one at addBuddy. A Pending relationship with NO runtime and NO
                  // parked prekey is an un-completed PQ initiator (its prekey was aborted); refuse
                  // rather than confirm a buddy that could never send/receive. This also blocks any path
                  // where a PQ initiator could reach a silent non-PQ (classical) confirm.
                  if !runtime.contains(pairId) then
                    Left(EngineError("pq_prekey_required", "pairing not ready to confirm"))
                  else
                    book = nb
                    book
                      .get(pairId)
                      .foreach(r => emit(EngineEvent.BuddyConfirmed(r.pairId, r.safetyNumber)))
                    Right(ConfirmResult())
                else
                  // Mismatch is terminal (relationship now Removed): drop the buddy's runtime + outbox so
                  // no seeded ratchet lingers past the rejected pairing (parallels removeBuddy's cleanup).
                  book = nb
                  runtime.remove(pairId)
                  outbox.remove(pairId)
                  Right(ConfirmResult())
              case Left(reason) => Left(EngineError("confirm_failed", reason))

  /** Complete an initiator PQ pairing prekey: `decaps` the responder's ciphertext, fold the recovered
    * shared secret into the base content root (identically to the responder's `encaps` path, so both
    * sides seed a byte-identical ratchet), KEY-CONFIRM against the responder's `/r` tag, then seed the
    * deferred initiator ratchet, confirm, and RETURN the initiator's own `/i` tag for the app to relay
    * back to the responder (which verifies it before it confirms — bidirectional confirmation, US7).
    *
    * ==Key confirmation (the ML-KEM implicit-rejection defense)==
    * ML-KEM `decaps` does NOT throw on a tampered SAME-LENGTH ciphertext — it silently returns a
    * pseudo-random secret. Without an explicit check, a tampered `kemCiphertext`/`kemPublicKey` would
    * "succeed", emit `buddyConfirmed`, and seed a ratchet that can never interoperate (a confirmed-but-
    * dead pairing that also strips the PQ hardening — the safety numbers still match). So we recompute
    * our own tag from our `rootP` and CONSTANT-TIME compare it (`RetrievalToken.equalsCT`, no
    * secret-dependent early exit) to the responder's `expectedTag` BEFORE any state change. Because
    * `rootP` depends on the KEM shared secret, ANY tamper ⇒ different `rootP` ⇒ different tag ⇒
    * explicit `pq_confirm_failed`, fail closed.
    *
    * ==Failure-before-mutation ordering==
    * The tag check runs, then the (pure) `book.confirm` is validated BEFORE the `BuddyRuntime` is
    * constructed and `book` committed — so a failure never leaves a Confirmed relationship with no
    * runtime, nor a throwaway ratchet holding un-wiped keys.
    *
    * The transient secrets `ss` (KEM shared secret) and `rootP` (seed) are ALWAYS wiped in `finally`.
    * The parked `pending` is wiped + removed ONLY on a successful completion — on ANY failure (bad
    * ciphertext, tag mismatch, `book.confirm` refusal) it is RETAINED so a corrected retry can still
    * complete. `removeBuddy` wipes the parked state if the app abandons the pairing instead. */
  private def completePqInitiator(
      pairId: String,
      pending: PendingPq,
      ct: Array[Byte],
      expectedTag: Array[Byte]
  ): Either[EngineError, ConfirmResult] =
    var ss: Array[Byte] = null
    var rootP: Array[Byte] = null
    try
      ss = HybridKem.decaps(ct, pending.kemSecret)
      rootP = KeySchedule.pqContentRoot(pending.baseContentRoot, ss)
      // Verify the responder's `/r` key-confirmation tag FIRST (constant time). A mismatch means the KEM
      // material was tampered (or is for a different peer): reject, retain the parked prekey, seed/
      // confirm nothing.
      if !token.RetrievalToken.equalsCT(KeySchedule.pqConfirmTagResponder(rootP), expectedTag) then
        Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
      else
        // The initiator's own `/i` tag — the responder will constant-time verify it before IT confirms,
        // so both sides fail closed. Computed while `rootP` is live (it is wiped in the `finally`). It is
        // a one-way HMAC of the root (PUBLIC), returned to the caller to relay out of band.
        val initiatorTag = KeySchedule.pqConfirmTagInitiator(rootP)
        // `book.confirm` is PURE (returns a new book, no mutation), so validate it BEFORE constructing
        // the ratchet: on a refusal we never build a throwaway `BuddyRuntime` that would strand live,
        // un-wiped ratchet keys (root/chain/header + a fresh X25519 private) with no erasure
        // (Constitution II) — and never leave a Confirmed relationship with no runtime.
        book.confirm(pairId, matched = true) match
          case Right(nb) =>
            // Seed the deferred initiator ratchet now that confirm is committed-to (only an
            // initiator's prekey is ever parked — see PendingPq).
            val rt = BuddyRuntime(BuddyRole.Initiator, rootP)
            book = nb
            runtime(pairId) = rt
            book
              .get(pairId)
              .foreach(r => emit(EngineEvent.BuddyConfirmed(r.pairId, r.safetyNumber)))
            // Success: the parked prekey is consumed — wipe + remove it now.
            pending.wipe()
            pendingPq.remove(pairId)
            // Retain a COPY of the /i tag (PUBLIC) so a repeat confirm can idempotently re-return it if
            // the app lost the ConfirmResult — otherwise `rootP`/the prekey are wiped and it is gone.
            completedInitiatorTag(pairId) = initiatorTag.clone()
            Right(ConfirmResult(initiatorConfirmTag = Some(initiatorTag)))
          case Left(reason) =>
            Left(EngineError("confirm_failed", reason)) // retain pending for a legitimate retry
    catch case _: Throwable => Left(EngineError("pq_prekey_failed", "prekey completion failed"))
    finally
      if ss != null then wipe(ss)
      if rootP != null then wipe(rootP)

  /** Complete a RESPONDER PQ pairing: the responder already `encaps`ed + seeded its ratchet at
    * `addBuddy` and parked the EXPECTED initiator `/i` tag. Here it constant-time verifies the
    * initiator's returned `initiatorConfirmTag` against that parked value before emitting
    * `BuddyConfirmed`, so a `kemPublicKey` tampered in transit (⇒ the real initiator's tag differs)
    * makes the responder fail closed instead of confirming a dead ratchet (bidirectional confirmation).
    *
    * Fail closed — a matched confirm WITHOUT the initiator tag is refused (`pq_prekey_required`), and a
    * tag mismatch is refused (`pq_confirm_failed`) with the parked tag RETAINED for a legitimate retry.
    * The ratchet is already seeded, so there is no runtime to construct; the tag check runs BEFORE the
    * (pure) `book.confirm` is committed. On a safety-number mismatch (`matched == false`) the pairing is
    * terminal: the parked tag is wiped and the seeded runtime/outbox dropped. */
  private def completePqResponder(
      pairId: String,
      expectedInitTag: Array[Byte],
      matched: Boolean,
      initiatorConfirmTag: Option[Array[Byte]]
  ): Either[EngineError, ConfirmResult] =
    if !matched then
      // Safety-number mismatch is terminal: wipe the parked tag and drop the seeded ratchet + outbox so
      // nothing lingers past the rejected pairing (parallels the classical-mismatch/removeBuddy cleanup).
      book.confirm(pairId, matched = false) match
        case Right(nb) =>
          book = nb
          runtime.remove(pairId)
          outbox.remove(pairId)
          wipe(expectedInitTag)
          pendingResponderTag.remove(pairId)
          Right(ConfirmResult())
        case Left(reason) => Left(EngineError("confirm_failed", reason))
    else
      initiatorConfirmTag match
        case None =>
          Left(EngineError("pq_prekey_required", "initiator confirmation tag required to confirm"))
        case Some(gotTag) =>
          // Constant-time verify the initiator's tag FIRST (before any book mutation). A mismatch ⇒ the
          // KEM material was tampered (e.g. a swapped initiator `kemPublicKey`): reject and RETAIN the
          // parked tag so a legitimate retry can complete.
          if !token.RetrievalToken.equalsCT(gotTag, expectedInitTag) then
            Left(EngineError("pq_confirm_failed", "KEM key confirmation failed"))
          else
            // `book.confirm` is pure — validate it, then commit + emit. The ratchet was already seeded
            // at addBuddy, so there is no throwaway runtime to strand on a refusal.
            book.confirm(pairId, matched = true) match
              case Right(nb) =>
                book = nb
                book
                  .get(pairId)
                  .foreach(r => emit(EngineEvent.BuddyConfirmed(r.pairId, r.safetyNumber)))
                wipe(expectedInitTag)
                pendingResponderTag.remove(pairId)
                Right(ConfirmResult())
              case Left(reason) =>
                Left(EngineError("confirm_failed", reason)) // retain the parked tag for a retry

  /** Remove a buddy. Stops future delivery (FR-018) without leaking prior existence — no event. Any
    * parked (un-completed) PQ pairing-prekey secret for this pair is wiped here too. */
  def removeBuddy(pairId: String): Either[EngineError, Unit] =
    book.remove(pairId) match
      case Right(nb) =>
        book = nb
        outbox.remove(pairId)
        runtime.remove(pairId)
        pendingPq.remove(pairId).foreach(_.wipe())
        pendingResponderTag.remove(pairId).foreach(wipe)
        completedInitiatorTag.remove(pairId).foreach(wipe)
        Right(())
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
                      // A frame WAS present at THIS pair's read token but didn't decrypt. Invariant: only
                      // this pair's writer can produce a frame here — cover writes use cover-derived
                      // tokens, ack-only frames are encrypted fresh (always decode), and a cross-pair
                      // frame is under a different addrKey's token — so a None here is a cached CONTENT
                      // retransmit whose ratchet key we consumed on first delivery. We therefore owe a
                      // (re-)ack so the peer stops retransmitting. Gate on `highRecv != NoSeq` so the
                      // re-ack is keyed to "we have delivered content from this buddy" (the retransmit
                      // case) rather than to any decrypt failure: a None before any delivery (which the
                      // invariant says shouldn't occur) does not spuriously activate an idle engine.
                      if rt.highRecv != ArqFrame.NoSeq then rt.ackOwed = true
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
