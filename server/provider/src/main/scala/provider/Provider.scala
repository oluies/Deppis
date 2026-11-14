package provider

import engine.{Delegation, DelegationBundle, NotifyDigest, RoundOps, RoundReceipt, RoundTransport}
import privacy.Privacy

import scala.collection.mutable

/** The untrusted service provider (T038, `design/offline-delegation.md` §2 Option 3, §3, §5).
  *
  * It fronts EVERY round of every registered user, online or not. Each round runs in two phases
  * (§3.1):
  *   - [[openRound]] (phase A): fetch each user's notify digest for the previous round — exactly
  *     once per `(round, label)`, whoever is online — and hold it for the device.
  *   - [[submitLive]]: an online device hands in its live operations for the open round, before the
  *     cutoff. A late or duplicate submission is refused, never queued.
  *   - [[closeRound]] (phase B, the cutoff): for each user run EXACTLY ONE operation set — the live
  *     one if it arrived, else the user's standing-bundle slot for that round, else nothing (an
  *     expired bundle: silence) — and keep a receipt.
  *
  * The backend therefore sees one write, one signal and one read per user per round from the
  * provider's connection, whether the device behind it is online, offline or late (§6). The
  * provider holds no keys and makes no decisions: it never interprets a token, frame, signal,
  * digest or read result.
  *
  * Bounded retention (§5): per user, one standing bundle of at most `maxHorizon` slots, and at most
  * `maxHorizon` receipts. A slot is deleted when its round closes, whether or not it ran; a receipt
  * when it is collected.
  *
  * LABELING (Constitution IV): `DEV, NO METADATA PRIVACY`. Until Phase 4 the provider relays
  * PLAINTEXT tokens, frames, signals and digests, so one provider serving both ends of a
  * conversation could link them and see read hits (§4.6, §6 residual). It must never be labeled
  * otherwise before that lands.
  *
  * Rounds are driven by an external clock (the round orchestrator): `openRound` / `closeRound` for
  * strictly increasing round ids. Every public method is atomic under one lock. */
final class Provider(
    backend: RoundTransport,
    store: ProviderStore = InMemoryProviderStore(),
    val maxHorizon: Int = Delegation.HorizonRounds
) extends ProviderApi:
  require(maxHorizon > 0, "maxHorizon must be positive")

  /** Always DEV until Phase 4 seals what the provider relays (see the class doc). */
  val privacyStatus: Privacy.BuildPrivacyStatus =
    Privacy.BuildPrivacyStatus(Privacy.Backend.Dev, attestationPassed = false)
  def metadataPrivate: Boolean = privacyStatus.metadataPrivate
  def label: String = privacyStatus.label

  // user -> client label / session-secret hash, reloaded from the store so registrations survive a
  // restart of the provider when the store does (JdbcProviderStore).
  private val labels = mutable.LinkedHashMap.empty[String, Array[Byte]]
  private val sessionHashes = mutable.Map.empty[String, Array[Byte]]
  store.users.foreach { u =>
    labels(u.user) = u.clientLabel
    u.sessionHash.foreach(h => sessionHashes(u.user) = h)
  }
  private var open: Option[Long] = None // the round between phase A and the cutoff
  private var lastClosed: Long = Long.MinValue
  private val digests = mutable.Map.empty[String, Array[Byte]] // this open round's phase-A digests
  private val live = mutable.Map.empty[String, RoundOps] // live sets received for the open round

  /** Register `user` with its notify `clientLabel`. Idempotent; the label is fixed once set. */
  def register(user: String, clientLabel: Array[Byte]): Either[String, Unit] =
    register(user, clientLabel, sessionHash = None)

  /** Register `user`, optionally with the SHA-256 of the session secret the gRPC front issued it, and
    * persist the registration. A user name longer than [[Provider.MaxUserLength]] is refused. */
  def register(
      user: String,
      clientLabel: Array[Byte],
      sessionHash: Option[Array[Byte]]
  ): Either[String, Unit] = synchronized {
    if user.isEmpty || user.length > Provider.MaxUserLength then Left("bad user name")
    else
      labels.get(user) match
        case Some(l) if !l.sameElements(clientLabel) => Left("user already registered with a label")
        case _ =>
          labels(user) = clientLabel.clone()
          sessionHash.foreach(h => sessionHashes(user) = h.clone())
          store.putUser(
            StoredUser(user, clientLabel.clone(), sessionHashes.get(user).map(_.clone()))
          )
          Right(())
  }

  /** Whether `user` is registered (in this process or, with a persistent store, before a restart). */
  def isRegistered(user: String): Boolean = synchronized(labels.contains(user))

  /** The SHA-256 of `user`'s session secret, if the gRPC front issued one. */
  def sessionHashOf(user: String): Option[Array[Byte]] =
    synchronized(sessionHashes.get(user).map(_.clone()))

  /** Replace `user`'s standing bundle (§3.3), atomically. Refused if the bundle is longer than
    * `maxHorizon`, not one slot per consecutive round, or starts at or before a closed round. */
  def uploadBundle(user: String, bundle: DelegationBundle): Either[String, Unit] = synchronized {
    val slots = bundle.slots
    if !labels.contains(user) then Left("unknown user")
    else if slots.isEmpty || slots.size > maxHorizon then Left("bundle size out of range")
    else if slots.zipWithIndex.exists((s, i) => s.roundId != bundle.fromRound + i) then
      Left("bundle slots must cover consecutive rounds from fromRound")
    else if bundle.fromRound <= lastClosed then Left("bundle starts at a closed round")
    else
      store.replaceBundle(user, slots)
      Right(())
  }

  /** Phase A for `roundId`: fetch each registered user's digest for `roundId - 1`, once. */
  def openRound(roundId: Long): Either[String, Unit] = synchronized {
    if open.isDefined then Left("a round is already open")
    else if roundId <= lastClosed then Left("round ids must increase")
    else
      digests.clear()
      live.clear()
      for (user, lbl) <- labels do
        digests(user) = backend.fetchDigest(roundId - 1, NotifyDigest.labelTag(lbl))
      open = Some(roundId)
      Right(())
  }

  /** The phase-A digest for `user` in the open round, for an online device to build its live set. */
  def digestFor(user: String, roundId: Long): Option[Array[Byte]] = synchronized {
    if open.contains(roundId) then digests.get(user).map(_.clone()) else None
  }

  /** An online device's live operations for the open round. `true` = accepted: they will run at the
    * cutoff instead of the bundle slot. `false` = refused (no such round open — e.g. past its
    * cutoff — a mismatched round, an unknown user, or a second submission): the device must treat
    * its live set as never sent. */
  def submitLive(user: String, ops: RoundOps): Boolean = synchronized {
    val ok = open.contains(ops.roundId) && labels.contains(user) && !live.contains(user)
    if ok then live(user) = ops
    ok
  }

  /** Phase B — the cutoff — for the open `roundId`: run exactly one operation set per user and keep
    * its receipt. Returns how many users had operations run (the rest were silent: no live set and
    * no slot, i.e. an expired bundle). */
  def closeRound(roundId: Long): Either[String, Int] = synchronized {
    if !open.contains(roundId) then Left("that round is not open")
    else
      var ran = 0
      for user <- labels.keys do
        val liveOps = live.get(user)
        val slot = store.takeSlot(user, roundId) // the slot is consumed either way
        liveOps.orElse(slot).foreach { ops =>
          val accepted = backend.submit(ops.writeToken, ops.frame)
          // The real signal only when the write was accepted — a rejected write never announces
          // mail — exactly as `Engine.tick` executes a round.
          val sig = if accepted then ops.signal else ops.fallbackSignal
          backend.signal(roundId, sig.label, sig.bit)
          val retrieved = backend.retrieve(ops.readToken)
          val receipt = RoundReceipt(roundId, ranLive = liveOps.isDefined, accepted, retrieved)
          store.putReceipt(user, StoredReceipt(receipt, digests(user)), maxHorizon)
          ran += 1
        }
        store.dropSlotsBefore(user, roundId + 1) // §5: nothing older than the current round
      open = None
      lastClosed = roundId
      live.clear()
      digests.clear()
      Right(ran)
  }

  /** The receipt for `user`'s round `roundId`, removed on delivery: for an online device whose live
    * set ran, or to learn that a slot ran in its place. */
  def collectReceipt(user: String, roundId: Long): Option[StoredReceipt] = synchronized {
    store.takeReceipt(user, roundId)
  }

  /** Everything kept for `user` — the receipts for rounds its bundle ran while it was away — removed
    * on delivery, oldest first. */
  def collectAll(user: String): Vector[StoredReceipt] = synchronized(store.drainReceipts(user))

  /** Observability + tests: `user`'s unexecuted slots and kept receipts. */
  def slotCount(user: String): Int = synchronized(store.slotCount(user))
  def receiptCount(user: String): Int = synchronized(store.receiptCount(user))

object Provider:
  /** Longest accepted user name — bounded so every store can index it. */
  val MaxUserLength: Int = 256
