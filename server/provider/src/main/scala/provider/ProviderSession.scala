package provider

import engine.{Delegation, Engine, RoundReceipt}

/** The device side of provider routing (`design/offline-delegation.md` §3): drives one device's
  * [[engine.Engine]] through its provider — in-process [[Provider]] or networked, via
  * [[ProviderApi]] — instead of a direct backend transport.
  *
  * While the device is online, each round it calls [[beforeCutoff]] (after the provider's phase A)
  * and [[afterCutoff]] (after the cutoff). It refreshes its standing bundle on the fixed,
  * network-wide cadence — never because something was queued, which would tell the provider when
  * real messages exist (§3.3). When the device disappears — however abruptly — it simply stops
  * calling: the provider runs its bundle slots, and nothing has to be announced.
  *
  * On return the device just resumes calling `beforeCutoff` for the current round; building a
  * bundle left the engine in a state the next live round continues from. [[collectAway]] drains
  * what the provider kept meanwhile; it carries nothing the device needs, because senders are still
  * retransmitting (§1), so the live round shows the same mail.
  *
  * Registers the device with the provider and uploads a first bundle at construction. */
final class ProviderSession(
    val user: String,
    engine: Engine,
    provider: ProviderApi,
    clientLabel: Array[Byte],
    val refreshEveryRounds: Int = Delegation.RefreshEveryRounds,
    val horizonRounds: Int = Delegation.HorizonRounds,
    firstRound: Long = 1L
):
  require(refreshEveryRounds > 0 && horizonRounds > refreshEveryRounds, "need 0 < F < H")
  provider.register(user, clientLabel).fold(e => throw IllegalStateException(e), identity)
  refreshBundle(firstRound)

  // The round whose live set was handed in, and whether the provider accepted it.
  private var submitted: Option[(Long, Boolean)] = None

  /** Online in `roundId`, after the provider's phase A: build the live set from the phase-A digest
    * and hand it in before the cutoff. */
  def beforeCutoff(roundId: Long): Unit =
    val digest = provider.digestFor(user, roundId).getOrElse(Array.emptyByteArray)
    val ops = engine.beginRound(roundId, digest)
    submitted = Some(roundId -> provider.submitLive(user, ops))

  /** Online in `roundId`, after the cutoff: apply the receipt — or, if the live set was refused
    * (late), a slot-ran receipt, so nothing of the live set is applied — then refresh the bundle on
    * the fixed cadence. */
  def afterCutoff(roundId: Long): Unit =
    submitted.filter(_._1 == roundId).foreach { (_, accepted) =>
      // Always collect this round's receipt, so the provider keeps nothing it need not.
      val kept = provider.collectReceipt(user, roundId).map(_.receipt)
      val receipt =
        if accepted then kept.getOrElse(RoundReceipt(roundId, ranLive = false, false, None))
        else RoundReceipt(roundId, ranLive = false, writeAccepted = false, retrieved = None)
      engine.applyReceipt(receipt).fold(e => throw IllegalStateException(e.message), identity): Unit
    }
    submitted = None
    if roundId % refreshEveryRounds == 0 then refreshBundle(roundId + 1)

  /** Replace the standing bundle with one covering `[fromRound, fromRound + H)`. */
  def refreshBundle(fromRound: Long): Unit =
    val bundle = engine
      .buildBundle(fromRound, horizonRounds)
      .fold(e => throw IllegalStateException(e.message), identity)
    provider.uploadBundle(user, bundle).fold(e => throw IllegalStateException(e), identity)

  /** Back after an absence: take everything the provider kept for this device. */
  def collectAway(): Vector[StoredReceipt] = provider.collectAll(user)
