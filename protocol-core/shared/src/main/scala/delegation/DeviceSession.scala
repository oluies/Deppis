package delegation

import engine.{Delegation, Engine, RoundReceipt}

import scala.concurrent.{ExecutionContext, Future}

/** The device side of provider routing (`design/offline-delegation.md` §3) — the ONE implementation,
  * shared by the JVM (`provider.ProviderSession`, a synchronous wrapper) and the browser
  * (`engine.ProviderSessionJs`, Scala.js), so both run exactly the same protocol logic.
  *
  * While the device is online, each round it calls [[beforeCutoff]] (after the provider's phase A)
  * and [[afterCutoff]] (after the cutoff), usually through a [[DeviceClock]]. It refreshes its
  * standing bundle on the fixed, network-wide cadence — never because something was queued, which
  * would tell the provider when real messages exist (§3.3). When the device disappears, however
  * abruptly, it simply stops calling: the provider runs its bundle slots.
  *
  * Call [[start]] once (register + first bundle) before anything else. Calls must not overlap;
  * [[DeviceClock]] guarantees that. */
final class DeviceSession(
    val user: String,
    engine: Engine,
    port: ProviderPort,
    clientLabel: Array[Byte],
    val refreshEveryRounds: Int = Delegation.RefreshEveryRounds,
    val horizonRounds: Int = Delegation.HorizonRounds
)(using ec: ExecutionContext):
  require(refreshEveryRounds > 0 && horizonRounds > refreshEveryRounds, "need 0 < F < H")

  // The round whose live set was handed in, and whether the provider accepted it.
  private var submitted: Option[(Long, Boolean)] = None

  /** Register with the provider and upload the first standing bundle, from `firstRound`. */
  def start(firstRound: Long = 1L): Future[Unit] =
    port.register(user, clientLabel).flatMap {
      case Left(e) => Future.failed(IllegalStateException(e))
      case Right(()) => refreshBundle(firstRound)
    }

  /** Online in `roundId`, after the provider's phase A: build the live set from the phase-A digest
    * and hand it in before the cutoff. Completes with whether it was handed in and accepted. Without
    * the round's digest (the provider has not opened the round yet, or the call failed) nothing is
    * built or handed in — a live set built on no digest would read every buddy as idle — and the
    * caller may try again before the cutoff. */
  def beforeCutoff(roundId: Long): Future[Boolean] =
    port.digestFor(user, roundId).flatMap {
      case None => Future.successful(false)
      case Some(digest) =>
        val ops = engine.beginRound(roundId, digest)
        port.submitLive(user, ops).map { accepted =>
          submitted = Some(roundId -> accepted)
          accepted
        }
    }

  /** Online in `roundId`, after the cutoff: apply the receipt — or, if the live set was refused
    * (late), a slot-ran receipt, so nothing of the live set is applied — then refresh the bundle on
    * the fixed cadence. */
  def afterCutoff(roundId: Long): Future[Unit] =
    val applied = submitted.filter(_._1 == roundId) match
      case None => Future.unit
      case Some((_, accepted)) =>
        // Always collect this round's receipt, so the provider keeps nothing it need not.
        port.collectReceipt(user, roundId).map { kept =>
          val slotRan = RoundReceipt(roundId, ranLive = false, writeAccepted = false, None)
          val receipt = if accepted then kept.getOrElse(slotRan) else slotRan
          engine.applyReceipt(receipt).fold(e => throw IllegalStateException(e.message), identity)
          ()
        }
    applied.flatMap { _ =>
      submitted = None
      if roundId % refreshEveryRounds == 0 then refreshBundle(roundId + 1) else Future.unit
    }

  /** Replace the standing bundle with one covering `[fromRound, fromRound + H)`. */
  def refreshBundle(fromRound: Long): Future[Unit] =
    engine.buildBundle(fromRound, horizonRounds) match
      case Left(e) => Future.failed(IllegalStateException(e.message))
      case Right(bundle) =>
        port.uploadBundle(user, bundle).flatMap {
          case Left(e) => Future.failed(IllegalStateException(e))
          case Right(()) => Future.unit
        }

  /** Back after an absence: drop what the provider kept meanwhile. It carries nothing the device
    * needs — senders are still retransmitting (§1), so the live round shows the same mail. */
  def collectAway(): Future[Int] = port.collectAll(user)
