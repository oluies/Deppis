package delegation

import scala.concurrent.{ExecutionContext, Future}

/** Drives one online device's [[DeviceSession]] from wall-clock time against the shared
  * [[RoundSchedule]] (`design/offline-delegation.md` §3.1, §3.2): once the provider has opened the
  * round, hand in the live set; after the cutoff, apply the receipt. Shared by the JVM
  * (`provider.DeviceRoundDriver`) and the browser (`engine.ProviderSessionJs`).
  *
  * `openGraceMillis` / `closeGraceMillis` absorb clock skew between device and provider; the live
  * set is never handed in later than `cutoff − submitMarginMillis`. If the round's digest is not
  * available by then, nothing is handed in and the provider runs the bundle slot instead.
  *
  * Steps never overlap: a [[step]] called while the previous one's calls are still in flight (a
  * browser timer firing during a slow network call) returns at once and does nothing — the next
  * step picks up from wherever time has got to. A device app calls `step` on a timer while it is in
  * the foreground and simply stops when it is not: that is the abrupt disconnect the design is
  * built for. */
final class DeviceClock(
    session: DeviceSession,
    val schedule: RoundSchedule = RoundSchedule(),
    openGraceMillis: Long = 500L,
    closeGraceMillis: Long = 500L,
    submitMarginMillis: Long = 1_000L
)(using ec: ExecutionContext):
  // Without this, a device whose margins do not fit its schedule NEVER hands a live set in and
  // silently runs on its bundle forever — fail at construction instead.
  require(
    openGraceMillis >= 0 && closeGraceMillis >= 0 && submitMarginMillis >= 0 &&
      openGraceMillis + submitMarginMillis < schedule.cutoffMillis,
    "the schedule leaves no window to hand a live set in: need openGrace + submitMargin < cutoff"
  )
  private var round: Option[Long] = None // the round this device is working on
  private var handedIn = false // its live set has been handed in
  private var finished = false // afterCutoff has run for it
  private var busy = false // a step's calls are in flight

  /** Advance this device to `nowMillis`. A no-op while a previous step is still in flight. */
  def step(nowMillis: Long): Future[Unit] =
    if busy then Future.unit
    else
      busy = true
      val f =
        try advance(nowMillis)
        catch case e: IllegalStateException => Future.failed(e)
      f.onComplete(_ => busy = false)
      f

  private def advance(nowMillis: Long): Future[Unit] =
    val current = schedule.roundAt(nowMillis)
    // A previous round we never finished (the device slept through its cutoff): finish it first.
    val finishPrevious = round.filter(r => r < current && !finished) match
      case Some(r) => session.afterCutoff(r)
      case None => Future.unit
    finishPrevious.flatMap { _ =>
      if !round.contains(current) then
        round = Some(current)
        handedIn = false
        finished = false
      val r = current
      val handIn =
        if !handedIn && nowMillis >= schedule.openAt(r) + openGraceMillis &&
          nowMillis < schedule.cutoffAt(r) - submitMarginMillis
        then session.beforeCutoff(r).map(accepted => handedIn = accepted)
        else Future.unit
      handIn.flatMap { _ =>
        if !finished && nowMillis >= schedule.cutoffAt(r) + closeGraceMillis then
          session.afterCutoff(r).map(_ => finished = true)
        else Future.unit
      }
    }
