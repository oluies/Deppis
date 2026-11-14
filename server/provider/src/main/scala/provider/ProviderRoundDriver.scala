package provider

import java.util.concurrent.{Executors, ScheduledExecutorService, TimeUnit}
import scala.util.control.NonFatal

/** Drives a [[Provider]]'s round clock from wall-clock time (`design/offline-delegation.md` §3.2):
  * opens each round at its scheduled start (phase A) and closes it at its cutoff (phase B), in
  * order, one round at a time.
  *
  * [[step]] is the whole state machine and takes the time as an argument, so it is deterministic and
  * tested with a simulated clock; [[start]] just calls it on a timer.
  *
  * A round whose cutoff has ALREADY passed by the time the driver gets to it — the provider was
  * down, or a step came very late — is SKIPPED, not replayed in a burst: its slots never run and its
  * users are silent that round, which is the §6 "provider downtime" residual. Replaying it late would
  * put a burst of stale rounds on the backend instead. `skippedRounds` counts them. */
final class ProviderRoundDriver(provider: Provider, val schedule: RoundSchedule = RoundSchedule()):
  private var open: Option[Long] = None // the round between phase A and its cutoff
  private var next: Option[Long] = None // the next round to open; None until the first step
  private var skipped: Long = 0L

  /** Rounds skipped because their cutoff passed before the driver reached them. */
  def skippedRounds: Long = synchronized(skipped)

  /** The round currently open (between phase A and its cutoff), if any. */
  def openRound: Option[Long] = synchronized(open)

  /** Advance the provider's clock to `nowMillis`: close the open round if its cutoff has passed,
    * then open the next round if it is due, skipping any whose cutoff is already behind us. */
  def step(nowMillis: Long): Unit = synchronized {
    open.foreach { r =>
      if nowMillis >= schedule.cutoffAt(r) then
        provider.closeRound(r).fold(e => throw IllegalStateException(e), identity): Unit
        open = None
        next = Some(r + 1)
    }
    if open.isEmpty then
      val current = schedule.roundAt(nowMillis)
      var n = next.getOrElse(current)
      // A round already past its cutoff can no longer take live sets: skip it rather than run it late.
      while schedule.cutoffAt(n) <= nowMillis do
        if next.isDefined then skipped += 1
        n += 1
      if nowMillis >= schedule.openAt(n) then
        provider.openRound(n).fold(e => throw IllegalStateException(e), identity)
        open = Some(n)
        next = None
      else next = Some(n)
  }

  /** Run [[step]] every `tickMillis` on a single background thread until the returned handle is
    * closed. The cutoff is enforced to within one tick. A failing step is logged generically and the
    * timer keeps going (Constitution II: no secret-dependent detail in the message). */
  def start(
      tickMillis: Long = 100L,
      clock: () => Long = () => System.currentTimeMillis()
  ): AutoCloseable =
    val exec: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r =>
      val t = Thread(r, "provider-round-driver"); t.setDaemon(true); t
    }
    val tick: Runnable = () =>
      try step(clock())
      catch case NonFatal(_) => System.err.println("[provider] round driver step failed")
    exec.scheduleAtFixedRate(tick, 0L, tickMillis, TimeUnit.MILLISECONDS): Unit
    () => exec.shutdownNow(): Unit
