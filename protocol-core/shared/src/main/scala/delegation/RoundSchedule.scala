package delegation

/** The public, network-wide round schedule (`design/offline-delegation.md` §3.2): round `r` opens at
  * `epochMillis + r × intervalMillis` (phase A) and its cutoff falls `cutoffMillis` later (phase B).
  * Pure — a function of wall-clock time — so the provider and every device derive the same rounds
  * from the same constants, and both drivers can be tested with a simulated clock.
  *
  * Defaults: the 15 s round interval (`schedule.Latency`) and the design's proposed 10 s cutoff,
  * which leaves a device 10 s to fetch its digest and hand in its live set, and the provider 5 s to
  * run the round before the next one opens. */
final case class RoundSchedule(
    epochMillis: Long = 0L,
    intervalMillis: Long = schedule.Latency.RoundIntervalSeconds * 1000L,
    cutoffMillis: Long = 10_000L
):
  require(intervalMillis > 0, "interval must be positive")
  require(cutoffMillis > 0 && cutoffMillis < intervalMillis, "need 0 < cutoff < interval")

  /** The round in progress at `nowMillis` (the one whose interval contains it). */
  def roundAt(nowMillis: Long): Long = Math.floorDiv(nowMillis - epochMillis, intervalMillis)

  /** When round `r` opens (phase A). */
  def openAt(r: Long): Long = epochMillis + r * intervalMillis

  /** Round `r`'s cutoff (phase B): live sets handed in later are refused. */
  def cutoffAt(r: Long): Long = openAt(r) + cutoffMillis
