package provider

/** Drives one online device's [[ProviderSession]] from wall-clock time against the shared
  * [[RoundSchedule]] (`design/offline-delegation.md` §3.1, §3.2): once its provider has opened the
  * round, hand in the live set; after the cutoff, apply the receipt.
  *
  * `openGraceMillis` / `closeGraceMillis` absorb clock skew between device and provider: the device
  * asks for the round's digest a little after the scheduled open, and collects a little after the
  * scheduled cutoff. If the digest is not available before `cutoff − submitMarginMillis` (the
  * provider has not opened the round yet, or the call fails), the device does not hand anything in
  * that round and the provider runs its bundle slot instead.
  *
  * [[step]] takes the time as an argument (deterministic tests); a device app calls it on a timer
  * while it is in the foreground and simply stops when it is not — that is the abrupt disconnect the
  * design is built for. */
final class DeviceRoundDriver(
    session: ProviderSession,
    val schedule: RoundSchedule = RoundSchedule(),
    openGraceMillis: Long = 500L,
    closeGraceMillis: Long = 500L,
    submitMarginMillis: Long = 1_000L
):
  private var round: Option[Long] = None // the round this device is working on
  private var handedIn = false // its live set has been handed in
  private var finished = false // afterCutoff has run for it

  /** Advance this device to `nowMillis`. */
  def step(nowMillis: Long): Unit = synchronized {
    val current = schedule.roundAt(nowMillis)
    // A previous round we never finished (the device slept through its cutoff): finish it first.
    round.filter(r => r < current && !finished).foreach(session.afterCutoff)
    if !round.contains(current) then
      round = Some(current)
      handedIn = false
      finished = false
    val r = current
    if !handedIn && nowMillis >= schedule.openAt(r) + openGraceMillis &&
      nowMillis < schedule.cutoffAt(r) - submitMarginMillis
    then handedIn = session.beforeCutoff(r)
    if !finished && nowMillis >= schedule.cutoffAt(r) + closeGraceMillis then
      session.afterCutoff(r)
      finished = true
  }
