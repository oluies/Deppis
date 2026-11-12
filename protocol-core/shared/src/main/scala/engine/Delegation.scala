package engine

/** Offline-delegation constants (`design/offline-delegation.md` §3.3). NETWORK-WIDE: every device
  * and every provider uses the same values, because a per-device horizon or cadence would itself be
  * a fingerprint the provider could see. */
object Delegation:
  /** H — how many rounds a standing bundle covers: one day at the 15 s round interval
    * (`schedule.Latency`). An absence longer than this goes silent (§5, horizon expiry). */
  val HorizonRounds: Int = 5760

  /** F — the fixed cadence, in rounds, at which an online device replaces its standing bundle: one
    * hour. Fixed so that refreshes never reveal when real messages are queued (§3.3). */
  val RefreshEveryRounds: Int = 240
