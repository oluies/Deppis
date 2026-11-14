package provider

import delegation.{DeviceClock, RoundSchedule}

import scala.concurrent.ExecutionContext

/** Drives one online device's [[ProviderSession]] from wall-clock time on the JVM: a synchronous
  * wrapper over the shared [[delegation.DeviceClock]] — the same timing logic the browser runs.
  * See [[DeviceClock]] for the contract (grace periods, submit margin, finishing a round slept
  * through). [[step]] takes the time as an argument, so it is deterministic in tests. */
final class DeviceRoundDriver(
    session: ProviderSession,
    val schedule: RoundSchedule = RoundSchedule(),
    openGraceMillis: Long = 500L,
    closeGraceMillis: Long = 500L,
    submitMarginMillis: Long = 1_000L
):
  private given ExecutionContext = ExecutionContext.parasitic
  private val clock =
    DeviceClock(session.core, schedule, openGraceMillis, closeGraceMillis, submitMarginMillis)

  /** Advance this device to `nowMillis`. */
  def step(nowMillis: Long): Unit = synchronized(ProviderSession.await(clock.step(nowMillis)))
