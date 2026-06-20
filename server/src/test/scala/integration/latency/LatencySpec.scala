package integration.latency

import schedule.{Latency, Schedule}
import org.scalatest.funsuite.AnyFunSuite

/** SC-001 (T036a): a two-party exchange completes within minute-order latency in single-digit
  * rounds, and the tuned round interval is what makes that hold. Deterministic — it asserts the
  * latency MODEL (rounds × interval), not wall-clock, so it runs in CI without waiting minutes. */
class LatencySpec extends AnyFunSuite:

  test("the tuned round interval is within the planned 10–30 s window (research D)"):
    assert(Latency.RoundIntervalSeconds >= 10 && Latency.RoundIntervalSeconds <= 30)

  test("one-way delivery is single-digit rounds and minute-order (SC-001)"):
    assert(Latency.isSingleDigitRounds(Latency.OneWayRoundsWorstCase))
    assert(Latency.meetsSc001(Latency.OneWayRoundsWorstCase))

  test("a full round-trip exchange is single-digit rounds and minute-order (SC-001)"):
    val rt = Latency.RoundTripRoundsWorstCase
    assert(Latency.isSingleDigitRounds(rt), s"round-trip rounds $rt must be single digit")
    assert(Latency.meetsSc001(rt), s"round-trip latency ${Latency.latencySeconds(rt)}s must be minute-order")

  test("the round count is consistent with the Schedule invariant (one retrieve per round)"):
    // Each planned round emits exactly one retrieve, so a message stored in round r is retrievable
    // by round r+1 at the latest — i.e. one-way delivery is bounded by 2 rounds.
    val plan = Schedule.planRound(1L, realPayload = None).toOption.get
    assert(plan.retrieve, "every round must retrieve, which is what bounds delivery at 2 rounds")
    assert(Latency.OneWayRoundsWorstCase == 2)

  test("the interval is a guarded invariant: too-slow intervals would break minute-order"):
    // If the interval were pushed out of range (e.g. 60 s), a single-digit round-trip would no
    // longer be minute-order — this is the regression the constant guards against.
    val tooSlow = 60
    assert(Latency.RoundTripRoundsWorstCase.toLong * tooSlow > 120, "guard rationale holds")
    assert(Latency.meetsSc001(Latency.RoundTripRoundsWorstCase), "the ACTUAL tuned interval still passes")
