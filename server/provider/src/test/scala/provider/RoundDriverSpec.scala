package provider

import delegation.RoundSchedule

import crypto.Crypto
import engine.{BuddyRole, Engine, EngineEvent, RoundTransport}
import org.scalatest.funsuite.AnyFunSuite
import ping.DevNotificationServer

import scala.collection.mutable

/** The wall-clock round drivers (`design/offline-delegation.md` §3.2): [[ProviderRoundDriver]] opens
  * and closes the provider's rounds on a [[RoundSchedule]], [[DeviceRoundDriver]] hands a device's
  * live set in and applies its receipt on the same schedule. All but the last test run on a
  * SIMULATED clock (deterministic); the last checks the real timer. */
class RoundDriverSpec extends AnyFunSuite:

  // 1 s rounds with a 600 ms cutoff, starting at t = 0 — small numbers, same shape as production.
  private val sched = RoundSchedule(epochMillis = 0L, intervalMillis = 1000L, cutoffMillis = 600L)
  private val Horizon = 120
  private val Refresh = 20
  private val aLabel = "alice-label".getBytes("UTF-8")
  private val bLabel = "bob-label".getBytes("UTF-8")
  private val oob = "round-driver-oob".getBytes("UTF-8")

  private final class CountingBackend(inner: RoundTransport) extends RoundTransport:
    var fetches = 0
    var writes = 0
    def submit(t: Array[Byte], f: Array[Byte]) = { writes += 1; inner.submit(t, f) }
    def retrieve(t: Array[Byte]) = inner.retrieve(t)
    override def signal(r: Long, l: Array[Byte], b: Int): Unit = inner.signal(r, l, b)
    def fetchDigest(r: Long, l: Array[Byte]) = { fetches += 1; inner.fetchDigest(r, l) }

  private def backend() = CountingBackend(
    DevProviderBackend(notifications =
      DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))
    )
  )

  // ================================================================ the schedule and the provider clock

  test("RoundSchedule: rounds, opens and cutoffs line up"):
    assert(sched.roundAt(0) == 0 && sched.roundAt(999) == 0 && sched.roundAt(1000) == 1)
    assert(sched.openAt(7) == 7000 && sched.cutoffAt(7) == 7600)
    assert(RoundSchedule().intervalMillis == 15000 && RoundSchedule().cutoffMillis == 10000)
    intercept[IllegalArgumentException](
      RoundSchedule(intervalMillis = 1000, cutoffMillis = 1000)
    ): Unit

  test("the provider clock opens each round at its start and closes it at its cutoff"):
    val p = Provider(backend())
    val d = ProviderRoundDriver(p, sched)
    d.step(1000)
    assert(d.openRound.contains(1L), "round 1 opens at its start")
    d.step(1599)
    assert(d.openRound.contains(1L), "still open just before the cutoff")
    d.step(1600)
    assert(d.openRound.isEmpty, "closed at the cutoff; round 2 is not due yet")
    d.step(2000)
    assert(d.openRound.contains(2L))
    assert(d.skippedRounds == 0)

  test("provider downtime: rounds whose cutoff passed are skipped, not replayed in a burst"):
    val be = backend()
    val p = Provider(be)
    p.register("u", "u-label".getBytes).toOption.get
    val d = ProviderRoundDriver(p, sched)
    d.step(1000) // opens round 1
    d.step(5300) // down until round 5: close 1 late, skip 2..4, open 5
    assert(d.openRound.contains(5L))
    assert(d.skippedRounds == 3, s"rounds 2, 3 and 4 were skipped: ${d.skippedRounds}")
    assert(be.fetches == 2, "only rounds 1 and 5 were opened — no burst of stale rounds")

  // ================================================================ devices on the same clock

  private final class World:
    val be = backend()
    val provider = Provider(be, maxHorizon = Horizon)
    val clock = ProviderRoundDriver(provider, sched)
    val alice = Engine(clientLabel = aLabel)
    val bob = Engine(clientLabel = bLabel)
    val pid: String =
      val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get
      bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get: Unit
      alice.confirmBuddy(a.pairId, matched = true).toOption.get
      bob.confirmBuddy(a.pairId, matched = true).toOption.get
      alice.drainEvents(); bob.drainEvents()
      a.pairId
    val sa = ProviderSession("alice", alice, provider, aLabel, Refresh, Horizon)
    val sb = ProviderSession("bob", bob, provider, bLabel, Refresh, Horizon)
    val da = DeviceRoundDriver(
      sa,
      sched,
      openGraceMillis = 50,
      closeGraceMillis = 50,
      submitMarginMillis = 100
    )
    val db = DeviceRoundDriver(
      sb,
      sched,
      openGraceMillis = 50,
      closeGraceMillis = 50,
      submitMarginMillis = 100
    )
    var aliceUp = true
    var bobUp = true
    var now = 1000L
    val toBob = mutable.ArrayBuffer.empty[(Long, String)]

    /** Run the world on the simulated clock until `untilRound` starts, in 50 ms steps. */
    def runUntil(untilRound: Long): Unit =
      while now < sched.openAt(untilRound) do
        clock.step(now)
        if aliceUp then da.step(now)
        if bobUp then db.step(now)
        toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) =>
          (sched.roundAt(now), t)
        }
        alice.drainEvents(): Unit
        now += 50

  test(
    "T037 on the wall clock: the offline buddy gets m1 from the bundle, m2 once the sender is back"
  ):
    val w = World()
    w.runUntil(11)
    w.bobUp = false
    w.alice.sendMessage(w.pid, "m1"): Unit
    w.alice.sendMessage(w.pid, "m2"): Unit
    w.runUntil(31)
    w.aliceUp = false
    w.runUntil(60)
    assert(w.toBob.isEmpty)
    w.bobUp = true
    w.runUntil(90)
    assert(w.toBob.map(_._2) == Seq("m1"), s"m1 from alice's bundle while she is away: ${w.toBob}")
    w.aliceUp = true
    w.runUntil(120)
    assert(w.toBob.map(_._2) == Seq("m1", "m2"), s"m2 follows in order, each once: ${w.toBob}")
    assert(w.clock.skippedRounds == 0)

  test("a device that only wakes after the cutoff hands nothing in, and its slot runs"):
    val w = World()
    w.runUntil(5)
    w.provider.collectAll("alice"): Unit // start clean: nothing kept for alice
    // Alice's device sleeps through round 5's submit window and wakes at the cutoff + grace.
    w.clock.step(5000) // provider opens round 5
    w.db.step(5100) // bob hands his live set in
    w.clock.step(5600) // the cutoff: bob's live set runs, alice's bundle slot runs
    w.da.step(5650) // alice wakes: too late to submit, but she still finishes the round
    w.db.step(5650)
    val kept = w.provider.collectAll("alice")
    assert(kept.map(_.receipt.roundId) == Vector(5L), s"one receipt kept for alice: round 5: $kept")
    assert(!kept.head.receipt.ranLive, "her bundle slot ran in round 5, not a live set")
    // The world carries on normally, and she keeps refreshing on the cadence.
    w.now = 5700
    w.runUntil(30)
    assert(w.provider.slotCount("alice") > Horizon - Refresh, "alice kept refreshing her bundle")

  test("a device whose provider has not opened the round yet retries until it has"):
    val w = World()
    w.runUntil(3)
    // Round 3: the device steps BEFORE the provider has opened it (device clock slightly ahead).
    w.da.step(3060)
    w.db.step(3060)
    w.clock.step(3070) // now the provider opens round 3
    w.da.step(3080) // the retry hands the live set in
    w.db.step(3080)
    w.clock.step(3600)
    w.da.step(3650); w.db.step(3650)
    assert(
      w.provider.collectAll("alice").isEmpty,
      "alice's live set ran and her receipt was collected"
    )

  // ================================================================ the real timer

  test("start() drives the provider clock on a real timer"):
    val be = backend()
    val p = Provider(be)
    p.register("u", "u-label".getBytes).toOption.get
    val fast = RoundSchedule(System.currentTimeMillis(), intervalMillis = 200L, cutoffMillis = 120L)
    val handle = ProviderRoundDriver(p, fast).start(tickMillis = 10L)
    try Thread.sleep(1500)
    finally handle.close()
    assert(be.fetches >= 4, s"rounds opened on the timer: ${be.fetches}")
