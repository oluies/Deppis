package delegation

import engine.{BuddyRole, Engine, EngineEvent}
import org.scalatest.funsuite.AsyncFunSuite

import scala.collection.mutable
import scala.concurrent.Future

/** The shared device session and clock (`design/offline-delegation.md` §3), on BOTH platforms: the
  * T037 scenario driven through [[DeviceSession]] + [[DeviceClock]] on a simulated clock, over an
  * in-memory [[FakeProvider]]. On Scala.js every call genuinely completes asynchronously, which is
  * exactly the browser's situation. */
class DeviceSessionCrossSpec extends AsyncFunSuite:

  private val sched = RoundSchedule(epochMillis = 0L, intervalMillis = 1000L, cutoffMillis = 600L)
  private val aLabel = "alice".getBytes("UTF-8")
  private val bLabel = "bob".getBytes("UTF-8")

  private final class World:
    val provider = FakeProvider()
    val alice = Engine(clientLabel = aLabel)
    val bob = Engine(clientLabel = bLabel)
    val pid: String =
      val oob = "device-session-oob".getBytes("UTF-8")
      val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get
      bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get: Unit
      alice.confirmBuddy(a.pairId, matched = true).toOption.get
      bob.confirmBuddy(a.pairId, matched = true).toOption.get
      alice.drainEvents(); bob.drainEvents()
      a.pairId
    val sa =
      DeviceSession("alice", alice, provider, aLabel, refreshEveryRounds = 20, horizonRounds = 120)
    val sb =
      DeviceSession("bob", bob, provider, bLabel, refreshEveryRounds = 20, horizonRounds = 120)
    val ca = DeviceClock(sa, sched, 50, 50, 100)
    val cb = DeviceClock(sb, sched, 50, 50, 100)
    var aliceUp = true
    var bobUp = true
    var now = 1000L
    val toBob = mutable.ArrayBuffer.empty[String]

    def start(): Future[Unit] = sa.start(1).flatMap(_ => sb.start(1))

    /** The provider's clock and both devices, in 50 ms steps, until `untilRound` starts. */
    def runUntil(untilRound: Long): Future[Unit] =
      if now >= sched.openAt(untilRound) then Future.unit
      else
        val r = sched.roundAt(now)
        if now == sched.openAt(r) then provider.openRound(r)
        if now == sched.cutoffAt(r) then provider.closeRound(r)
        val a = if aliceUp then ca.step(now) else Future.unit
        a.flatMap(_ => if bobUp then cb.step(now) else Future.unit).flatMap { _ =>
          toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
          alice.drainEvents(): Unit
          now += 50
          runUntil(untilRound)
        }

  test("T037 through the shared session: m1 reaches the offline buddy from the bundle, then m2"):
    val w = World()
    for
      _ <- w.start()
      _ <- w.runUntil(11)
      _ = w.bobUp = false
      _ = w.alice.sendMessage(w.pid, "m1")
      _ = w.alice.sendMessage(w.pid, "m2")
      _ <- w.runUntil(31)
      _ = w.aliceUp = false
      _ <- w.runUntil(60)
      _ = assert(w.toBob.isEmpty)
      _ = w.bobUp = true
      _ <- w.sb.collectAway()
      _ <- w.runUntil(90)
      _ = assert(w.toBob == Seq("m1"), s"m1 from alice's bundle while she is away: ${w.toBob}")
      _ = w.aliceUp = true
      _ <- w.sa.collectAway()
      _ <- w.runUntil(120)
    yield assert(w.toBob == Seq("m1", "m2"), s"m2 follows in order, each once: ${w.toBob}")

  test("every round the provider runs exactly one operation set per user, online or not"):
    val w = World()
    for
      _ <- w.start()
      _ <- w.runUntil(21)
      _ = w.aliceUp = false
      _ <- w.runUntil(41)
    yield assert(w.provider.writes == 2 * 40, s"two users × 40 rounds: ${w.provider.writes}")
