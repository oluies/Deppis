package provider

import crypto.Crypto
import engine.{BuddyRole, DelegationBundle, Engine, EngineEvent, RoundTransport}
import org.scalatest.funsuite.AnyFunSuite
import ping.DevNotificationServer

import scala.collection.mutable

/** T037 end to end + T038 (`design/offline-delegation.md` §3, §5, §7 Phases 1 and 3): two engines
  * whose every round goes through one untrusted [[Provider]] over the dev backend (dev PONG store +
  * dev PING notify server), each driven by a [[ProviderSession]].
  *
  * Small H and F (`Horizon`, `Refresh`) keep the runs short; the production values are network-wide
  * constants in `engine.Delegation`, and nothing here depends on their size. */
class ProviderSpec extends AnyFunSuite:

  private val Horizon = 200
  private val Refresh = 20
  private val aLabel = "alice-label".getBytes("UTF-8")
  private val bLabel = "bob-label".getBytes("UTF-8")
  private val oob = "provider-spec-oob".getBytes("UTF-8")
  private def hex(b: Array[Byte]) = b.map(x => f"${x & 0xff}%02x").mkString

  /** What the BACKEND sees, per round: the provider's writes and signals, and its digest fetches per
    * `(round, label)`. Rounds are the provider's open round (set by the world before each cutoff). */
  private final class CountingBackend(inner: RoundTransport) extends RoundTransport:
    var round: Long = 0L
    val writes = mutable.Map.empty[Long, Int].withDefaultValue(0)
    val signals = mutable.Map.empty[Long, Int].withDefaultValue(0)
    val fetches = mutable.Map.empty[(Long, String), Int].withDefaultValue(0)
    def submit(t: Array[Byte], f: Array[Byte]) = { writes(round) += 1; inner.submit(t, f) }
    def retrieve(t: Array[Byte]) = inner.retrieve(t)
    override def signal(r: Long, l: Array[Byte], b: Int): Unit =
      signals(r) += 1; inner.signal(r, l, b)
    def fetchDigest(r: Long, l: Array[Byte]) =
      fetches((r, hex(l))) += 1; inner.fetchDigest(r, l)

  private final class World:
    val backend = CountingBackend(
      DevProviderBackend(notifications =
        DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))
      )
    )
    val provider = Provider(backend, maxHorizon = Horizon)
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
    var aliceUp = true
    var bobUp = true
    val toBob = mutable.ArrayBuffer.empty[(Long, String)]
    val toAlice = mutable.ArrayBuffer.empty[(Long, String)]

    def round(r: Long): Unit =
      backend.round = r
      provider.openRound(r).toOption.get
      if aliceUp then sa.beforeCutoff(r)
      if bobUp then sb.beforeCutoff(r)
      provider.closeRound(r).toOption.get: Unit
      if aliceUp then sa.afterCutoff(r)
      if bobUp then sb.afterCutoff(r)
      toAlice ++= alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) =>
        (r, t)
      }
      toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => (r, t) }

  // ============================================================ T037 — the §1 row-3 case, end to end

  test("T037: a message sent to an offline buddy arrives after the sender disconnects abruptly"):
    val w = World()
    for r <- 1L to 10L do w.round(r)
    w.bobUp = false // bob goes offline, no warning: his standing bundle runs his rounds
    w.alice.sendMessage(w.pid, "m1"): Unit
    w.alice.sendMessage(w.pid, "m2"): Unit
    for r <- 11L to 30L do w.round(r) // alice retransmits m1 live; she refreshes her bundle at 20
    w.aliceUp = false // alice disconnects abruptly too: now BOTH run from bundles
    for r <- 31L to 99L do w.round(r)
    assert(w.toBob.isEmpty, "nothing can be read while bob is away")
    w.bobUp = true // bob returns; alice is still away
    w.sb.collectAway(): Unit
    for r <- 100L to 149L do w.round(r)
    assert(
      w.toBob.map(_._2) == Seq("m1"),
      s"m1 arrives from alice's bundle while she is away: ${w.toBob}"
    )
    w.aliceUp = true // alice returns; the queue drains in order
    w.sa.collectAway(): Unit
    for r <- 150L to 199L do w.round(r)
    assert(
      w.toBob.map(_._2) == Seq("m1", "m2"),
      s"m2 follows in order, each exactly once: ${w.toBob}"
    )
    assert(w.toBob.head._1 < 150, "m1 was delivered before alice came back")

  test(
    "T037: across disconnect → reconnect the backend sees one fetch per (round, label) and one write and one signal per user per round"
  ):
    val w = World()
    w.alice.sendMessage(w.pid, "hello"): Unit
    for r <- 1L to 40L do w.round(r)
    w.aliceUp = false
    for r <- 41L to 80L do w.round(r)
    w.bobUp = false
    for r <- 81L to 120L do w.round(r)
    w.aliceUp = true; w.bobUp = true
    for r <- 121L to 160L do w.round(r)
    for r <- 1L to 160L do
      assert(w.backend.writes(r) == 2, s"round $r: ${w.backend.writes(r)} writes, not one per user")
      assert(
        w.backend.signals(r) == 2,
        s"round $r: ${w.backend.signals(r)} signals, not one per user"
      )
      for lbl <- Seq(aLabel, bLabel) do
        val tag = hex(engine.NotifyDigest.labelTag(lbl))
        assert(w.backend.fetches((r - 1, tag)) == 1, s"round $r: digest fetched ≠ once")
    assert(w.toBob.map(_._2) == Seq("hello"))

  // ================================================================== T038 — the provider's rules

  test(
    "the cutoff: a live set handed in after its round closed is refused, and the slot ran instead"
  ):
    val w = World()
    for r <- 1L to 3L do w.round(r)
    w.provider.openRound(4).toOption.get
    w.provider.closeRound(4).toOption.get: Unit // alice misses the cutoff entirely
    val late = w.alice.beginRound(4, Array.emptyByteArray)
    assert(!w.provider.submitLive("alice", late), "a live set for a closed round is refused")
    val kept = w.provider.collectReceipt("alice", 4).get
    assert(!kept.receipt.ranLive, "her bundle slot ran in round 4")

  test("one live set per user per round; unknown users and mismatched rounds are refused"):
    val w = World()
    w.provider.openRound(1).toOption.get
    val ops = w.alice.beginRound(1, Array.emptyByteArray)
    assert(w.provider.submitLive("alice", ops))
    assert(!w.provider.submitLive("alice", ops), "a second live set for the same round")
    assert(!w.provider.submitLive("mallory", ops), "an unknown user")
    assert(!w.provider.submitLive("bob", ops.copy(roundId = 2)), "a round that is not open")

  test(
    "bundle uploads are validated: size, consecutive rounds, not starting in the past, known user"
  ):
    val w = World()
    def bundle(from: Long, n: Int) = w.alice.buildBundle(from, n).toOption.get
    assert(w.provider.uploadBundle("alice", bundle(1, Horizon + 1)).isLeft, "longer than H")
    val b = bundle(10, 5)
    val gap = DelegationBundle(10, b.slots.updated(2, b.slots(2).copy(roundId = 99)))
    assert(w.provider.uploadBundle("alice", gap).isLeft, "slots must be consecutive rounds")
    assert(w.provider.uploadBundle("mallory", bundle(10, 5)).isLeft, "unknown user")
    for r <- 1L to 5L do w.round(r)
    assert(w.provider.uploadBundle("alice", bundle(5, 5)).isLeft, "starts at a closed round")
    assert(w.provider.uploadBundle("alice", bundle(6, 5)).isRight)

  test("§5 retention: slots are deleted as their rounds close, receipts are bounded by H"):
    val w = World()
    w.aliceUp = false; w.bobUp = false // both away: only slots run, and nothing collects receipts
    val before = w.provider.slotCount("alice")
    assert(before == Horizon, s"a full standing bundle: $before")
    for r <- 1L to 50L do w.round(r)
    assert(w.provider.slotCount("alice") == Horizon - 50, "each closed round's slot is gone")
    assert(w.provider.receiptCount("alice") == 50, "one receipt kept per round run while away")
    for r <- 51L to Horizon.toLong + 30 do w.round(r)
    assert(w.provider.slotCount("alice") == 0, "the bundle ran out")
    assert(w.provider.receiptCount("alice") <= Horizon, "receipts never exceed H")
    assert(w.sa.collectAway().size <= Horizon)
    assert(w.provider.receiptCount("alice") == 0, "collected receipts are gone")

  test("an expired bundle goes silent (the §6 horizon-expiry residual)"):
    val w = World()
    w.aliceUp = false; w.bobUp = false
    for r <- 1L to Horizon.toLong do w.round(r)
    w.backend.round = Horizon + 1L
    w.provider.openRound(Horizon + 1L).toOption.get
    assert(w.provider.closeRound(Horizon + 1L) == Right(0), "no slot left and no live set: silence")

  test("rounds must be opened and closed in order"):
    val w = World()
    w.provider.openRound(5).toOption.get
    assert(w.provider.openRound(6).isLeft, "a round is already open")
    assert(w.provider.closeRound(6).isLeft, "not the open round")
    w.provider.closeRound(5).toOption.get: Unit
    assert(w.provider.openRound(5).isLeft, "round ids must increase")

  test("labeling: the provider is DEV, never metadata-private, before Phase 4 (Constitution IV)"):
    val w = World()
    assert(!w.provider.metadataPrivate)
    assert(w.provider.label == privacy.Privacy.DevLabel)
