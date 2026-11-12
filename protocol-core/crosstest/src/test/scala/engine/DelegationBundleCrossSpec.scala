package engine

import engine.PqTestKit.FakeBackend
import org.scalatest.funsuite.AnyFunSuite

import scala.collection.mutable

/** The split round and the standing bundle (offline-delegation.md §3.1, §3.3, §3.4) — Phase 2 step 3.
  * Cross-platform (JVM + Scala.js).
  *
  * `Engine.tick` is now `beginRound` → execute → `applyReceipt`; the existing suites pin that `tick`
  * behaves exactly as before. This suite pins what the split adds:
  *   - a bundle steps the ratchet at most once per head and once per ack value, however often it is
  *     rebuilt (§3.4);
  *   - every slot has the same shape whatever is queued, and no two slots share bytes or tokens;
  *   - no token recurs across build → absence → resume, even for bundles that never ran (FR-014);
  *   - a receipt for a slot that ran instead of the live round applies nothing;
  *   - end to end at engine level: a message queued before an abrupt disconnect reaches a buddy who
  *     was offline too, carried by the bundle, and the queue drains in order once the sender is back
  *     — the case `design/offline-delegation.md` §1 row 3 says fails without delegation. */
class DelegationBundleCrossSpec extends AnyFunSuite:

  private val aLabel = "alice".getBytes("UTF-8")
  private val bLabel = "bob".getBytes("UTF-8")
  private val oob = "oob-shared-secret".getBytes("UTF-8")
  private def hex(b: Array[Byte]) = PqTestKit.hex(b)

  private final class Pair:
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val pid: String =
      val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get
      val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get
      alice.confirmBuddy(a.pairId, matched = true).toOption.get
      bob.confirmBuddy(b.pairId, matched = true).toOption.get
      alice.drainEvents(); bob.drainEvents()
      a.pairId
    val toAlice = mutable.ArrayBuffer.empty[String]
    val toBob = mutable.ArrayBuffer.empty[String]
    def collect(): Unit =
      toAlice ++= alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }

    /** What a provider does with one slot: submit, signal (the real one only if the write was
      * accepted), read — and drop the read result, since the device is away. */
    def runSlot(slot: RoundOps): Unit =
      val net = be.transport()
      val accepted = net.submit(slot.writeToken, slot.frame)
      val sig = if accepted then slot.signal else slot.fallbackSignal
      net.signal(slot.roundId, sig.label, sig.bit)
      net.retrieve(slot.readToken): Unit

  private def isCover(s: RoundOps) = s.signal.label.sameElements(s.fallbackSignal.label)

  /** Tick both until bob has delivered `msg` to alice and alice has just received it — alice then
    * owes an ack and has nothing queued. Returns the next free round. */
  private def aliceOwesAck(p: Pair, msg: String): Long =
    p.bob.sendMessage(p.pid, msg): Unit
    // Bob is the responder: he can only send once alice's first frame has opened his chain.
    p.alice.sendMessage(p.pid, "hi"): Unit
    var r = 1L
    while !p.toAlice.contains(msg) && r < 200 do
      p.alice.tick(r): Unit; p.bob.tick(r): Unit
      p.collect()
      r += 1
    assert(p.toAlice.contains(msg), s"precondition: bob's message reached alice: ${p.toAlice}")
    r

  // ================================================================= §3.4 ratchet-step bound

  test("§3.4: a bundle opens at most one head per buddy, however often it is rebuilt"):
    val p = Pair()
    for i <- 1 to 3 do p.alice.sendMessage(p.pid, s"m$i"): Unit
    val before = p.alice.sendIndexForTest(p.pid)
    p.alice.buildBundle(100, 50).toOption.get: Unit
    val afterFirst = p.alice.sendIndexForTest(p.pid)
    assert(
      afterFirst == before + 1,
      s"the first build opens the head — exactly one step: $before → $afterFirst"
    )
    for _ <- 0 until 10 do p.alice.buildBundle(100, 50).toOption.get: Unit
    assert(p.alice.sendIndexForTest(p.pid) == afterFirst, "rebuilding steps nothing more")

  test("§3.4: a bundle builds at most one ack-only frame per ack value, however often rebuilt"):
    val p = Pair()
    aliceOwesAck(p, "from-bob")
    val before = p.alice.sendIndexForTest(p.pid)
    val b = p.alice.buildBundle(1000, 40).toOption.get
    assert(b.slots.forall(s => !isCover(s)), "with an ack owed, every slot carries the ack")
    val afterFirst = p.alice.sendIndexForTest(p.pid)
    assert(afterFirst == before + 1, s"exactly one ack-only frame: $before → $afterFirst")
    for _ <- 0 until 10 do p.alice.buildBundle(1000, 40).toOption.get: Unit
    assert(p.alice.sendIndexForTest(p.pid) == afterFirst, "rebuilding builds no new ack frame")

  // ========================================================= shape, distinctness, no recurrence

  test("§3.3: every slot has the same shape, empty outbox or full"):
    val idle = Pair().alice.buildBundle(10, 30).toOption.get
    val p = Pair()
    for i <- 1 to 5 do p.alice.sendMessage(p.pid, s"m$i"): Unit
    val busy = p.alice.buildBundle(10, 30).toOption.get
    def shape(s: RoundOps) =
      (
        s.writeToken.length,
        s.frame.length,
        s.signal.label.length,
        s.fallbackSignal.label.length,
        s.readToken.length
      )
    assert(idle.slots.size == 30 && busy.slots.size == 30)
    assert(idle.slots.map(shape).distinct == busy.slots.map(shape).distinct)
    assert(busy.slots.forall(_.frame.length == frame.Frame.Size))
    assert(busy.slots.map(_.roundId) == (10L until 40L).toVector, "one slot per round, in order")

  test("§3.3: no two slots share frame bytes, write tokens or read tokens"):
    val p = Pair()
    p.alice.sendMessage(p.pid, "m1"): Unit
    for b <- Seq(Pair().alice.buildBundle(5, 200), p.alice.buildBundle(5, 200)) do
      val slots = b.toOption.get.slots
      for (name, f) <- Seq[(String, RoundOps => Array[Byte])](
          "frame" -> (_.frame),
          "write token" -> (_.writeToken),
          "read token" -> (_.readToken)
        )
      do
        val hs = slots.map(s => hex(f(s)))
        assert(hs.distinct.size == hs.size, s"a $name repeats within one bundle")

  test("FR-014: no token recurs across build → absence → resume, even from bundles that never ran"):
    val p = Pair()
    p.alice.sendMessage(p.pid, "m1"): Unit
    // A few stale bundles that never run, then the one that does.
    val stale = (0 until 3).map(_ => p.alice.buildBundle(50, 40).toOption.get)
    val bundle = p.alice.buildBundle(50, 40).toOption.get
    val ran = bundle.slots.take(25) // alice is away for rounds 50..74, then comes back
    ran.foreach(p.runSlot)
    // Alice resumes live at round 75, with a transport that records what she presents.
    val presentedWrites = mutable.ArrayBuffer.empty[String]
    val presentedReads = mutable.ArrayBuffer.empty[String]
    val recording = new RoundTransport:
      private val inner = p.be.transport()
      def submit(t: Array[Byte], f: Array[Byte]) = { presentedWrites += hex(t); inner.submit(t, f) }
      def retrieve(t: Array[Byte]) = { presentedReads += hex(t); inner.retrieve(t) }
      override def signal(r: Long, l: Array[Byte], b: Int): Unit = inner.signal(r, l, b)
      def fetchDigest(r: Long, l: Array[Byte]) = inner.fetchDigest(r, l)
    // Same engine state, new transport: rebuild alice around a recording transport is not possible
    // without re-pairing, so drive her rounds by hand through the split API instead.
    for r <- 75L until 200L do
      val ops = p.alice.beginRound(r, recording.fetchDigest(r - 1, NotifyDigest.labelTag(aLabel)))
      val ok = recording.submit(ops.writeToken, ops.frame)
      val sig = if ok then ops.signal else ops.fallbackSignal
      recording.signal(r, sig.label, sig.bit)
      val got = recording.retrieve(ops.readToken)
      p.alice.applyReceipt(RoundReceipt(r, ranLive = true, ok, got)).toOption.get: Unit
    val executedWrites = ran.map(s => hex(s.writeToken)) ++ presentedWrites
    val executedReads = ran.map(s => hex(s.readToken)) ++ presentedReads
    assert(executedWrites.distinct.size == executedWrites.size, "a write token was presented twice")
    assert(executedReads.distinct.size == executedReads.size, "a read token was presented twice")
    // Cover tokens of EVERY built bundle — including the stale ones that never ran — stay retired.
    val bundleCovers =
      (stale :+ bundle).flatMap(_.slots.filter(isCover)).map(s => hex(s.writeToken))
    val bundleReads = (stale :+ bundle).flatMap(_.slots).map(s => hex(s.readToken))
    assert(
      presentedWrites.toSet.intersect(bundleCovers.toSet).isEmpty,
      "a bundle cover write recurred"
    )
    assert(
      presentedReads.toSet.intersect(bundleReads.toSet).isEmpty,
      "a bundle cover read recurred"
    )

  // ============================================================== §3.1 receipts

  test("§3.1: a receipt for a round that ran from a slot applies nothing of the live set"):
    val p = Pair()
    var r = aliceOwesAck(p, "from-bob")
    val digest = new Array[Byte](64)
    // The live set carries the owed ack, but a slot ran instead: the ack is still owed next round.
    val ops1 = p.alice.beginRound(r, digest)
    assert(!isCover(ops1), "the live round would have sent the ack")
    assert(p.alice.applyReceipt(RoundReceipt(r, ranLive = false, true, None)) == Right(false))
    r += 1
    val ops2 = p.alice.beginRound(r, digest)
    assert(!isCover(ops2), "the ack is still owed after a slot ran in its place")
    // This time the live set runs and is accepted: the ack is paid, and the next round is a cover.
    assert(p.alice.applyReceipt(RoundReceipt(r, ranLive = true, true, None)) == Right(true))
    r += 1
    assert(isCover(p.alice.beginRound(r, digest)), "nothing left to send once the ack was accepted")

  test("§3.1: a receipt that does not match the pending round is refused"):
    val p = Pair()
    assert(
      p.alice.applyReceipt(RoundReceipt(7, ranLive = true, true, None)).isLeft,
      "nothing pending"
    )
    p.alice.beginRound(8, new Array[Byte](64)): Unit
    assert(p.alice.applyReceipt(RoundReceipt(9, ranLive = true, true, None)).isLeft, "wrong round")
    assert(p.alice.applyReceipt(RoundReceipt(8, ranLive = true, true, None)).isRight)

  // ============================================== end to end: the §1 row-3 case, carried by a bundle

  test("§1: a message queued before an abrupt disconnect reaches an offline buddy via the bundle"):
    val p = Pair()
    // Bob is offline from the start. Alice queues two messages and runs a few rounds herself.
    p.alice.sendMessage(p.pid, "m1"): Unit
    p.alice.sendMessage(p.pid, "m2"): Unit
    for r <- 1L to 5L do p.alice.tick(r): Unit
    // Her standing bundle covers rounds 6..305; then she disconnects with no warning.
    val bundle = p.alice.buildBundle(6, 300).toOption.get
    // Rounds 6..199: the provider runs alice's slots; bob comes online at round 60.
    for r <- 6L until 200L do
      p.runSlot(bundle.slots((r - 6).toInt))
      if r >= 60 then p.bob.tick(r): Unit
      p.collect()
    assert(p.toBob == Seq("m1"), s"m1 reaches bob while alice is away: ${p.toBob}")
    // Alice comes back at round 200 (the provider stops running her slots) and the queue drains.
    for r <- 200L until 260L do
      p.alice.tick(r): Unit; p.bob.tick(r): Unit
      p.collect()
    assert(p.toBob == Seq("m1", "m2"), s"m2 follows once alice is back, in order, once: ${p.toBob}")
