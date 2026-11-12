package engine

import engine.PqTestKit.FakeBackend
import org.scalatest.funsuite.AnyFunSuite

import scala.collection.mutable

/** Phase 1 of `design/offline-delegation.md` (T037, US4): the engine-level tests written BEFORE the
  * Phase 2 engine changes they describe.
  *
  * Cross-platform (JVM + Scala.js), and in `crosstest/` rather than `shared/` because the rekey
  * scenarios need ML-KEM, which every engine-level rekey test already gets here.
  *
  * ==How "absence" is modelled==
  * An absent device simply stops ticking: it makes no live round. Where the design has the provider
  * running a bundle slot instead, [[SimulatedBundle]] replays what a stale bundle would put on the
  * wire for that device. The tests only use the public engine API plus the same public token
  * derivations the engine uses, so they need no Phase 2 API to compile.
  *
  * ==History==
  * These were written first (Phase 1) and wrapped in `pendingUntilFixed` while they failed. Phase 2
  * step 1 (re-seal, cached re-acks) made the MaxSkip test pass; step 2 (the paused-but-bounded rekey
  * clock) made the four absence tests pass. The silent-peer tests passed throughout and guard the
  * bound on the pause.
  *
  * Out of scope here, by design: the §3.4 ratchet-step bound for bundle building (it is a property
  * of the bundle builder and lands with it in Phase 2), and the end-to-end provider tests
  * (`server/provider`, created with T038 in Phase 3). `DEV, NO METADATA PRIVACY` stands. */
class OfflineDelegationCrossSpec extends AnyFunSuite:

  private val aLabel = "alice".getBytes("UTF-8")
  private val bLabel = "bob".getBytes("UTF-8")
  private val oob = "oob-shared-secret".getBytes("UTF-8")

  /** A confirmed classical pairing over one backend. `aliceUp` / `bobUp` let a test take either
    * device away (it stops ticking) and bring it back. */
  private final class Pair:
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val pid: String =
      val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get
      val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get
      assert(a.pairId == b.pairId)
      alice.confirmBuddy(a.pairId, matched = true).toOption.get
      bob.confirmBuddy(b.pairId, matched = true).toOption.get
      alice.drainEvents(); bob.drainEvents()
      a.pairId
    var aliceUp = true
    var bobUp = true
    val toAlice = mutable.ArrayBuffer.empty[String]
    val toBob = mutable.ArrayBuffer.empty[String]

    /** One round: every present device ticks; deliveries are collected. */
    def round(r: Long): Unit =
      if aliceUp then alice.tick(r): Unit
      if bobUp then bob.tick(r): Unit
      toAlice ++= alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      toBob ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }

    def run(rounds: Iterable[Long]): Unit = rounds.foreach(round)

    def status(e: Engine): RekeyStatus = e.rekeyStatus(pid).get

  /** Exchange `n` messages each way so the rekey cadence counter passes `PqRekey.IdleMinSteps`
    * (the initiator then starts an attempt on its own). Returns the next free round. */
  private def warm(p: Pair, n: Int, from: Long): Long =
    var r = from
    for i <- 0 until n do
      p.alice.sendMessage(p.pid, s"warm-a$i"): Unit
      p.bob.sendMessage(p.pid, s"warm-b$i"): Unit
      p.run(r until r + 12)
      r += 12
    r

  /** Tick both devices until `ready` holds for `side`'s rekey status. Returns the next free round. */
  private def driveUntil(p: Pair, side: Engine, from: Long)(ready: RekeyStatus => Boolean): Long =
    var r = from
    while r < from + 900 && !ready(p.status(side)) do
      p.round(r)
      r += 1
    assert(
      ready(p.status(side)),
      s"the test must reach the phase it targets, got ${p.status(side)}"
    )
    r

  /** What a stale bundle puts on the wire for an absent INITIATOR (alice): her head, re-presented
    * every round under that round's token, with the round's notify bit set for bob. Byte-identical
    * copies are what today's cached head is; the design's re-sealed copies (§4.1) carry the same
    * consumed message key, so the receiver treats both the same way: they fail to decrypt. */
  private final class SimulatedBundle(p: Pair, wire: Array[Byte]):
    private val addrKey = KeySchedule.addrKey(handshake.Handshake.init(oob).pairKey)
    private val net = p.be.transport()
    def slot(r: Long): Unit =
      net.submit(
        token.RetrievalToken.derive(
          addrKey,
          BuddyRole.Initiator.toString,
          BuddyRole.Responder.toString,
          r
        ),
        wire
      ): Unit
      net.signal(r, NotifyDigest.labelTag(bLabel), NotifyDigest.bit(addrKey, r))

  // ============================================================== §4.5 MaxSkip across an absence

  test(
    "§4.5: a long absence must not push the pair past MaxSkip (re-acks must not step the ratchet)"
  ):
    val p = Pair()
    // Alice sends one message, bob receives and acks it. Capture the wire that carried it: the
    // first frame alice writes under her alice→bob token.
    val addrKey = KeySchedule.addrKey(handshake.Handshake.init(oob).pairKey)
    def aToB(r: Long) =
      PqTestKit.hex(
        token.RetrievalToken.derive(
          addrKey,
          BuddyRole.Initiator.toString,
          BuddyRole.Responder.toString,
          r
        )
      )
    p.alice.sendMessage(p.pid, "before"): Unit
    var head: Array[Byte] = null
    var r = 1L
    while r <= 40 do
      p.round(r)
      if head == null then p.be.store.get(aToB(r)).foreach(f => head = f.clone())
      r += 1
    assert(
      p.toBob.contains("before"),
      s"precondition: the first message is delivered: ${p.toBob}"
    )
    assert(head != null, "precondition: alice's content wire was captured")

    // Alice disconnects abruptly. Her stale bundle keeps re-presenting that (already consumed)
    // head for longer than MaxSkip rounds, while bob stays online and idle.
    p.aliceUp = false
    val bundle = SimulatedBundle(p, head)
    val absence = DoubleRatchet.MaxSkip.toLong + 500L
    for x <- r until r + absence do
      bundle.slot(x)
      p.round(x)
    r += absence

    // Alice comes back. Bob's next messages must still decrypt at alice: bob's sending chain may
    // have advanced by at most one step per content message alice actually delivered, never once
    // per copy he could not decrypt.
    p.aliceUp = true
    p.bob.sendMessage(p.pid, "after-1"): Unit
    p.bob.sendMessage(p.pid, "after-2"): Unit
    p.run(r until r + 80)
    assert(
      p.toAlice.containsSlice(Seq("after-1", "after-2")),
      s"bob → alice must survive alice's absence, in order: ${p.toAlice}"
    )

  // ====================================================== §4.1 retained (MK, HK) wipe table

  test("§4.1: at most two retained key pairs per buddy, wiped at the listed points"):
    val p = Pair()
    def held(e: Engine) = e.retainedKeyPairsForTest(p.pid)
    var r = 1L
    def step(n: Int): Unit =
      for _ <- 0 until n do
        p.round(r)
        assert(held(p.alice) <= 2 && held(p.bob) <= 2, s"round $r: more than two retained pairs")
        r += 1
    // Alice's head is retained while in flight…
    p.alice.sendMessage(p.pid, "m1"): Unit
    p.round(r); r += 1
    assert(held(p.alice) == 1, "alice retains her in-flight head")
    // …and wiped once bob's ack lands. Bob, having received content, retains his ack-only frame.
    step(20)
    assert(p.toBob.contains("m1"))
    assert(held(p.alice) == 0, "the head's keys are wiped when it is acked")
    assert(held(p.bob) == 1, "bob retains the ack-only frame for his current ack")
    // A content frame from bob carries the ack, so his cached ack-only frame is wiped; and alice's
    // own ack for it follows the same rules.
    p.bob.sendMessage(p.pid, "b1"): Unit
    step(20)
    assert(p.toAlice.contains("b1"))
    assert(held(p.bob) <= 1, "bob's ack-only frame went once a content frame carried the ack")
    // A burst both ways keeps within the bound throughout (checked every round by `step`).
    for i <- 0 until 5 do
      p.alice.sendMessage(p.pid, s"a$i"): Unit
      p.bob.sendMessage(p.pid, s"b$i"): Unit
    step(120)
    // Removal wipes everything.
    p.alice.removeBuddy(p.pid): Unit
    assert(held(p.alice) == 0, "removeBuddy wipes both retained pairs")

  // ======================================================= §4.4 rekey timeout across an absence

  private enum Absent:
    case Initiator, Responder

  private enum Phase:
    case PreCommit, PostCommit

  /** The four absence variants: start a rekey, drop one device abruptly in the given phase, keep it
    * away for longer than `TimeoutRounds` (but far less than H) while its peer stays online, bring
    * it back. Neither end may abort or strand the attempt, queued content is delivered both ways,
    * and the pair completes the rekey. */
  private def absenceAcrossRekey(absent: Absent, phase: Phase): Unit =
    val p = Pair()
    var r = warm(p, PqRekey.IdleMinSteps, from = 1)
    r = phase match
      case Phase.PreCommit => driveUntil(p, p.alice, r)(s => s.inProgress && s.abortSafe)
      case Phase.PostCommit => driveUntil(p, p.alice, r)(s => s.inProgress && !s.abortSafe)
    val before = (p.status(p.alice), p.status(p.bob))

    absent match
      case Absent.Initiator => p.aliceUp = false
      case Absent.Responder => p.bobUp = false
    // Content queued on the present side while the other is away.
    if p.aliceUp then p.alice.sendMessage(p.pid, "queued-a"): Unit
    if p.bobUp then p.bob.sendMessage(p.pid, "queued-b"): Unit
    val away = PqRekey.TimeoutRounds + 200L
    p.run(r until r + away)
    r += away

    p.aliceUp = true; p.bobUp = true
    if absent == Absent.Initiator then p.alice.sendMessage(p.pid, "queued-a"): Unit
    else p.bob.sendMessage(p.pid, "queued-b"): Unit
    p.run(r until r + 1500)

    val (sa, sb) = (p.status(p.alice), p.status(p.bob))
    for (who, s, s0) <- Seq(("alice", sa, before._1), ("bob", sb, before._2)) do
      assert(s.aborts == s0.aborts, s"$who must not abort the attempt over an absence: $s")
      assert(s.strandedAttemptAgeRounds == 0, s"$who must not report a stranding: $s")
      assert(
        s.lastAbort != "pq_rekey_timeout" && s.lastAbort != "pq_rekey_stranded",
        s"$who timed out over an absence: $s"
      )
    assert(p.toBob.contains("queued-a"), s"alice → bob delivered after the absence: ${p.toBob}")
    assert(p.toAlice.contains("queued-b"), s"bob → alice delivered after the absence: ${p.toAlice}")
    assert(sa.ratchetFolds == sb.ratchetFolds, s"both sides fold in lockstep: $sa vs $sb")
    assert(sa.epochsFolded >= 1 && sb.epochsFolded >= 1, s"the paused rekey completes: $sa / $sb")

  test("§4.4: initiator absent during a pre-commit rekey — no timeout, rekey completes"):
    absenceAcrossRekey(Absent.Initiator, Phase.PreCommit)

  test("§4.4: responder absent during a pre-commit rekey — no timeout, rekey completes"):
    absenceAcrossRekey(Absent.Responder, Phase.PreCommit)

  test("§4.4: initiator absent after commit — no stranding, rekey completes"):
    absenceAcrossRekey(Absent.Initiator, Phase.PostCommit)

  test("§4.4: responder absent after commit — no stranding, rekey completes"):
    absenceAcrossRekey(Absent.Responder, Phase.PostCommit)

  // ============================================================ §4.4 silent peer still times out

  /** The fifth variant: the peer stays away for good. The pause must be bounded, so the attempt
    * still ends — aborted before commit, reported stranded after — within `TimeoutRounds` + P
    * rounds of alice running. This holds today (no pause at all) and must keep holding after
    * Phase 2 adds the pause. */
  private def silentPeer(phase: Phase): (RekeyStatus, RekeyStatus, Long, Long) =
    val p = Pair()
    var r = warm(p, PqRekey.IdleMinSteps, from = 1)
    r = phase match
      case Phase.PreCommit => driveUntil(p, p.alice, r)(s => s.inProgress && s.abortSafe)
      case Phase.PostCommit => driveUntil(p, p.alice, r)(s => s.inProgress && !s.abortSafe)
    val before = p.status(p.alice)
    p.bobUp = false
    // "Overdue" is STRICTLY more than `TimeoutRounds` counted rounds, and counting starts on the
    // tick after the attempt opens, so the latest the attempt can end is one round past the sum.
    val bound = before.attemptStartRound + PqRekey.TimeoutRounds + PqRekey.PauseAllowanceRounds + 1
    // An aborted attempt frees the slot and the initiator starts a NEW one straight away, so "no
    // attempt in progress" is never observed. What ends THIS attempt is an abort (pre-commit) or a
    // stranding report (post-commit).
    def ended(s: RekeyStatus) = phase match
      case Phase.PreCommit => s.aborts > before.aborts
      case Phase.PostCommit => s.strandedAttemptAgeRounds > 0
    while r <= bound + 1 && !ended(p.status(p.alice)) do
      p.round(r)
      r += 1
    (before, p.status(p.alice), r - 1, bound)

  test("§4.4: a silent peer still times out a pre-commit attempt within TimeoutRounds + P"):
    val (before, s, at, bound) = silentPeer(Phase.PreCommit)
    assert(s.aborts == before.aborts + 1, s"the attempt must be aborted by round $bound: $s")
    assert(at <= bound, s"aborted at round $at, after the bound $bound")
    assert(s.lastAbort == "pq_rekey_timeout", s"it ends by timing out: $s")
    // The abort freed the slot: `maybeStartRekey` only runs when no attempt is held, so a NEW
    // attempt starting proves the old one — and its KEM secret — is gone.
    assert(s.attempts > before.attempts, s"the pair can rekey again: $s")

  test("§4.4: a silent peer is reported stranded after commit within TimeoutRounds + P"):
    val (_, s, at, bound) = silentPeer(Phase.PostCommit)
    assert(s.strandedAttemptAgeRounds > 0, s"stranding must be reported by round $bound: $s")
    assert(at <= bound, s"reported at round $at, after the bound $bound")
    assert(s.lastAbort == "pq_rekey_stranded", s"reported as stranded: $s")
