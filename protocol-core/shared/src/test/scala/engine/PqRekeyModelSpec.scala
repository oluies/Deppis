package engine

import engine.PqTestKit.FakeBackend
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

import scala.collection.mutable

/** Model-based property test for the continuous-PQ rekey STATE MACHINE against two REAL engines and
  * a REAL (in-memory) store — Phase 4 of `design/continuous-pq-ratchet.md` (§7 Phase 4, §8.2,
  * §9 Q5). The companion to `DoubleRatchetModelSpec`'s rekey section: that one models the fold at
  * the ratchet layer with the engine's driving supplied by the test; this one drives nothing —
  * `Engine.tick` runs the actual rekey state machine, the actual `ChunkStream` transfer, the actual
  * hybrid KEM, over a store that randomly eats frames.
  *
  * ==What this adds over Phase 3 (Constitution IV — no padding the count)==
  * `PqRekeyCrossSpec` already drives a full fold end-to-end and already loses frames during a
  * rekey — but on ONE fixed script (drop every 3rd round, from round 200, one message cadence).
  * What did not exist is the MODEL: ScalaCheck choosing the loss rate, the traffic cadence and the
  * drop targets, so "a rekey never diverges the pair" is asserted across the reachable space of
  * loss/retransmit/duplicate interleavings rather than at one point in it. The state machine has
  * many timing-sensitive branches (idle-vs-busy trigger, chunk retransmit, the tag exchange, the
  * commit's anchor chosen at send time, the timeout, the point of no return) and a fixed script
  * visits exactly one path through them.
  *
  * ==The adversary is the honest one==
  * The store may DROP a frame (ARQ then retransmits it — which is also how DUPLICATES arise: a
  * lost ack makes the sender re-present a frame the peer already took). It may not forge or
  * reorder: every frame is AEAD-sealed under keys the store does not have, so a tampered frame is
  * simply a dropped one (already covered by the ratchet's no-mutation-on-undecryptable invariant),
  * and round-derived addressing plus stop-and-wait mean an in-flight frame cannot be overtaken.
  * Modeling a forge or a reorder here would be inventing an adversary the transport does not admit
  * — the forged-envelope cases are exercised where they ARE reachable (a malicious PEER) in
  * `PqRekeyCrossSpec`.
  *
  * ==What this model does NOT reach (measured, not guessed)==
  * The TIMEOUT paths are outside its horizon: `PqRekey.TimeoutRounds` is 2000 and a run drives ~1100
  * rounds, so no attempt here ever times out and nothing exercises the point of no return
  * (`Engine.safeToAbort`) or stranding (§9 Q5). Verified by mutation: replacing `safeToAbort` with
  * `true` leaves this suite GREEN — and turns four `PqRekeyCrossSpec` tests red, which is where that
  * property is tested with the explicit round arithmetic it needs. Stretching the horizon past 2000
  * rounds per case only to duplicate that coverage would cost minutes of CI for nothing, so this
  * model deliberately does not claim it. What it does catch, by the same mutation method: a
  * committer that arms the wrong anchor, and any divergence between the two roots.
  *
  * ==Honest scope==
  * Green here is NOT a PQ claim: it says the mechanism survives a lossy network without diverging.
  * The `pq_post_compromise_security` property is Phase 5's formal analysis under an attacker model
  * no test here represents. `DEV, NO METADATA PRIVACY` stands. */
class PqRekeyModelSpec extends AnyFunSuite with ScalaCheckPropertyChecks:

  // A run drives ~900 rounds of two real engines including ML-KEM keygen/encaps/decaps per
  // attempt, so the run count is deliberately small (see `minSuccessful` at the `forAll` below):
  // this explores the state machine's ORDERINGS, and the primitives underneath are KAT-pinned
  // elsewhere (kem.HybridKemCrossSpec, EpochKdfCrossSpec).
  private final case class Pair(be: FakeBackend, alice: Engine, bob: Engine, pid: String)

  /** A confirmed CLASSICAL pairing — `addBuddy`'s default, and per design §1.2 the pairing kind
    * with the most to gain from the fold. */
  private def pair(): Pair =
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = "alice".getBytes("UTF-8"))
    val bob = Engine(Some(be.transport()), clientLabel = "bob".getBytes("UTF-8"))
    val oob = "oob-shared-secret".getBytes("UTF-8")
    val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes("UTF-8"))
    val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = "alice".getBytes("UTF-8"))
    val ar = a.toOption.get
    val br = b.toOption.get
    alice.confirmBuddy(ar.pairId, matched = true).toOption.get
    bob.confirmBuddy(br.pairId, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    Pair(be, alice, bob, ar.pairId)

  private def status(e: Engine, pid: String): RekeyStatus = e.rekeyStatus(pid).get

  private val genScript: Gen[(Int, Int, Long)] = for {
    dropEvery <- Gen.choose(2, 9) // lose 1 round's frame in k — ARQ must carry the transfer
    sendEvery <- Gen.choose(0, 15) // 0 ⇒ a silent pair (the idle/opportunistic trigger path)
    seed <- Gen.choose(0L, Long.MaxValue) // which frame the store eats
  } yield (dropEvery, sendEvery, seed)

  /** Messages queued per side during the adversarial phase.
    *
    * BOUNDED ON PURPOSE, and the bound is load-bearing for the test's honesty. The transport is
    * stop-and-wait: one message in flight per pair, several rounds each, fewer still when the store
    * is eating frames. An unbounded send cadence therefore builds a backlog the recovery phase can
    * never drain, and then "the message I sent last never arrived" is a statement about QUEUE DEPTH,
    * not about the ratchet — it fires on a perfectly healthy pair and, worse, it fires for the same
    * reason on a broken one, so it cannot tell them apart. Capping the backlog is what makes the
    * post-rekey delivery below an actual divergence detector. (Learned the hard way: an earlier
    * revision of this test had no cap and "failed" identically whether or not the code was mutated.) */
  private val MaxQueuedPerSide = 8

  test("model: a rekey over a lossy store never diverges the pair (§7 Phase 4, §9 Q5)"):
    var totalFolds = 0
    var totalDrops = 0
    forAll(genScript, minSuccessful(6)) { case (dropEvery, sendEvery, seed) =>
      val p = pair()
      val rng = new scala.util.Random(seed)
      var drops = 0
      var sent = 0

      // Warm the pair so the cadence counter can arm the trigger, then run the adversarial phase.
      for r <- 1 to 40 do
        p.alice.tick(r.toLong): Unit
        p.bob.tick(r.toLong): Unit
        p.alice.drainEvents(): Unit
        p.bob.drainEvents(): Unit

      for r <- 41 to 700 do
        if sendEvery > 0 && sent < MaxQueuedPerSide && r % sendEvery == 0 then
          p.alice.sendMessage(p.pid, s"a$sent"): Unit
          p.bob.sendMessage(p.pid, s"b$sent"): Unit
          sent += 1
        p.alice.tick(r.toLong): Unit
        p.bob.tick(r.toLong): Unit
        p.alice.drainEvents(): Unit
        p.bob.drainEvents(): Unit
        // The store eats a frame: ARQ must recover it, and the rekey must not be diverged by the
        // retransmit (or by the duplicate a lost ack produces).
        if r % dropEvery == 0 && p.be.store.nonEmpty then
          val keys = p.be.store.keysIterator.toVector
          p.be.store.remove(keys(rng.nextInt(keys.size))): Unit
          drops += 1
      assert(drops > 0, "the script must actually have lost frames")
      totalDrops += drops

      // Recovery phase: a clean network, long enough to drain the bounded backlog. Whatever the
      // loss did to the rekey, the two sides must still be on the SAME root — and the only honest
      // observable is that they still talk (no oracle exposes a root, and two ratchets interoperate
      // iff their roots agree). A diverged pair delivers NOTHING from here on, in either direction.
      p.alice.sendMessage(p.pid, "after-a"): Unit
      p.bob.sendMessage(p.pid, "after-b"): Unit
      val gotA = mutable.ArrayBuffer.empty[String]
      val gotB = mutable.ArrayBuffer.empty[String]
      for r <- 701 to 1100 do
        p.alice.tick(r.toLong): Unit
        p.bob.tick(r.toLong): Unit
        gotA ++= p.alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
        gotB ++= p.bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }

      val sa = status(p.alice, p.pid)
      val sb = status(p.bob, p.pid)
      assert(gotB.contains("after-a"), s"a->b must still deliver after a lossy rekey: $sa")
      assert(gotA.contains("after-b"), s"b->a must still deliver after a lossy rekey: $sb")
      // Lockstep, within the one-step window the design permits: the committer arms its fold at its
      // OWN NEXT root index, so it legitimately lags the initiator by at most one fold until its
      // next DH step. Anything wider is a fold one side took and the other never will.
      assert(
        math.abs(sa.ratchetFolds - sb.ratchetFolds) <= 1,
        s"the two sides must fold in lockstep (±1 armed): $sa vs $sb"
      )
      assert(sa.ratchetFolds <= sa.epochsFolded + 1, s"a fold applies at most once per epoch: $sa")
      assert(sb.ratchetFolds <= sb.epochsFolded + 1, s"a fold applies at most once per epoch: $sb")
      totalFolds += sa.ratchetFolds
    }
    // ANTI-VACUITY: every assertion above holds trivially on a run where no rekey ever completed,
    // so pin that the model actually reaches the fold. Without this, a change that stopped the
    // rekey from ever triggering would leave this suite green.
    assert(totalFolds > 0, "the model must actually fold under loss, or it proves nothing")
    assert(totalDrops > 0, "and must actually have exercised the lossy network")
