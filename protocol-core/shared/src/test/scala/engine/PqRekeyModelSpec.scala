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
  * hybrid KEM, over a network that eats frames.
  *
  * ==What this adds over Phase 3 (Constitution IV — no padding the count)==
  * `PqRekeyCrossSpec` already drives a full fold end-to-end and already loses frames during a
  * rekey — but on ONE fixed script (drop every 3rd round, from round 200, one message cadence).
  * What did not exist is the MODEL: ScalaCheck choosing the loss rate and the traffic cadence, so
  * "a rekey never diverges the pair" is asserted across the reachable space of loss/retransmit/
  * duplicate interleavings rather than at one point in it. The state machine has many
  * timing-sensitive branches (idle-vs-busy trigger, chunk retransmit, the tag exchange, the
  * commit's anchor chosen at send time) and a fixed script visits exactly one path through them.
  *
  * ==The adversary drops LIVE FRAMES, not map entries (and this is load-bearing)==
  * Loss is injected by swallowing a `retrieve` that would have returned a live frame
  * ([[PqTestKit.UnreliableTransport]]), so every drop is exactly one real frame the peer wrote —
  * countable, and impossible to waste. That class's doc carries the full account: what `lost` does
  * and does not mean, why reaching into `FakeBackend.store` to `remove` a key is a TRAP that an
  * earlier revision of this test fell into, and why counting retransmissions would not have caught
  * it either. The adversary may not forge or reorder; the forged-envelope cases are exercised where
  * they ARE reachable (a malicious PEER) in `PqRekeyCrossSpec`.
  *
  * ==What this model does NOT reach (measured, not guessed)==
  * LANE ARBITRATION is still not pinned HERE, but it is no longer unpinned anywhere: the follow-up
  * this doc used to record has landed as `RekeyStatus.ctrlHeads` / `ctrlHeadsOverContent`, asserted
  * in `PqRekeyCrossSpec`'s "the chunk lane wins heads AGAINST pending content". The history is worth
  * keeping, because two earlier attempts to claim it from this model were both wrong. A counter of
  * rounds where a rekey was in progress while content was unacked is trivially satisfied: the
  * warm-up ends idle with `stepsSinceFold >= IdleMinSteps`, so an attempt is ALREADY open when the
  * adversarial phase starts (measured: `inProgress = true` at `advStart`, 3/3 runs) and the first
  * send makes the condition true on round 0 — for every busy case, whatever the scheduler does. It
  * also measures the wrong thing: `decide` is consulted once per HEAD with
  * `chunkPending = rt.ctrl.nonEmpty`, while `inProgress` stays true across long stretches with an
  * empty `ctrl` (awaiting the peer's pub or tag). Only a counter incremented AT the decision, and
  * only its content-was-also-pending half, states the property. `busyCases > 0` below still guards
  * only what it says: that the generator produces busy cases at all.
  *
  * CROSS-SIDE ROOT AGREEMENT is not directly assertable, and the reason is worth recording so the
  * dead end is not re-walked. `DoubleRatchet.rootIndex` is public, so a root fingerprint seam looks
  * like it would let a test state "both sides hold the same root at the same chain index" instead of
  * inferring agreement from continued delivery. It does not: sampled once per round, the two sides'
  * indices are DISJOINT (measured over a full rekey — initiator 1,3,5,…; responder 0,2,4,…; zero
  * shared indices, folds observed at 51 and 52). That is a sampling artifact, not an asymmetry — a
  * side can take a receive-DH and a send-DH step inside ONE `tick`, advancing the root twice, so
  * per-round sampling only ever catches one parity. Observing the overlap would need sampling inside
  * the ratchet's step, which is far more intrusive than the assertion is worth. Agreement therefore
  * stays inferred from the pair continuing to decrypt across the fold, which every fold test does.
  *
  * The TIMEOUT paths are outside its horizon: `PqRekey.TimeoutRounds` is 2000, while a run is
  * capped at 96 warm + 660 adversarial + 600 drain + 200 probe = 1,556 rounds (typically ~820). No
  * attempt
  * can therefore reach the 2000-round timeout, so nothing here exercises the point of no return
  * (`Engine.safeToAbort`) or stranding (§9 Q5). Verified by mutation: replacing `safeToAbort` with
  * `true` leaves this suite GREEN — and turns four `PqRekeyCrossSpec` tests red, which is where
  * that property is tested with the explicit round arithmetic it needs. Stretching every case past
  * 2000 rounds only to duplicate that coverage would cost CI minutes for nothing, so this model
  * deliberately does not claim it.
  *
  * ==Honest scope==
  * Green here is NOT a PQ claim: it says the mechanism survives a lossy network without diverging.
  * The `pq_post_compromise_security` property lives in the Phase 5 formal analysis
  * (`design/formal-analysis/ratchet-pq-epoch.spthy`, landed in #87), under a
  * classical-compromise-plus-CRQC attacker that no test here represents — and that model assumes an
  * authentic rekey channel, which no test can supply either. `DEV, NO METADATA PRIVACY` stands: the
  * remaining gate is human security review, not this suite. */
class PqRekeyModelSpec extends AnyFunSuite with ScalaCheckPropertyChecks:

  private final case class Pair(
      be: FakeBackend,
      la: PqTestKit.UnreliableTransport,
      lb: PqTestKit.UnreliableTransport,
      alice: Engine,
      bob: Engine,
      pid: String
  ):
    def lossy(oneIn: Int): Unit = { la.dropOneIn = oneIn; lb.dropOneIn = oneIn }
    def lost: Int = la.lost + lb.lost

  /** A confirmed CLASSICAL pairing — `addBuddy`'s default, and per design §1.2 the pairing kind
    * with the most to gain from the fold. */
  private def pair(rng: scala.util.Random): Pair =
    val be = FakeBackend()
    val la = PqTestKit.UnreliableTransport(be.transport(), rng)
    val lb = PqTestKit.UnreliableTransport(be.transport(), rng)
    val alice = Engine(Some(la), clientLabel = "alice".getBytes("UTF-8"))
    val bob = Engine(Some(lb), clientLabel = "bob".getBytes("UTF-8"))
    val oob = "oob-shared-secret".getBytes("UTF-8")
    val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes("UTF-8"))
    val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = "alice".getBytes("UTF-8"))
    val ar = a.toOption.get
    val br = b.toOption.get
    alice.confirmBuddy(ar.pairId, matched = true).toOption.get
    bob.confirmBuddy(br.pairId, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    Pair(be, la, lb, alice, bob, ar.pairId)

  private def status(e: Engine, pid: String): RekeyStatus = e.rekeyStatus(pid).get

  /** Message cadence, in rounds per message.
    *
    * `0` means "silent after the warm-up" — a GENUINE case, but only because of the warm-up: the
    * trigger is `stepsSinceFold >= IdleMinSteps`, and `stepsSinceFold` only advances on real
    * content (`Engine.scala:446-451`). A pair that never sends keeps `stepsSinceFold == 0` and
    * NEVER rekeys — measured: 0 folds over 700 rounds, i.e. the case would contribute nothing while
    * appearing to cover the idle/opportunistic trigger. Warming with `IdleMinSteps` content
    * messages first is what makes the silent phase actually exercise it (measured: 1 fold).
    *
    * WEIGHTED, not uniform. `Gen.oneOf(const(0), choose(...))` picks between the two GENERATORS
    * 50/50, which would spend half the state space on the silent pair — and the silent pair reaches
    * neither the busy trigger nor `ChunkScheduler`'s `busyStride` contention (`decide` never sees
    * `contentPending`), so half the runs would skip the paths this suite's doc claims. That is the
    * coverage hole the send-cap revision was rejected for, re-entering through weights instead of
    * through the loop. 1:5 keeps the idle probe as the deliberate single case it honestly is. */
  private val genCadence: Gen[Int] = Gen.frequency(1 -> Gen.const(0), 5 -> Gen.choose(5, 40))

  /** Messages allowed in flight per direction — a SLIDING WINDOW, which is what actually bounds the
    * backlog.
    *
    * The transport is strict stop-and-wait (~12 rounds/message, worse under loss, worse again when
    * the chunk lane takes a head), so an ungated cadence outruns delivery and builds a backlog the
    * recovery phase cannot drain. Then "the message I sent never arrived" is a statement about
    * QUEUE DEPTH, not the ratchet: it fires on a healthy pair and a broken one alike, so it cannot
    * tell them apart. An earlier revision had exactly that bug — two mutations "failed" through the
    * flake rather than through the property.
    *
    * A cadence floor alone does not fix it: the backlog scales with the loss rate too, so any fixed
    * "cadence >= N plus a generous drain budget" merely BETS that the estimate holds at the worst
    * generated combination. This window bounds in-flight work directly, independently of both
    * `sendEvery` and `dropOneIn`. Measured at the worst combination the generator can produce
    * (`sendEvery = 5` with `dropOneIn = 2`, i.e. a saturated channel losing half its live frames):
    * in-flight peaks at exactly 4, the residual backlog is 4, and the drain reaches quiescence in
    * 61 rounds against the 600-round cap — so the cap is a safety net rather than the argument, and
    * traffic still runs the whole phase (109 messages sent). */
  private val Window = 4

  private val genScript: Gen[(Int, Int, Long)] = for {
    dropOneIn <- Gen.choose(2, 9) // swallow 1 live frame in k
    sendEvery <- genCadence
    seed <- Gen.choose(0L, Long.MaxValue)
  } yield (dropOneIn, sendEvery, seed)

  test("model: a rekey over a lossy network never diverges the pair (§7 Phase 4)"):
    var totalFolds = 0
    var busyCases = 0
    forAll(genScript, minSuccessful(6)) { case (dropOneIn, sendEvery, seed) =>
      val rng = new scala.util.Random(seed)
      val p = pair(rng)
      var round = 1
      val gotA = mutable.ArrayBuffer.empty[String]
      val gotB = mutable.ArrayBuffer.empty[String]

      /** One round of both engines; returns whether either side delivered content. */
      def tick(): Boolean =
        p.alice.tick(round.toLong): Unit
        p.bob.tick(round.toLong): Unit
        val a = p.alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
        val b = p.bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
        gotA ++= a; gotB ++= b
        round += 1
        a.nonEmpty || b.nonEmpty

      // WARM (clean): real content, so `stepsSinceFold` passes `IdleMinSteps` and the trigger can
      // arm at all — without this the silent case below is dead weight (see `genCadence`).
      for i <- 0 until PqRekey.IdleMinSteps do
        p.alice.sendMessage(p.pid, s"w$i"): Unit
        p.bob.sendMessage(p.pid, s"w$i"): Unit
        for _ <- 1 to 12 do tick(): Unit
      assert(
        status(p.alice, p.pid).stepsSinceFold >= PqRekey.IdleMinSteps,
        "warm-up must arm the cadence trigger, or the adversarial phase tests nothing"
      )

      // ADVERSARIAL: the network eats live frames while the rekey runs. Sends are windowed (see
      // `Window`), so traffic continues for the whole phase without the backlog running away.
      p.lossy(dropOneIn)
      val advStart = round
      var aSent = 0
      var bSent = 0
      def aInFlight = aSent - gotB.count(_.startsWith("m"))
      def bInFlight = bSent - gotA.count(_.startsWith("n"))
      while round < advStart + 660 do
        if sendEvery > 0 && (round - advStart) % sendEvery == 0 then
          if aInFlight < Window then
            p.alice.sendMessage(p.pid, s"m$aSent"): Unit
            aSent += 1
          if bInFlight < Window then
            p.bob.sendMessage(p.pid, s"n$bSent"): Unit
            bSent += 1
        tick(): Unit
      // Per-iteration, so no aggregate tally is needed (or honest — one would only restate this).
      assert(p.lost > 0, "the network must actually have eaten live frames")
      if sendEvery > 0 then busyCases += 1

      // RECOVERY: a clean network. First DRAIN to quiescence, so the probe below measures the
      // ratchet rather than the queue; then probe. Whatever the loss did to the rekey, the two
      // sides must still be on the SAME root — and the only honest observable is that they still
      // talk (no oracle exposes a root, and two ratchets interoperate iff their roots agree). A
      // diverged pair delivers NOTHING from here on, in either direction.
      p.lossy(0)
      var quiet = 0
      val drainCap = round + 600
      while round < drainCap && quiet < 40 do if tick() then quiet = 0 else quiet += 1
      assert(
        quiet >= 40,
        "the backlog must drain before the probe, or the probe measures the queue"
      )

      p.alice.sendMessage(p.pid, "after-a"): Unit
      p.bob.sendMessage(p.pid, "after-b"): Unit
      val probeCap = round + 200
      while round < probeCap && !(gotB.contains("after-a") && gotA.contains("after-b")) do
        tick(): Unit

      val sa = status(p.alice, p.pid)
      val sb = status(p.bob, p.pid)
      assert(gotB.contains("after-a"), s"a->b must still deliver after a lossy rekey: $sa")
      assert(gotA.contains("after-b"), s"b->a must still deliver after a lossy rekey: $sb")
      // EXACTLY-ONCE under retransmission — the "duplicated frames" half of §7 Phase 4's property.
      // A lost ack makes the sender re-present a frame the peer already took, so this is reachable
      // only because the network above really does eat live frames; every message text is unique
      // per direction, so a repeat means ARQ dedup let a retransmit through as a fresh message.
      assert(
        gotB.distinct.size == gotB.size,
        s"a->b delivered a message twice under retransmits: ${gotB.diff(gotB.distinct)}"
      )
      assert(
        gotA.distinct.size == gotA.size,
        s"b->a delivered a message twice under retransmits: ${gotA.diff(gotA.distinct)}"
      )
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
    // ANTI-VACUITY, and ONLY what has no per-iteration counterpart. The two FOLD assertions inside
    // the loop are relative (folds within +-1 of each other, at most one fold per epoch) and so hold
    // on a run that never folded at all, which is what `totalFolds` pins. (The rest of the loop's
    // assertions are absolute — `lost > 0`, the delivery probes, the dedup checks, the drain — and
    // would fail on a broken run regardless of `totalFolds`; this block is not their backstop and
    // must not be read as one.) `busyCases` guards the
    // generator WEIGHTS — a revision that let the silent pair own half the state space is exactly
    // what happened once — and claims nothing more; the class doc records the lane arbitration this
    // suite does NOT pin.
    //
    // Deliberately NOT tallied: live frames swallowed. `assert(p.lost > 0, ...)` already runs every
    // iteration and `lost` only grows, so an aggregate `totalLost > 0` could not fail unless
    // `forAll` ran zero cases — coverage theatre of exactly the kind removed twice already
    // (`refused`, and the contention counter). An assertion that cannot fail is worse than none: it
    // reads as a guarantee nobody is getting.
    assert(totalFolds > 0, "the model must actually fold under loss, or it proves nothing")
    assert(busyCases > 0, "the generator must produce busy cases, not only the idle probe")
