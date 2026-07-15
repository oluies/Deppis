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
  * ==The adversary drops DELIVERIES, not map entries (and this is load-bearing)==
  * Loss is injected by swallowing a `retrieve` that WOULD have returned a frame ([[Lossy]]), so
  * every drop is exactly one real, live frame that the peer was about to receive — countable, and
  * impossible to waste.
  *
  * The obvious alternative — reach into the store map and `remove` a random key — is a TRAP, and an
  * earlier revision of this test fell into it. `FakeBackend.store` is append-only apart from
  * successfully-retrieved directional tokens: cover writes go under a `coverKey`-derived token that
  * is NEVER retrieved, so they accumulate forever. Measured on a warmed pair over 700 rounds: an
  * idle pair leaves ~1,200 dead cover entries against ~1 live frame, and a uniformly random
  * `remove` hit a live frame 7 times out of 233 — the "lossy network" was almost fictional, and
  * `assert(drops > 0)` could not tell, because it counted map removals rather than lost deliveries.
  * (A busy pair happens to fare better — its store stays nearly empty — which is exactly how such a
  * bug hides: it is invisible in the case you look at first.) Counting retransmissions instead
  * would not have saved it either: stop-and-wait re-presents an unacked head EVERY round, so
  * retransmits are ~1,000 per run even with a perfectly clean network.
  *
  * The adversary may not forge or reorder: every frame is AEAD-sealed under keys the network does
  * not have, so a tampered frame is simply a dropped one (covered by the ratchet's
  * no-mutation-on-undecryptable invariant), and round-derived addressing plus stop-and-wait mean an
  * in-flight frame cannot be overtaken. Modeling those would be inventing an adversary the
  * transport does not admit — the forged-envelope cases are exercised where they ARE reachable
  * (a malicious PEER) in `PqRekeyCrossSpec`.
  *
  * ==What this model does NOT reach (measured, not guessed)==
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
  * The `pq_post_compromise_security` property is Phase 5's formal analysis under an attacker model
  * no test here represents. `DEV, NO METADATA PRIVACY` stands. */
class PqRekeyModelSpec extends AnyFunSuite with ScalaCheckPropertyChecks:

  /** A network that eats live frames: swallows a `retrieve` that would have delivered, one in
    * `dropOneIn` (0 = clean). `retrieve` has already consumed the frame from the store, so the
    * frame is gone for good and ARQ must recover it — a genuine loss, and `lost` counts exactly
    * how many happened rather than how often we tried. */
  private final class Lossy(inner: RoundTransport, rng: scala.util.Random) extends RoundTransport:
    var dropOneIn: Int = 0
    var lost: Int = 0
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean = inner.submit(token, frame)
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      inner.retrieve(token) match
        case Some(_) if dropOneIn > 0 && rng.nextInt(dropOneIn) == 0 =>
          lost += 1
          None
        case other => other
    override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
      inner.signal(roundId, label, bit)
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      inner.fetchDigest(roundId, clientLabel)

  private final case class Pair(
      be: FakeBackend,
      la: Lossy,
      lb: Lossy,
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
    val la = Lossy(be.transport(), rng)
    val lb = Lossy(be.transport(), rng)
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
    * The nonzero range is bounded BELOW on purpose. The transport is strict stop-and-wait — one
    * message in flight, ~12 rounds each, fewer under loss — so a cadence faster than that outruns
    * delivery and builds a backlog the recovery phase cannot drain. Then "the message I sent never
    * arrived" is a statement about QUEUE DEPTH, not about the ratchet: it fires on a healthy pair
    * and on a broken one alike, so it cannot tell them apart. (An earlier revision of this test had
    * exactly that bug and two mutations "failed" through the flake rather than through the
    * property.) A cadence of >= 15 sustains traffic for the whole phase without saturating, which
    * is what keeps the busy-trigger and chunk-contention paths covered. */
  private val genCadence: Gen[Int] = Gen.oneOf(Gen.const(0), Gen.choose(15, 40))

  private val genScript: Gen[(Int, Int, Long)] = for {
    dropOneIn <- Gen.choose(2, 9) // swallow 1 live delivery in k
    sendEvery <- genCadence
    seed <- Gen.choose(0L, Long.MaxValue)
  } yield (dropOneIn, sendEvery, seed)

  test("model: a rekey over a lossy network never diverges the pair (§7 Phase 4)"):
    var totalFolds = 0
    var totalLost = 0
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

      // ADVERSARIAL: the network eats live deliveries while the rekey runs.
      p.lossy(dropOneIn)
      val advStart = round
      var sent = 0
      while round < advStart + 660 do
        if sendEvery > 0 && (round - advStart) % sendEvery == 0 then
          p.alice.sendMessage(p.pid, s"a$sent"): Unit
          p.bob.sendMessage(p.pid, s"b$sent"): Unit
          sent += 1
        tick(): Unit
      assert(p.lost > 0, "the network must actually have eaten live frames")
      totalLost += p.lost

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
    // ANTI-VACUITY: every assertion above holds trivially on a run where no rekey ever completed or
    // where the network never actually ate anything, so pin both. `totalLost` counts real lost
    // deliveries (not attempts to lose one) — the metric an earlier revision got wrong.
    assert(totalFolds > 0, "the model must actually fold under loss, or it proves nothing")
    assert(totalLost > 0, "and the network must actually have eaten live frames")
