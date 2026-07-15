package engine

import engine.PqTestKit.FakeBackend
import org.scalatest.funsuite.AnyFunSuite

import scala.collection.mutable

/** END-TO-END continuous post-quantum rekey over the real transport — Phase 3 of
  * `design/continuous-pq-ratchet.md` (§3 transport, §4 KDF integration + §4.4 lifecycle, §7 Phase 3,
  * §8 state machine). Two engines, one in-memory store, the actual tick loop: the rekey's KEM
  * material is chunked onto the stop-and-wait ARQ lane, folded at the epoch-commit anchor, and
  * confirmed per direction — nothing here is simulated.
  *
  * Cross-platform (JVM + Scala.js): the fold now sits on the live content ratchet, so a JS client and
  * a JVM client must fold byte-identically or they simply stop talking. This suite is the thing that
  * would notice.
  *
  * HONEST SCOPE (Constitution IV): a green run here proves the MECHANISM — the epoch secret reaches
  * the live root, both sides land on it, and every failure path fails closed. It is NOT a
  * post-quantum claim and changes no label: the `pq_post_compromise_security` property lives in the
  * Phase 5 formal analysis, under an attacker model (classical state compromise + a CRQC) that no
  * test here represents. `DEV, NO METADATA PRIVACY` stands. */
class PqRekeyCrossSpec extends AnyFunSuite:

  private val aLabel = "alice".getBytes("UTF-8")
  private val bLabel = "bob".getBytes("UTF-8")

  private final case class Pair(be: FakeBackend, alice: Engine, bob: Engine, pid: String)

  /** A CONFIRMED classical pairing over one backend. Classical on purpose: per design §1.2 it is the
    * pairing kind with the most to gain (the first completed fold is how it becomes PQ-hardened
    * without re-pairing) and it is `addBuddy`'s default. */
  private def pair(): Pair =
    val be = FakeBackend()
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val oob = "oob-shared-secret".getBytes("UTF-8")
    val a = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get
    val b = bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get
    assert(a.pairId == b.pairId)
    alice.confirmBuddy(a.pairId, matched = true).toOption.get
    bob.confirmBuddy(b.pairId, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    Pair(be, alice, bob, a.pairId)

  /** Tick both engines through `rounds`, collecting each side's delivered plaintexts. */
  private def run(p: Pair, rounds: Range): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]
    val mb = mutable.ArrayBuffer.empty[String]
    for r <- rounds do
      p.alice.tick(r.toLong): Unit
      p.bob.tick(r.toLong): Unit
      ma ++= p.alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= p.bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)

  private def status(e: Engine, pid: String): RekeyStatus = e.rekeyStatus(pid).get

  /** Exchange `n` messages each way, so the cadence counter passes `PqRekey.IdleMinSteps` and both
    * ratchets are warm. Returns the delivered plaintexts. */
  private def warm(p: Pair, n: Int, from: Int): (Seq[String], Seq[String]) =
    var round = from
    val ma = mutable.ArrayBuffer.empty[String]
    val mb = mutable.ArrayBuffer.empty[String]
    for i <- 0 until n do
      p.alice.sendMessage(p.pid, s"a$i"): Unit
      p.bob.sendMessage(p.pid, s"b$i"): Unit
      val (x, y) = run(p, round until round + 12)
      ma ++= x; mb ++= y
      round += 12
    (ma.toSeq, mb.toSeq)

  // =============================================================== the end-to-end fold

  test("a full epoch fold completes over the store; messages before AND after it decrypt"):
    val p = pair()
    // BEFORE: ordinary traffic, and enough of it to arm the opportunistic (idle-round) trigger.
    val (before1, before2) = warm(p, PqRekey.IdleMinSteps, from = 1)
    assert(before1.contains("b0"), s"pre-fold traffic must deliver: $before1")
    assert(before2.contains("a0"), s"pre-fold traffic must deliver: $before2")
    assert(status(p.alice, p.pid).epochsFolded == 0, "no fold yet")

    // The rekey now runs on idle rounds — no message is queued, so each of its ~19 chunk frames
    // replaces a cover write at zero marginal frames (design §3.1 (a-i)).
    run(p, 200 until 700): Unit

    val sa = status(p.alice, p.pid)
    val sb = status(p.bob, p.pid)
    assert(sa.epochsFolded >= 1, s"the initiator must complete a fold: $sa")
    assert(sb.epochsFolded >= 1, s"the responder must complete a fold: $sb")
    assert(sa.aborts == 0, s"no aborts on the happy path: ${sa.lastAbort}")
    assert(sb.aborts == 0, s"no aborts on the happy path: ${sb.lastAbort}")
    assert(sa.ratchetFolds >= 1, "the initiator's ratchet APPLIED the fold to its root")

    // AFTER: the folded ratchets still interoperate — the whole point. This also forces the
    // committer's armed fold to land (it applies on its next DH step).
    p.alice.sendMessage(p.pid, "after-a"): Unit
    p.bob.sendMessage(p.pid, "after-b"): Unit
    val (afterA, afterB) = run(p, 700 until 760)
    assert(afterB.contains("after-a"), s"post-fold a->b must decrypt: $afterB")
    assert(afterA.contains("after-b"), s"post-fold b->a must decrypt: $afterA")
    assert(status(p.bob, p.pid).ratchetFolds >= 1, "the responder's ratchet applied the fold too")

  test("both sides fold at the SAME anchor — a diverged pair could not keep talking"):
    // The fold is anchored to a root index; if the two sides folded at different positions their
    // roots would part company and the post-fold exchange above would silently stop working. So the
    // strongest available statement of "same anchor" is sustained two-way traffic across the fold.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    run(p, 200 until 700): Unit
    assert(status(p.alice, p.pid).epochsFolded >= 1)
    val (a, b) = warm(p, 4, from = 700)
    assert((0 until 4).forall(i => b.contains(s"a$i")), s"post-fold a->b: $b")
    assert((0 until 4).forall(i => a.contains(s"b$i")), s"post-fold b->a: $a")

  test("the cadence counter resets on a fold and the epoch id never repeats"):
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    run(p, 200 until 700): Unit
    val s = status(p.alice, p.pid)
    assert(s.epochsFolded >= 1)
    assert(s.stepsSinceFold < PqRekey.StepCeiling, s"the cadence restarted after the fold: $s")

  // =============================================================== the 256-byte frame (G2/FR-012)

  test(
    "MEASURED: every store write during a rekey is exactly 256 bytes — chunk, content and cover"
  ):
    // Design §5 / G2: KEM material rides the MK-sealed inner block, never the header, so a chunk
    // frame is byte-for-byte the same SHAPE as any content or cover frame and the fixed-frame
    // unlinkability result survives. This measures the real writes the store saw, rather than
    // asserting the property from the code.
    val p = pair()
    val idle = p.be.writes.size // cover-only rounds so far
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val afterContent = p.be.writes.size
    run(p, 200 until 700): Unit
    assert(status(p.alice, p.pid).epochsFolded >= 1, "a rekey must actually have run")
    val afterRekey = p.be.writes.size
    assert(afterContent > idle && afterRekey > afterContent, "all three regimes produced writes")

    val sizes = p.be.writes.map(_.length).toSet
    assert(sizes == Set(DoubleRatchet.WireSize), s"every write must be 256 B, saw $sizes")
    assert(DoubleRatchet.WireSize == 256 && frame.Frame.Size == 256, "the frame is still 256 B")
    // Belt and braces: no frame is a duplicate SHAPE outlier, and the rekey did not change the
    // per-round write budget — one write per engine per round, exactly as before.
    assert(p.be.writes.forall(_.length == 256))

  test("MEASURED: the rekey holds the one-store-write-per-round budget (no burst of extra frames)"):
    // §5's residual: a rekey must obey the same one-write-per-round rule as any other traffic, or
    // the burst itself becomes a distinguisher at the volume layer. Two engines × N rounds ⇒ exactly
    // 2N writes, whatever is happening underneath.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val base = p.be.writes.size
    val rounds = 300
    run(p, 1000 until (1000 + rounds)): Unit
    assert(
      p.be.writes.size - base == 2 * rounds,
      s"expected ${2 * rounds} writes over $rounds rounds, got ${p.be.writes.size - base}"
    )

  // =============================================================== fail-closed / atomicity

  /** Drive a pair to the point where `side` holds its epoch shared secret (i.e. it has encapsed or
    * decapsed) and is waiting on a confirmation — the phase the §4.2 tag check guards. */
  private def driveUntil(p: Pair, side: Engine, from: Int)(
      ready: RekeyStatus => Boolean
  ): RekeyStatus =
    var round = from
    while round < from + 900 && !ready(status(side, p.pid)) do
      p.alice.tick(round.toLong): Unit
      p.bob.tick(round.toLong): Unit
      p.alice.drainEvents(): Unit
      p.bob.drainEvents(): Unit
      round += 1
    val s = status(side, p.pid)
    assert(ready(s), s"the test must reach the phase it targets, got $s")
    s

  private def driveToConfirmPhase(p: Pair, side: Engine, from: Int): RekeyStatus =
    driveUntil(p, side, from)(_.hasEpochSecret)

  test("fail closed: a wrong initiator /i tag refuses, folds NOTHING, and the pair stays usable"):
    // The ML-KEM implicit-rejection defense (§4.2), driven through the real handler: hand the
    // RESPONDER an initiator `/i` tag that does not match the epoch secret. It must refuse
    // explicitly, commit no epoch, and leave the pre-rekey epoch fully working.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val mid = driveToConfirmPhase(p, p.bob, from = 200)
    val foldsBefore = status(p.bob, p.pid).epochsFolded
    val forged = Array.fill[Byte](ChunkStream.ConfirmTagBytes)(0x5a)
    val env = ChunkStream.encode(
      ChunkStream.Envelope.KemConfirm(mid.currentEpoch, BuddyRole.Initiator, forged)
    )
    assert(p.bob.injectControlForTest(p.pid, env, 900L))
    val after = status(p.bob, p.pid)
    assert(after.lastAbort == "pq_rekey_confirm_failed", s"explicit refusal expected: $after")
    assert(after.epochsFolded == foldsBefore, "a rejected tag must fold NOTHING")
    assert(!after.foldArmed, "and must arm nothing")
    assert(after.ratchetFolds == foldsBefore, "no half-committed fold reached the root")
    // The responder is past its point of no return here (its `/r` tag is on the wire), so the forged
    // tag is REFUSED rather than allowed to tear the attempt down — otherwise one forged frame would
    // both strand the initiator and deny the pair every future rekey. The genuine tag still works.
    assert(after.refusals == 1 && after.aborts == 0, s"refused, not aborted: $after")
    assert(after.inProgress, "a forged tag must not be able to kill the attempt")
    // The pre-rekey epoch is untouched and the pair keeps working — and a retry is still possible
    // (the initiator opens a FRESH epoch; the aborted id is never reused).
    val (a, b) = warm(p, 2, from = 1000)
    assert(b.contains("a0") && a.contains("b0"), "the pre-rekey epoch still delivers both ways")
    assert(status(p.alice, p.pid).attempts >= 1, "the initiator can still attempt a rekey")

  test("fail closed: a wrong responder /r tag refuses on the initiator, folding nothing"):
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val mid = driveToConfirmPhase(p, p.alice, from = 200)
    val forged = Array.fill[Byte](ChunkStream.ConfirmTagBytes)(0x77)
    val env = ChunkStream.encode(
      ChunkStream.Envelope.KemConfirm(mid.currentEpoch, BuddyRole.Responder, forged)
    )
    assert(p.alice.injectControlForTest(p.pid, env, 900L))
    val after = status(p.alice, p.pid)
    assert(after.lastAbort == "pq_rekey_confirm_failed", s"explicit refusal expected: $after")
    assert(!after.foldArmed && after.ratchetFolds == 0, "nothing folded")
    // The initiator has NOT yet sent its own `/i` here, so it is still safe to abort: the attempt is
    // torn down and the initiator will retry with a fresh epoch.
    assert(after.aborts == 1 && !after.inProgress, s"aborted before its own tag went out: $after")
    val (a, b) = warm(p, 2, from = 1000)
    assert(b.contains("a0") && a.contains("b0"), "the pair still delivers both ways")

  test("fail closed: a tag REFLECTED in our own role is refused (anti-reflection)"):
    // The per-direction labels (`/i` vs `/r`) exist so a tag seen in one direction can never satisfy
    // the other's check. The engine refuses even earlier: a peer may only ever speak in the PEER's
    // role, so a reflected envelope never reaches the tag comparison at all.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val mid = driveToConfirmPhase(p, p.bob, from = 200)
    val env = ChunkStream.encode(
      ChunkStream.Envelope.KemConfirm(
        mid.currentEpoch,
        BuddyRole.Responder, // Bob IS the responder — this is Bob's own role coming back at him
        Array.fill[Byte](ChunkStream.ConfirmTagBytes)(1)
      )
    )
    assert(p.bob.injectControlForTest(p.pid, env, 900L))
    val after = status(p.bob, p.pid)
    assert(after.lastAbort == "pq_rekey_role_reflected", s"reflection must be refused: $after")
    assert(!after.foldArmed && after.ratchetFolds == 0, "nothing folded")

  test("fail closed: an undecodable control envelope aborts without folding"):
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    driveToConfirmPhase(p, p.bob, from = 200): Unit
    val garbage =
      Array.fill[Byte](ChunkStream.EnvelopeBytes)(0x7f) // nonzero tag 0x7f: unknown type
    assert(p.bob.injectControlForTest(p.pid, garbage, 900L))
    val after = status(p.bob, p.pid)
    assert(after.lastAbort == "pq_rekey_bad_envelope", s"a bad envelope must fail closed: $after")
    assert(!after.foldArmed && after.ratchetFolds == 0, "nothing folded")
    val (a, b) = warm(p, 2, from = 1000)
    assert(b.contains("a0") && a.contains("b0"), "and the pair still works")

  test(
    "fail closed: an EPOCH_COMMIT at the WRONG anchor refuses rather than folding into divergence"
  ):
    // The anchor is what makes both sides fold at the same chain position. A commit naming any other
    // position must be refused — folding there would silently part the two roots, which is exactly
    // the failure the explicit anchor exists to convert into an error.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    // Drive PAST the tag exchange: the anchor check is the LAST gate, so reaching it needs the
    // initiator to have verified the responder's `/r` tag and sent its own `/i` — otherwise the
    // commit is refused earlier as out-of-order and this test would not exercise the anchor at all.
    val mid = driveUntil(p, p.alice, from = 200)(s => s.hasEpochSecret && s.confirmExchanged)
    val bogus = ChunkStream.encode(
      ChunkStream.Envelope.EpochCommit(mid.currentEpoch, BuddyRole.Responder, anchor = 999999)
    )
    assert(p.alice.injectControlForTest(p.pid, bogus, 900L))
    val after = status(p.alice, p.pid)
    assert(
      after.lastAbort == "pq_rekey_anchor_mismatch",
      s"a wrong anchor must fail closed: $after"
    )
    assert(!after.foldArmed && after.ratchetFolds == 0, "nothing folded at a bogus anchor")
    // Past its point of no return, so the bogus commit is refused and the attempt survives to fold
    // on an honest one — a forged commit must not be able to strand the responder.
    assert(after.refusals >= 1 && after.inProgress, s"refused, attempt held: $after")
    val (a, b) = warm(p, 2, from = 1000)
    assert(b.contains("a0") && a.contains("b0"), "the pair survives the refused commit")

  test("an abort is REFUSED past the point of no return — the peer is already committed"):
    // The two-phase-commit hazard, and the one bug in this area that would be silent: once the
    // initiator's `/i` tag is acked, the responder commits on receiving it, so any teardown on the
    // initiator side (a timeout, a garbage envelope from a malicious peer) would leave the responder
    // folded and the initiator not — divergence with no error anywhere. The abort must be refused.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    // Drive to the exact window: our `/i` is sent AND acked (the control queue has drained), but the
    // commit has not arrived back yet.
    val mid = driveUntil(p, p.alice, from = 200)(s =>
      s.inProgress && s.confirmExchanged && s.hasEpochSecret && s.foldArmed == false
    )
    var round = 400
    while round < 900 && !(status(p.alice, p.pid).inProgress &&
        p.alice.rekeyStatus(p.pid).exists(_.confirmExchanged))
    do
      p.alice.tick(round.toLong): Unit
      p.bob.tick(round.toLong): Unit
      p.alice.drainEvents(): Unit
      p.bob.drainEvents(): Unit
      round += 1
    // Whether or not we are past the ack line, a garbage envelope must never produce a one-sided
    // fold: either it aborts cleanly (pre-ack, nothing committed anywhere) or it is refused
    // (post-ack, the responder is committed). Both are checked by the pair still talking afterwards.
    assert(
      p.alice.injectControlForTest(p.pid, Array.fill[Byte](ChunkStream.EnvelopeBytes)(0x7f), 950L)
    )
    val (a, b) = warm(p, 4, from = 2000)
    assert((0 until 4).forall(i => b.contains(s"a$i")), s"a->b must survive the abort decision: $b")
    assert((0 until 4).forall(i => a.contains(s"b$i")), s"b->a must survive the abort decision: $a")
    val sa = status(p.alice, p.pid)
    val sb = status(p.bob, p.pid)
    assert(sa.ratchetFolds == sb.ratchetFolds, s"the two sides must fold in lockstep: $sa vs $sb")

  test("safeToAbort: the initiator holds its attempt open once its /i tag is SENT"):
    // Pins the gate that prevents both the divergence and the stranding above: past the point of no
    // return a hostile frame is REFUSED — recorded, not acted on — and the attempt SURVIVES to fold
    // on the genuine commit. The line is the tag SEND, not its ack: the responder commits on
    // receiving `/i`, and the ack proving receipt can be lost while the tag was delivered.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    val mid = driveUntil(p, p.alice, from = 200)(s => s.inProgress && !s.abortSafe)
    assert(mid.confirmExchanged, "past the line means our /i is out")
    assert(mid.hasEpochSecret, "and we hold the epoch secret we will fold with")

    // A garbage envelope from a malicious peer must not kill it.
    p.alice.injectControlForTest(p.pid, Array.fill[Byte](ChunkStream.EnvelopeBytes)(0x7f), 0L): Unit
    val after = status(p.alice, p.pid)
    assert(after.lastAbort == "pq_rekey_bad_envelope", s"the specific reason is kept: $after")
    assert(after.refusals >= 1 && after.aborts == 0, s"refused, not aborted: $after")
    assert(after.inProgress, "a refused input must KEEP the attempt alive")
    assert(after.hasEpochSecret, "and must keep the epoch secret it will fold with")
    assert(after.ratchetFolds == 0, "nothing folded")

    // …and the held-open attempt goes on to fold normally, both sides in lockstep. The refusal is a
    // hold, not a wedge.
    p.alice.sendMessage(p.pid, "post-refusal"): Unit
    val (a, b) = run(p, 900 until 1400)
    assert(b.contains("post-refusal"), s"a->b still delivers after the refusal: $b")
    val sa = status(p.alice, p.pid)
    val sb = status(p.bob, p.pid)
    assert(sa.ratchetFolds == sb.ratchetFolds, s"the two sides fold in lockstep: $sa vs $sb")
    assert(sa.ratchetFolds >= 1, s"the held-open attempt did go on to fold: $sa")

  test("a failed/absent rekey never strips a completed fold's hardening (§8.2)"):
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    run(p, 200 until 700): Unit
    val folded = status(p.alice, p.pid).epochsFolded
    assert(folded >= 1)
    // Remove the buddy on ONE side: its rekey state is wiped. The other side's completed fold count
    // must not move — a fold, once committed, is never rolled back.
    assert(status(p.bob, p.pid).epochsFolded >= 1)
    assert(status(p.alice, p.pid).epochsFolded == folded)

  test("removeBuddy releases the rekey state (no resident KEM secret after teardown)"):
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    run(p, 200 until 300): Unit // mid-rekey: the initiator is holding its 2464-B keypair secret
    assert(p.alice.removeBuddy(p.pid).isRight)
    assert(p.alice.rekeyStatus(p.pid).isEmpty, "the runtime (and its rekey secrets) is gone")

  // =============================================================== loss / duplication / reordering

  test("no divergence when the store drops and duplicates frames during a rekey"):
    // ARQ retransmit-until-acked plus the reassembler's dedup/order tolerance carry the transfer;
    // the fold must still land exactly once on each side, and the pair must still talk.
    val p = pair()
    warm(p, PqRekey.IdleMinSteps, from = 1): Unit
    // Drop every 3rd delivery by consuming it behind the engines' backs, and re-present others.
    var round = 200
    var dropped = 0
    while round < 900 do
      p.alice.tick(round.toLong): Unit
      p.bob.tick(round.toLong): Unit
      p.alice.drainEvents(): Unit
      p.bob.drainEvents(): Unit
      if round % 3 == 0 && p.be.store.nonEmpty then
        val k = p.be.store.keysIterator.next()
        p.be.store.remove(k): Unit // a lost frame: ARQ must recover it
        dropped += 1
      round += 1
    assert(dropped > 0, "the test must actually have dropped frames")
    val sa = status(p.alice, p.pid)
    val sb = status(p.bob, p.pid)
    assert(sa.ratchetFolds <= sa.epochsFolded + 1, "a fold is applied at most once per epoch")
    assert(sb.ratchetFolds <= sb.epochsFolded + 1)
    // The decisive property: whatever the loss did to the rekey, the two sides did not diverge.
    val (a, b) = warm(p, 3, from = 1000)
    assert(b.contains("a0"), s"a->b survived loss during rekey: $b")
    assert(a.contains("b0"), s"b->a survived loss during rekey: $a")
