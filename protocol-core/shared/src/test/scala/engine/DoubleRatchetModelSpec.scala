package engine

import frame.Frame
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

import java.nio.charset.StandardCharsets.UTF_8
import scala.collection.mutable

/** Stateful, model-based property tests for the DH double ratchet — the mechanical complement to the
  * example-based `DoubleRatchetSpec`. ScalaCheck generates random scripts of (send / deliver / tamper
  * / replay) operations across BOTH directions and a reference oracle checks the ratchet's invariants
  * after every step; on a failure ScalaCheck shrinks to a minimal counter-example. This is the class
  * of test that catches state-machine bugs an example test can miss — e.g. the "mutate before the body
  * is verified" atomicity bug found in review: here the `tamper-then-genuine` operation asserts the
  * no-mutation-on-undecryptable invariant under every reachable interleaving, not just one.
  *
  * JVM-only: ScalaCheck is on the JVM test classpath (`build.sbt`), and the ratchet logic is
  * platform-independent — the JVM↔JS primitive parity is already pinned byte-for-byte by
  * `DoubleRatchetJsSpec` + the X25519 / AEAD KATs, so the model need not re-run under Node.
  *
  * Oracle soundness note: deliveries are generated PER DIRECTION in FIFO order, so a genuine delivery
  * MUST decrypt to exactly the plaintext that was sent at that position (no skip-bound guesswork). The
  * dedicated out-of-order property below covers permuted delivery within one chain. */
class DoubleRatchetModelSpec extends AnyFunSuite with ScalaCheckPropertyChecks:

  private def contentRoot(seed: Byte): Array[Byte] = Array.fill(32)(seed)
  private def pair(): (DoubleRatchet, DoubleRatchet) =
    (DoubleRatchet.initInitiator(contentRoot(7)), DoubleRatchet.initResponder(contentRoot(7)))
  private def inner(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), DoubleRatchet.InnerSize).toOption.get
  private def text(in: Array[Byte]): String =
    new String(Frame.unpad(in, DoubleRatchet.InnerSize).toOption.get, UTF_8)
  private def tamperBody(w: Array[Byte]): Array[Byte] =
    val bad = w.clone()
    val i = DoubleRatchet.WireSize - 1 // a byte in the message region (≥ MsgOffset)
    bad(i) = (bad(i) ^ 0x01).toByte
    bad

  /** One scripted operation. `fromInitiator` picks the direction (Alice→Bob vs Bob→Alice). */
  private enum Op:
    case Send(fromInitiator: Boolean, msg: String)
    case DeliverNext(fromInitiator: Boolean)
    case TamperThenDeliver(fromInitiator: Boolean)
    case ReplayConsumed(fromInitiator: Boolean)

  private val genMsg: Gen[String] =
    Gen.choose(0, 40).flatMap(n => Gen.listOfN(n, Gen.alphaNumChar).map(_.mkString))
  private val genDir: Gen[Boolean] = Gen.oneOf(true, false)
  private val genOp: Gen[Op] = Gen.frequency(
    4 -> (for { d <- genDir; m <- genMsg } yield Op.Send(d, m)),
    5 -> genDir.map(Op.DeliverNext(_)),
    2 -> genDir.map(Op.TamperThenDeliver(_)),
    1 -> genDir.map(Op.ReplayConsumed(_))
  )
  private val genScript: Gen[List[Op]] = Gen.choose(0, 120).flatMap(Gen.listOfN(_, genOp))

  test("model: any interleaving of send/deliver/tamper/replay preserves the ratchet invariants"):
    forAll(genScript) { script =>
      val (alice, bob) = pair()
      // In-flight FIFO (plaintext, wire) and the consumed wires, per direction.
      val a2b = mutable.Queue.empty[(String, Array[Byte])]
      val b2a = mutable.Queue.empty[(String, Array[Byte])]
      val consumedA2B = mutable.ArrayBuffer.empty[Array[Byte]]
      val consumedB2A = mutable.ArrayBuffer.empty[Array[Byte]]

      // (in-flight queue, receiver, consumed list) for a direction.
      def chan(fromInit: Boolean) =
        if fromInit then (a2b, bob, consumedA2B) else (b2a, alice, consumedB2A)

      script.foreach {
        case Op.Send(fromInit, m) =>
          if fromInit then a2b.enqueue((m, alice.encrypt(inner(m))))
          else if bob.canSend then b2a.enqueue((m, bob.encrypt(inner(m))))
        // else: the responder has not received yet — it has no sending chain, so the send is held
        // (initiator-sends-first). Dropping the op models that hold.

        case Op.DeliverNext(fromInit) =>
          val (q, recv, consumed) = chan(fromInit)
          if q.nonEmpty then
            val (m, w) = q.dequeue()
            assert(recv.decrypt(w).map(text).contains(m), s"in-order delivery must decrypt to '$m'")
            consumed += w

        case Op.TamperThenDeliver(fromInit) =>
          val (q, recv, consumed) = chan(fromInit)
          if q.nonEmpty then
            val (m, w) = q.dequeue()
            assert(recv.decrypt(tamperBody(w)).isEmpty, "a tampered body must be rejected")
            // Atomicity: the failed decrypt must NOT have advanced the ratchet, so the genuine frame
            // for the same position still decrypts.
            assert(
              recv.decrypt(w).map(text).contains(m),
              s"genuine frame still decrypts after a tamper attempt: '$m'"
            )
            consumed += w

        case Op.ReplayConsumed(fromInit) =>
          val (_, recv, consumed) = chan(fromInit)
          if consumed.nonEmpty then
            assert(recv.decrypt(consumed.last).isEmpty, "a consumed frame must not decrypt twice")
      }
    }

  /** Out-of-order within a single chain: a batch of K (< MaxSkip) frames delivered in any permutation
    * must ALL decrypt — the skipped-key machinery recovers every position regardless of order. */
  test("model: any permutation of a single-chain batch decrypts completely"):
    val gen = for {
      msgs <- Gen.choose(1, 40).flatMap(Gen.listOfN(_, genMsg))
      keys <- Gen.listOfN(
        msgs.size,
        Gen.choose(0, 1 << 20)
      ) // sort keys ⇒ a reproducible permutation
    } yield (msgs, keys)
    forAll(gen) { case (msgs, keys) =>
      val (alice, bob) = pair()
      val wires = msgs.map(m => alice.encrypt(inner(m)))
      val order = wires.zip(keys).zipWithIndex.sortBy(_._1._2).map(_._2) // permuted indices
      val got = order.map(i => bob.decrypt(wires(i)).map(text))
      assert(got.forall(_.isDefined), "every frame in the batch decrypts under permuted delivery")
      assert(got.flatten.sorted == msgs.sorted, "the recovered multiset equals what was sent")
    }

  // ============ continuous-PQ epoch rekey (design/continuous-pq-ratchet.md §7 Phase 4) ==========
  //
  // WHAT THIS SECTION ADDS, AND WHAT IT DELIBERATELY DOES NOT (Constitution IV — a test whose
  // name over-promises is worse than no test).
  //
  // Phase 3 already covers the rekey END-TO-END over two real engines and a real store
  // (`crosstest/PqRekeyCrossSpec`: the full fold, measured 256-B frames, forged tags, wrong anchor,
  // stranding, drop+duplicate) and at the ratchet layer with hand-driven folds
  // (`crosstest/EpochFoldCrossSpec`: the shared root chain, the three no-fold/one-sided/
  // different-ss controls, disarm, §8.2 retention). Those are EXAMPLES: one fixed script each.
  // What §7 Phase 4 asks for here — and what did not exist — is the MODEL: ScalaCheck generating
  // random INTERLEAVINGS of traffic and rekey, so the fold's invariants are asserted under every
  // reachable ordering rather than the handful a fixed script happens to visit.
  //
  // The system under test is real: `DoubleRatchet.armEpochFold`/`disarmEpochFold`/`rootIndex` (the
  // fold + its anchor), `EpochKdf.epochConfirmTag{Initiator,Responder}` + `RetrievalToken.equalsCT`
  // (the §4.2 confirmation), and `ChunkStream`'s real envelopes inside real `ArqFrame`s inside the
  // real sealed inner block. The MODEL supplies only the driving: which side speaks when. That
  // driver mirrors `Engine`'s state machine (`Engine.scala:587-757`) and is NOT itself the SUT —
  // so this section asserts only properties that live in the code above, never in the driver:
  //
  //   - NOT COVERED HERE (they live in `Engine`, and are covered against the real engine in
  //     `PqRekeyCrossSpec`): duplicate/stale EPOCH_COMMIT suppression, the abort-vs-refuse point of
  //     no return, timeouts/stranding. A ratchet-level model would have to implement those in the
  //     driver and would then be testing the driver. `DoubleRatchet.armEpochFold` on its own would
  //     happily fold twice at the same index — that dedup is the engine's job, so it is asserted
  //     where it lives, not faked here.
  //   - THE KEM IS ELIDED. The model hands each side a 32-byte epoch secret directly instead of
  //     running ML-KEM. That is the point of the `mismatchedSecret` op: two sides holding DIFFERENT
  //     `ss` is EXACTLY what ML-KEM's implicit rejection produces on a tampered ciphertext (§4.2),
  //     and it is the case the confirmation tags exist for. The KEM itself is KAT-pinned
  //     (`kem.HybridKemCrossSpec`) and driven for real end-to-end in `PqRekeyCrossSpec`.
  //   - REORDERING ACROSS the ARQ lane is not modeled because the transport forbids it: stop-and-
  //     wait keeps one message in flight and retransmits it until acked, so a control frame cannot
  //     be overtaken (`retry-safe-addressing.md`). Modeling an impossible reorder would be
  //     inventing a property. What IS modeled is arbitrary LATENCY between arming and delivery
  //     (§9 Q5's "must tolerate arbitrary chunk-delivery latency without diverging") — the queue
  //     holds the commit while both sides ratchet on around it.

  /** A frame in flight. Both kinds ride the REAL inner block — `Frame.pad`ed user text or a
    * `ChunkStream` envelope, each wrapped in a real `ArqFrame` and sealed by the real ratchet —
    * so the model exercises the actual byte-0 control/content discrimination, not a stand-in. */
  private sealed trait Wire:
    def bytes: Array[Byte]
  private final case class Content(text: String, bytes: Array[Byte]) extends Wire
  private final case class Control(bytes: Array[Byte]) extends Wire

  private def arqInner(payload: Array[Byte], seq: Long): Array[Byte] =
    ArqFrame.encode(ArqFrame.NoSeq, seq, payload)
  private def contentPayload(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), ArqFrame.PayloadBytes).toOption.get

  /** One rekey attempt. `aliceSs`/`bobSs` are the two sides' epoch secrets — EQUAL on the honest
    * path, DIFFERENT when the op models ML-KEM implicit rejection (§4.2). */
  private final class Attempt(val epoch: Int, val aliceSs: Array[Byte], val bobSs: Array[Byte]):
    var confirmSent = false // alice verified /r and put her own /i on the wire
    var armed = false // bob armed the fold and its EPOCH_COMMIT is on the wire
    var aliceFolded = false

  /** The model world: two real ratchets, one FIFO channel per direction (stop-and-wait ARQ), and
    * the rekey attempt state machine driven per `Engine`. Every `assert` below is on real code. */
  private final class World:
    val alice: DoubleRatchet = DoubleRatchet.initInitiator(contentRoot(7)) // initiator
    val bob: DoubleRatchet = DoubleRatchet.initResponder(contentRoot(7)) // responder = committer
    val a2b: mutable.Queue[Wire] = mutable.Queue.empty
    val b2a: mutable.Queue[Wire] = mutable.Queue.empty
    var attempt: Option[Attempt] = None
    var nextEpoch: Int = 1
    var seq: Long = 0L
    var foldsCompleted: Int = 0 // epochs that folded on BOTH sides
    var attemptsAborted: Int = 0

    private def chan(fromInit: Boolean) = if fromInit then a2b else b2a
    private def recv(fromInit: Boolean) = if fromInit then bob else alice

    private def enqueue(fromInit: Boolean, w: Wire): Unit =
      chan(fromInit).enqueue(w)

    private def sealFrom(fromInit: Boolean, payload: Array[Byte]): Array[Byte] =
      seq += 1
      (if fromInit then alice else bob).encrypt(arqInner(payload, seq))

    /** A responder with no sending chain yet (initiator-sends-first) holds the send; dropping
      * the op models that hold, exactly as the base model above does. */
    def send(fromInit: Boolean, msg: String): Unit =
      if fromInit || bob.canSend then
        enqueue(fromInit, Content(msg, sealFrom(fromInit, contentPayload(msg))))

    /** Open an attempt: the KEM transfer is elided (see the section note), so this jumps straight
      * to the responder putting its `/r` confirmation tag on the wire — the first point at which
      * any rekey state becomes observable to the ratchet. */
    def start(mismatchedSecret: Boolean): Unit =
      if attempt.isEmpty && bob.canSend && !bob.epochFoldArmed then
        val ss = random.Rand.bytes(EpochKdf.KeyBytes)
        val bobSs = if mismatchedSecret then random.Rand.bytes(EpochKdf.KeyBytes) else ss.clone()
        val a = Attempt(nextEpoch, ss, bobSs)
        nextEpoch += 1
        attempt = Some(a)
        val tag = EpochKdf.epochConfirmTagResponder(a.bobSs)
        enqueue(
          fromInit = false,
          Control(
            sealFrom(
              false,
              ChunkStream.encode(
                ChunkStream.Envelope.KemConfirm(a.epoch, BuddyRole.Responder, tag)
              )
            )
          )
        )

    /** Abort BEFORE either side is past the point of no return (§8.2 "Aborted"): every secret
      * released, the pre-rekey epoch retained. The engine REFUSES an abort past that line; that is
      * the engine's property and is asserted against the real engine in `PqRekeyCrossSpec`, so the
      * model simply does not generate it. */
    def abort(): Unit =
      attempt.foreach { a =>
        if !a.armed then
          val foldsA = alice.epochFoldsApplied
          val foldsB = bob.epochFoldsApplied
          alice.disarmEpochFold()
          bob.disarmEpochFold()
          attempt = None
          attemptsAborted += 1
          // §8.2 "Aborted → PqEpoch": an abort must never strip a prior fold's hardening.
          assert(alice.epochFoldsApplied == foldsA, "an abort must not un-apply a committed fold")
          assert(bob.epochFoldsApplied == foldsB, "an abort must not un-apply a committed fold")
      }

    def deliver(fromInit: Boolean): Unit =
      val q = chan(fromInit)
      if q.nonEmpty then
        val w = q.dequeue()
        val opened = recv(fromInit).decrypt(w.bytes)
        assert(opened.isDefined, "an in-order genuine frame must decrypt")
        val payload = ArqFrame.payloadOf(opened.get)
        w match
          case Content(text, _) =>
            assert(!ChunkStream.isControl(payload), "user content must not decode as control")
            val got = Frame.unpad(payload, ArqFrame.PayloadBytes).toOption.get
            assert(new String(got, UTF_8) == text, s"delivery must decrypt to '$text'")
          case Control(_) =>
            assert(ChunkStream.isControl(payload), "a control envelope must be seen as control")
            ChunkStream.decode(payload) match
              case Right(ChunkStream.Envelope.KemConfirm(e, role, tag)) => onConfirm(e, role, tag)
              case Right(ChunkStream.Envelope.EpochCommit(e, _, anchor)) => onCommit(e, anchor)
              case other => fail(s"the model only emits confirm/commit envelopes, got $other")

    /** The §4.2 confirmation, both directions, on the real tags under the real constant-time
      * compare. The decisive assertion is the biconditional: the tag verifies EXACTLY when the two
      * sides hold the same epoch secret — soundness (a mismatched `ss`, i.e. what ML-KEM implicit
      * rejection hands back, is always caught) AND completeness (a matching one is never rejected,
      * so the check cannot be passing for the wrong reason). */
    private def onConfirm(epoch: Int, role: BuddyRole, tag: Array[Byte]): Unit =
      attempt.foreach { a =>
        if a.epoch == epoch then
          val secretsMatch = java.util.Arrays.equals(a.aliceSs, a.bobSs)
          role match
            case BuddyRole.Responder => // alice checks the responder's /r
              val ok = token.RetrievalToken
                .equalsCT(EpochKdf.epochConfirmTagResponder(a.aliceSs), tag)
              assert(ok == secretsMatch, "the /r tag must verify exactly when the secrets match")
              if !ok then failAttempt()
              else if !a.confirmSent then
                a.confirmSent = true
                enqueue(
                  fromInit = true,
                  Control(
                    sealFrom(
                      true,
                      ChunkStream.encode(
                        ChunkStream.Envelope.KemConfirm(
                          a.epoch,
                          BuddyRole.Initiator,
                          EpochKdf.epochConfirmTagInitiator(a.aliceSs)
                        )
                      )
                    )
                  )
                )
            case BuddyRole.Initiator => // bob checks the initiator's /i, then commits
              val ok = token.RetrievalToken
                .equalsCT(EpochKdf.epochConfirmTagInitiator(a.bobSs), tag)
              assert(ok == secretsMatch, "the /i tag must verify exactly when the secrets match")
              if !ok then failAttempt()
              else if !a.armed && bob.canSend && !bob.epochFoldArmed then queueCommit(a)
      }

    /** A failed confirmation (§4.2 fail-closed): nothing folds, every secret is released, and the
      * pre-rekey epoch stays usable — the last of which the surviving script asserts for us,
      * since every later delivery must still decrypt. */
    private def failAttempt(): Unit =
      val foldsA = alice.epochFoldsApplied
      val foldsB = bob.epochFoldsApplied
      alice.disarmEpochFold()
      bob.disarmEpochFold()
      attempt = None
      attemptsAborted += 1
      assert(alice.epochFoldsApplied == foldsA, "a refused tag must fold NOTHING")
      assert(bob.epochFoldsApplied == foldsB, "a refused tag must fold NOTHING")

    /** The committer's point of no return, mirroring `Engine.ctrlHeadBytes`: arm the fold at OUR
      * NEXT root index and name that index in the EPOCH_COMMIT that goes out. */
    private def queueCommit(a: Attempt): Unit =
      val anchor = bob.rootIndex + 1
      val foldsBefore = bob.epochFoldsApplied
      assert(bob.armEpochFold(anchor, a.bobSs), "arming at our next index must succeed")
      assert(bob.epochFoldArmed, "the committer's fold is ARMED, not yet applied")
      assert(
        bob.epochFoldsApplied == foldsBefore,
        "arming ahead of the chain must not fold anything yet — no half-commit"
      )
      a.armed = true
      enqueue(
        fromInit = false,
        Control(
          sealFrom(
            false,
            ChunkStream.encode(
              ChunkStream.Envelope.EpochCommit(a.epoch, BuddyRole.Responder, anchor)
            )
          )
        )
      )

    /** The initiator's fold point (`Engine.onEpochCommit`). Having just processed the committer's
      * frame this side sits on exactly the committer's anchor — §4.2's whole anchoring claim,
      * and the reason the two sides derive a byte-identical `RK_epoch`. The model ASSERTS that
      * rather than assuming it: an implementation that armed the wrong index, or a chain that
      * could slip past an armed anchor, shows up here. */
    private def onCommit(epoch: Int, anchor: Int): Unit =
      attempt.foreach { a =>
        if a.epoch == epoch && a.confirmSent && !a.aliceFolded then
          assert(
            anchor == alice.rootIndex,
            s"the commit anchor $anchor must be the receiver's live root index ${alice.rootIndex}"
          )
          assert(alice.armEpochFold(anchor, a.aliceSs), "a fold at our live root must apply")
          assert(!alice.epochFoldArmed, "a fold at the live root commits NOW, arming nothing")
          a.aliceFolded = true
          attempt = None
          foldsCompleted += 1
      }

    /** Deliver everything still in flight, in FIFO order, then force the committer's armed fold to
      * land (it applies on its next DH step) with a full ping-pong. Interoperability IS the root
      * comparison: no oracle exposes the root, and two ratchets talk iff their roots agree. */
    def settle(): Unit =
      while a2b.nonEmpty || b2a.nonEmpty do
        if a2b.nonEmpty then deliver(fromInit = true)
        if b2a.nonEmpty then deliver(fromInit = false)
      send(fromInit = true, "settle-a")
      deliver(fromInit = true)
      send(fromInit = false, "settle-b")
      deliver(fromInit = false)

    /** THE CONTROL, and the reason the convergence assertion above is not vacuous.
      *
      * "Both sides still talk" is SYMMETRIC: a fold that quietly did nothing — a half-commit that
      * derived `RK_epoch` and never replaced the root, say — leaves both roots equal and passes
      * every convergence assertion in this file. (Checked, not assumed: that exact mutation passes
      * the property above and fails HERE.) So each script that folded ends by folding ONE side only
      * and proving the roots part company. Without a root oracle — and production code must never
      * expose one — interoperability is the only honest observable: two ratchets talk iff their
      * roots agree, so a one-sided fold that does NOT break them means the fold never reached the
      * root.
      *
      * Terminal: it deliberately desynchronizes the pair, so nothing may run after it. */
    def assertFoldIsLoadBearing(): Unit =
      assert(bob.canSend && !bob.epochFoldArmed, "precondition: a settled pair")
      assert(bob.armEpochFold(bob.rootIndex + 1, random.Rand.bytes(EpochKdf.KeyBytes)))
      // Drive the committer to its next DH step so the armed fold lands. `a → b` is always safe:
      // the receiving chain is derived by the `kdfRk` that PRODUCED the anchor root, so it predates
      // the fold — only the committer's REPLY is keyed under the folded root.
      var guard = 0
      while bob.epochFoldArmed && guard < 3 do
        send(fromInit = true, s"control-a$guard")
        deliver(fromInit = true)
        if bob.epochFoldArmed then
          // The committer did not step (it was already on this chain): make the initiator ratchet
          // so her NEXT frame carries a fresh key and forces the step.
          send(fromInit = false, s"control-b$guard")
          deliver(fromInit = false)
        guard += 1
      assert(!bob.epochFoldArmed, "the control fold must land within a bounded ping-pong")
      // The committer's root moved and the initiator's did not, so its reply — keyed from the
      // folded root via the next `kdfRk` — must be undecryptable to her.
      seq += 1
      val reply = bob.encrypt(arqInner(contentPayload("control-reply"), seq))
      assert(
        alice.decrypt(reply).isEmpty,
        "a ONE-SIDED fold MUST diverge — otherwise the fold never reached the root"
      )

  private val genRekeyOp: Gen[World => Unit] = Gen.frequency(
    4 -> (for { d <- genDir; m <- genMsg } yield (w: World) => w.send(d, m)),
    6 -> genDir.map(d => (w: World) => w.deliver(d)),
    1 -> Gen.const((w: World) => w.start(mismatchedSecret = false)),
    1 -> Gen.const((w: World) => w.start(mismatchedSecret = true)),
    1 -> Gen.const((w: World) => w.abort())
  )

  /** THE Phase 4 property. Every op sequence — traffic and rekey interleaved arbitrarily — must
    * leave the two ratchets converged: the fold is atomic (armed or applied, never half), a failed
    * confirmation folds nothing and retains any prior epoch's hardening, an arbitrary delay between
    * arming and delivery still lands on the same anchor, and after the dust settles both sides
    * still talk — which they can only do if their roots are byte-identical. */
  test("model: rekey interleaved with traffic never half-commits and never diverges (§7 Phase 4)"):
    var totalFolds = 0
    var totalAborts = 0
    forAll(Gen.choose(0, 120).flatMap(Gen.listOfN(_, genRekeyOp))) { ops =>
      val w = World()
      ops.foreach(_(w))
      w.settle()
      // Convergence: the committer's armed fold has now landed, so the two sides must have folded
      // the SAME number of times. A one-sided fold is the divergence this whole design fears.
      assert(!w.bob.epochFoldArmed, "the settling ping-pong lands any armed fold")
      assert(
        w.alice.epochFoldsApplied == w.bob.epochFoldsApplied,
        s"the two sides must fold in lockstep: ${w.alice.epochFoldsApplied} vs " +
          s"${w.bob.epochFoldsApplied}"
      )
      assert(
        w.alice.epochFoldsApplied == w.foldsCompleted,
        "exactly the epochs that confirmed on both sides folded — no fold without a confirmation"
      )
      // …and that convergence is not the convergence of two ratchets that both folded NOTHING.
      w.assertFoldIsLoadBearing()
      totalFolds += w.foldsCompleted
      totalAborts += w.attemptsAborted
    }
    // ANTI-VACUITY. Every assertion above holds trivially on a script that never reaches a fold, so
    // pin that the generator actually drives the rekey paths this test claims to cover. Without
    // this, a change that stopped the model from ever folding would leave the suite green.
    assert(totalFolds > 0, "the model must actually complete folds, or it proves nothing")
    assert(totalAborts > 0, "the model must actually exercise the fail-closed path")

  /** The §4.2 confirmation's reason for existing, isolated: ML-KEM implicit rejection means a
    * tampered ciphertext yields a SILENTLY WRONG epoch secret rather than an error, so the tags are
    * the only thing standing between that and a fold into a dead, PQ-stripped fork. Under every
    * interleaving, a mismatched secret must be refused BEFORE any ratchet state moves, and the pair
    * must survive to rekey again. */
  test("model: a mismatched epoch secret (ML-KEM implicit rejection) never reaches the root"):
    val gen = for {
      lead <- Gen.choose(0, 20).flatMap(Gen.listOfN(_, genRekeyOp))
      tail <- Gen.choose(0, 20).flatMap(Gen.listOfN(_, genRekeyOp))
    } yield (lead, tail)
    var refused = 0
    forAll(gen) { case (lead, tail) =>
      val w = World()
      lead.foreach(_(w))
      // Force the implicit-rejection case, then drive the confirmation to completion.
      w.attempt = None
      w.start(mismatchedSecret = true)
      val opened = w.attempt.isDefined
      val foldsBefore = w.alice.epochFoldsApplied
      while w.a2b.nonEmpty || w.b2a.nonEmpty do
        if w.a2b.nonEmpty then w.deliver(fromInit = true)
        if w.b2a.nonEmpty then w.deliver(fromInit = false)
      if opened then
        refused += 1
        assert(w.attempt.isEmpty, "the mismatched attempt must have been torn down")
        assert(
          w.alice.epochFoldsApplied == foldsBefore && !w.alice.epochFoldArmed,
          "a mismatched epoch secret must not fold or arm anything on the initiator"
        )
        assert(!w.bob.epochFoldArmed, "nor on the committer")
      // The pair is still usable and can still rekey: run an HONEST attempt to completion.
      tail.foreach(_(w))
      w.attempt = None
      val before = w.foldsCompleted
      w.start(mismatchedSecret = false)
      if w.attempt.isDefined then
        w.settle()
        assert(w.foldsCompleted == before + 1, "a retry after a refused epoch must still fold")
        assert(
          w.alice.epochFoldsApplied == w.bob.epochFoldsApplied,
          "and the retry leaves both sides in lockstep"
        )
    }
    assert(refused > 0, "the model must actually reach the confirmation with a mismatched secret")
