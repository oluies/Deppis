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
