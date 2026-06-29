package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** Which-buddy anonymity (T053a, SC-002): with `N` buddies and one of them communicating, the store
  * host — which sees the retrieval tokens the client reads/writes — cannot identify WHICH buddy better
  * than `1/N`.
  *
  * The store host's anonymity-relevant observable is exactly the (token, frame) bytes the engine
  * submits and the read tokens it retrieves. This test captures that observable across the `N` "which
  * buddy is active" worlds and asserts it is INDISTINGUISHABLE between them: identical shape (one read
  * per round, fixed token length, fixed 256-byte high-entropy frames) and pseudorandom, non-recurrent
  * tokens that the host — lacking the per-buddy keys — cannot attribute to a buddy. Identical observable
  * across all `N` worlds ⇒ the host's best guess is the `1/N` prior. (The frame bytes are encrypted —
  * proven in `RoundTransportSpec`/T042; the NOTIFY host's anonymity is the oblivious aggregation proven
  * by obsd's selftest — T053; and the store doesn't distinguish, proven by obsd's oblivious selftest +
  * the real-obsd E2E. This spec pins the engine-level property the whole stack rests on.)
  *
  * SCOPE: collision-free notify is now handled by T041c (per-round bit ROTATION + ambiguity-cover in
  * `Engine.tick`), so read-token non-recurrence holds even when two of a receiver's buddies' bits
  * collide in a round — no distinct-bit precondition is needed (a colliding round defers to a cover
  * read; see `RecurrenceGapsSpec`). One modeled assumption remains: the store accepts every write
  * (`HostView.submit` returns `true`); a store that selectively REJECTS a write still makes the
  * OUTGOING token recur on retry (GAP #2, retry-safe addressing — pinned in `RecurrenceGapsSpec`). */
class AnonymitySpec extends AnyFunSuite:

  import token.RetrievalToken

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def bitOf(pairKey: Array[Byte], roundId: Long): Int =
    NotifyDigest.bit(KeySchedule.addrKey(pairKey), roundId)

  /** A transport that records the store host's full observable: every submit (token, frame) and every
    * retrieve token. `signalMail` QUEUES a buddy as having mail; `fetchDigest(roundId)` sets that
    * buddy's ROUND-ROTATED bit (T041c) and clears the queue — matching the engine's per-round bit. */
  private final class HostView(store: mutable.Map[String, Array[Byte]]) extends RoundTransport:
    private val pendingMail = mutable.ArrayBuffer.empty[Array[Byte]]
    val submits = mutable.ArrayBuffer.empty[(Vector[Byte], Vector[Byte])]
    val retrieves = mutable.ArrayBuffer.empty[Vector[Byte]]
    def signalMail(pairKey: Array[Byte]): Unit = pendingMail += pairKey
    def submit(t: Array[Byte], f: Array[Byte]): Boolean =
      submits += ((t.toVector, f.toVector)); store(t.toVector.toString) = f; true
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = new Array[Byte](64)
      for pk <- pendingMail do
        val b = bitOf(pk, roundId); out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte
      pendingMail.clear(); out
    def retrieve(t: Array[Byte]): Option[Array[Byte]] =
      retrieves += t.toVector; store.remove(t.toVector.toString)

  private val N = 4
  // The active buddy sends ONE message, held in flight (retry-safe addressing retransmits it each
  // round under a fresh round-derived token). One in-flight message suffices to pin the anonymity
  // observable; stop-and-wait ARQ would only advance to a second message after an ack round-trip,
  // which this manual HostView (no ack path back to the sender) does not model.
  private val K = 1
  // Rounds run per world — a FIXED length so the per-world observables stay comparable for the
  // indistinguishability assertions. The active buddy retransmits + signals every round; the receiver
  // reads one (round-derived, always-distinct) token per round.
  private val R = 8
  private val buddySecrets = (0 until N).map(i => secret(s"buddy-$i"))

  /** The store host's full observable for one world, plus a delivery count (non-vacuity). */
  private case class Observable(
      reads: Vector[Vector[Byte]],
      writes: Vector[(Vector[Byte], Vector[Byte])], // (token, frame), the store-write view
      delivered: Int
  )

  /** A receiver with all `N` buddies confirmed (the anonymity set), where ONLY buddy `active` actually
    * communicates: it sends `K` real messages and the receiver reads them over `R` rounds. Returns the
    * store host's full observable (the writes it sees + the reads the receiver issues) and the count
    * delivered. */
  private def world(active: Int): Observable =
    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = HostView(store)
    val sendHost = HostView(store)
    val s = buddySecrets(active)
    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    buddySecrets.foreach { sec => // Bob confirms ALL N — the host can't even tell N apart
      val r = bob.addBuddy(sec, BuddyRole.Responder).toOption.get
      bob.confirmBuddy(r.pairId, matched = true)
    }
    bob.drainEvents()
    val alice = Engine(Some(sendHost), clientLabel = secret("alice"))
    val pid = alice.addBuddy(s, BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    var delivered = 0
    (1 to R).foreach { round =>
      if round <= K then alice.sendMessage(pid, s"m$round")
      alice.tick(round.toLong) // active buddy writes a real frame (rounds 1..K), else a carrier
      // Re-signal while mail is undelivered: a rare ambiguous round defers one delivery, so the active
      // buddy re-signals until all K land (within the R-round buffer).
      if delivered < K then recvHost.signalMail(handshake.Handshake.init(s).pairKey)
      bob.tick(round.toLong) // serves the active buddy when its rotated bit is unambiguous (a hit)
      delivered += bob.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
    }
    // The store host sees every write: the active buddy's real frames AND the receiver's cover writes.
    Observable(
      (recvHost.retrieves).toVector,
      (sendHost.submits ++ recvHost.submits).toVector,
      delivered
    )

  // No distinct-bit precondition is needed anymore: T041c rotates each buddy's bit per round and the
  // engine serves only UNAMBIGUOUS set bits (a colliding round defers to a cover read), so the
  // anonymity below holds unconditionally over collisions. (Bit collisions are exercised directly in
  // `RecurrenceGapsSpec`.)

  test("the host's read-token trace has the same SHAPE no matter which buddy is active"):
    val traces = (0 until N).map(i => world(i).reads)
    // One read per round in every world, every token a full retrieval token — the host sees the same
    // shape regardless of which buddy is communicating (count/size leak nothing).
    traces.foreach(tr => assert(tr.size == R, s"expected $R reads, got ${tr.size}"))
    traces.foreach(tr =>
      assert(tr.forall(_.size == RetrievalToken.Length), "all tokens full length")
    )

  test("the host's WRITE trace is also shape-uniform across worlds (token len + 256B frames)"):
    val writes = (0 until N).map(i => world(i).writes)
    // Same number of writes per world, every frame a fixed 256-byte block, every write token full
    // length — the active buddy's real frames are indistinguishable in shape from the cover writes.
    writes.foreach(w => assert(w.forall(_._2.size == frame.Frame.Size), "every frame is 256 bytes"))
    writes.foreach(w =>
      assert(w.forall(_._1.size == RetrievalToken.Length), "every write token is full length")
    )
    assert(writes.map(_.size).distinct.size == 1, "the write count does not depend on which buddy")

  test("read AND write tokens are non-recurrent across ALL buddies and rounds (no clustering)"):
    val obs = (0 until N).map(world)
    val reads = obs.flatMap(_.reads)
    assert(reads.size == N * R && reads.distinct.size == reads.size, "read tokens all unique")
    val writeTokens = obs.flatMap(_.writes.map(_._1))
    assert(
      writeTokens.distinct.size == writeTokens.size,
      "write tokens all unique — nothing to cluster"
    )

  test(
    "which-buddy is key-dependent, not structural: same position, different buddy ⇒ different token"
  ):
    // If the read token were a function of public data (round/counter) it would leak the buddy; it is
    // a keyed PRF over the per-buddy addressing root, so two buddies' tokens at the SAME position
    // differ unpredictably — the host, lacking the keys, cannot map a token to a buddy.
    val firstReads = (0 until N).map(i => world(i).reads.head)
    assert(firstReads.distinct.size == N, "first-round read tokens differ across buddies")
    firstReads.foreach(t => assert(t.distinct.size > 1, "a token must not be a constant byte"))

  test("anonymity is not of a dead channel: every world actually delivers (SC-002 in force)"):
    // Non-vacuity: the indistinguishable observable above is of a WORKING channel — in every world the
    // active buddy's messages reach the receiver.
    (0 until N).foreach { i =>
      val d = world(i).delivered
      assert(d == K, s"world $i delivered $d/$K")
    }
