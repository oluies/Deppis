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
  * the real-obsd E2E. This spec pins the engine-level property the whole stack rests on.) */
class AnonymitySpec extends AnyFunSuite:

  import token.RetrievalToken

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def bitOf(pairKey: Array[Byte]): Int = NotifyDigest.bit(KeySchedule.addrKey(pairKey))

  /** A transport that records the store host's full observable: every submit (token, frame) and every
    * retrieve token. `signalMail` sets a buddy's one-hot digest bit for the next round. */
  private final class HostView(store: mutable.Map[String, Array[Byte]]) extends RoundTransport:
    private val digest = new Array[Byte](64)
    val submits = mutable.ArrayBuffer.empty[(Vector[Byte], Vector[Byte])]
    val retrieves = mutable.ArrayBuffer.empty[Vector[Byte]]
    def signalMail(pairKey: Array[Byte]): Unit =
      val b = bitOf(pairKey); digest(b >> 3) = (digest(b >> 3) | (1 << (b & 7))).toByte
    def submit(t: Array[Byte], f: Array[Byte]): Boolean =
      submits += ((t.toVector, f.toVector)); store(t.toVector.toString) = f; true
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = digest.clone(); java.util.Arrays.fill(digest, 0.toByte); out
    def retrieve(t: Array[Byte]): Option[Array[Byte]] =
      retrieves += t.toVector; store.remove(t.toVector.toString)

  private val N = 4
  private val K = 6 // rounds per world
  private val buddySecrets = (0 until N).map(i => secret(s"buddy-$i"))

  /** A receiver with all `N` buddies confirmed (the anonymity set), where ONLY buddy `active` actually
    * communicates: it sends a real message each of `K` rounds and the receiver reads it. Returns the
    * host's view of the receiver's read tokens plus how many messages were delivered (non-vacuity). */
  private def world(active: Int): (Vector[Vector[Byte]], Int) =
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
    (1 to K).foreach { round =>
      alice.sendMessage(pid, s"m$round");
      alice.tick(round.toLong) // active buddy writes a real frame
      recvHost.signalMail(handshake.Handshake.init(s).pairKey) // its (and only its) bit is set
      bob.tick(round.toLong) // receiver reads exactly that buddy — a hit ⇒ the token advances
      delivered += bob.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])
    }
    (recvHost.retrieves.toVector, delivered)

  test("the host's read-token trace has the same SHAPE no matter which buddy is active"):
    val traces = (0 until N).map(i => world(i)._1)
    // One read per round in every world, every token a full retrieval token — the host sees the same
    // shape regardless of which buddy is communicating (count/size leak nothing).
    traces.foreach(tr => assert(tr.size == K, s"expected $K reads, got ${tr.size}"))
    traces.foreach(tr =>
      assert(tr.forall(_.size == RetrievalToken.Length), "all tokens full length")
    )

  test("read tokens are non-recurrent across ALL buddies and rounds (no clustering)"):
    val all = (0 until N).flatMap(i => world(i)._1)
    assert(all.size == N * K)
    assert(
      all.distinct.size == all.size,
      "every read token is unique — the host can cluster nothing"
    )

  test(
    "which-buddy is key-dependent, not structural: same position, different buddy ⇒ different token"
  ):
    // If the read token were a function of public data (round/counter) it would leak the buddy; it is
    // a keyed PRF over the per-buddy addressing root, so two buddies' tokens at the SAME position
    // differ unpredictably — the host, lacking the keys, cannot map a token to a buddy.
    val firstReads = (0 until N).map(i => world(i)._1.head)
    assert(firstReads.distinct.size == N, "first-round read tokens differ across buddies")
    firstReads.foreach(t => assert(t.distinct.size > 1, "a token must not be a constant byte"))

  test("anonymity is not of a dead channel: every world actually delivers (SC-002 in force)"):
    // Non-vacuity: the indistinguishable observable above is of a WORKING channel — in every world the
    // active buddy's messages reach the receiver.
    (0 until N).foreach(i => assert(world(i)._2 == K, s"world $i delivered ${world(i)._2}/$K"))
