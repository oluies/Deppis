package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** CHARACTERIZATION TESTS for two KNOWN, currently-open metadata-privacy gaps in the addressing /
  * notify layer. They assert the present (leaky) behaviour ON PURPOSE so the gaps cannot be silently
  * forgotten and so the day either is fixed THIS spec fails and forces the unconditional FR-014/SC-002
  * claims (in `AnonymitySpec`, `threat-model.md`, the `Engine` comments) to be restored together.
  *
  * Neither gap is a content-crypto or attestation flaw (those paths reviewed clean); both are in the
  * addressing/notify scheme that the metadata-privacy claim rests on:
  *
  *   #1 notify-bit collision — `NotifyDigest.bit` is `HMAC mod 512` with no collision avoidance, so two
  *      buddies collide at birthday rate. A set bit then signals BOTH; the loser's `retrieve` misses,
  *      `recvCounter` does not advance, and the SAME read token recurs. Closed by the unimplemented
  *      T041c pairing-time bit-lease (collision-free bit assignment).
  *
  *   #2 rejected-submit recurrence — `sendCounter` advances only on a SUCCESSFUL submit (to keep
  *      sender/receiver tokens in lockstep), so an untrusted store that REJECTS a write makes the next
  *      round retry under the SAME outgoing token. An idle client always writes a fresh cover token, so
  *      the recurrence is both an FR-014 token recurrence and an active-vs-idle tell. Closed by
  *      round-id-derived addressing or a bounded receiver-side skip window. */
class RecurrenceGapsSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  // ---- GAP #2: a rejected submit makes the outgoing token recur on retry --------------------------

  /** A store that REJECTS every write (an untrusted store can do this to force a retry) and records the
    * tokens it was asked to write. Everything else is inert. */
  private final class RejectingStore extends RoundTransport:
    val writeTokens = mutable.ArrayBuffer.empty[Vector[Byte]]
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      writeTokens += token.toVector; false
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] = new Array[Byte](64)
    def retrieve(token: Array[Byte]): Option[Array[Byte]] = None

  test(
    "GAP #2: a rejected submit makes the write token RECUR next round (breaks FR-014 + active/idle)"
  ):
    val store = RejectingStore()
    val alice = Engine(Some(store), clientLabel = secret("alice"))
    val pid = alice.addBuddy(secret("buddy-0"), BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    alice.sendMessage(pid, "hello") // initiator can send immediately
    alice.tick(1L); alice.tick(2L)
    assert(store.writeTokens.size == 2, "one store write per round")
    // THE GAP: both rounds presented the SAME outgoing token, because sendCounter only advances on a
    // successful submit. An idle client writes a fresh cover token each round, so this recurrence lets
    // the rejecting store flag an actively-retrying real sender. When retry-safe addressing lands the
    // two tokens will differ and this assertion must flip to `!=`.
    assert(
      store.writeTokens(0) == store.writeTokens(1),
      "KNOWN GAP: rejected-submit retry reuses the outgoing token (fix: flip to assertNotEquals)"
    )

  // ---- GAP #1: a notify-bit collision makes the loser's read token RECUR through the engine -------

  private def bitOf(s: Array[Byte]): Int =
    NotifyDigest.bit(KeySchedule.addrKey(handshake.Handshake.init(s).pairKey))

  /** Find two distinct buddy secrets that map to the SAME notify bit (a birthday collision over the
    * 512-bit space — expected within ~27 labels, so a 1000-label scan is a near-certain find). */
  private def collidingPair(): (Array[Byte], Array[Byte]) =
    val seen = mutable.Map.empty[Int, Array[Byte]]
    var found: Option[(Array[Byte], Array[Byte])] = None
    var i = 0
    while found.isEmpty && i < 1000 do
      val s = secret(s"buddy-$i")
      seen.get(bitOf(s)) match
        case Some(prev) => found = Some((prev, s))
        case None => seen(bitOf(s)) = s
      i += 1
    found.getOrElse(fail("no notify-bit collision found within 1000 labels"))

  /** A store the receiver reads from, recording every read token, plus a one-shot notify digest the
    * sender's bit can be set into (mirrors `AnonymitySpec.HostView`). */
  private final class RecvHost(store: mutable.Map[String, Array[Byte]]) extends RoundTransport:
    private val digest = new Array[Byte](64)
    val reads = mutable.ArrayBuffer.empty[Vector[Byte]]
    def signalMail(s: Array[Byte]): Unit =
      val b = bitOf(s); digest(b >> 3) = (digest(b >> 3) | (1 << (b & 7))).toByte
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      store(token.toVector.toString) = frame; true
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = digest.clone(); java.util.Arrays.fill(digest, 0.toByte); out
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      reads += token.toVector; store.remove(token.toVector.toString)

  test(
    "GAP #1: a notify-bit collision makes the loser's read token RECUR through the engine (T041c)"
  ):
    // Two buddies sharing a notify bit, only ONE of which actually has a sender. Each round the shared
    // bit is set, so the receiver sees BOTH as signaled and the fairness cursor alternates between them:
    // on the active buddy it hits (counter advances ⇒ fresh token); on the idle buddy it MISSES (counter
    // frozen ⇒ the SAME read token re-issued). That recurring read token is the store's clustering
    // handle. The T041c bit-lease (collision-free bit assignment) removes the collision and the miss.
    val (sActive, sIdle) = collidingPair()
    assert(bitOf(sActive) == bitOf(sIdle), "precondition: the pair collides on one notify bit")

    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = RecvHost(store)
    val sendHost = new RoundTransport: // the active buddy's sender; writes into the shared store
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        store(token.toVector.toString) = frame; true
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] = new Array[Byte](64)
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = None

    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    Seq(sActive, sIdle).foreach { s => // Bob confirms BOTH colliding buddies
      val r = bob.addBuddy(s, BuddyRole.Responder).toOption.get
      bob.confirmBuddy(r.pairId, matched = true)
    }
    bob.drainEvents()
    val alice = Engine(Some(sendHost), clientLabel = secret("alice"))
    val pid = alice.addBuddy(sActive, BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()

    val K = 6
    (1 to K).foreach { round =>
      alice.sendMessage(pid, s"m$round");
      alice.tick(round.toLong) // active buddy writes a real frame
      recvHost.signalMail(sActive) // the shared bit ⇒ BOTH colliding buddies look signaled
      bob.tick(round.toLong) // cursor alternates: active hits, idle misses
      bob.drainEvents()
    }

    // THE GAP: the idle buddy's read token recurs every time the cursor lands on it (its counter never
    // advances), so the read trace is NOT all-distinct — exactly the clustering FR-014 forbids. Under
    // collision-free bits (T041c) every read would be a hit and all K tokens distinct; when that lands
    // this assertion must flip to `==`.
    assert(recvHost.reads.size == K, "one read per round")
    assert(
      recvHost.reads.distinct.size < recvHost.reads.size,
      "KNOWN GAP: a colliding idle buddy's read token recurs (fix: assert all reads distinct)"
    )
