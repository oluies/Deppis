package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** Regression tests for the three addressing/notify recurrence concerns surfaced by the holistic crypto
  * review — ALL now CLOSED by retry-safe (round-derived) addressing. None was a content-crypto or
  * attestation flaw; all were in the addressing/notify scheme:
  *
  *   #1 notify-bit collision — closed by T041c (per-round bit rotation + serve-only-when-unambiguous).
  *   #2 rejected-submit recurrence (write-side) — closed by round-derived addressing: a rejected submit
  *      retransmits under a FRESH round token, never the same one.
  *   #3 removed-peer read recurrence (read-side) — closed by the same: a false/colliding serve reads a
  *      round-derived token used at most once, so it can never recur even if `recvCounter` would have
  *      frozen under the old counter scheme.
  *
  * Each test drives the original failure scenario and asserts NON-recurrence — it FAILS loudly if the
  * round-derived addressing regresses to counter-based. (Addressing reads the PREVIOUS round's writes,
  * `readRound = roundId - 1`, so a collision the engine acts on at `readRound = c` is exercised by
  * ticking at round `c + 1`.) */
class RecurrenceGapsSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def bitOf(s: Array[Byte], roundId: Long): Int =
    NotifyDigest.bit(KeySchedule.addrKey(handshake.Handshake.init(s).pairKey), roundId)

  /** The first `count` rounds in which two distinct buddy secrets' rotated notify bits collide.
    * Deterministic for the fixed secrets; a `fail` makes a derivation change loud, not flaky. */
  private def collisionRounds(a: Array[Byte], b: Array[Byte], count: Int): Seq[Long] =
    val acc = mutable.ArrayBuffer.empty[Long]
    var r = 1L
    while acc.size < count && r <= 200000L do
      if bitOf(a, r) == bitOf(b, r) then acc += r
      r += 1
    if acc.size < count then
      fail(
        s"found only ${acc.size}/$count colliding rounds in 200000 — did the bit derivation change?"
      )
    acc.toSeq

  // ---- #2 (write-side): a rejected submit retransmits under FRESH round tokens ---------------------

  /** A store that REJECTS every write, recording every token it was asked to write. */
  private final class RejectingStore extends RoundTransport:
    val writeTokens = mutable.ArrayBuffer.empty[Vector[Byte]]
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      writeTokens += token.toVector; false
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] = new Array[Byte](64)
    def retrieve(token: Array[Byte]): Option[Array[Byte]] = None

  test(
    "#2 FIXED: a rejected submit retransmits under a FRESH round token — the write token never recurs"
  ):
    val store = RejectingStore()
    val alice = Engine(Some(store), clientLabel = secret("alice"))
    val pid = alice.addBuddy(secret("buddy-0"), BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()
    alice.sendMessage(
      pid,
      "hello"
    ) // initiator can send immediately; held + retransmitted (unacked)
    for r <- 1L to 6L do alice.tick(r)
    // The store sees one write per round, each REJECTED, each retried — under a round-derived token, so
    // all six are DISTINCT (pre-fix they were the same counter token, a clustering / active-vs-idle tell).
    assert(store.writeTokens.size == 6, "one store write per round")
    assert(
      store.writeTokens.distinct.size == store.writeTokens.size,
      "retry-safe: every rejected-retry write token is distinct — no recurrence"
    )

  // ---- #1/#3 (read-side): collisions serve round-derived read tokens that never recur --------------

  /** A store the receiver reads from, recording every read token; `signalMail` QUEUES a buddy and
    * `fetchDigest(roundId)` sets its rotated bit (matching the engine's per-round derivation). */
  private final class RecvHost(store: mutable.Map[String, Array[Byte]]) extends RoundTransport:
    private val pendingMail = mutable.ArrayBuffer.empty[Array[Byte]]
    val reads = mutable.ArrayBuffer.empty[Vector[Byte]]
    def signalMail(s: Array[Byte]): Unit = pendingMail += handshake.Handshake.init(s).pairKey
    def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
      store(token.toVector.toString) = frame; true
    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      val out = new Array[Byte](64)
      for pk <- pendingMail do
        val b = NotifyDigest.bit(KeySchedule.addrKey(pk), roundId)
        out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte
      pendingMail.clear(); out
    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      reads += token.toVector; store.remove(token.toVector.toString)

  /** Bob with a confirmed idle buddy C and a second buddy `other` (pending or removed) that keeps
    * signaling; on rounds where their bits collide Bob may serve C (a miss). Returns Bob's read tokens
    * over those collision rounds — which must all be DISTINCT (round-derived), never a recurrence. */
  private def readsUnderCollision(
      sIdleC: Array[Byte],
      sOther: Array[Byte],
      makeRemoved: Boolean
  ): Seq[Vector[Byte]] =
    val cols = collisionRounds(sIdleC, sOther, 3)
    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = RecvHost(store)
    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    bob.confirmBuddy(bob.addBuddy(sIdleC, BuddyRole.Responder).toOption.get.pairId, matched = true)
    val rOther = bob.addBuddy(sOther, BuddyRole.Responder).toOption.get
    if makeRemoved then {
      bob.confirmBuddy(rOther.pairId, matched = true); bob.removeBuddy(rOther.pairId)
    }
    // else: leave `other` PENDING (added, not confirmed)
    bob.drainEvents()
    // The engine acts on the digest at readRound = tick - 1, so tick at c+1 to exercise collision c.
    for c <- cols do
      recvHost.signalMail(sOther)
      bob.tick(c + 1)
      bob.drainEvents()
    recvHost.reads.toSeq

  test(
    "#1/#3 FIXED: a REMOVED peer colliding with a confirmed idle buddy cannot recur a read token"
  ):
    val reads = readsUnderCollision(secret("idle-c"), secret("removed-x"), makeRemoved = true)
    assert(reads.nonEmpty, "the collision must actually serve the idle buddy at least once")
    assert(
      reads.distinct.size == reads.size,
      "round-derived: read tokens across removed-peer collisions are all distinct — no recurrence"
    )

  test("#1 FIXED: a PENDING peer colliding with a confirmed idle buddy cannot recur a read token"):
    val reads = readsUnderCollision(secret("idle-c2"), secret("pending-x2"), makeRemoved = false)
    assert(
      reads.distinct.size == reads.size,
      "round-derived: read tokens across pending-peer collisions are all distinct — no recurrence"
    )
