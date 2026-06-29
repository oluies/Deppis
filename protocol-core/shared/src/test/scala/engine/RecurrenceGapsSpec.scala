package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** CHARACTERIZATION TESTS for three metadata-privacy concerns in the addressing / notify layer. None
  * is a content-crypto or attestation flaw (those paths reviewed clean); all are in the addressing /
  * notify scheme the metadata-privacy claim rests on:
  *
  *   #1 notify-bit collision — FIXED by T041c. `NotifyDigest.bit(pairKey, roundId)` now ROTATES the bit
  *      per round, and `Engine.tick` serves a buddy only when its set bit is UNAMBIGUOUS among the
  *      client's ACTIVE relationships that round (a guaranteed hit) — a colliding round defers to a
  *      cover read. So the loser's read token no longer recurs; the tests assert that fix (incl. a
  *      pending colliding peer) and FAIL if the rotation/ambiguity handling regresses.
  *
  * #2 and #3 are the WRITE-side and READ-side of the SAME counter-frozen-on-miss class; both are STILL
  * OPEN and closed by the same retry-safe / round-id-derived addressing. Each asserts the present
  * (leaky) behaviour ON PURPOSE so the gap is not silently forgotten, and flips when that lands:
  *
  *   #2 rejected-submit recurrence (write-side, `sendCounter`) — `sendCounter` advances only on a
  *      SUCCESSFUL submit (to keep sender/receiver tokens in lockstep), so an untrusted store that
  *      REJECTS a write makes the next round retry under the SAME outgoing token — an FR-014 recurrence
  *      and an active-vs-idle tell.
  *
  *   #3 removed-peer read recurrence (read-side, `recvCounter`) — removed relationships are excluded
  *      from the bounded T041c ambiguity set, so a peer still signaling after we removed it can collide
  *      with a confirmed idle buddy, get it served, MISS (no frame), freeze its `recvCounter`, and recur
  *      its read token. */
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

  // ---- T041c: a notify-bit collision no longer makes the loser's read token recur ----------------

  private def bitOf(s: Array[Byte], roundId: Long): Int =
    NotifyDigest.bit(KeySchedule.addrKey(handshake.Handshake.init(s).pairKey), roundId)

  /** The first `count` rounds in which two distinct buddy secrets' ROTATED notify bits collide — used
    * to GUARANTEE the ambiguity-cover path is exercised. NOTE: deterministic for the fixed secrets (not
    * statistical); the scan window is generous, and a `fail` makes a derivation change loud, not flaky. */
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

  private def collisionRound(a: Array[Byte], b: Array[Byte]): Long = collisionRounds(a, b, 1).head

  /** A store the receiver reads from, recording every read token; `signalMail` QUEUES a buddy and
    * `fetchDigest(roundId)` sets its ROUND-ROTATED bit (matching the engine), then clears the queue. */
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

  test(
    "T041c: a notify-bit collision no longer makes the loser's read token recur (FR-014 restored)"
  ):
    // Bob has two confirmed buddies that COLLIDE on a notify bit in round `rc`, and only one (sActive)
    // ever sends. Pre-T041c the cursor could land on the idle buddy on the colliding round, miss, and
    // re-issue its frozen read token. Now bits rotate per round and the engine serves a buddy only when
    // its set bit is UNAMBIGUOUS that round, so on the colliding round it serves NEITHER and issues a
    // fresh cover read — the idle buddy's token is never issued and no read token recurs, while the
    // active buddy is still fully delivered.
    val sActive = secret("buddy-active")
    val sIdle = secret("buddy-idle")
    val rc = collisionRound(sActive, sIdle)
    assert(bitOf(sActive, rc) == bitOf(sIdle, rc), "the pair collides on round rc")

    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = RecvHost(store)
    val sendHost = new RoundTransport: // the active buddy's sender; writes into the shared store
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        store(token.toVector.toString) = frame; true
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] = new Array[Byte](64)
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = None

    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    Seq(sActive, sIdle).foreach { s => // Bob confirms BOTH (the colliding pair)
      val r = bob.addBuddy(s, BuddyRole.Responder).toOption.get
      bob.confirmBuddy(r.pairId, matched = true)
    }
    bob.drainEvents()
    val alice = Engine(Some(sendHost), clientLabel = secret("alice"))
    val pid = alice.addBuddy(sActive, BuddyRole.Initiator).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true); alice.drainEvents()

    // A window of rounds that SPANS the colliding round rc (which falls on the 2nd round, so the active
    // buddy is still undelivered ⇒ signals ⇒ the ambiguity-cover path runs there).
    val msgs = 3
    val rounds = (rc - 1) to (rc + msgs + 2)
    var delivered = 0
    var sent = 0
    for round <- rounds do
      if sent < msgs then { alice.sendMessage(pid, s"m$round"); sent += 1 }
      alice.tick(round)
      if delivered < msgs then recvHost.signalMail(sActive) // ONLY the active buddy ever signals
      bob.tick(round)
      delivered += bob.drainEvents().count(_.isInstanceOf[EngineEvent.MessageReceived])

    assert(recvHost.reads.size == rounds.size, "one read per round")
    // THE FIX: every read token is distinct — the idle buddy's token is never issued and the colliding
    // round is a fresh cover read — and the active buddy is still fully delivered.
    assert(
      recvHost.reads.distinct.size == recvHost.reads.size,
      "T041c: every read token is distinct — no recurrence even across a colliding round"
    )
    assert(
      delivered == msgs,
      s"active buddy delivered $delivered/$msgs despite the collision round"
    )

  test("T041c: a pending/colliding peer cannot make a confirmed idle buddy's read token recur"):
    // Bob has a CONFIRMED idle buddy C (no sender) and a still-PENDING buddy X (added, not yet
    // confirmed — the confirm window). X's peer keeps signaling X's bit. On rounds where X's rotated
    // bit collides with C's, C's bit appears SET; if ambiguity ranged only over CONFIRMED buddies the
    // engine would serve C, MISS (C has no mail), and re-issue C's frozen read token — recurrence.
    // Because ambiguity ranges over ALL relationships (X is pending-but-present), those rounds are
    // ambiguous ⇒ a fresh cover read ⇒ no recurrence. Two colliding rounds are used so a confirmed-only
    // regression would serve C twice at the same frozen counter and fail this test.
    val sIdleC = secret("confirmed-idle")
    val sPendX = secret("pending-peer")
    val cols = collisionRounds(sIdleC, sPendX, 2)

    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = RecvHost(store)
    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    val rcC = bob.addBuddy(sIdleC, BuddyRole.Responder).toOption.get
    bob.confirmBuddy(rcC.pairId, matched = true) // C: confirmed, idle
    bob.addBuddy(sPendX, BuddyRole.Responder) // X: added but NOT confirmed ⇒ Pending
    bob.drainEvents()

    for r <- cols do
      recvHost.signalMail(
        sPendX
      ) // X's (pending) peer signals — sets X's rotated bit, == C's that round
      bob.tick(r)
      bob.drainEvents()

    assert(recvHost.reads.size == cols.size, "one read per round")
    assert(
      recvHost.reads.distinct.size == recvHost.reads.size,
      "no recurrence: a pending/colliding peer must not force a confirmed idle buddy to be served"
    )

  test(
    "GAP #3 (read-side, still open): a REMOVED peer still signaling can recur a confirmed idle buddy's read token"
  ):
    // Counterpart to the pending-peer test: a peer X we REMOVED (kept in the book for duplicate-add
    // detection but EXCLUDED from the bounded ambiguity set) whose peer keeps signaling. On rounds where
    // X's rotated bit collides with a confirmed idle buddy C's bit, C looks UNAMBIGUOUS (X is excluded),
    // so the engine serves C, MISSES (C is idle), C's recvCounter stays frozen, and C's read token
    // RECURS. This is the READ-side (recvCounter) analogue of GAP #2's WRITE-side (sendCounter)
    // recurrence — the SAME CLASS of retry-safe / round-id-derived addressing closes both. Removed
    // peers are excluded on purpose to keep the ambiguity set bounded (else it grows forever ⇒
    // starvation); the residual is pinned here ON PURPOSE and this assertion flips when read-side
    // retry-safe addressing lands.
    val sIdleC = secret("confirmed-idle-3")
    val sRemX = secret("removed-peer-3")
    val cols =
      collisionRounds(sIdleC, sRemX, 2) // 2 collisions ⇒ C served twice at the same frozen token

    val store = mutable.Map.empty[String, Array[Byte]]
    val recvHost = RecvHost(store)
    val bob = Engine(Some(recvHost), clientLabel = secret("bob"))
    val rcC = bob.addBuddy(sIdleC, BuddyRole.Responder).toOption.get
    bob.confirmBuddy(rcC.pairId, matched = true) // C: confirmed, idle
    val rX = bob.addBuddy(sRemX, BuddyRole.Responder).toOption.get
    bob.confirmBuddy(rX.pairId, matched = true)
    bob.removeBuddy(
      rX.pairId
    ) // X: removed (kept in book for dup-add detection, excluded from ambiguity)
    bob.drainEvents()

    for r <- cols do
      recvHost.signalMail(sRemX) // the removed peer keeps signaling its (now-uncounted) bit
      bob.tick(r)
      bob.drainEvents()

    assert(recvHost.reads.size == cols.size && cols.size == 2, "two reads, one per collision round")
    // Mirror GAP #2's explicit form: BOTH reads are C's SAME frozen token (recvCounter never advanced).
    assert(
      recvHost.reads(0) == recvHost.reads(1),
      "KNOWN GAP #3: a removed-but-signaling peer recurs C's SAME frozen read token (fix: flip to !=)"
    )
