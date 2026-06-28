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

  // ---- GAP #1: NotifyDigest.bit admits birthday collisions ---------------------------------------

  test(
    "GAP #1: NotifyDigest.bit admits a collision, so read non-recurrence is conditional (T041c)"
  ):
    // Scan distinct addressing roots: over a 512-bit space a collision appears well within the birthday
    // bound (~27 expected). Its existence is exactly why a signaled bit can target the wrong buddy,
    // miss, and re-issue the same read token next round — what the T041c bit-lease would make
    // impossible. When T041c lands (collision-free assignment), the recurrence path this guards is gone.
    val seen = mutable.Map.empty[Int, String]
    var collision: Option[(String, String)] = None
    var i = 0
    while collision.isEmpty && i < 1000 do
      val label = s"buddy-$i"
      val bit =
        NotifyDigest.bit(KeySchedule.addrKey(handshake.Handshake.init(secret(label)).pairKey))
      seen.get(bit) match
        case Some(prev) => collision = Some((prev, label))
        case None => seen(bit) = label
      i += 1
    assert(
      collision.isDefined,
      "KNOWN GAP: notify bits collide at birthday rate; T041c bit-lease assigns collision-free bits"
    )
