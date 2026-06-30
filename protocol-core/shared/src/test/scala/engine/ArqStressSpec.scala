package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** Stress tests for the stop-and-wait ARQ over round-derived addressing, probing the robustness edge a
  * holistic review flagged: the re-encrypt-on-ack-advance path advances the sending ratchet `Ns` per
  * delivered PEER message, which (with round-derived stranding) could in principle inflate the
  * receiver's skipped-key gap past `MaxSkip` (1000) and stall an epoch. The hypothesis under test is
  * that stop-and-wait bounds the peer's send rate (≤ ~1 in-flight message) and DH-epoch turnover resets
  * `nr`, so a sustained heavy exchange delivers everything without stalling. If any of these stalls,
  * the `Ns`-coupling is a real bug to fix; if they all deliver, the bound holds in practice. */
class ArqStressSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  /** Connected backend: one store + a signal→fetchDigest notify aggregator, shared by both engines. */
  private final class Backend:
    private val store = mutable.Map.empty[String, Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean = {
        store(hex(token)) = frame; true
      }
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
        out

  private def pair(): (Engine, Engine, String) =
    val be = Backend()
    val a = Engine(Some(be.transport()), clientLabel = "alice".getBytes)
    val pid =
      a.addBuddy(secret("shared"), BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes)
        .toOption
        .get
        .pairId
    a.confirmBuddy(pid, matched = true); a.drainEvents()
    val b = Engine(Some(be.transport()), clientLabel = "bob".getBytes)
    b.addBuddy(secret("shared"), BuddyRole.Responder, peerNotifyLabel = "alice".getBytes)
    b.confirmBuddy(pid, matched = true); b.drainEvents()
    (a, b, pid)

  test(
    "SUSTAINED bidirectional: 50 messages each way all deliver in order over a long run (no stall)"
  ):
    val (alice, bob, pid) = pair()
    val n = 50
    val aGot = mutable.ArrayBuffer.empty[String]; val bGot = mutable.ArrayBuffer.empty[String]
    var as = 0; var bs = 0
    for r <- 1L to 2000L do
      // Each side keeps a steady backlog so a head is almost always in flight while it receives the
      // peer's stream — maximizing the re-encrypt-on-ack-advance path.
      if as < n then { alice.sendMessage(pid, s"a$as"); as += 1 }
      if bs < n then { bob.sendMessage(pid, s"b$bs"); bs += 1 }
      alice.tick(r); bob.tick(r)
      aGot ++= alice.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      bGot ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    assert(bGot == (0 until n).map(i => s"a$i"), s"bob delivered ${bGot.size}/$n: ${bGot.take(60)}")
    assert(
      aGot == (0 until n).map(i => s"b$i"),
      s"alice delivered ${aGot.size}/$n: ${aGot.take(60)}"
    )

  test("ONE-DIRECTIONAL: the initiator streams 80 messages while the peer only acks — all deliver"):
    // Alice (initiator, can send immediately) streams; Bob never originates content (only receives +
    // acks). The closest the protocol allows to a one-directional flood: Alice is still stop-and-wait
    // (one in-flight), advancing only as Bob acks — the natural bound on the skipped-key gap. (Alice's
    // highRecv never advances, so this also confirms delivery when the re-encrypt path is NOT engaged.)
    val (alice, bob, pid) = pair()
    val n = 80
    val bGot = mutable.ArrayBuffer.empty[String]
    var as = 0
    for r <- 1L to 2000L do
      if as < n then { alice.sendMessage(pid, s"m$as"); as += 1 }
      alice.tick(r); bob.tick(r)
      bGot ++= bob.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    assert(bGot == (0 until n).map(i => s"m$i"), s"bob delivered ${bGot.size}/$n: ${bGot.take(90)}")
