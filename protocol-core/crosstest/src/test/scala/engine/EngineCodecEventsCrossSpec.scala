package engine

import engine.PqTestKit.FakeBackend
import org.scalatest.funsuite.AnyFunSuite

/** The JSON types of the engine's events (engine-api.md), on BOTH platforms — what a client parses.
  *
  * Regression for a bug found in the first live browser run of provider routing: `notified.roundId`
  * and `messageReceived.receivedAt` were emitted as JSON STRINGS (ujson renders a bare `Long` that
  * way), the Dart client reads them `as num`, the translation threw, and because the codec had
  * already drained the engine's events, every message of that batch was lost — silently. Here Bob is
  * driven ONLY through the JSON boundary, as the browser drives him, and receives a real message. */
class EngineCodecEventsCrossSpec extends AnyFunSuite:

  test("notified.roundId and messageReceived.receivedAt are JSON numbers"):
    val be = FakeBackend()
    val aLabel = "alice".getBytes("UTF-8")
    val bLabel = "bob".getBytes("UTF-8")
    val oob = "codec-events-oob".getBytes("UTF-8")
    val alice = Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = Engine(Some(be.transport()), clientLabel = bLabel)
    val bobJson = EngineCodec(bob)
    val pid = alice.addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = bLabel).toOption.get.pairId
    alice.confirmBuddy(pid, matched = true).toOption.get
    bob.addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = aLabel).toOption.get: Unit
    bob.confirmBuddy(pid, matched = true).toOption.get
    alice.drainEvents(); bob.drainEvents()
    alice.sendMessage(pid, "hello"): Unit

    val events = (1L to 6L).flatMap { r =>
      alice.tick(r): Unit
      val resp = ujson.read(
        bobJson.handle(s"""{"apiVersion":"1","command":"tick","args":{"roundId":$r}}""")
      )
      resp("events").arr.toSeq
    }
    val notified = events.filter(_("event").str == "notified")
    val received = events.filter(_("event").str == "messageReceived")
    assert(received.map(_("plaintext").str) == Seq("hello"), s"the message arrives: $events")
    assert(notified.nonEmpty, "and was notified first")
    for e <- notified do
      assert(e("roundId").isInstanceOf[ujson.Num], s"notified.roundId must be a number: $e")
    for e <- received do
      assert(
        e("receivedAt").isInstanceOf[ujson.Num],
        s"messageReceived.receivedAt must be a number: $e"
      )
