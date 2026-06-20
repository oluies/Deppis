package engine

import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable
import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array

/** T032b (runs under Node): proves the SAME `Engine.tick` notify-before-retrieval logic validated
  * on the JVM drives a JS backend through [[JsRoundTransport]]/[[JsTransport]]. Two `ProtocolEngine`
  * instances (a sender + a receiver) share an in-memory fake JS transport, so a real message
  * round-trips and surfaces `notified`/`messageReceived` through the JSON boundary — without a
  * network (the real gRPC-web client is the deployment piece; this proves the bridge). */
class JsRoundTransportSpec extends AnyFunSuite:

  private def hexU8(u: Uint8Array): String =
    val sb = new StringBuilder
    var i  = 0
    while i < u.length do
      sb.append(f"${u(i).toInt & 0xff}%02x")
      i += 1
    sb.toString

  private def u8(s: String): Uint8Array =
    val b = s.getBytes("UTF-8")
    val u = new Uint8Array(b.length)
    var i = 0
    while i < b.length do
      u(i) = (b(i) & 0xff).toShort
      i += 1
    u

  /** A synchronous in-memory JS transport (a real JS object with the methods the host supplies). */
  private final class FakeJsTransport(store: mutable.Map[String, Uint8Array]) extends js.Object:
    var mail: Boolean = false
    def submit(token: Uint8Array, frame: Uint8Array): Boolean =
      store(hexU8(token)) = frame; true
    def mailWaiting(roundId: Double, clientLabel: Uint8Array): Boolean = mail
    def retrieve(token: Uint8Array): Uint8Array = store.remove(hexU8(token)).orNull

  private def addBuddy(e: EngineJs, role: String): String =
    val resp = ujson.read(e.handle(
      s"""{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"shared","role":"$role"}}"""
    ))
    resp("result")("pairId").str

  private def confirm(e: EngineJs, pairId: String): Unit =
    e.handle(s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true}}""")

  private def tickEvents(e: EngineJs, round: Int): Seq[String] =
    ujson.read(e.handle(s"""{"apiVersion":"1","command":"tick","args":{"roundId":$round}}"""))(
      "events").arr.toSeq.map(_("event").str)

  test("a JS-transport-backed engine surfaces notified + messageReceived through the bundle"):
    val store = mutable.Map.empty[String, Uint8Array]
    val fakeA = new FakeJsTransport(store)
    val fakeB = new FakeJsTransport(store)
    val alice = new EngineJs(fakeA.asInstanceOf[JsTransport], u8("alice"))
    val bob   = new EngineJs(fakeB.asInstanceOf[JsTransport], u8("bob"))

    val pairId = addBuddy(alice, "initiator")
    confirm(alice, pairId)
    addBuddy(bob, "responder")
    confirm(bob, pairId)

    // Alice sends + ticks → submits the frame into the shared store.
    alice.handle(s"""{"apiVersion":"1","command":"sendMessage","args":{"pairId":"$pairId","plaintext":"on my way"}}""")
    assert(!tickEvents(alice, 1).contains("messageReceived"))

    // Bob has mail this round; his tick emits notified BEFORE the retrieved message.
    fakeB.mail = true
    val bobResp = ujson.read(bob.handle("""{"apiVersion":"1","command":"tick","args":{"roundId":2}}"""))
    val events  = bobResp("events").arr.toSeq
    val names   = events.map(_("event").str)
    assert(names.contains("notified"))
    assert(names.contains("messageReceived"))
    assert(names.indexOf("notified") < names.indexOf("messageReceived"), "notify-before-retrieval order")
    val msg = events.find(_("event").str == "messageReceived").get
    assert(msg("pairId").str == pairId)
    assert(msg("plaintext").str == "on my way")

  test("with no transport the engine is local-only (no delivery events)"):
    val e = new EngineJs() // no transport
    val pairId = addBuddy(e, "initiator")
    confirm(e, pairId)
    e.handle(s"""{"apiVersion":"1","command":"sendMessage","args":{"pairId":"$pairId","plaintext":"x"}}""")
    assert(tickEvents(e, 1).isEmpty)
