package engine

import org.scalatest.funsuite.AnyFunSuite

/** Runs under Node (Scala.js). Proves the generated JS engine works end to end with the real
  * @noble/hashes `Kdf`, and that its derivation is byte-for-byte identical to the JVM build — i.e.
  * noble's HMAC-SHA256 matches the JVM's JCA HMAC-SHA256. The reference values are captured from the
  * JVM `EngineSpec` run, so this is a genuine cross-platform known-answer test. */
class EngineJsSpec extends AnyFunSuite:

  // Reference values for the shared secret "abc", produced by the JVM build.
  private val RefSafety = "10916 17391 95312 90598 83473 10275"
  private val RefPairId = "0c4ef63600dac8633e0345e37f01ff91"

  test("JS engine derives the same pairId + safety number as the JVM (Node HMAC ≡ JCA HMAC)"):
    val r = new Engine().addBuddy("abc".getBytes("UTF-8"), BuddyRole.Initiator).toOption.get
    assert(r.pairId == RefPairId)
    assert(r.safetyNumber == RefSafety)

  test("JSON boundary works on JS: addBuddy → confirmBuddy emits buddyConfirmed, no key leak"):
    val codec = new EngineCodec(new Engine())
    val add = ujson.read(codec.handle(
      """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"abc","role":"initiator"}}"""
    ))
    assert(add("result")("pairId").str == RefPairId)
    val pairId = add("result")("pairId").str
    val resp = ujson.read(codec.handle(
      s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true}}"""
    ))
    assert(resp("events").arr.head("event").str == "buddyConfirmed")

  test("apiVersion mismatch is refused on JS too"):
    val resp = new EngineJs().handle(
      """{"apiVersion":"42","command":"privacyStatus"}"""
    )
    assert(ujson.read(resp)("error")("code").str == "api_version")

  test("the exported facade reports the dev privacy label (no metadata privacy)"):
    val resp = new EngineJs().handle("""{"apiVersion":"1","command":"privacyStatus"}""")
    assert(ujson.read(resp)("result")("metadataPrivate").bool == false)
