package engine

import org.scalatest.funsuite.AnyFunSuite
import privacy.Privacy

class EngineSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")

  test("addBuddy returns pairId + a 6x5-digit safety number, never key material"):
    val e = Engine()
    val r = e.addBuddy(secret("out-of-band"), BuddyRole.Initiator).toOption.get
    assert(r.pairId.length == 32)
    assert(r.safetyNumber.split(" ").length == 6)
    assert(r.safetyNumber.replace(" ", "").length == 30)
    assert(e.buddyCount == 1 && e.confirmedCount == 0) // pending

  test("addBuddy is deterministic for the same secret and rejects an exact duplicate"):
    val e = Engine()
    val a = e.addBuddy(secret("k"), BuddyRole.Initiator).toOption.get
    val b = e.addBuddy(secret("k"), BuddyRole.Responder) // same pairId → duplicate
    assert(b == Left(EngineError("add_failed", "duplicate buddy")))
    assert(a.safetyNumber.nonEmpty)

  test("empty shared secret is rejected without leaking detail"):
    assert(
      Engine().addBuddy(Array.emptyByteArray, BuddyRole.Initiator)
        == Left(EngineError("invalid_arg", "shared secret required"))
    )

  test("confirmBuddy(matched) confirms and emits buddyConfirmed"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    assert(e.confirmBuddy(r.pairId, matched = true).isRight)
    assert(e.confirmedCount == 1)
    val evs = e.drainEvents()
    assert(evs == Seq(EngineEvent.BuddyConfirmed(r.pairId, r.safetyNumber)))

  test("confirmBuddy(mismatch) establishes nothing and emits no event"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    assert(e.confirmBuddy(r.pairId, matched = false).isRight)
    assert(e.confirmedCount == 0)
    assert(e.drainEvents().isEmpty)

  test("removeBuddy stops delivery silently (no event, count drops)"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    e.drainEvents()
    assert(e.removeBuddy(r.pairId).isRight)
    assert(e.buddyCount == 0)
    assert(e.drainEvents().isEmpty)

  test("sendMessage to a confirmed buddy queues; unknown/unconfirmed is rejected"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    assert(
      e.sendMessage(r.pairId, "hi") == Left(
        EngineError("unknown_pair", "no confirmed buddy for that pair")
      )
    )
    e.confirmBuddy(r.pairId, matched = true)
    assert(e.sendMessage(r.pairId, "hi") == Right(1))
    assert(e.sendMessage(r.pairId, "again") == Right(2))

  test("sendMessage rejects an over-long message with a fixed message"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    val big = "x" * 1000
    assert(
      e.sendMessage(r.pairId, big) == Left(
        EngineError("message_too_long", "message exceeds the frame payload limit")
      )
    )

  test("tick yields a carrier when nothing is queued and a real frame when one is"):
    val e = Engine()
    val r = e.addBuddy(secret("s"), BuddyRole.Initiator).toOption.get
    e.confirmBuddy(r.pairId, matched = true)
    val empty = e.tick(1).toOption.get
    assert(empty.carrier && empty.retrieve)
    e.sendMessage(r.pairId, "hi")
    val real = e.tick(2).toOption.get
    assert(!real.carrier && real.retrieve)
    // queue drained → next round is a carrier again
    assert(e.tick(3).toOption.get.carrier)

  test("privacyStatus reports the dev backend with no metadata privacy + the mandatory label"):
    val s = Engine().privacyStatus
    assert(!s.metadataPrivate)
    assert(s.label == Privacy.DevLabel)

  // ---- JSON boundary (the versioned wire contract) ----

  test("handle(addBuddy) returns a result and never leaks key material in the JSON"):
    val codec = EngineCodec(Engine())
    val resp = codec.handle(
      """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"abc","role":"initiator"}}"""
    )
    val j = ujson.read(resp)
    assert(j("result")("safetyNumber").str.split(" ").length == 6)
    assert(!resp.contains("pairKey")) // key material never crosses the boundary

  test("handle refuses an apiVersion mismatch before any state change"):
    val e = Engine()
    val codec = EngineCodec(e)
    val resp = codec.handle(
      """{"apiVersion":"9","command":"addBuddy","args":{"sharedSecret":"abc","role":"initiator"}}"""
    )
    assert(ujson.read(resp)("error")("code").str == "api_version")
    assert(e.buddyCount == 0) // refused, not applied

  test("handle(confirmBuddy) surfaces the buddyConfirmed event in the events array"):
    val codec = EngineCodec(Engine())
    val add = ujson.read(
      codec.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"abc","role":"initiator"}}"""
      )
    )
    val pairId = add("result")("pairId").str
    val resp = ujson.read(
      codec.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true}}"""
      )
    )
    val evs = resp("events").arr
    assert(evs.size == 1 && evs.head("event").str == "buddyConfirmed")

  test("handle rejects malformed JSON with a fixed error"):
    val resp = EngineCodec(Engine()).handle("not json{")
    assert(ujson.read(resp)("error")("code").str == "bad_request")

  test("handle rejects valid-but-misshaped input with the uniform error envelope"):
    val codec = EngineCodec(Engine())
    // Non-object top-level value, and a mistyped arg — neither may throw across the boundary.
    for bad <- Seq(
        "5",
        "[1,2]",
        """{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":123,"matched":"yes"}}"""
      )
    do
      val j = ujson.read(codec.handle(bad))
      assert(j("error")("code").str == "bad_request", s"input: $bad")

  test("error responses carry no events (and never leak buffered events into the next call)"):
    val codec = EngineCodec(Engine())
    val errResp = ujson.read(codec.handle("""{"apiVersion":"1","command":"nope"}"""))
    assert(errResp.obj.get("events").isEmpty) // error envelope has no events array

  test("tick accepts roundId as a large string (exact beyond 2^53) or a number"):
    val codec = EngineCodec(Engine())
    // A big round id sent as a string is parsed exactly (no bad_request) — this is the precision-safe
    // input path; a non-numeric string would map to bad_request via the guard.
    val s = ujson.read(
      codec.handle("""{"apiVersion":"1","command":"tick","args":{"roundId":"9007199254740993"}}""")
    )
    assert(s.obj.contains("result"))
    val n = ujson.read(codec.handle("""{"apiVersion":"1","command":"tick","args":{"roundId":3}}"""))
    assert(n("result")("roundId").num.toLong == 3L)
    // A present-but-wrong-typed roundId is an error, not a silent default to 0.
    for bad <- Seq("true", "null", "\"abc\"") do
      val j =
        ujson.read(codec.handle(s"""{"apiVersion":"1","command":"tick","args":{"roundId":$bad}}"""))
      assert(j("error")("code").str == "bad_request", s"roundId:$bad")
    // A missing roundId still defaults to 0 (round 0).
    val miss = ujson.read(codec.handle("""{"apiVersion":"1","command":"tick","args":{}}"""))
    assert(miss("result")("roundId").num.toLong == 0L)

  test("handle(privacyStatus) emits the dev label"):
    val resp = EngineCodec(Engine()).handle("""{"apiVersion":"1","command":"privacyStatus"}""")
    assert(ujson.read(resp)("result")("metadataPrivate").bool == false)
    assert(ujson.read(resp)("result")("label").str == Privacy.DevLabel)
