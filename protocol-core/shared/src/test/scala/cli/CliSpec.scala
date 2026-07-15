package cli

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64
import org.scalatest.funsuite.AnyFunSuite
import frame.Frame
import handshake.Handshake
import token.RetrievalToken
import privacy.Privacy

/** Tests for the `pcore`/`pstatus` CLI cores (Constitution V). Exercises the pure `run` functions
  * directly (the `main` shells only add stdin/stdout/exit), covering each subcommand's happy path —
  * cross-checked against the library it wraps — plus the error envelope (unknown subcommand,
  * malformed JSON, missing field, library-rejected input) returning `Left` instead of throwing. */
class CliSpec extends AnyFunSuite:
  private def b64e(b: Array[Byte]): String = Base64.getEncoder.encodeToString(b)
  private def b64d(s: String): Array[Byte] = Base64.getDecoder.decode(s)

  // ---- Pcore ----

  test("pcore handshake-init mirrors Handshake.init (default pqRequired=false, classical)"):
    val secret = "out-of-band-secret".getBytes(UTF_8)
    val out = Pcore.run("handshake-init", s"""{"sharedSecret":"${b64e(secret)}"}""").toOption.get
    val want = Handshake.init(secret)
    assert(out("pairId").str == want.pairId)
    assert(out("safetyNumber").str == want.safetyNumber)
    assert(b64d(out("pairKey").str).sameElements(want.pairKey))
    // Explicit pqRequired=false must be byte-identical to the default (backward compatible).
    val outFalse = Pcore
      .run("handshake-init", s"""{"sharedSecret":"${b64e(secret)}","pqRequired":false}""")
      .toOption
      .get
    assert(outFalse("pairId").str == want.pairId)
    assert(outFalse("safetyNumber").str == want.safetyNumber)

  test("pcore handshake-init threads pqRequired=true (PQ-intent binding, US7)"):
    val secret = "out-of-band-secret".getBytes(UTF_8)
    val out = Pcore
      .run("handshake-init", s"""{"sharedSecret":"${b64e(secret)}","pqRequired":true}""")
      .toOption
      .get
    val want = Handshake.init(secret, pqRequired = true)
    assert(out("pairId").str == want.pairId)
    assert(out("safetyNumber").str == want.safetyNumber)
    assert(b64d(out("pairKey").str).sameElements(want.pairKey))
    // The PQ-required derivation DIFFERS from the classical one (the bit is bound into the safety number).
    assert(out("pairId").str != Handshake.init(secret).pairId)
    assert(out("safetyNumber").str != Handshake.init(secret).safetyNumber)

  test("pcore handshake-init FAILS LOUD on a typo'd pqRequired key (no silent classical fallback)"):
    // `pqRequired` is a security intent flag: a misspelling must be rejected, never silently ignored
    // (which would emit the classical, non-PQ derivation). Unknown keys ⇒ Left, not a silent fallback.
    val secret = b64e("out-of-band-secret".getBytes(UTF_8))
    val misspelled =
      Pcore.run("handshake-init", s"""{"sharedSecret":"$secret","pq_required":true}""")
    assert(
      misspelled.isLeft,
      "a misspelled pqRequired key must be rejected, not silently classical"
    )
    // Sanity: the same object with the CORRECT key is accepted and yields the PQ-required derivation.
    val ok = Pcore
      .run("handshake-init", s"""{"sharedSecret":"$secret","pqRequired":true}""")
      .toOption
      .get
    assert(ok("pairId").str == Handshake.init("out-of-band-secret".getBytes(UTF_8), true).pairId)

  test("pcore retrieval-token mirrors RetrievalToken.derive"):
    val key = Array.tabulate(32)(_.toByte)
    val in = s"""{"key":"${b64e(key)}","senderId":"alice","receiverId":"bob","counter":7}"""
    val tok = Pcore.run("retrieval-token", in).toOption.get("token").str
    assert(b64d(tok).sameElements(RetrievalToken.derive(key, "alice", "bob", 7L)))

  test("pcore retrieval-token: counter as a JSON string parses exactly (precision-safe path)"):
    val key = Array.tabulate(32)(_.toByte)
    def tokFor(c: String): String =
      Pcore
        .run(
          "retrieval-token",
          s"""{"key":"${b64e(key)}","senderId":"a","receiverId":"b","counter":$c}"""
        )
        .toOption
        .get("token")
        .str
    // string "5" and number 5 agree
    assert(tokFor("\"5\"") == tokFor("5"))
    // a counter beyond 2^53 is accepted exactly via the string path (a JSON number would round)
    val big = 9007199254740993L // 2^53 + 1
    val viaCli = b64d(tokFor(s""""$big""""))
    assert(viaCli.sameElements(RetrievalToken.derive(key, "a", "b", big)))

  test("pcore frame/deframe round-trips"):
    val payload = "hi".getBytes(UTF_8)
    val frameB64 =
      Pcore.run("frame", s"""{"payload":"${b64e(payload)}"}""").toOption.get("frame").str
    assert(b64d(frameB64).length == Frame.Size)
    val back = Pcore.run("deframe", s"""{"frame":"$frameB64"}""").toOption.get("payload").str
    assert(b64d(back).sameElements(payload))

  test("pcore frame rejects an oversized payload (Left, not a process exit)"):
    val tooBig = b64e(new Array[Byte](Frame.MaxPayload + 1))
    assert(Pcore.run("frame", s"""{"payload":"$tooBig"}""").isLeft)

  test("pcore deframe rejects a wrong-size frame"):
    val notAFrame = b64e(new Array[Byte](10))
    assert(Pcore.run("deframe", s"""{"frame":"$notAFrame"}""").isLeft)

  test("pcore schedule-next produces a fixed-size cover frame and a retrieve flag"):
    val out = Pcore.run("schedule-next", """{"roundId":3}""").toOption.get
    // ujson renders a bare Long as a JSON string (same as the engine's roundId echo).
    assert(out("roundId").str == "3")
    assert(b64d(out("frame").str).length == Frame.Size)
    assert(out.obj.contains("kind") && out.obj.contains("retrieve"))

  test("pcore unknown subcommand -> Left"):
    assert(Pcore.run("frobnicate", "{}") == Left("unknown subcommand: frobnicate"))

  test("pcore malformed JSON -> Left (no throw across the boundary)"):
    assert(Pcore.run("frame", "not json{").isLeft)

  test("pcore missing required field -> Left (no throw)"):
    assert(Pcore.run("retrieval-token", """{"senderId":"a"}""").isLeft)

  // ---- Pstatus ----

  test("pstatus defaults to the dev backend with the dev label (no privacy)"):
    val out = Pstatus.run(Map.empty)
    assert(out("backend").str == "Dev")
    assert(!out("metadataPrivate").bool)
    assert(out("label").str == Privacy.DevLabel)

  test("pstatus enclave-target WITH attestation is metadata-private"):
    val out = Pstatus.run(Map("STORE_BACKEND" -> "enclave-target", "ATTESTATION_PASSED" -> "true"))
    assert(out("backend").str == "EnclaveTarget")
    assert(out("metadataPrivate").bool)
    assert(out("label").str == Privacy.PrivateLabel)

  test("pstatus enclave-target WITHOUT attestation keeps the dev label (labeling rule)"):
    val out = Pstatus.run(Map("STORE_BACKEND" -> "enclave-target"))
    assert(!out("metadataPrivate").bool)
    assert(out("label").str == Privacy.DevLabel)

  test("pstatus unknown backend falls back to dev (no privacy)"):
    val out = Pstatus.run(Map("STORE_BACKEND" -> "bogus"))
    assert(out("backend").str == "Dev")
    assert(!out("metadataPrivate").bool)
