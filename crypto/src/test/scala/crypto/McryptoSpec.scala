package crypto

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64
import org.scalatest.funsuite.AnyFunSuite

/** Tests for the `mcrypto` CLI core (Constitution V). Exercises the pure `run` function directly
  * (the `main` shell only adds stdin/stdout/exit): an AEAD seal→open round trip, the auth-failure
  * path mapping to `Left` (not a throw), the KDF length/value matching `Crypto.kdf`, the static-KAT
  * report, and the unknown-subcommand / malformed-JSON error envelope. */
class McryptoSpec extends AnyFunSuite:
  private def b64e(b: Array[Byte]): String = Base64.getEncoder.encodeToString(b)
  private def b64d(s: String): Array[Byte] = Base64.getDecoder.decode(s)

  private val key = Array.tabulate(32)(_.toByte)
  private val nonce = Array.tabulate(12)(_.toByte)

  test("aead-seal then aead-open round-trips through the CLI core"):
    val pt = "secret message".getBytes(UTF_8)
    val res = Mcrypto.run(
      "aead-seal",
      s"""{"key":"${b64e(key)}","nonce":"${b64e(nonce)}","plaintext":"${b64e(pt)}"}"""
    )
    val ct = res.toOption.get("ciphertext").str
    val opened = Mcrypto.run(
      "aead-open",
      s"""{"key":"${b64e(key)}","nonce":"${b64e(nonce)}","ciphertext":"$ct"}"""
    )
    assert(b64d(opened.toOption.get("plaintext").str).sameElements(pt))

  test("aead-open of a tampered ciphertext -> Left (auth failure surfaced, no throw)"):
    val pt = "x".getBytes(UTF_8)
    val ct = b64d(
      Mcrypto
        .run(
          "aead-seal",
          s"""{"key":"${b64e(key)}","nonce":"${b64e(nonce)}","plaintext":"${b64e(pt)}"}"""
        )
        .toOption
        .get("ciphertext")
        .str
    )
    ct(ct.length - 1) = (ct(ct.length - 1) ^ 0x01).toByte
    assert(
      Mcrypto
        .run(
          "aead-open",
          s"""{"key":"${b64e(key)}","nonce":"${b64e(nonce)}","ciphertext":"${b64e(ct)}"}"""
        )
        .isLeft
    )

  test("kdf mirrors Crypto.kdf and honors the requested length"):
    val ikm = Array.tabulate(32)(i => (i + 1).toByte)
    val okm =
      b64d(Mcrypto.run("kdf", s"""{"ikm":"${b64e(ikm)}","len":48}""").toOption.get("okm").str)
    assert(okm.length == 48)
    assert(okm.sameElements(Crypto.kdf(ikm, Array.emptyByteArray, Array.emptyByteArray, 48)))

  test("kat reports both published vectors passing"):
    val out = Mcrypto.run("kat", "{}").toOption.get
    assert(out("pass").bool)
    assert(out("vectors").num.toInt == 2)

  test("unknown subcommand -> Left"):
    assert(Mcrypto.run("nope", "{}") == Left("unknown subcommand: nope"))

  test("malformed JSON -> Left (no throw)"):
    assert(Mcrypto.run("aead-seal", "not json{").isLeft)
