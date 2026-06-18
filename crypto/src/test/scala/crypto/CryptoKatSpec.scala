package crypto

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

/** Known-answer tests for the Blake2b path: libsodium is cross-checked byte-for-byte against
  * Bouncy Castle's independent vetted Blake2b (so a wrong-but-self-consistent output is caught),
  * plus the RFC 7693 published `BLAKE2b-512("abc")` static vector. AEAD KATs live in
  * `CryptoSpec` (cross-checked against the JDK). */
class CryptoKatSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private def bcBlake2b(in: Array[Byte], digestBytes: Int, key: Array[Byte]): Array[Byte] =
    val d =
      if key.isEmpty then new Blake2bDigest(digestBytes * 8)
      else new Blake2bDigest(key, digestBytes, null, null)
    d.update(in, 0, in.length)
    val out = new Array[Byte](d.getDigestSize)
    d.doFinal(out, 0)
    out

  private val bytes: Gen[Array[Byte]] = Gen.listOf(arbitrary[Byte]).map(_.toArray)

  test("Blake2b-256 matches Bouncy Castle (independent vetted impl)"):
    forAll(bytes) { in =>
      assert(Crypto.blake2b(in, 32).sameElements(bcBlake2b(in, 32, Array.emptyByteArray)))
    }

  test("Blake2b-512 matches Bouncy Castle (independent vetted impl)"):
    forAll(bytes) { in =>
      assert(Crypto.blake2b(in, 64).sameElements(bcBlake2b(in, 64, Array.emptyByteArray)))
    }

  test("keyed Blake2b (KDF core) matches Bouncy Castle keyed Blake2b"):
    val keys: Gen[Array[Byte]] = Gen.choose(1, 64).flatMap(Gen.listOfN(_, arbitrary[Byte]).map(_.toArray))
    forAll(keys, bytes) { (k, in) =>
      assert(Crypto.blake2b(in, 64, k).sameElements(bcBlake2b(in, 64, k)))
    }

  test("RFC 7693 published vector: BLAKE2b-512(\"abc\")"):
    val expected = hex(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    )
    assert(Crypto.blake2b("abc".getBytes, 64).sameElements(expected))

  test("KDF rejects over-long output and ikm with a clear error"):
    assertThrows[IllegalArgumentException](Crypto.kdf("ikm".getBytes, Array(), Array(), 65))
    assertThrows[IllegalArgumentException](Crypto.kdf(new Array[Byte](65), Array(), Array(), 32))
