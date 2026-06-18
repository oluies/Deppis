package crypto

import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

/** Known-answer tests for both crypto paths against published vectors and independent vetted
  * impls: Blake2b vs Bouncy Castle (256/512/keyed) + RFC 7693 `BLAKE2b-512("abc")`; AEAD vs the
  * RFC 8439 §2.8.2 vector, cross-validated against the JDK so a wrong literal can't slip through.
  * Vectors are shared via [[Kat]] so the CLI and tests cannot drift. */
class CryptoKatSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

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
    assert(Crypto.blake2b("abc".getBytes, 64).sameElements(Kat.Blake2b512Abc))

  test("RFC 8439 published vector: ChaCha20-Poly1305 (libsodium == vector == JDK)"):
    import Kat.Rfc8439.*
    val lib = Crypto.aeadSeal(key, nonce, aad, plaintext)
    val jdk =
      val c = Cipher.getInstance("ChaCha20-Poly1305")
      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce))
      c.updateAAD(aad)
      c.doFinal(plaintext)
    assert(lib.sameElements(ciphertext)) // libsodium matches the published vector
    assert(jdk.sameElements(ciphertext)) // and so does the JDK, validating the literal

  test("KDF rejects over-long output and ikm with a clear error"):
    assertThrows[IllegalArgumentException](Crypto.kdf("ikm".getBytes, Array(), Array(), 65))
    assertThrows[IllegalArgumentException](Crypto.kdf(new Array[Byte](65), Array(), Array(), 32))
