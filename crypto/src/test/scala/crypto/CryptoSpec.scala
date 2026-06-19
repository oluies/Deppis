package crypto

import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class CryptoSpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private val keys: Gen[Array[Byte]]   = Gen.listOfN(Crypto.KeyBytes, arbitrary[Byte]).map(_.toArray)
  private val nonces: Gen[Array[Byte]] = Gen.listOfN(Crypto.NonceBytes, arbitrary[Byte]).map(_.toArray)
  private val bytes: Gen[Array[Byte]]  = Gen.listOf(arbitrary[Byte]).map(_.toArray)

  /** JDK's own (independent, vetted) ChaCha20-Poly1305 — IETF 12-byte nonce, tag appended. */
  private def jdkSeal(key: Array[Byte], nonce: Array[Byte], ad: Array[Byte], pt: Array[Byte]): Array[Byte] =
    val c = Cipher.getInstance("ChaCha20-Poly1305")
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce))
    if ad.nonEmpty then c.updateAAD(ad)
    c.doFinal(pt)

  test("AEAD round-trips: open(seal(m)) == m"):
    forAll(keys, nonces, bytes, bytes) { (k, n, ad, m) =>
      val ct = Crypto.aeadSeal(k, n, ad, m)
      assert(Crypto.aeadOpen(k, n, ad, ct).exists(_.sameElements(m)))
    }

  test("KAT: libsodium output is byte-identical to the JDK ChaCha20-Poly1305 (two vetted impls)"):
    forAll(keys, nonces, bytes, bytes) { (k, n, ad, m) =>
      assert(Crypto.aeadSeal(k, n, ad, m).sameElements(jdkSeal(k, n, ad, m)))
    }

  test("AEAD rejects tampered ciphertext (authentication)"):
    forAll(keys, nonces, bytes, bytes) { (k, n, ad, m) =>
      val ct = Crypto.aeadSeal(k, n, ad, m)
      ct(0) = (ct(0) ^ 0x01).toByte
      assert(Crypto.aeadOpen(k, n, ad, ct).isLeft)
    }

  test("AEAD rejects wrong associated data"):
    val k = Array.fill(Crypto.KeyBytes)(1.toByte)
    val n = Array.fill(Crypto.NonceBytes)(2.toByte)
    val ct = Crypto.aeadSeal(k, n, "aad-1".getBytes, "secret".getBytes)
    assert(Crypto.aeadOpen(k, n, "aad-2".getBytes, ct).isLeft)

  test("Blake2b is deterministic, 32 bytes, and distinguishes distinct inputs"):
    forAll(bytes, bytes) { (a, b) =>
      val ha = Crypto.blake2b(a)
      assert(ha.length == 32)
      assert(ha.sameElements(Crypto.blake2b(a)))
      whenever(!a.sameElements(b)) {
        assert(!ha.sameElements(Crypto.blake2b(b)))
      }
    }

  test("keyed-Blake2b KDF is deterministic and key-dependent"):
    val okm1 = Crypto.kdf("ikm".getBytes, "salt".getBytes, "info".getBytes, 32)
    val okm2 = Crypto.kdf("ikm".getBytes, "salt".getBytes, "info".getBytes, 32)
    val okm3 = Crypto.kdf("other".getBytes, "salt".getBytes, "info".getBytes, 32)
    assert(okm1.length == 32 && okm1.sameElements(okm2) && !okm1.sameElements(okm3))
