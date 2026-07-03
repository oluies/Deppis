package crypto

import org.scalatest.funsuite.AnyFunSuite

/** ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) via liboqs, exercised through the [[Oqs]] FFM binding.
  * These are functional/consistency known-answer tests: encapsulate-then-decapsulate must agree, a
  * signature must verify, and every tamper must be rejected. FIPS *conformance* of the primitives is
  * provided by liboqs upstream (it passes the NIST ACVP KATs); these prove our binding drives it
  * correctly with the right buffer sizes and status handling. */
class OqsSpec extends AnyFunSuite:

  test("ML-KEM-768: encaps/decaps agree on the shared secret; sizes match FIPS 203"):
    val kp = Oqs.kemKeypair()
    assert(kp.publicKey.length == Oqs.MlKem768.PublicKeyBytes)
    assert(kp.secretKey.length == Oqs.MlKem768.SecretKeyBytes)
    val enc = Oqs.kemEncaps(kp.publicKey)
    assert(enc.ciphertext.length == Oqs.MlKem768.CiphertextBytes)
    assert(enc.sharedSecret.length == Oqs.MlKem768.SharedSecretBytes)
    val ss = Oqs.kemDecaps(enc.ciphertext, kp.secretKey)
    assert(ss.sameElements(enc.sharedSecret), "decapsulated shared secret must match encapsulated")

  test("ML-KEM-768: a tampered ciphertext yields a DIFFERENT shared secret (implicit rejection)"):
    // ML-KEM is IND-CCA2 with implicit rejection: decaps of a modified ciphertext returns a
    // pseudo-random secret, NOT the original — so the two sides fail to agree (no oracle, no throw).
    val kp = Oqs.kemKeypair()
    val enc = Oqs.kemEncaps(kp.publicKey)
    val bad = enc.ciphertext.clone(); bad(0) = (bad(0) ^ 0x01).toByte
    assert(!Oqs.kemDecaps(bad, kp.secretKey).sameElements(enc.sharedSecret))

  test("ML-KEM-768: two keypairs give independent shared secrets (no cross-decapsulation)"):
    val a = Oqs.kemKeypair(); val b = Oqs.kemKeypair()
    val enc = Oqs.kemEncaps(a.publicKey)
    assert(!Oqs.kemDecaps(enc.ciphertext, b.secretKey).sameElements(enc.sharedSecret))

  test("ML-DSA-65: a real signature verifies; sizes match FIPS 204"):
    val kp = Oqs.sigKeypair()
    assert(kp.publicKey.length == Oqs.MlDsa65.PublicKeyBytes)
    assert(kp.secretKey.length == Oqs.MlDsa65.SecretKeyBytes)
    val msg = "attest this enclave measurement".getBytes("UTF-8")
    val sig = Oqs.sign(msg, kp.secretKey)
    assert(sig.length <= Oqs.MlDsa65.SignatureMaxBytes && sig.nonEmpty)
    assert(Oqs.verify(msg, sig, kp.publicKey), "a valid signature must verify")

  test("ML-DSA-65: verification rejects a tampered message, a tampered signature, and a wrong key"):
    val kp = Oqs.sigKeypair()
    val other = Oqs.sigKeypair()
    val msg = "bind the PQ handshake transcript".getBytes("UTF-8")
    val sig = Oqs.sign(msg, kp.secretKey)
    assert(!Oqs.verify("bind the PQ handshake transcripX".getBytes("UTF-8"), sig, kp.publicKey))
    val badSig = sig.clone(); badSig(0) = (badSig(0) ^ 0x01).toByte
    assert(!Oqs.verify(msg, badSig, kp.publicKey))
    assert(!Oqs.verify(msg, sig, other.publicKey))
    assert(!Oqs.verify(msg, sig, Array[Byte](1, 2, 3)), "malformed key ⇒ false, not an exception")
