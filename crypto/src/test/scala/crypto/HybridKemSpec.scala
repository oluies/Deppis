package crypto

import org.scalatest.funsuite.AnyFunSuite

/** Hybrid X25519 + ML-KEM-768 KEM ([[HybridKem]]). These are functional/consistency tests for the
  * generic combiner: encaps-then-decaps must agree, sizes must match, independent keypairs give
  * independent secrets, and — crucially for a HYBRID — tampering with EITHER leg's wire bytes must
  * change the derived secret (proving both legs bind). The underlying primitives' conformance is
  * upstream (JCA X25519/SHA-256, liboqs ML-KEM-768 ACVP KATs). */
class HybridKemSpec extends AnyFunSuite:

  test("encaps/decaps agree on the shared secret; sizes match"):
    val kp = HybridKem.hybridKeypair()
    assert(kp.publicKey.length == HybridKem.PublicKeyBytes)
    val (ct, ssEnc) = HybridKem.hybridEncaps(kp.publicKey)
    assert(ct.length == HybridKem.CiphertextBytes)
    assert(ssEnc.length == HybridKem.SharedSecretBytes)
    val ssDec = HybridKem.hybridDecaps(ct, kp.secret)
    assert(ssDec.length == HybridKem.SharedSecretBytes)
    assert(HybridKem.constantTimeEquals(ssEnc, ssDec), "both sides must derive the same secret")

  test("a tampered ML-KEM ciphertext yields a DIFFERENT shared secret"):
    val kp = HybridKem.hybridKeypair()
    val (ct, ssEnc) = HybridKem.hybridEncaps(kp.publicKey)
    // Flip a byte inside the ML-KEM ciphertext portion (after the 32-byte ephemeral X25519 pub).
    val bad = ct.clone()
    val idx = HybridKem.X25519PublicKeyBytes + 10
    bad(idx) = (bad(idx) ^ 0x01).toByte
    val ssDec = HybridKem.hybridDecaps(bad, kp.secret)
    assert(!HybridKem.constantTimeEquals(ssEnc, ssDec))

  test("a tampered X25519 ephemeral key yields a DIFFERENT shared secret"):
    val kp = HybridKem.hybridKeypair()
    val (ct, ssEnc) = HybridKem.hybridEncaps(kp.publicKey)
    // Flip a byte inside the ephemeral X25519 public key (first 32 bytes).
    val bad = ct.clone()
    bad(0) = (bad(0) ^ 0x01).toByte
    val ssDec = HybridKem.hybridDecaps(bad, kp.secret)
    assert(!HybridKem.constantTimeEquals(ssEnc, ssDec))

  test("two independent keypairs give independent shared secrets"):
    val a = HybridKem.hybridKeypair()
    val b = HybridKem.hybridKeypair()
    val (ct, ssA) = HybridKem.hybridEncaps(a.publicKey)
    // Decapsulating A's ciphertext with B's secret must NOT recover A's secret.
    val ssB = HybridKem.hybridDecaps(ct, b.secret)
    assert(!HybridKem.constantTimeEquals(ssA, ssB))
    // And two fresh encapsulations to the same peer differ (fresh ephemeral + fresh ML-KEM).
    val (_, ssA2) = HybridKem.hybridEncaps(a.publicKey)
    assert(!HybridKem.constantTimeEquals(ssA, ssA2))

  test("swapping ONLY the ML-KEM leg breaks agreement (the PQ leg binds)"):
    // Build a ciphertext with A's ephemeral X25519 but B's ML-KEM ciphertext: decaps with A's
    // secret gets the right classical leg but a wrong PQ leg ⇒ must not agree with either secret.
    val a = HybridKem.hybridKeypair()
    val b = HybridKem.hybridKeypair()
    val (ctA, ssA) = HybridKem.hybridEncaps(a.publicKey)
    val (ctB, _) = HybridKem.hybridEncaps(b.publicKey)
    val ephA = java.util.Arrays.copyOfRange(ctA, 0, HybridKem.X25519PublicKeyBytes)
    val mlkemB = java.util.Arrays.copyOfRange(ctB, HybridKem.X25519PublicKeyBytes, ctB.length)
    val mixed = ephA ++ mlkemB
    val ssMixed = HybridKem.hybridDecaps(mixed, a.secret)
    assert(
      !HybridKem.constantTimeEquals(ssA, ssMixed),
      "wrong PQ leg must change the hybrid secret"
    )

  test("swapping ONLY the X25519 ephemeral leg breaks agreement (the classical leg binds)"):
    val a = HybridKem.hybridKeypair()
    val (ctA, ssA) = HybridKem.hybridEncaps(a.publicKey)
    val (ctB, _) = HybridKem.hybridEncaps(a.publicKey) // same peer, fresh ephemeral
    val ephB = java.util.Arrays.copyOfRange(ctB, 0, HybridKem.X25519PublicKeyBytes)
    val mlkemA = java.util.Arrays.copyOfRange(ctA, HybridKem.X25519PublicKeyBytes, ctA.length)
    val mixed = ephB ++ mlkemA
    val ssMixed = HybridKem.hybridDecaps(mixed, a.secret)
    assert(
      !HybridKem.constantTimeEquals(ssA, ssMixed),
      "wrong classical leg must change the hybrid secret"
    )

  test("destroy() best-effort zeroes retained secret material"):
    val kp = HybridKem.hybridKeypair()
    kp.secret.destroy()
    assert(kp.secret.x25519Private.forall(_ == 0.toByte))
    assert(kp.secret.mlkemSecret.forall(_ == 0.toByte))
