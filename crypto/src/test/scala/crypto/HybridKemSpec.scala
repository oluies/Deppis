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

  test("combiner KAT: fixed inputs pin the exact 32-byte SHA-256 output"):
    // Pins Label, field order (label ++ ssX ++ ssMl ++ eph ++ peer ++ ct), and the digest alg.
    // A silent change to any of these would break interop with the future JS @noble/post-quantum
    // side while still passing every self-consistency/tamper test above. Regenerate ONLY if the
    // wire construction is INTENTIONALLY changed (and bump the Label/version if so).
    def fill(n: Int, v: Int): Array[Byte] = Array.fill(n)(v.toByte)
    val out = HybridKem.combine(
      ssX25519 = fill(32, 0x11),
      ssMlKem = fill(32, 0x22),
      ephemeralX25519Raw = fill(32, 0x33),
      peerX25519Raw = fill(32, 0x44),
      mlkemCiphertext = fill(1088, 0x55)
    )
    val expectedHex = "fd00ed12313e19b3c4241905c9904c4e7678df58de7f39d2a77e4a6a1f0769d8"
    val gotHex = out.map(b => "%02x".format(b)).mkString
    assert(gotHex == expectedHex, s"combiner output drifted: $gotHex")

  test("hybridDecaps rejects a wrong-length ciphertext"):
    val kp = HybridKem.hybridKeypair()
    assertThrows[IllegalArgumentException](HybridKem.hybridDecaps(Array.emptyByteArray, kp.secret))
    assertThrows[IllegalArgumentException](
      HybridKem.hybridDecaps(new Array[Byte](HybridKem.CiphertextBytes - 1), kp.secret)
    )

  test("hybridEncaps rejects a wrong-length peer public key"):
    assertThrows[IllegalArgumentException](HybridKem.hybridEncaps(Array.emptyByteArray))
    assertThrows[IllegalArgumentException](
      HybridKem.hybridEncaps(new Array[Byte](HybridKem.PublicKeyBytes + 1))
    )

  // ---- Classical-leg peer-key validation (Finding 2 + roborev LOW 1/2) -----------------------

  /** Splice a raw X25519 u-coordinate (LE hex) into the X25519 slot of an otherwise valid hybrid
    * public key, so hybridEncaps runs its classical-leg validation against a chosen point. */
  private def peerKeyWithX25519(leHex: String): Array[Byte] =
    val kp = HybridKem.hybridKeypair()
    val bad = kp.publicKey.clone()
    var i = 0
    while i < HybridKem.X25519PublicKeyBytes do
      bad(i) = Integer.parseInt(leHex.substring(i * 2, i * 2 + 2), 16).toByte
      i += 1
    bad

  test("hybridEncaps rejects a low-order X25519 peer point (blocklist, layer 1)"):
    // all-zero (order-1) u-coordinate — rejected by the masked blocklist before agreement runs.
    assertThrows[IllegalArgumentException](
      HybridKem.hybridEncaps(
        peerKeyWithX25519("0000000000000000000000000000000000000000000000000000000000000000")
      )
    )

  test("hybridEncaps rejects a low-order point whose top bit (255) is SET (roborev LOW 1)"):
    // The order-8 point 5f9c..1157 with bit 255 set is 5f9c..11d7. X25519 masks bit 255 on decode,
    // so it is the SAME low-order point; the masked blocklist must catch it (before this fix it
    // slipped past the raw-byte blocklist and only the deeper layers stopped it).
    assertThrows[IllegalArgumentException](
      HybridKem.hybridEncaps(
        peerKeyWithX25519("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7")
      )
    )
    // and the canonical (top-bit-clear) encoding is likewise rejected.
    assertThrows[IllegalArgumentException](
      HybridKem.hybridEncaps(
        peerKeyWithX25519("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
      )
    )

  test("hybridEncaps uniformly rejects the order-8 low-order point (SunEC guard, layer 2/3)"):
    // The other order-8 base point e0eb..b800 and its top-bit-set twin e0eb..b880 both denote the
    // same non-contributory point. All three validation layers (blocklist, SunEC's own "small
    // order" rejection re-wrapped, all-zero backstop) surface a uniform IllegalArgumentException —
    // never a raw java.security.InvalidKeyException leaking to the caller.
    for hex <- Seq(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"
      )
    do assertThrows[IllegalArgumentException](HybridKem.hybridEncaps(peerKeyWithX25519(hex)))
