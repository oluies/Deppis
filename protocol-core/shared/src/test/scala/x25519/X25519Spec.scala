package x25519

import org.scalatest.funsuite.AnyFunSuite

/** X25519 ECDH known-answer test (RFC 7748 §6.1). The SAME vectors run on the JVM (JCA) here and under
  * Node (`@noble/curves`) via the JS mirror, proving the cross-platform seam is byte-for-byte — the
  * contract the double ratchet (post-compromise security) depends on. */
class X25519Spec extends AnyFunSuite:

  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  private def hx(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  // RFC 7748 §6.1.
  private val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  private val alicePub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
  private val bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
  private val bobPub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  private val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

  test("publicKey matches the RFC 7748 §6.1 vectors (deterministic base-point scalar mult)"):
    assert(hx(X25519.publicKey(alicePriv)) == hx(alicePub))
    assert(hx(X25519.publicKey(bobPriv)) == hx(bobPub))

  test("sharedSecret matches the RFC 7748 §6.1 vector and is symmetric"):
    assert(hx(X25519.sharedSecret(alicePriv, bobPub)) == hx(shared))
    assert(hx(X25519.sharedSecret(bobPriv, alicePub)) == hx(shared))

  test("a freshly generated pair agrees in both directions"):
    val (aPriv, aPub) = X25519.generateKeyPair()
    val (bPriv, bPub) = X25519.generateKeyPair()
    assert(aPub.length == X25519.KeyBytes && aPriv.length == X25519.KeyBytes)
    assert(X25519.sharedSecret(aPriv, bPub).sameElements(X25519.sharedSecret(bPriv, aPub)))
    // distinct pairs ⇒ distinct public keys (sanity)
    assert(!aPub.sameElements(bPub))

  test("every small-order / non-canonical peer key is rejected with IllegalArgumentException"):
    // Peer public keys arrive in headers and are attacker-controllable. The classic Curve25519
    // small-order points (orders 1/2/4/8 — the libsodium blacklist) all yield the all-zero secret
    // under the clamped scalar; the list also contains non-canonical `u >= p` encodings (p, p+1).
    // JCA and @noble/curves must AGREE to reject EACH with the SAME exception TYPE
    // (IllegalArgumentException) so the Stage-2 ratchet can treat a bad DH as a carrier frame
    // uniformly. A divergence here (one throws a different type, or accepts) would be a cross-platform
    // oracle the RFC-7748 KAT does not catch.
    val priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    X25519Spec.smallOrderPoints.foreach: u =>
      assertThrows[IllegalArgumentException](X25519.sharedSecret(priv, hex(u)))

  test("a low-order (all-zero) AND a non-canonical (u = p) peer key both reject identically"):
    // The two distinct rejection paths, pinned explicitly and to the SAME exception type on JVM & JS:
    //   - all-zero u (order-2, canonical): passes the u<p range check, rejected by the all-zero ECDH;
    //   - u = p (edff…7f): rejected up front by the canonical `u < p` range check.
    val priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val lowOrderZero = hex("0000000000000000000000000000000000000000000000000000000000000000")
    val nonCanonicalP = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    assertThrows[IllegalArgumentException](X25519.sharedSecret(priv, lowOrderZero))
    assertThrows[IllegalArgumentException](X25519.sharedSecret(priv, nonCanonicalP))

object X25519Spec:
  /** Canonical Curve25519 small-order u-coordinates (little-endian), the libsodium blacklist: 0, 1,
    * the two order-8 points, and p-1 / p / p+1. Each yields the all-zero shared secret. */
  val smallOrderPoints: Seq[String] = Seq(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  )
