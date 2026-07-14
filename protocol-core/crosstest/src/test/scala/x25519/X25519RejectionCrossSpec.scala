package x25519

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform peer-key REJECTION parity for [[X25519]]. Compiled into BOTH the JVM
  * `protocolCore` build (JCA) and the Scala.js `protocolCoreJS` build (`@noble/curves`) via each
  * project's `crosstest/src/test` source dir (see build.sbt), so the "which peer keys are rejected,
  * and with what exception type" contract is asserted ONCE and holds identically on both platforms —
  * no lockstep-drift hazard between a JVM spec and a hand-copied JS mirror.
  *
  * The RFC 7748 KAT / round-trip parity (valid inputs) stays in the platform mirrors
  * (`x25519.X25519Spec` / `X25519JsSpec`); this file owns only the rejection (invalid-peer) contract:
  * every rejected key throws the dedicated `PeerKeyRejected` subtype of `IllegalArgumentException`. */
class X25519RejectionCrossSpec extends AnyFunSuite:

  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private val priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")

  /** Canonical Curve25519 small-order u-coordinates (little-endian), the libsodium blacklist: 0, 1,
    * the two order-8 points, and p-1 / p / p+1. Each is rejected — the canonical ones by the all-zero
    * ECDH, the `>= p` ones (p, p+1) by the canonicality range check. */
  private val smallOrderPoints: Seq[String] = Seq(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  )

  test(
    "every small-order / non-canonical peer key is rejected with PeerKeyRejected on both platforms"
  ):
    // Peer public keys arrive in headers and are attacker-controllable. JCA and @noble/curves must
    // AGREE to reject EACH with the SAME dedicated exception type so the Stage-2 ratchet can treat a
    // bad DH as a carrier frame uniformly. A divergence (one throws a different type, or accepts)
    // would be a cross-platform oracle the RFC-7748 KAT does not catch.
    smallOrderPoints.foreach: u =>
      assertThrows[PeerKeyRejected](X25519.sharedSecret(priv, hex(u)))

  test("a low-order (all-zero) AND a non-canonical (u = p) peer key both reject identically"):
    // The two distinct rejection paths, pinned explicitly and to the SAME exception type on JVM & JS:
    //   - all-zero u (order-2, canonical): passes the u<p range check, rejected by the all-zero ECDH;
    //   - u = p (edff…7f): rejected up front by the canonical `u < p` range check.
    val lowOrderZero = hex("0000000000000000000000000000000000000000000000000000000000000000")
    val nonCanonicalP = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    assertThrows[PeerKeyRejected](X25519.sharedSecret(priv, lowOrderZero))
    assertThrows[PeerKeyRejected](X25519.sharedSecret(priv, nonCanonicalP))

  test("a wrong-length peer key is rejected as PeerKeyRejected, a wrong-length private key is not"):
    // A wrong-length PEER key is a peer rejection (PeerKeyRejected); a wrong-length PRIVATE key is a
    // LOCAL key-management error — a plain IllegalArgumentException that is NOT a PeerKeyRejected, so
    // the DoubleRatchet (which catches only PeerKeyRejected) never masks a local bug as a carrier.
    assertThrows[PeerKeyRejected](X25519.sharedSecret(priv, new Array[Byte](31)))
    val badPriv =
      intercept[IllegalArgumentException](X25519.sharedSecret(new Array[Byte](31), priv))
    assert(
      !badPriv.isInstanceOf[PeerKeyRejected],
      "a local private-key error is not a peer rejection"
    )
