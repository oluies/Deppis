package x25519

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform ACCEPTANCE-set parity for [[X25519]] — the other half of the
  * property `X25519RejectionCrossSpec` pins. Compiled into BOTH the JVM `protocolCore` build (JCA) and
  * the Scala.js `protocolCoreJS` build (`@noble/curves`) via each project's `crosstest/src/test` dir
  * (see build.sbt), so "which peer encodings are ACCEPTED, and to what secret" is asserted once and
  * holds identically on both platforms.
  *
  * The RFC 7748 §6.1 KAT with a CANONICAL peer key lives in the platform mirrors
  * (`x25519.X25519Spec` / `X25519JsSpec`); this file owns the non-obvious acceptance case: a peer key
  * with the unused top bit (bit 255) SET is still accepted and masked to the same shared secret — NOT
  * rejected — on both backends, so the accepted set is genuinely identical (not just the rejected
  * set). */
class X25519AcceptCrossSpec extends AnyFunSuite:

  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  private def hx(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  // RFC 7748 §6.1.
  private val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  private val bobPub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  private val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

  test("a peer key with bit 255 SET is ACCEPTED and masked to the same secret on both platforms"):
    // RFC 7748 decode ignores the unused top bit of the u-coordinate. A peer that sets it must NOT be
    // rejected (it is a valid re-encoding of the same u) and must agree to the SAME shared secret — so
    // the ACCEPTED set is identical across JVM (JCA) and JS (@noble), just like the rejected set. If
    // one backend masked and the other rejected, that divergence would be a cross-platform oracle the
    // RFC-7748 KAT (canonical encoding only) does not catch.
    val bobPubTopBitSet = bobPub.clone()
    bobPubTopBitSet(31) = (bobPubTopBitSet(31) | 0x80.toByte).toByte // set bit 255
    assert(
      !bobPubTopBitSet.sameElements(bobPub),
      "byte 31 top bit must actually differ from the KAT"
    )
    assert(hx(X25519.sharedSecret(alicePriv, bobPubTopBitSet)) == hx(shared))
