package x25519

import engine.Uint8
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** X25519 ECDH (Scala.js) via **@noble/curves** — audited, synchronous, browser-safe (Constitution I).
  * RFC 7748: raw 32-byte little-endian keys, byte-for-byte identical to the JVM JCA build, which a
  * cross-platform KAT pins (`x25519.X25519Spec` on the JVM, `X25519JsSpec` here). */
@js.native
@JSImport("@noble/curves/ed25519", "x25519")
private object nobleX25519 extends js.Object:
  def getPublicKey(privateKey: Uint8Array): Uint8Array = js.native
  def getSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array = js.native
  val utils: js.Dynamic = js.native

object X25519:
  val KeyBytes: Int = 32

  /** A fresh `(privateKey, publicKey)` pair, raw 32-byte each. */
  def generateKeyPair(): (Array[Byte], Array[Byte]) =
    val priv = Uint8.toBytes(nobleX25519.utils.randomPrivateKey().asInstanceOf[Uint8Array])
    (priv, publicKey(priv))

  /** The raw public key for a raw private key (deterministic): `X25519(priv, base)`. */
  def publicKey(privateKey: Array[Byte]): Array[Byte] =
    Uint8.toBytes(nobleX25519.getPublicKey(Uint8.toJs(privateKey)))

  // Curve25519 field prime p = 2^255 - 19 (RFC 7748). A well-formed peer u-coordinate satisfies
  // u < p after the unused top bit is masked; an out-of-range `p <= u < 2^255` encoding could
  // otherwise be reduced differently by different peers, silently disagreeing on the DH leg — a
  // cross-platform oracle. `scala.math.BigInt` (not java.math.BigInteger) so this stays Scala.js-safe.
  private val P25519: BigInt = (BigInt(1) << 255) - 19

  /** Reject a non-canonical peer u-coordinate (`u >= p` after masking bit 255) with
    * `IllegalArgumentException`. Pure validation over the PUBLIC, attacker-supplied peer bytes — no
    * secret-dependent branch, no curve arithmetic (Constitution I/II). Identical logic to the JVM
    * build so both platforms accept exactly the same encodings. */
  private def requireCanonicalU(peerPublic: Array[Byte]): Unit =
    require(peerPublic.length == KeyBytes, s"X25519 peer public key must be $KeyBytes bytes")
    var u = BigInt(0)
    var i = KeyBytes - 1
    while i >= 0 do
      val b = if i == KeyBytes - 1 then peerPublic(i) & 0x7f else peerPublic(i) & 0xff
      u = (u << 8) | BigInt(b)
      i -= 1
    require(u < P25519, "X25519: non-canonical peer u-coordinate (>= p)")

  /** The 32-byte X25519 shared secret between our raw private key and a raw peer public key.
    *
    * Peer keys arrive in headers / ciphertexts and are attacker-controllable, so the acceptance set
    * and the rejection exception are UNIFORM across platforms (pinned by `X25519Spec` /
    * `X25519JsSpec`), matching the JVM JCA build byte-for-byte on valid inputs:
    *   - a non-canonical encoding whose (bit-255-masked, little-endian) u-coordinate is `>= p` is
    *     rejected up front by `requireCanonicalU`;
    *   - a degenerate / low-order peer key (all-zero ECDH result) is rejected by `@noble/curves`
    *     throwing, which we NORMALIZE to `IllegalArgumentException` — the same exception type the JVM
    *     build raises, so callers (the classical `DoubleRatchet`, the hybrid `kem.HybridKem`) treat a
    *     rejected peer key uniformly on both platforms (an undecryptable / carrier frame). */
  def sharedSecret(privateKey: Array[Byte], peerPublic: Array[Byte]): Array[Byte] =
    requireCanonicalU(peerPublic)
    try Uint8.toBytes(nobleX25519.getSharedSecret(Uint8.toJs(privateKey), Uint8.toJs(peerPublic)))
    catch
      case e: js.JavaScriptException =>
        throw new IllegalArgumentException(s"X25519 peer key rejected: ${e.getMessage}", e)
