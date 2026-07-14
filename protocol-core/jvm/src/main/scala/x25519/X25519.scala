package x25519

import java.math.BigInteger
import java.security.interfaces.XECPrivateKey
import java.security.spec.{NamedParameterSpec, XECPrivateKeySpec, XECPublicKeySpec}
import java.security.{KeyFactory, KeyPairGenerator, PrivateKey, PublicKey, SecureRandom}
import javax.crypto.KeyAgreement

/** X25519 ECDH (JVM) over JCA (`KeyAgreement "X25519"`, JDK 11+, RFC 7748). The DH primitive for the
  * double ratchet's post-compromise security. Raw 32-byte little-endian keys throughout, byte-for-byte
  * identical to the Scala.js `@noble/curves` build — pinned by a cross-platform RFC 7748 KAT
  * (`X25519Spec`). A vetted primitive (Constitution I): the curve arithmetic is JCA's, never local. */
object X25519:
  val KeyBytes: Int = 32

  /** u = 9, the X25519 base point; `publicKey(priv) = X25519(priv, base)`. */
  private val BasePoint: Array[Byte] =
    val b = new Array[Byte](KeyBytes); b(0) = 9.toByte; b

  /** A fresh `(privateKey, publicKey)` pair, raw 32-byte each (the scalar is clamped by X25519). */
  def generateKeyPair(): (Array[Byte], Array[Byte]) =
    // Reuse JCA's keygen for a well-formed scalar, then take the raw scalar; the public key is derived
    // by the agreement against the base point (so the encoding path is identical on both platforms).
    val kpg = KeyPairGenerator.getInstance("X25519")
    kpg.initialize(NamedParameterSpec.X25519, new SecureRandom())
    val priv = kpg.generateKeyPair().getPrivate.asInstanceOf[XECPrivateKey].getScalar.get
    (priv, publicKey(priv))

  /** The raw public key for a raw private key (deterministic): `X25519(priv, base)`. */
  def publicKey(privateKey: Array[Byte]): Array[Byte] = sharedSecret(privateKey, BasePoint)

  // Curve25519 field prime p = 2^255 - 19 (RFC 7748). A well-formed peer u-coordinate satisfies
  // u < p after the unused top bit is masked; an out-of-range `p <= u < 2^255` encoding could
  // otherwise be reduced differently by different peers, silently disagreeing on the DH leg — a
  // cross-platform oracle. `scala.math.BigInt` so the check is byte-identical to the Scala.js build.
  private val P25519: BigInt = (BigInt(1) << 255) - 19

  /** Reject a non-canonical peer u-coordinate (`u >= p` after masking bit 255) with
    * `IllegalArgumentException`. Pure validation over the PUBLIC, attacker-supplied peer bytes — no
    * secret-dependent branch, no curve arithmetic (Constitution I/II). Identical logic to the
    * Scala.js build so both platforms accept exactly the same encodings. */
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
    * `X25519JsSpec`), byte-for-byte identical to the Scala.js `@noble/curves` build on valid inputs:
    *   - a non-canonical encoding whose (bit-255-masked, little-endian) u-coordinate is `>= p` is
    *     rejected up front by `requireCanonicalU` (`IllegalArgumentException`);
    *   - a degenerate / low-order peer key — one whose contributory check fails, i.e. would yield the
    *     all-zero secret — is rejected: JCA raises `InvalidKeyException`, which we NORMALIZE to
    *     `IllegalArgumentException` (the same type the JS build raises). The explicit all-zero check
    *     is a backstop for any JCA provider that returns the zero secret instead of rejecting it.
    * So callers (the classical `DoubleRatchet`, the hybrid `kem.HybridKem`) treat a rejected peer key
    * uniformly on both platforms (an undecryptable / carrier frame). */
  def sharedSecret(privateKey: Array[Byte], peerPublic: Array[Byte]): Array[Byte] =
    requireCanonicalU(peerPublic)
    val secret =
      try
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateFromRaw(privateKey))
        ka.doPhase(publicFromRaw(peerPublic), true)
        ka.generateSecret()
      catch
        case e: java.security.InvalidKeyException =>
          throw new IllegalArgumentException(s"X25519 peer key rejected: ${e.getMessage}", e)
    // OR-accumulate every byte before the test (no short-circuit) so the all-zero scan is independent
    // of byte positions — Constitution II's constant-time discipline, even though the outcome here is
    // governed by the public, attacker-supplied peer key rather than our private scalar.
    var acc = 0
    var i = 0
    while i < secret.length do
      acc |= secret(i) & 0xff
      i += 1
    if acc == 0 then
      throw new IllegalArgumentException("X25519: degenerate (all-zero) shared secret")
    secret

  private def privateFromRaw(raw: Array[Byte]): PrivateKey =
    KeyFactory
      .getInstance("X25519")
      .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, raw.clone()))

  private def publicFromRaw(raw: Array[Byte]): PublicKey =
    // raw is the little-endian u-coordinate; clear the high (sign) bit per RFC 7748, then big-endian.
    val u = raw.clone()
    u(KeyBytes - 1) = (u(KeyBytes - 1) & 0x7f).toByte
    val uInt = new BigInteger(1, u.reverse)
    KeyFactory
      .getInstance("X25519")
      .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, uInt))
