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

  /** The 32-byte X25519 shared secret between our raw private key and a raw peer public key.
    *
    * Peer keys arrive in headers / ciphertexts and are attacker-controllable, so the acceptance set
    * and the rejection exception are UNIFORM across platforms (pinned by `X25519Spec` /
    * `X25519JsSpec` + the shared `X25519RejectionCrossSpec`), byte-for-byte identical to the Scala.js
    * `@noble/curves` build on valid inputs:
    *   - a non-canonical encoding whose (bit-255-masked, little-endian) u-coordinate is `>= p` is
    *     rejected up front by the shared `CanonicalU.requireCanonical` (`PeerKeyRejected`);
    *   - a degenerate / low-order peer key — one whose contributory check fails, i.e. would yield the
    *     all-zero secret — is rejected: JCA raises `InvalidKeyException` from `doPhase`/`generateSecret`,
    *     which we NORMALIZE to `PeerKeyRejected` (the same dedicated type the JS build raises). The
    *     explicit all-zero check is a backstop for any JCA provider that returns the zero secret.
    * A wrong-length PRIVATE key is a LOCAL key-management error, not a peer rejection: it is rejected
    * up front with a plain `IllegalArgumentException`, and `privateFromRaw`/`ka.init` are kept OUTSIDE
    * the peer-key try so a private-key `InvalidKeyException` propagates un-normalized (never mislabeled
    * as a peer rejection). So callers (the classical `DoubleRatchet`, the hybrid `kem.HybridKem`) treat
    * a rejected peer key uniformly on both platforms (an undecryptable / carrier frame). */
  def sharedSecret(privateKey: Array[Byte], peerPublic: Array[Byte]): Array[Byte] =
    require(privateKey.length == KeyBytes, s"X25519 private key must be $KeyBytes bytes")
    CanonicalU.requireCanonical(peerPublic)
    val ka = KeyAgreement.getInstance("X25519")
    ka.init(privateFromRaw(privateKey)) // OUTSIDE the try: a local-key failure stays un-normalized.
    val secret =
      try
        ka.doPhase(publicFromRaw(peerPublic), true)
        ka.generateSecret()
      catch
        case e: java.security.InvalidKeyException =>
          throw new PeerKeyRejected(s"X25519 peer key rejected: ${e.getMessage}", e)
    // OR-accumulate every byte before the test (no short-circuit) so the all-zero scan is independent
    // of byte positions — Constitution II's constant-time discipline, even though the outcome here is
    // governed by the public, attacker-supplied peer key rather than our private scalar.
    var acc = 0
    var i = 0
    while i < secret.length do
      acc |= secret(i) & 0xff
      i += 1
    if acc == 0 then throw new PeerKeyRejected("X25519: degenerate (all-zero) shared secret")
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
