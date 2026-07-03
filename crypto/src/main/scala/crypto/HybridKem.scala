package crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

/** Hybrid post-quantum KEM: **X25519 (classical) ⊕ ML-KEM-768 (post-quantum)**.
  *
  * ==Why hybrid (US7 — harvest-now-decrypt-later)==
  * A network adversary can record ciphertext today and decrypt it years from now once a large
  * quantum computer exists. Defending *recorded* traffic requires a shared secret a future quantum
  * adversary cannot recover. This KEM runs BOTH an X25519 ECDH and an ML-KEM-768 encapsulation,
  * then mixes the two shared secrets: the result is secure as long as **either** leg is unbroken.
  * X25519 covers a classical break of a young PQ scheme; ML-KEM-768 (FIPS 203) covers a future
  * quantum break of X25519.
  *
  * ==Combiner==
  * The 32-byte hybrid shared secret is
  * {{{ SHA-256( label ++ ssX25519(32) ++ ssMlKem(32) ++ transcript ) }}}
  * with `transcript = ephemeralX25519RawPub ++ peerX25519RawPub ++ mlkemCiphertext`. Both KEM
  * shared secrets are fixed 32-byte outputs, so their concatenation is unambiguous (no length
  * framing needed). This is a standard "KDF over the concatenation of both shared secrets, bound
  * to both transcripts" hybrid combiner:
  *   - secure if either KEM is secure — an attacker who breaks only one leg still faces a
  *     preimage-resistant hash over a secret it cannot fully reconstruct;
  *   - binding the full transcript (ephemeral + static X25519 public keys and the PQ ciphertext)
  *     makes the derived key agreement-committing: tampering with EITHER leg's wire bytes changes
  *     the derived secret, so the two sides then fail to agree rather than silently sharing a key
  *     that reflects only one leg.
  *
  * The standardization target for exactly X25519 + ML-KEM-768 is **X-Wing**
  * (draft-connolly-cfrg-xwing-kem). This follows the same generic-combiner design (a hash over both
  * shared secrets + transcript, with domain separation) but is a SOUND GENERIC COMBINER over vetted
  * primitives, NOT a byte-for-byte X-Wing implementation (X-Wing fixes SHA3-256, a specific label,
  * and precise transcript framing; and uses a static — not ephemeral-per-encaps — X25519 share).
  * A spec-exact X-Wing and the cross-platform protocol-core handshake are the documented follow-up.
  *
  * ==Constitution==
  *   - I: no hand-rolled crypto — X25519 + SHA-256 via JCA, ML-KEM-768 via [[Oqs]]/liboqs. The
  *     combiner is a standard construction over those vetted primitives; no curve/hash/KEM here.
  *   - II: no secret-dependent branches; secrets compared constant-time ([[constantTimeEquals]]) and
  *     heap secret arrays best-effort zeroed. NOTE (as in [[Oqs]]): a copying GC may leave un-zeroed
  *     copies of the heap arrays this API returns — those are the caller's to manage.
  */
object HybridKem:

  // Raw X25519 public key = the 32-byte little-endian u-coordinate (RFC 7748).
  val X25519PublicKeyBytes: Int = 32
  val X25519SharedSecretBytes: Int = 32

  /** publicKey = x25519RawPub(32) ++ mlkemPub(1184) */
  val PublicKeyBytes: Int = X25519PublicKeyBytes + Oqs.MlKem768.PublicKeyBytes

  /** ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088) */
  val CiphertextBytes: Int = X25519PublicKeyBytes + Oqs.MlKem768.CiphertextBytes

  val SharedSecretBytes: Int = 32

  // Domain-separation label. Distinct from any real X-Wing label precisely because this is a
  // generic combiner, not spec-exact X-Wing — so its outputs never collide with an X-Wing KEM.
  private val Label: Array[Byte] =
    "Deppis-HybridKEM-v1 X25519+ML-KEM-768 (generic combiner)".getBytes("UTF-8")

  private val X25519 = NamedParameterSpec.X25519
  private def x25519KeyFactory: KeyFactory = KeyFactory.getInstance("XDH")

  /** Secret holder: the X25519 raw private scalar, our own X25519 raw public key (public, retained
    * so decaps can reproduce the transcript without a base-point mul JCA does not expose), and the
    * ML-KEM-768 secret key. Raw bytes (not opaque JCA keys) so [[HybridSecret.destroy]] can zero the
    * secret material best-effort. */
  final case class HybridSecret(
      x25519Private: Array[Byte],
      x25519PublicRaw: Array[Byte],
      mlkemSecret: Array[Byte]
  ):
    /** Best-effort zeroing of the retained SECRET material (Constitution II). The public key is not
      * secret and is left intact. */
    def destroy(): Unit =
      java.util.Arrays.fill(x25519Private, 0.toByte)
      java.util.Arrays.fill(mlkemSecret, 0.toByte)

  final case class HybridKeyPair(publicKey: Array[Byte], secret: HybridSecret)

  // ---- X25519 raw-key (de)serialization via JCA ----------------------------------------------

  /** JCA exposes the X25519 public key as the u-coordinate BigInteger; RFC 7748 wire format is its
    * 32-byte little-endian encoding (top bit unused). */
  private def x25519PubToRaw(pub: XECPublicKey): Array[Byte] =
    val u = pub.getU // unsigned magnitude, per JCA
    val be = u.toByteArray // big-endian, possibly with a sign byte / shorter than 32
    val raw = new Array[Byte](X25519PublicKeyBytes)
    // big-endian magnitude -> 32-byte little-endian, dropping any leading sign byte.
    var i = be.length - 1
    var j = 0
    while i >= 0 && j < X25519PublicKeyBytes do
      raw(j) = be(i)
      i -= 1
      j += 1
    raw

  private def x25519RawToPub(raw: Array[Byte]): XECPublicKey =
    require(raw.length == X25519PublicKeyBytes, "X25519 raw public key must be 32 bytes")
    // little-endian -> unsigned BigInteger; clear the unused top bit (RFC 7748 masks bit 255 on
    // decode) so we reconstruct exactly what a peer computes.
    val le = raw.clone()
    le(X25519PublicKeyBytes - 1) = (le(X25519PublicKeyBytes - 1) & 0x7f).toByte
    val be = new Array[Byte](X25519PublicKeyBytes)
    var i = 0
    while i < X25519PublicKeyBytes do
      be(i) = le(X25519PublicKeyBytes - 1 - i)
      i += 1
    val u = new BigInteger(1, be)
    x25519KeyFactory.generatePublic(new XECPublicKeySpec(X25519, u)).asInstanceOf[XECPublicKey]

  private def x25519ScalarOf(priv: XECPrivateKey): Array[Byte] =
    priv.getScalar.orElseThrow(() => new RuntimeException("X25519 private scalar unavailable"))

  /** X25519 ECDH producing the raw 32-byte shared secret from a raw private scalar + a peer raw
    * public key, via JCA `KeyAgreement`. No branch on the secret. */
  private def x25519Agree(privateScalar: Array[Byte], peerRaw: Array[Byte]): Array[Byte] =
    val priv =
      x25519KeyFactory.generatePrivate(new XECPrivateKeySpec(X25519, privateScalar.clone()))
    val ka = KeyAgreement.getInstance("XDH")
    ka.init(priv)
    ka.doPhase(x25519RawToPub(peerRaw), true)
    ka.generateSecret()

  // ---- The combiner --------------------------------------------------------------------------

  private def combine(
      ssX25519: Array[Byte],
      ssMlKem: Array[Byte],
      ephemeralX25519Raw: Array[Byte],
      peerX25519Raw: Array[Byte],
      mlkemCiphertext: Array[Byte]
  ): Array[Byte] =
    val md = MessageDigest.getInstance("SHA-256")
    md.update(Label)
    md.update(ssX25519) // 32 — fixed length ⇒ concatenation unambiguous
    md.update(ssMlKem) // 32 — fixed length
    // transcript: ephemeral (initiator) pub, responder (static) pub, PQ ciphertext.
    md.update(ephemeralX25519Raw)
    md.update(peerX25519Raw)
    md.update(mlkemCiphertext)
    md.digest() // 32 bytes == SharedSecretBytes

  // ---- Public KEM API ------------------------------------------------------------------------

  /** Generate a hybrid keypair. `publicKey = x25519RawPub(32) ++ mlkemPub(1184)`. */
  def hybridKeypair(): HybridKeyPair =
    val kpg = KeyPairGenerator.getInstance("XDH")
    kpg.initialize(X25519)
    val xkp = kpg.generateKeyPair()
    val xPubRaw = x25519PubToRaw(xkp.getPublic.asInstanceOf[XECPublicKey])
    val xPrivRaw = x25519ScalarOf(xkp.getPrivate.asInstanceOf[XECPrivateKey])

    val mlkem = Oqs.kemKeypair()
    val pub = xPubRaw ++ mlkem.publicKey
    HybridKeyPair(pub, HybridSecret(xPrivRaw, xPubRaw, mlkem.secretKey))

  private def splitPublicKey(peerPublicKey: Array[Byte]): (Array[Byte], Array[Byte]) =
    require(
      peerPublicKey.length == PublicKeyBytes,
      s"hybrid public key must be $PublicKeyBytes bytes"
    )
    val xPub = java.util.Arrays.copyOfRange(peerPublicKey, 0, X25519PublicKeyBytes)
    val mlkemPub = java.util.Arrays.copyOfRange(peerPublicKey, X25519PublicKeyBytes, PublicKeyBytes)
    (xPub, mlkemPub)

  /** Encapsulate to a peer's hybrid public key.
    * `ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088)`; `sharedSecret` = 32 bytes.
    */
  def hybridEncaps(peerPublicKey: Array[Byte]): (Array[Byte], Array[Byte]) =
    val (peerXRaw, peerMlkemPub) = splitPublicKey(peerPublicKey)

    // Ephemeral X25519 for forward secrecy of the classical leg.
    val kpg = KeyPairGenerator.getInstance("XDH")
    kpg.initialize(X25519)
    val eph = kpg.generateKeyPair()
    val ephPubRaw = x25519PubToRaw(eph.getPublic.asInstanceOf[XECPublicKey])
    val ephPrivRaw = x25519ScalarOf(eph.getPrivate.asInstanceOf[XECPrivateKey])

    var ssX: Array[Byte] = null
    var enc: Oqs.Encapsulation = null
    try
      ssX = x25519Agree(ephPrivRaw, peerXRaw)
      enc = Oqs.kemEncaps(peerMlkemPub)
      val ct = ephPubRaw ++ enc.ciphertext
      val ss = combine(ssX, enc.sharedSecret, ephPubRaw, peerXRaw, enc.ciphertext)
      (ct, ss)
    finally
      java.util.Arrays.fill(ephPrivRaw, 0.toByte)
      if ssX != null then java.util.Arrays.fill(ssX, 0.toByte)
      if enc != null then java.util.Arrays.fill(enc.sharedSecret, 0.toByte)

  /** Decapsulate: recover the 32-byte hybrid shared secret from a ciphertext + our secret. */
  def hybridDecaps(ciphertext: Array[Byte], secret: HybridSecret): Array[Byte] =
    require(
      ciphertext.length == CiphertextBytes,
      s"hybrid ciphertext must be $CiphertextBytes bytes"
    )
    val ephXRaw = java.util.Arrays.copyOfRange(ciphertext, 0, X25519PublicKeyBytes)
    val mlkemCt = java.util.Arrays.copyOfRange(ciphertext, X25519PublicKeyBytes, CiphertextBytes)

    var ssX: Array[Byte] = null
    var ssMl: Array[Byte] = null
    try
      // Classical leg: our static private × the peer's ephemeral public.
      ssX = x25519Agree(secret.x25519Private, ephXRaw)
      ssMl = Oqs.kemDecaps(mlkemCt, secret.mlkemSecret)
      // Same transcript order as encaps: ephemeral (initiator) pub, static (our) pub, PQ ciphertext.
      combine(ssX, ssMl, ephXRaw, secret.x25519PublicRaw, mlkemCt)
    finally
      if ssX != null then java.util.Arrays.fill(ssX, 0.toByte)
      if ssMl != null then java.util.Arrays.fill(ssMl, 0.toByte)

  /** Constant-time equality for comparing shared secrets (Constitution II) — no early-exit branch
    * on secret content. */
  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    MessageDigest.isEqual(a, b)
