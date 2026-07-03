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
  *
  * ==Peer-key validation (classical leg)==
  * The X25519 leg rejects a non-contributory / malformed PUBLIC peer u-coordinate through three
  * layers (all raising a uniform `IllegalArgumentException`): (1) a fast blocklist of the known
  * small-subgroup encodings (bit-255-masked so top-bit twins collapse) plus a `u < p` range check;
  * (2) SunEC's own "Point has small order" rejection in the key agreement — the PRIMARY, exhaustive
  * small-order guard on the JDK provider, which catches low-order encodings absent from layer 1; and
  * (3) an all-zero shared-secret backstop for any provider that does NOT reject low-order points
  * (SunEC does, so on the JDK it throws before layer 3 — the layer stays for portability). Do not
  * remove the SunEC/all-zero layers on the assumption the blocklist is exhaustive. This keeps the
  * classical leg's "secure if either leg holds" contribution honest against a malicious peer key.
  * (A spec-exact X-Wing follow-up would fold this into the standard's own decode rules.)
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

  // Curve25519 field prime p = 2^255 - 19 (RFC 7748). A well-formed u-coordinate satisfies u < p
  // after the top bit is masked; an out-of-range p <= u < 2^255 encoding could otherwise be reduced
  // differently by different peers, silently disagreeing on the classical leg.
  private val P25519: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))

  /** The 32-byte little-endian encodings of the low-order Curve25519 u-coordinates (order 1, 2, 4,
    * and 8 points, plus the field-boundary encodings that reduce to them). A peer point equal to one
    * of these forces the RFC 7748 X25519 shared secret to all-zero regardless of our scalar, i.e. a
    * non-contributory point. Values from the standard small-subgroup list (RFC 7748 §7 / libsodium's
    * blocklist). Entries are stored bit-255-MASKED (top bit cleared) so the comparison in
    * [[validatePeerX25519]] matches an encoding whether or not the sender set the unused top bit
    * (X25519 masks bit 255 on decode, so `xxxx…b800` and `xxxx…b880` are the same point). */
  private val X25519LowOrderMasked: Array[Array[Byte]] =
    def le(hex: String): Array[Byte] =
      val b = new Array[Byte](X25519PublicKeyBytes)
      var i = 0
      while i < X25519PublicKeyBytes do
        b(i) = Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16).toByte
        i += 1
      // mask bit 255 (top bit of the last little-endian byte) so top-bit-set twins collapse.
      b(X25519PublicKeyBytes - 1) = (b(X25519PublicKeyBytes - 1) & 0x7f).toByte
      b
    Array(
      // 0 (order 1) and 1 (order 2)
      le("0000000000000000000000000000000000000000000000000000000000000000"),
      le("0100000000000000000000000000000000000000000000000000000000000000"),
      // order-4 / order-8 points
      le("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
      le("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
      // p-1, p, p+1 (the field-boundary encodings that reduce to the above)
      le("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
      le("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
      le("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    )

  /** Reject non-contributory / malformed peer u-coordinates (Finding 2): a low-order point drives
    * the RFC 7748 shared secret to all-zero, and an out-of-range encoding (u >= p) can be reduced
    * differently by different implementations. This validates the PUBLIC peer key only, so the
    * branch is not on secret data (Constitution II). Comparison of the (public) raw bytes is
    * constant-time.
    *
    * The blocklist is a best-effort fast reject; the LOAD-BEARING invariant is the all-zero
    * shared-secret check in [[x25519Agree]] — it catches EVERY non-contributory point (any encoding
    * whose masked value lies in the small subgroup) regardless of whether it appears here. Do not
    * remove that check on the assumption this list is exhaustive. */
  private def validatePeerX25519(raw: Array[Byte]): Unit =
    require(raw.length == X25519PublicKeyBytes, "X25519 raw public key must be 32 bytes")
    // Mask bit 255 on the peer bytes too, so the comparison matches the canonical encodings
    // regardless of the (ignored) top bit the sender may have set.
    val masked = raw.clone()
    masked(X25519PublicKeyBytes - 1) = (masked(X25519PublicKeyBytes - 1) & 0x7f).toByte
    val isLowOrder = X25519LowOrderMasked.exists(MessageDigest.isEqual(_, masked))
    require(!isLowOrder, "X25519 peer key is a low-order point (non-contributory)")
    // Masked (bit 255 cleared) u must be a canonical field element: u < p.
    require(x25519RawToBigInteger(raw).compareTo(P25519) < 0, "X25519 peer u-coordinate is >= p")

  /** Masked little-endian raw -> the u-coordinate BigInteger (bit 255 cleared per RFC 7748). */
  private def x25519RawToBigInteger(raw: Array[Byte]): BigInteger =
    val le = raw.clone()
    le(X25519PublicKeyBytes - 1) = (le(X25519PublicKeyBytes - 1) & 0x7f).toByte
    val be = new Array[Byte](X25519PublicKeyBytes)
    var i = 0
    while i < X25519PublicKeyBytes do
      be(i) = le(X25519PublicKeyBytes - 1 - i)
      i += 1
    new BigInteger(1, be)

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
    val u = x25519RawToBigInteger(raw)
    x25519KeyFactory.generatePublic(new XECPublicKeySpec(X25519, u)).asInstanceOf[XECPublicKey]

  private def x25519ScalarOf(priv: XECPrivateKey): Array[Byte] =
    priv.getScalar.orElseThrow(() => new RuntimeException("X25519 private scalar unavailable"))

  /** X25519 ECDH producing the raw 32-byte shared secret from a raw private scalar + a peer raw
    * public key, via JCA `KeyAgreement`. Rejects a non-contributory / malformed peer key through
    * THREE layers, so every one throws a uniform `IllegalArgumentException` (Finding 2):
    *   1. [[validatePeerX25519]] — fast reject of the known small-subgroup encodings and `u >= p`;
    *   2. SunEC's own "Point has small order" check in `doPhase` (an `InvalidKeyException` we
    *      re-wrap) — this is the primary, exhaustive small-order guard on the JDK provider and
    *      catches low-order encodings absent from the layer-1 blocklist;
    *   3. an all-zero shared-secret backstop for any provider that does NOT reject a low-order point
    *      (SunEC does, so it throws before we reach here — this layer must stay for portability).
    *
    * No branch on the secret; the all-zero check compares against a fixed zero buffer in constant
    * time. */
  private def x25519Agree(privateScalar: Array[Byte], peerRaw: Array[Byte]): Array[Byte] =
    validatePeerX25519(peerRaw)
    val priv =
      x25519KeyFactory.generatePrivate(new XECPrivateKeySpec(X25519, privateScalar.clone()))
    val ka = KeyAgreement.getInstance("XDH")
    ka.init(priv)
    try ka.doPhase(x25519RawToPub(peerRaw), true)
    catch
      // SunEC rejects low-order points here with InvalidKeyException("Point has small order");
      // surface it as our uniform peer-key rejection rather than a KeyException.
      case e: java.security.InvalidKeyException =>
        throw new IllegalArgumentException(s"X25519 peer key rejected: ${e.getMessage}", e)
    val ss = ka.generateSecret()
    // RFC 7748: an all-zero output means a non-contributory (low-order) peer point slipped through.
    if MessageDigest.isEqual(ss, new Array[Byte](ss.length)) then
      java.util.Arrays.fill(ss, 0.toByte)
      throw new IllegalArgumentException(
        "X25519 shared secret is all-zero (non-contributory point)"
      )
    ss

  // ---- The combiner --------------------------------------------------------------------------

  // package-private (not `private`) so the pinned combiner KAT in HybridKemSpec can drive it with
  // fixed inputs — pinning the byte output guards Label, field order, and the digest alg against a
  // silent change that would break interop with the JS `@noble/post-quantum` side (Finding 1).
  private[crypto] def combine(
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
