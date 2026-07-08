package kem

import engine.Uint8
import x25519.X25519
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Plain SHA-256 facade over **@noble/hashes** (audited, browser-safe — Constitution I). noble's
  * `sha256` is a callable hash: `sha256(msg) -> 32-byte digest`. This mirrors the JVM combiner's
  * `MessageDigest.getInstance("SHA-256")`. (kdf.Kdf imports the same module for HMAC; here we need
  * the bare hash.) */
@js.native
@JSImport("@noble/hashes/sha256", JSImport.Namespace)
private object Sha256Module extends js.Object:
  def sha256(msg: Uint8Array): Uint8Array = js.native

/** Cross-platform hybrid post-quantum KEM — **Scala.js platform object** (the JVM counterpart is
  * `protocol-core/jvm/src/main/scala/kem/HybridKem.scala`, which delegates to the vetted
  * `crypto.HybridKem`). Same-named `object` per the protocol-core platform convention (like
  * `x25519.X25519`, `kdf.Kdf`) — the JS build links this copy.
  *
  * This is **X25519 (classical) ⊕ ML-KEM-768 (post-quantum)**: it runs BOTH an X25519 ECDH and an
  * ML-KEM-768 encapsulation, then mixes the two shared secrets so the result is secure as long as
  * EITHER leg is unbroken (US7 — harvest-now-decrypt-later). Composed ONLY from vetted primitives —
  * `x25519.X25519` (`@noble/curves`), `kem.Kem` (`@noble/post-quantum` ML-KEM-768), and SHA-256
  * (`@noble/hashes`). No lattice/curve/hash arithmetic is implemented here (Constitution I).
  *
  * ==Interop contract (identical to the JVM `crypto.HybridKem`, byte-for-byte)==
  *   - publicKey  = x25519RawPub(32) ++ mlkemPub(1184)                 = 1216
  *   - secret     = x25519Private(32) ++ x25519PublicRaw(32) ++ mlkemSecret(2400) = 2464 (opaque)
  *   - ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088) = 1120
  *   - sharedSecret = SHA-256( Label ++ ssX25519(32) ++ ssMlKem(32) ++ ephemeralX25519Raw(32) ++
  *     peerX25519Raw(32) ++ mlkemCiphertext(1088) ) = 32, with the EXACT same `Label` string as the
  *     JVM combiner. A shared decaps KAT (generated on the JVM) is pinned in BOTH platforms' specs.
  *
  * ==Peer-key validation asymmetry (HONEST LABELING — do not paper over)==
  * The JVM side (via `crypto.HybridKem`) performs an EXPLICIT X25519 low-order blocklist plus a
  * `u < p` range check (backed by SunEC's small-order rejection and an all-zero backstop). THIS JS
  * side performs NO explicit blocklist and NO `u < p` range check — it relies on `@noble/curves`
  * THROWING on a low-order / all-zero X25519 result (see `x25519.X25519.sharedSecret`). Consequences,
  * stated honestly:
  *   - Low-order / non-contributory peer points: REJECTED on BOTH platforms (JVM blocklist+backstop;
  *     JS via noble's all-zero throw) — neither derives a key from such a point.
  *   - Non-canonical encodings with `p <= u < 2^255`: the JVM REJECTS these (`u < p` check); the JS
  *     side lets noble reduce `u mod p` and proceeds. So a peer key with a non-canonical X25519
  *     component is usable from a JS initiator but refused by a JVM initiator — an availability /
  *     interop divergence (NOT a confidentiality break). This file does NOT claim to run the JVM's
  *     explicit blocklist or range check. */
object HybridKem:

  // FIPS 203 ML-KEM-768 sizes (mirror crypto.Oqs.MlKem768 / the JVM constants).
  private val X25519KeyBytes: Int = 32
  private val MlKemPublicBytes: Int = 1184
  private val MlKemSecretBytes: Int = 2400
  private val MlKemCiphertextBytes: Int = 1088

  /** publicKey = x25519RawPub(32) ++ mlkemPub(1184). */
  val PublicKeyBytes: Int = X25519KeyBytes + MlKemPublicBytes // 1216

  /** ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088). */
  val CiphertextBytes: Int = X25519KeyBytes + MlKemCiphertextBytes // 1120

  val SharedSecretBytes: Int = 32

  /** Opaque secret = x25519Private(32) ++ x25519PublicRaw(32) ++ mlkemSecret(2400). */
  val SecretKeyBytes: Int = X25519KeyBytes + X25519KeyBytes + MlKemSecretBytes // 2464

  // Domain-separation label — MUST be byte-for-byte identical to crypto.HybridKem.Label so the two
  // platforms derive the same shared secret. UTF-8 bytes of this ASCII string.
  private val Label: Array[Byte] =
    "Deppis-HybridKEM-v1 X25519+ML-KEM-768 (generic combiner)".getBytes("UTF-8")

  /** Generate a hybrid keypair. Returns `(publicKey 1216, secret 2464)`.
    * `publicKey = x25519StaticPub ++ mlkemPub`; `secret = x25519Priv ++ x25519StaticPub ++ mlkemSk`.
    */
  def keypair(): (Array[Byte], Array[Byte]) =
    val (xPriv, xPub) = X25519.generateKeyPair()
    val (mlkemPub, mlkemSk) = Kem.keypair()
    val publicKey = xPub ++ mlkemPub
    val secret = xPriv ++ xPub ++ mlkemSk
    (publicKey, secret)

  /** Encapsulate to a peer's hybrid public key. Returns `(ciphertext 1120, sharedSecret 32)`. A
    * fresh ephemeral X25519 keypair is generated per call (forward secrecy of the classical leg). */
  def encaps(peerPublicKey: Array[Byte]): (Array[Byte], Array[Byte]) =
    require(
      peerPublicKey.length == PublicKeyBytes,
      s"hybrid public key must be $PublicKeyBytes bytes"
    )
    val peerXStatic = peerPublicKey.slice(0, X25519KeyBytes)
    val peerMlkemPub = peerPublicKey.slice(X25519KeyBytes, PublicKeyBytes)

    val (ephPriv, ephPub) = X25519.generateKeyPair()
    var ssX: Array[Byte] = null
    var ssMl: Array[Byte] = null
    try
      // Throws (via @noble/curves) on a low-order / all-zero peer point — matching the JVM reject.
      ssX = X25519.sharedSecret(ephPriv, peerXStatic)
      val (mlCt, ssMlOut) = Kem.encaps(peerMlkemPub)
      ssMl = ssMlOut
      val ciphertext = ephPub ++ mlCt
      val ss = combine(ssX, ssMl, ephPub, peerXStatic, mlCt)
      (ciphertext, ss)
    finally
      // Best-effort zero the ephemeral private + both leg secrets (Constitution II), mirroring the
      // JVM crypto.HybridKem.hybridEncaps finally block. Same caveat as JVM: noble's internal buffers
      // are outside our reach, so this is best-effort, not a guarantee.
      wipe(ephPriv)
      if ssX != null then wipe(ssX)
      if ssMl != null then wipe(ssMl)

  /** Decapsulate: recover the 32-byte hybrid shared secret from a `ciphertext(1120)` and the opaque
    * `secret(2464)`. */
  def decaps(ciphertext: Array[Byte], secret: Array[Byte]): Array[Byte] =
    require(
      ciphertext.length == CiphertextBytes,
      s"hybrid ciphertext must be $CiphertextBytes bytes"
    )
    require(secret.length == SecretKeyBytes, s"hybrid secret must be $SecretKeyBytes bytes")

    val ephX = ciphertext.slice(0, X25519KeyBytes)
    val mlCt = ciphertext.slice(X25519KeyBytes, CiphertextBytes)

    // Sliced COPIES of the secret key material (the caller's `secret` array is left intact).
    val x25519Priv = secret.slice(0, X25519KeyBytes)
    val x25519StaticPub = secret.slice(X25519KeyBytes, X25519KeyBytes + X25519KeyBytes)
    val mlkemSk = secret.slice(X25519KeyBytes + X25519KeyBytes, SecretKeyBytes)

    var ssX: Array[Byte] = null
    var ssMl: Array[Byte] = null
    try
      // Classical leg: our static private × the peer's ephemeral public (throws on low-order).
      ssX = X25519.sharedSecret(x25519Priv, ephX)
      ssMl = Kem.decaps(mlCt, mlkemSk)
      // Same transcript order as encaps: ephemeral (initiator) pub, static (our) pub, PQ ciphertext.
      combine(ssX, ssMl, ephX, x25519StaticPub, mlCt)
    finally
      // Best-effort zero the reconstructed private-key copies + both leg secrets (Constitution II),
      // mirroring the JVM adapter's `reconstructed.destroy()` and crypto.HybridKem's finally block.
      // x25519StaticPub is public — left intact. Best-effort only (noble buffers are unreachable).
      wipe(x25519Priv)
      wipe(mlkemSk)
      if ssX != null then wipe(ssX)
      if ssMl != null then wipe(ssMl)

  /** The hybrid combiner — SHA-256 over `Label ++ ssX25519(32) ++ ssMlKem(32) ++
    * ephemeralX25519Raw(32) ++ peerX25519Raw(32) ++ mlkemCiphertext(1088)`. Byte-for-byte identical
    * to `crypto.HybridKem.combine` (same Label, same field order, same digest). Both KEM shared
    * secrets are fixed 32-byte outputs, so their concatenation is unambiguous (no length framing). */
  def combine(
      ssX25519: Array[Byte],
      ssMlKem: Array[Byte],
      ephemeralX25519Raw: Array[Byte],
      peerX25519Raw: Array[Byte],
      mlkemCiphertext: Array[Byte]
  ): Array[Byte] =
    val msg = Label ++ ssX25519 ++ ssMlKem ++ ephemeralX25519Raw ++ peerX25519Raw ++ mlkemCiphertext
    Uint8.toBytes(Sha256Module.sha256(Uint8.toJs(msg)))

  /** Best-effort zero a secret byte array (Constitution II). Best-effort on both platforms: a moving
    * GC may have copied it, and noble's own internal buffers are outside our reach. */
  private def wipe(a: Array[Byte]): Unit = java.util.Arrays.fill(a, 0.toByte)
