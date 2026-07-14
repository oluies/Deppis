package kem

import engine.Uint8
import x25519.X25519
import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array

/** Streaming SHA-256 facade over **@noble/hashes** (audited, browser-safe — Constitution I). We use
  * the INCREMENTAL API (`sha256.create().update(..)….digest()`) rather than the one-shot
  * `sha256(msg)` so `combine` never materializes a secret-bearing concatenation of the two KEM
  * shared secrets (Constitution II). `wrapConstructor` (noble 1.3.3) exposes `.create()` on the
  * `sha256` export; the returned hash's `update` absorbs the bytes into the hash state (it does not
  * retain the input array) and is chainable, and `digest()` returns a fresh 32-byte `Uint8Array`.
  * This mirrors the JVM combiner's streaming `MessageDigest.update(..)` calls. */
@js.native
@JSImport("@noble/hashes/sha256", JSImport.Namespace)
private object Sha256Module extends js.Object:
  val sha256: Sha256Fn = js.native

@js.native
private trait Sha256Fn extends js.Object:
  def create(): Sha256Hash = js.native

@js.native
private trait Sha256Hash extends js.Object:
  def update(data: Uint8Array): Sha256Hash = js.native
  def digest(): Uint8Array = js.native

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
  * ==Peer-key validation (identical outcome on both platforms)==
  * Peer X25519 material is attacker-controllable (it arrives in headers / ciphertexts), so both
  * platforms must accept the same encodings and raise the same exception type on rejection. This JS
  * side, via `x25519AgreeChecked`:
  *   - REJECTS a non-canonical encoding whose (bit-255-masked, little-endian) u-coordinate is
  *     `>= p` (p = 2^255-19), BEFORE the ECDH — matching the JVM `crypto.HybridKem` `u < p` range
  *     check. This is pure public-byte validation, not crypto (Constitution I).
  *   - REJECTS low-order / non-contributory (all-zero-result) peer points via `@noble/curves`
  *     THROWING (see `x25519.X25519.sharedSecret`), normalized to `IllegalArgumentException` — the
  *     same exception type the JVM adapter and both specs pin — so shared engine code catching
  *     `IllegalArgumentException` handles rejection uniformly on both platforms.
  * The two platforms therefore agree on which peer keys are accepted and on the thrown exception —
  * no availability / interop divergence (the JVM additionally runs an explicit small-subgroup
  * blocklist as a fast pre-check, but that is subsumed by noble's all-zero throw here). */
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
    // `mlkemSk` is populated inside the try so a throw from `Kem.keypair()` still runs the finally
    // (which then only has `xPriv` to wipe — `mlkemSk` is null-guarded), mirroring encaps/decaps.
    var mlkemSk: Array[Byte] = null
    try
      val (mlkemPub, mlkemSkOut) = Kem.keypair()
      mlkemSk = mlkemSkOut
      val publicKey = xPub ++ mlkemPub // both public — no secret intermediate
      // Assemble `secret` by copying the three parts into a preallocated buffer so NO intermediate
      // concatenation of secret material is ever materialized — a left-assoc `xPriv ++ xPub ++ mlkemSk`
      // would build an unwiped `(xPriv ++ xPub)` holding the private scalar. `xPub` is PUBLIC and
      // retained in both outputs — left intact.
      val secret = new Array[Byte](SecretKeyBytes)
      System.arraycopy(xPriv, 0, secret, 0, X25519KeyBytes)
      System.arraycopy(xPub, 0, secret, X25519KeyBytes, X25519KeyBytes)
      System.arraycopy(mlkemSk, 0, secret, X25519KeyBytes + X25519KeyBytes, MlKemSecretBytes)
      (publicKey, secret)
    finally
      // Zero the redundant private-key copies (Constitution II), mirroring the JVM adapter's
      // `HybridSecret.destroy()`. Runs on the happy path AND if any arraycopy/Kem.keypair throws.
      wipe(xPriv)
      if mlkemSk != null then wipe(mlkemSk)

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
      // Validates `u < p` then agrees, normalizing noble's low-order/degenerate throw to
      // IllegalArgumentException — cross-platform-uniform peer-key rejection (matching the JVM).
      ssX = x25519AgreeChecked(ephPriv, peerXStatic)
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
      // Classical leg: our static private × the peer's ephemeral public. Validates `u < p` then
      // agrees, normalizing noble's low-order/degenerate throw to IllegalArgumentException.
      ssX = x25519AgreeChecked(x25519Priv, ephX)
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
    // STREAM each field into SHA-256 (same order as crypto.HybridKem's MessageDigest.update calls) so
    // no secret-bearing CONCATENATION is ever materialized (Constitution II). The `Uint8Array` copies
    // of the two KEM shared secrets are zeroed the instant they are absorbed (noble's `update` copies
    // the bytes into the hash state and does not retain the input). The digest noble RETURNS *is* the
    // hybrid shared secret, so it is wiped after `Uint8.toBytes` copies it out for the caller. Byte
    // output is unchanged (combiner KAT fd00…69d8) — same Label, same field order, same digest.
    val h = Sha256Module.sha256.create()
    h.update(Uint8.toJs(Label)) // public domain-separation label
    var jsSsX: Uint8Array = null
    var jsSsMl: Uint8Array = null
    var digest: Uint8Array = null
    try
      jsSsX = Uint8.toJs(ssX25519)
      h.update(jsSsX) // secret: X25519 leg
      jsSsMl = Uint8.toJs(ssMlKem)
      h.update(jsSsMl) // secret: ML-KEM leg
      h.update(Uint8.toJs(ephemeralX25519Raw)) // public transcript
      h.update(Uint8.toJs(peerX25519Raw)) // public transcript
      h.update(Uint8.toJs(mlkemCiphertext)) // public transcript
      digest = h.digest()
      Uint8.toBytes(digest)
    finally
      // Zero every secret-bearing buffer we own regardless of a throw mid-stream (Constitution II):
      // the two KEM-shared-secret copies and the returned digest (itself the hybrid shared secret).
      // The public label/transcript copies need no wipe; noble's own state is self-zeroed by digest().
      if jsSsX != null then wipeJs(jsSsX)
      if jsSsMl != null then wipeJs(jsSsMl)
      if digest != null then wipeJs(digest)

  // Curve25519 field prime p = 2^255 - 19 (RFC 7748). A well-formed u-coordinate satisfies u < p
  // after the unused top bit is masked; an out-of-range `p <= u < 2^255` encoding could otherwise be
  // reduced differently by different peers, silently disagreeing on the classical leg. BigInt (not
  // java.math.BigInteger) so this stays Scala.js-compatible.
  private val P25519: BigInt = BigInt(2).pow(255) - 19

  /** Reject a non-canonical peer X25519 u-coordinate (`u >= p` after masking bit 255), matching the
    * JVM `crypto.HybridKem` `u < p` range check. Pure validation over the PUBLIC peer bytes — no
    * secret-dependent branch, no crypto (Constitution I/II). Throws `IllegalArgumentException`. */
  private def requireCanonicalX25519(raw: Array[Byte]): Unit =
    require(raw.length == X25519KeyBytes, s"X25519 raw public key must be $X25519KeyBytes bytes")
    // Interpret little-endian with bit 255 cleared (RFC 7748 ignores the top bit on decode).
    var u = BigInt(0)
    var i = X25519KeyBytes - 1
    while i >= 0 do
      val b = if i == X25519KeyBytes - 1 then raw(i) & 0x7f else raw(i) & 0xff
      u = (u << 8) | BigInt(b)
      i -= 1
    require(u < P25519, "X25519 peer u-coordinate is >= p")

  /** X25519 ECDH with cross-platform-uniform peer-key rejection: validates the peer u-coordinate is
    * canonical (`u < p`) BEFORE the ECDH, then normalizes `@noble/curves`' low-order / all-zero throw
    * (raised as `js.JavaScriptException`) to `IllegalArgumentException` — the same exception type the
    * JVM `crypto.HybridKem` raises for EVERY peer-key rejection, so shared engine code catching
    * `IllegalArgumentException` treats attacker peer material uniformly on both platforms. */
  private def x25519AgreeChecked(privateScalar: Array[Byte], peerRaw: Array[Byte]): Array[Byte] =
    requireCanonicalX25519(peerRaw)
    try X25519.sharedSecret(privateScalar, peerRaw)
    catch
      case e: js.JavaScriptException =>
        throw new IllegalArgumentException(s"X25519 peer key rejected: ${e.getMessage}", e)

  /** Best-effort zero a secret byte array (Constitution II). Best-effort on both platforms: a moving
    * GC may have copied it, and noble's own internal buffers are outside our reach. */
  private def wipe(a: Array[Byte]): Unit = java.util.Arrays.fill(a, 0.toByte)

  /** Zero a `Uint8Array` we own (e.g. the SHA-256 input copy in `combine`) — a real zeroization of
    * OUR buffer (Constitution II), not a best-effort reach into noble internals. */
  private def wipeJs(u: Uint8Array): Unit =
    var i = 0
    while i < u.length do
      u(i) = 0.toShort
      i += 1
