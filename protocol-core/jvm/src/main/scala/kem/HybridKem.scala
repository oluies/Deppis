package kem

import crypto.{HybridKem => CryptoHybridKem}

/** Cross-platform hybrid post-quantum KEM — **JVM platform object** (the Scala.js counterpart is
  * `protocol-core/js/src/main/scala/kem/HybridKem.scala`). Same-named `object` per the protocol-core
  * platform convention (like `x25519.X25519`, `kdf.Kdf`) — NOT expect/actual: the JVM build links
  * this copy, the JS build links the js copy, shared code calls `kem.HybridKem` uniformly.
  *
  * This JVM implementation is a thin delegating adapter over the **vetted** `crypto.HybridKem`
  * (X25519 via JCA + ML-KEM-768 via liboqs/`crypto.Oqs`, plus its explicit low-order peer-key
  * validation). No crypto is reimplemented here (Constitution I) — only the secret is re-encoded
  * from `crypto.HybridKem`'s `HybridSecret` struct into the uniform cross-platform byte layout so the
  * JVM and JS APIs are identical.
  *
  * ==Uniform secret representation==
  * `crypto.HybridKem.HybridSecret` is a JVM struct the JS side cannot use, so both platforms expose
  * the hybrid secret as an OPAQUE `Array[Byte]` with a fixed layout:
  * {{{ secret = x25519Private(32) ++ x25519PublicRaw(32) ++ mlkemSecret(2400) }}} ⇒ 2464 bytes.
  *
  * ==Wire layouts (identical on both platforms)==
  *   - publicKey  = x25519RawPub(32) ++ mlkemPub(1184)                = 1216
  *   - ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088) = 1120
  *   - sharedSecret                                                    = 32
  *
  * ==Peer-key validation asymmetry (honest labeling)==
  * This JVM side (via `crypto.HybridKem`) performs an EXPLICIT X25519 low-order blocklist plus a
  * `u < p` range check, backed by SunEC's own small-order rejection and an all-zero backstop. The JS
  * side has NO explicit blocklist — it relies on `@noble/curves` throwing on a low-order / all-zero
  * result. Both REJECT attacker low-order keys, but by different mechanisms; see the JS file's doc.
  */
object HybridKem:

  /** publicKey = x25519RawPub(32) ++ mlkemPub(1184). */
  val PublicKeyBytes: Int = CryptoHybridKem.PublicKeyBytes // 1216

  /** ciphertext = ephemeralX25519RawPub(32) ++ mlkemCiphertext(1088). */
  val CiphertextBytes: Int = CryptoHybridKem.CiphertextBytes // 1120

  val SharedSecretBytes: Int = CryptoHybridKem.SharedSecretBytes // 32

  // Component sizes of the opaque secret layout.
  private val X25519PrivateBytes: Int = 32
  private val X25519PublicBytes: Int = 32
  private val MlKemSecretBytes: Int = 2400

  /** Opaque secret = x25519Private(32) ++ x25519PublicRaw(32) ++ mlkemSecret(2400). */
  val SecretKeyBytes: Int = X25519PrivateBytes + X25519PublicBytes + MlKemSecretBytes // 2464

  /** Generate a hybrid keypair. Returns `(publicKey 1216, secret 2464)`, the secret serialized into
    * the uniform opaque layout above. */
  def keypair(): (Array[Byte], Array[Byte]) =
    val kp = CryptoHybridKem.hybridKeypair()
    val s = kp.secret
    val secretBytes = new Array[Byte](SecretKeyBytes)
    System.arraycopy(s.x25519Private, 0, secretBytes, 0, X25519PrivateBytes)
    System.arraycopy(s.x25519PublicRaw, 0, secretBytes, X25519PrivateBytes, X25519PublicBytes)
    System.arraycopy(
      s.mlkemSecret,
      0,
      secretBytes,
      X25519PrivateBytes + X25519PublicBytes,
      MlKemSecretBytes
    )
    // The struct's own secret arrays are now redundant copies of the serialized bytes; zero them
    // (Constitution II). The caller owns `secretBytes`.
    s.destroy()
    (kp.publicKey, secretBytes)

  /** Encapsulate to a peer's hybrid public key. Returns `(ciphertext 1120, sharedSecret 32)`. Fresh
    * ephemeral X25519 per call (delegated to `crypto.HybridKem`). */
  def encaps(peerPublicKey: Array[Byte]): (Array[Byte], Array[Byte]) =
    CryptoHybridKem.hybridEncaps(peerPublicKey)

  /** Decapsulate: recover the 32-byte hybrid shared secret from a `ciphertext(1120)` and the opaque
    * `secret(2464)`. The reconstructed `crypto.HybridKem.HybridSecret` is best-effort zeroed in a
    * `finally` (Constitution II) — the caller's `secret` bytes are left intact. */
  def decaps(ciphertext: Array[Byte], secret: Array[Byte]): Array[Byte] =
    require(secret.length == SecretKeyBytes, s"hybrid secret must be $SecretKeyBytes bytes")
    val x25519Private = new Array[Byte](X25519PrivateBytes)
    val x25519PublicRaw = new Array[Byte](X25519PublicBytes)
    val mlkemSecret = new Array[Byte](MlKemSecretBytes)
    System.arraycopy(secret, 0, x25519Private, 0, X25519PrivateBytes)
    System.arraycopy(secret, X25519PrivateBytes, x25519PublicRaw, 0, X25519PublicBytes)
    System.arraycopy(
      secret,
      X25519PrivateBytes + X25519PublicBytes,
      mlkemSecret,
      0,
      MlKemSecretBytes
    )
    val reconstructed = CryptoHybridKem.HybridSecret(x25519Private, x25519PublicRaw, mlkemSecret)
    try CryptoHybridKem.hybridDecaps(ciphertext, reconstructed)
    finally reconstructed.destroy() // zero the reconstructed secret copies (Constitution II)

  /** The hybrid combiner, exposed for KAT pinning. Delegates to the ONE vetted, KAT-pinned combiner
    * in `crypto.HybridKem` — a pure, deterministic SHA-256 over
    * `Label ++ ssX25519(32) ++ ssMlKem(32) ++ ephemeralX25519Raw(32) ++ peerX25519Raw(32) ++
    * mlkemCiphertext(1088)`. The JS side replicates this byte-for-byte. */
  def combine(
      ssX25519: Array[Byte],
      ssMlKem: Array[Byte],
      ephemeralX25519Raw: Array[Byte],
      peerX25519Raw: Array[Byte],
      mlkemCiphertext: Array[Byte]
  ): Array[Byte] =
    CryptoHybridKem.combine(ssX25519, ssMlKem, ephemeralX25519Raw, peerX25519Raw, mlkemCiphertext)
