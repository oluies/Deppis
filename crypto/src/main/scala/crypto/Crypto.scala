package crypto

/** Thin AEAD + KDF facade over libsodium (T011). ChaCha20-Poly1305 (IETF) for AEAD, Blake2b for
  * hashing and a keyed-Blake2b KDF — the primitives chosen in the plan (Groove's stack). */
object Crypto:
  val KeyBytes: Int   = Sodium.KeyBytes
  val NonceBytes: Int = Sodium.NpubBytes

  def aeadSeal(key: Array[Byte], nonce: Array[Byte], ad: Array[Byte], plaintext: Array[Byte]): Array[Byte] =
    Sodium.aeadEncrypt(plaintext, ad, nonce, key)

  def aeadOpen(key: Array[Byte], nonce: Array[Byte], ad: Array[Byte], ciphertext: Array[Byte]): Either[String, Array[Byte]] =
    Sodium.aeadDecrypt(ciphertext, ad, nonce, key)

  /** Blake2b output length must be 16..64 bytes; key (if any) at most 64 bytes (libsodium
    * `crypto_generichash` bounds). */
  val MinHash: Int = 16
  val MaxHash: Int = 64
  val MaxKey: Int  = 64

  def blake2b(in: Array[Byte], outLen: Int = 32, key: Array[Byte] = Array.emptyByteArray): Array[Byte] =
    require(outLen >= MinHash && outLen <= MaxHash, s"Blake2b outLen must be $MinHash..$MaxHash, got $outLen")
    require(key.length <= MaxKey, s"Blake2b key must be <= $MaxKey bytes, got ${key.length}")
    Sodium.blake2b(in, outLen, key)

  /** KDF via keyed Blake2b: okm = Blake2b(key = ikm, in = salt ‖ info, outLen = len).
    * Single-call (no expand), so `len` is bounded by Blake2b's max output (64 bytes) and `ikm`
    * by the key max (64 bytes); larger requests are rejected with a clear error rather than a
    * native failure. A counter-mode expand step can be added if a caller ever needs >64 bytes. */
  def kdf(ikm: Array[Byte], salt: Array[Byte], info: Array[Byte], len: Int): Array[Byte] =
    require(ikm.length <= MaxKey, s"KDF ikm must be <= $MaxKey bytes, got ${ikm.length}")
    blake2b(salt ++ info, len, ikm)
