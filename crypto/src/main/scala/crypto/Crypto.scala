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

  def blake2b(in: Array[Byte], outLen: Int = 32, key: Array[Byte] = Array.emptyByteArray): Array[Byte] =
    Sodium.blake2b(in, outLen, key)

  /** KDF via keyed Blake2b: okm = Blake2b(key = ikm, in = salt ‖ info, outLen = len). */
  def kdf(ikm: Array[Byte], salt: Array[Byte], info: Array[Byte], len: Int): Array[Byte] =
    Sodium.blake2b(salt ++ info, len, ikm)
