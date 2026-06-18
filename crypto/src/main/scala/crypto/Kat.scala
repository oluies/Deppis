package crypto

/** Shared known-answer test vectors and hex helper, referenced by both `mcrypto kat` (CLI) and
  * `CryptoKatSpec` so the literals live in exactly one place (no drift). Vectors are published
  * standards values:
  *   - RFC 7693 Appendix A: BLAKE2b-512("abc")
  *   - RFC 8439 §2.8.2: ChaCha20-Poly1305 (IETF) AEAD
  * The crypto values here are public test data, not secrets. */
object Kat:
  def hex(s: String): Array[Byte] =
    s.filterNot(_.isWhitespace).grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  /** RFC 7693: BLAKE2b-512("abc"). */
  val Blake2b512Abc: Array[Byte] = hex(
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
  )

  /** RFC 8439 §2.8.2: ChaCha20-Poly1305 (IETF) AEAD. `ciphertext` is the 114-byte ciphertext
    * followed by the 16-byte Poly1305 tag (libsodium and the JDK both emit tag-appended). */
  object Rfc8439:
    val key: Array[Byte]   = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    val nonce: Array[Byte] = hex("070000004041424344454647")
    val aad: Array[Byte]   = hex("50515253c0c1c2c3c4c5c6c7")
    val plaintext: Array[Byte] =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        .getBytes("US-ASCII")
    val ciphertext: Array[Byte] = hex(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b6116" +
        "1ae10b594f09e26a7e902ecbd0600691"
    )
